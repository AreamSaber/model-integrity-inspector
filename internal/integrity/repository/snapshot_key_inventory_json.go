package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Token scanning bounds nesting and per-object key metadata without building
// an arbitrary interface{} tree. It rejects duplicate AND case-folded aliases
// throughout nested JSON before encoding/json can silently choose a value.
func snapshotKeyStrictJSON(ctx context.Context, raw []byte) error {
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	if len(raw) == 0 || len(raw) > 8<<20 || !utf8.Valid(raw) {
		return errSnapshotKeyInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var visit func(int) error
	visit = func(depth int) error {
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		if depth > 32 {
			return errSnapshotKeyInvalid
		}
		token, err := decoder.Token()
		if err != nil {
			return errSnapshotKeyInvalid
		}
		delim, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				keyToken, err := decoder.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok || len(key) > 256 || len(seen) >= 8192 {
					return errSnapshotKeyInvalid
				}
				fold := snapshotKeyFoldName(key)
				if seen[fold] {
					return errSnapshotKeyInvalid
				}
				seen[fold] = true
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errSnapshotKeyInvalid
		}
		end, err := decoder.Token()
		if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
			return errSnapshotKeyInvalid
		}
		return nil
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errSnapshotKeyInvalid
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

// encoding/json matches object fields with Unicode SimpleFold, not ToLower.
// Choose one representative per rune cycle in linear key length, avoiding an
// O(number-of-keys squared) EqualFold search and preserving existing budgets.
func snapshotKeyFoldName(key string) string {
	var result strings.Builder
	result.Grow(len(key))
	for _, r := range key {
		minimum := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < minimum {
				minimum = next
			}
		}
		result.WriteRune(minimum)
	}
	return result.String()
}

// This narrow wire mirrors secret.wrappedKey (repository cannot import secret).
// It performs metadata/shape checks only, not AES/HKDF or authenticity checks.
func snapshotKeyEnvelope(ctx context.Context, raw []byte, column string) error {
	if len(raw) > 1024 {
		return errSnapshotKeyInvalid
	}
	if err := snapshotKeyStrictJSON(ctx, raw); err != nil {
		return err
	}
	object, ok := snapshotKeyObject(raw)
	if !ok || len(object) != 5 {
		return errSnapshotKeyInvalid
	}
	for _, name := range []string{"version", "algorithm", "key_version", "nonce", "ciphertext"} {
		if _, present := object[name]; !present {
			return errSnapshotKeyInvalid
		}
	}
	var wrapped struct {
		Version    int    `json:"version"`
		Algorithm  string `json:"algorithm"`
		KeyVersion string `json:"key_version"`
		Nonce      []byte `json:"nonce"`
		Ciphertext []byte `json:"ciphertext"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wrapped) != nil || wrapped.Version != 1 || wrapped.Algorithm != "AES-256-GCM" || wrapped.KeyVersion != column || !responseEvidenceVersion.MatchString(column) || len(wrapped.Nonce) != 12 || len(wrapped.Ciphertext) != 48 {
		return errSnapshotKeyInvalid
	}
	// The wrapper JSON encoding is not itself the typed record AAD used by
	// secret.unwrap, which accepts unambiguous field order/whitespace. Keep those
	// original bytes; requiring today's encoder output would reject decryptable
	// history. Exact names, types and duplicate/case rejection remain mandatory.
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

func snapshotKeyObject(raw []byte) (map[string]json.RawMessage, bool) {
	var object map[string]json.RawMessage
	err := json.Unmarshal(raw, &object)
	return object, err == nil && object != nil
}

// Single wrong-case critical names must not disappear into a legacy branch.
func snapshotKeyExactNames(object map[string]json.RawMessage, names ...string) bool {
	for key := range object {
		for _, name := range names {
			if strings.EqualFold(key, name) && key != name {
				return false
			}
		}
	}
	return true
}

func snapshotKeyJSONString(raw json.RawMessage) (string, bool) {
	var value string
	err := json.Unmarshal(raw, &value)
	return value, len(raw) > 0 && string(raw) != "null" && err == nil
}

func snapshotKeyManifest(ctx context.Context, raw []byte, row snapshotKeyRow, estimate bool) (string, int, error) {
	if err := snapshotKeyStrictJSON(ctx, raw); err != nil {
		return "", 0, err
	}
	outer, ok := snapshotKeyObject(raw)
	if !ok || !snapshotKeyExactNames(outer, "plan") {
		return "", 0, errSnapshotKeyInvalid
	}
	legacy := func() (string, int, error) {
		if estimate || row.AnalysisSource != AnalysisSourceLegacyV1 {
			return "", 0, errSnapshotKeyInvalid
		}
		return "", 2, nil
	}
	planRaw, present := outer["plan"]
	if !present {
		return legacy()
	}
	plan, ok := snapshotKeyObject(planRaw)
	if !ok || !snapshotKeyExactNames(plan, "manifest", "manifest_hash", "analysis_source_version") {
		return "", 0, errSnapshotKeyInvalid
	}
	if hashRaw, present := plan["manifest_hash"]; present {
		hash, ok := snapshotKeyJSONString(hashRaw)
		if !ok || hash != row.ManifestHash {
			return "", 0, errSnapshotKeyInvalid
		}
	}
	manifest, present := plan["manifest"]
	if !present {
		return legacy()
	}
	if len(manifest) == 0 || len(manifest) > 2<<20 || !executionHash.MatchString(row.ManifestHash) {
		return "", 0, errSnapshotKeyInvalid
	}
	planHash, ok := snapshotKeyJSONString(plan["manifest_hash"])
	hash := sha256.Sum256(manifest)
	if !ok || planHash != row.ManifestHash || hex.EncodeToString(hash[:]) != row.ManifestHash {
		return "", 0, errSnapshotKeyInvalid
	}
	m, ok := snapshotKeyObject(manifest)
	if !ok {
		return "", 0, errSnapshotKeyInvalid
	}
	// Current generator's complete top-level field set. Unknown implementations
	// need their actual historical codec: never substitute today's generator.
	version, ok := snapshotKeyJSONString(m["generator_version"])
	if !ok || version == "" {
		return "", 0, errSnapshotKeyInvalid
	}
	if version != "1.0.0-dev.1" {
		return "", 0, errSnapshotKeyUnsupported
	}
	allowed := []string{"generator_version", "options", "run_nonce", "key_version", "template_version", "template_hash", "tokenizer_version", "tokenizer_hash", "samples", "omissions", "warnings", "completeness", "projection", "integrity"}
	if len(m) != len(allowed) {
		return "", 0, errSnapshotKeyInvalid
	}
	for _, key := range allowed {
		if _, ok := m[key]; !ok {
			return "", 0, errSnapshotKeyInvalid
		}
	}
	key, ok := snapshotKeyJSONString(m["key_version"])
	if !ok || !responseEvidenceVersion.MatchString(key) {
		return "", 0, errSnapshotKeyInvalid
	}
	mac, ok := snapshotKeyJSONString(m["integrity"])
	if !ok || !executionHash.MatchString(mac) {
		return "", 0, errSnapshotKeyInvalid
	}
	options, ok := snapshotKeyObject(m["options"])
	if !ok || !snapshotKeyExactNames(options, "organization_id", "analysis_source_version") {
		return "", 0, errSnapshotKeyInvalid
	}
	org, ok := snapshotKeyJSONString(options["organization_id"])
	if !ok || org != strconv.FormatInt(row.OrganizationID, 10) {
		return "", 0, errSnapshotKeyInvalid
	}
	if !estimate {
		mode := AnalysisSourceLegacyV1
		if source, present := options["analysis_source_version"]; present {
			value, ok := snapshotKeyJSONString(source)
			if !ok || (value != "" && value != "mii.derived-s1.v1") {
				return "", 0, errSnapshotKeyInvalid
			}
			if value != "" {
				mode = value
			}
		}
		if mode != row.AnalysisSource {
			return "", 0, errSnapshotKeyInvalid
		}
	}
	if ctx.Err() != nil {
		return "", 0, ErrUnavailable
	}
	return key, 1, nil
}
