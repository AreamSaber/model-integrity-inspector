package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

type snapshotResultObservation struct {
	refs                map[snapshotResultReference]struct{}
	schema              string
	incomplete, unknown bool
	samples             []snapshotResultSampleReference
}
type snapshotResultSampleReference struct {
	id                      int64
	ordinal                 int64
	hasOrdinal              bool
	memberID, memberVersion string
}

// These are finite structural budgets, not online current-version admission.
// Unicode aliases use the existing SimpleFold helper. Never run a current
// analyzer, regenerate a manifest, or manufacture a hash during observation.
func snapshotResultStrictJSON(ctx context.Context, raw []byte) error {
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	if len(raw) == 0 || len(raw) > snapshotResultReferenceMaxBytes || !utf8.Valid(raw) {
		return errSnapshotResultReferenceInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tokens := 0
	var visit func(int) error
	visit = func(depth int) error {
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		if depth > 64 || tokens >= 200000 {
			return errSnapshotResultReferenceLimit
		}
		tokens++
		t, err := d.Token()
		if err != nil {
			return errSnapshotResultReferenceInvalid
		}
		open, compound := t.(json.Delim)
		if !compound {
			return nil
		}
		switch open {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				name, ok := k.(string)
				if err != nil || !ok {
					return errSnapshotResultReferenceInvalid
				}
				if len(name) > 128 || len(seen) >= 8192 {
					return errSnapshotResultReferenceLimit
				}
				fold := snapshotKeyFoldName(name)
				if seen[fold] {
					return errSnapshotResultReferenceInvalid
				}
				seen[fold] = true
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errSnapshotResultReferenceInvalid
		}
		end, err := d.Token()
		if err != nil || open == '{' && end != json.Delim('}') || open == '[' && end != json.Delim(']') {
			return errSnapshotResultReferenceInvalid
		}
		return nil
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errSnapshotResultReferenceInvalid
	}
	return nil
}

func snapshotResultObject(parent map[string]json.RawMessage, key string) (map[string]json.RawMessage, bool, error) {
	if !snapshotKeyExactNames(parent, key) {
		return nil, false, errSnapshotResultReferenceInvalid
	}
	raw, present := parent[key]
	if !present {
		return nil, false, nil
	}
	object, ok := snapshotKeyObject(raw)
	if !ok {
		return nil, true, errSnapshotResultReferenceInvalid
	}
	return object, true, nil
}
func snapshotResultString(parent map[string]json.RawMessage, key string, hash, empty bool) (string, bool, error) {
	if !snapshotKeyExactNames(parent, key) {
		return "", false, errSnapshotResultReferenceInvalid
	}
	raw, present := parent[key]
	if !present {
		return "", false, nil
	}
	value, ok := snapshotKeyJSONString(raw)
	if !ok || hash && !executionHash.MatchString(value) || !hash && (!empty || value != "") && !executionLabel.MatchString(value) {
		return "", true, errSnapshotResultReferenceInvalid
	}
	return value, true, nil
}
func snapshotResultDecimal(parent map[string]json.RawMessage, key string) (int64, bool, error) {
	value, present, err := snapshotResultString(parent, key, false, false)
	if err != nil || !present {
		return 0, present, err
	}
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id < 1 || strconv.FormatInt(id, 10) != value {
		return 0, true, errSnapshotResultReferenceInvalid
	}
	return id, true, nil
}

// Tokenizer implementation IDs are not execution bundle labels. The actual
// BPE implementation contains '+' and '@'; tokenrisk's producer accepts the
// bounded UTF-8 identifier wire below (and excludes unavailable from Series).
func snapshotResultTokenizerID(parent map[string]json.RawMessage, key string, empty bool) (string, bool, error) {
	if !snapshotKeyExactNames(parent, key) {
		return "", false, errSnapshotResultReferenceInvalid
	}
	raw, present := parent[key]
	if !present {
		return "", false, nil
	}
	value, ok := snapshotKeyJSONString(raw)
	if !ok || !empty && value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
		return "", true, errSnapshotResultReferenceInvalid
	}
	return value, true, nil
}
func snapshotResultArray(parent map[string]json.RawMessage, key string, limit int) ([]map[string]json.RawMessage, bool, error) {
	if !snapshotKeyExactNames(parent, key) {
		return nil, false, errSnapshotResultReferenceInvalid
	}
	raw, present := parent[key]
	if !present {
		return nil, false, nil
	}
	var items []json.RawMessage
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &items) != nil {
		return nil, true, errSnapshotResultReferenceInvalid
	}
	if len(items) > limit {
		return nil, true, errSnapshotResultReferenceLimit
	}
	objects := make([]map[string]json.RawMessage, 0, len(items))
	for _, item := range items {
		object, ok := snapshotKeyObject(item)
		if !ok {
			return nil, true, errSnapshotResultReferenceInvalid
		}
		objects = append(objects, object)
	}
	return objects, true, nil
}

func snapshotResultReferenceDocument(ctx context.Context, row snapshotResultReferenceRow, run snapshotReferenceRow, source snapshotReferenceObservation, raw []byte, limit int) (snapshotResultObservation, error) {
	zero := snapshotResultObservation{}
	if err := snapshotResultStrictJSON(ctx, raw); err != nil {
		return zero, err
	}
	root, ok := snapshotKeyObject(raw)
	if !ok {
		return zero, errSnapshotResultReferenceUnsupported
	}
	if !snapshotKeyExactNames(root, "schema_version") {
		return zero, errSnapshotResultReferenceInvalid
	}
	schema, present, err := snapshotResultString(root, "schema_version", false, false)
	if err != nil {
		return zero, err
	}
	out := snapshotResultObservation{refs: map[snapshotResultReference]struct{}{}, schema: schema, incomplete: source.legacy}
	if !present || schema != "mii.analysis.v1" {
		// Unknown codecs are retained as original bytes + an explicit gap. Do
		// not guess that their similarly spelled fields use today's protocol.
		out.incomplete, out.unknown = true, true
		return out, nil
	}
	add := func(role, version, digest, member, container, containerHash, qualifier string) error {
		if version == "" && digest == "" && member == "" {
			return nil
		}
		ref := snapshotResultReference{row.OrganizationID, source.versions, role, version, digest, member, container, containerHash, qualifier}
		if _, found := out.refs[ref]; !found && len(out.refs) >= limit {
			return errSnapshotResultReferenceLimit
		}
		out.refs[ref] = struct{}{}
		return nil
	}
	features, found, err := snapshotResultObject(root, "features")
	if err != nil {
		return zero, err
	}
	if !found {
		out.incomplete = true
	}
	for key, want := range map[string]int64{"organization_id": row.OrganizationID, "run_id": row.RunID} {
		id, found, err := snapshotResultDecimal(features, key)
		if err != nil || found && id != want {
			return zero, errSnapshotResultReferenceInvalid
		}
		if !found {
			out.incomplete = true
		}
	}
	manifestHash, found, err := snapshotResultString(features, "manifest_hash", true, false)
	if err != nil || found && manifestHash != run.ManifestHash {
		return zero, errSnapshotResultReferenceInvalid
	}
	if !found {
		out.incomplete = true
	}
	featureVersion, found, err := snapshotResultString(features, "version", false, false)
	if err != nil {
		return zero, err
	}
	if !found {
		out.incomplete = true
	}
	if err := add("feature_implementation", featureVersion, "", "", "", "", ""); err != nil {
		return zero, err
	}
	scores, found, err := snapshotResultObject(root, "scores")
	if err != nil {
		return zero, err
	}
	if !found {
		out.incomplete = true
	}
	scoreVersion, found, err := snapshotResultString(scores, "Version", false, false)
	if err != nil || found && scoreVersion != run.Scoring {
		return zero, errSnapshotResultReferenceInvalid
	}
	if !found {
		out.incomplete = true
	}
	scoreHash, found, err := snapshotResultString(scores, "RulesHash", true, false)
	if err != nil {
		return zero, err
	}
	if !found {
		out.incomplete = true
	}
	if err := add("scoring_parameters", scoreVersion, scoreHash, "", "", "", ""); err != nil {
		return zero, err
	}
	boundTokenHash, found, err := snapshotResultString(scores, "TokenRulesHash", true, false)
	if err != nil {
		return zero, err
	}
	if !found {
		out.incomplete = true
	}
	tokens, found, err := snapshotResultObject(root, "tokens")
	if err != nil {
		return zero, err
	}
	if !found {
		out.incomplete = true
	}
	tokenVersion, found, err := snapshotResultString(tokens, "Version", false, false)
	if err != nil {
		return zero, err
	}
	if !found {
		out.incomplete = true
	}
	tokenHash, found, err := snapshotResultString(tokens, "RulesHash", true, false)
	if err != nil {
		return zero, err
	}
	if !found {
		out.incomplete = true
	}
	if boundTokenHash != "" && tokenHash != "" && boundTokenHash != tokenHash {
		return zero, errSnapshotResultReferenceInvalid
	}
	if err := add("tokenrisk_parameters", tokenVersion, tokenHash, "", "", "", ""); err != nil {
		return zero, err
	}
	if err := add("scoring_tokenrisk_binding", tokenVersion, boundTokenHash, "", scoreVersion, "", ""); err != nil {
		return zero, err
	}
	behavior, found, err := snapshotResultObject(root, "behavior")
	if err != nil {
		return zero, err
	}
	if !found {
		out.incomplete = true
	}
	behaviorVersion, found, err := snapshotResultString(behavior, "version", false, false)
	if err != nil {
		return zero, err
	}
	if !found {
		out.incomplete = true
	}
	if err := add("behavior_implementation", behaviorVersion, "", "", "", "", ""); err != nil {
		return zero, err
	}
	members, found, err := snapshotResultArray(features, "samples", 1000)
	if err != nil {
		return zero, err
	}
	if !found {
		out.incomplete = true
	}
	if found && !source.legacy && len(members) != len(source.members) {
		return zero, errSnapshotResultReferenceInvalid
	}
	seenIDs, seenOrdinals := map[int64]bool{}, map[int64]bool{}
	for _, sample := range members {
		if ctx.Err() != nil {
			return zero, ErrUnavailable
		}
		member, partial, err := snapshotResultMember(sample, source)
		if err != nil {
			return zero, err
		}
		out.incomplete = out.incomplete || partial
		if member.id > 0 {
			if seenIDs[member.id] {
				return zero, errSnapshotResultReferenceInvalid
			}
			seenIDs[member.id] = true
		}
		if member.hasOrdinal && !source.legacy {
			if seenOrdinals[member.ordinal] {
				return zero, errSnapshotResultReferenceInvalid
			}
			seenOrdinals[member.ordinal] = true
		}
		out.samples = append(out.samples, member)
		if err := add("template_member", member.memberVersion, "", member.memberID, source.versions.Template, source.templateHash, ""); err != nil {
			return zero, err
		}
		for _, field := range []string{"structure", "behavior"} {
			object, found, err := snapshotResultObject(sample, field)
			if err != nil {
				return zero, err
			}
			if !found {
				continue
			}
			version, found, err := snapshotResultString(object, "version", false, false)
			if err != nil {
				return zero, err
			}
			if !found {
				out.incomplete = true
			}
			if field == "behavior" && version != "" && behaviorVersion != "" && version != behaviorVersion {
				return zero, errSnapshotResultReferenceInvalid
			}
			if field == "behavior" {
				id, found, err := snapshotResultDecimal(object, "sample_id")
				if err != nil || found && member.id > 0 && id != member.id {
					return zero, errSnapshotResultReferenceInvalid
				}
				if found {
					bound := member
					bound.id = id
					out.samples = append(out.samples, bound)
				}
			}
			if err := add(field+"_implementation", version, "", "", "", "", ""); err != nil {
				return zero, err
			}
		}
		local, found, err := snapshotResultObject(sample, "local")
		if err != nil {
			return zero, err
		}
		if found {
			version, vFound, err := snapshotResultString(local, "bundle_version", false, false)
			if err != nil || vFound && version != source.versions.Tokenizer {
				return zero, errSnapshotResultReferenceInvalid
			}
			digest, hFound, err := snapshotResultString(local, "bundle_hash", true, false)
			if err != nil || hFound && source.tokenizerHash != "" && digest != source.tokenizerHash {
				return zero, errSnapshotResultReferenceInvalid
			}
			if !vFound || !hFound {
				out.incomplete = true
			}
			if err := add("tokenizer_configuration", version, digest, "", "", "", ""); err != nil {
				return zero, err
			}
			implementation, iFound, err := snapshotResultTokenizerID(local, "tokenizer_version", true)
			if err != nil {
				return zero, err
			}
			encoding, _, err := snapshotResultTokenizerID(local, "tokenizer_id", true)
			if err != nil {
				return zero, err
			}
			if !iFound || implementation == "" {
				out.incomplete = true
			}
			if err := add("tokenizer_implementation", implementation, "", "", version, digest, encoding); err != nil {
				return zero, err
			}
		}
	}
	for _, key := range []string{"samples", "auxiliary_samples"} {
		items, found, err := snapshotResultArray(behavior, key, 1000)
		if err != nil {
			return zero, err
		}
		if !found {
			out.incomplete = true
		}
		seenBehavior := map[int64]bool{}
		for _, item := range items {
			version, found, err := snapshotResultString(item, "version", false, false)
			if err != nil || found && behaviorVersion != "" && version != behaviorVersion {
				return zero, errSnapshotResultReferenceInvalid
			}
			if !found {
				out.incomplete = true
			}
			id, found, err := snapshotResultDecimal(item, "sample_id")
			if err != nil || found && (seenBehavior[id] || len(seenIDs) > 0 && !seenIDs[id]) {
				return zero, errSnapshotResultReferenceInvalid
			}
			if !found {
				out.incomplete = true
			}
			if found {
				seenBehavior[id] = true
				out.samples = append(out.samples, snapshotResultSampleReference{id: id})
			}
			if err := add("behavior_implementation", version, "", "", "", "", ""); err != nil {
				return zero, err
			}
		}
	}
	series, _, err := snapshotResultArray(tokens, "Series", 1000)
	if err != nil {
		return zero, err
	}
	for _, item := range series {
		version, found, err := snapshotResultTokenizerID(item, "TokenizerVersion", false)
		if err != nil {
			return zero, err
		}
		if !found {
			out.incomplete = true
		}
		encoding, _, err := snapshotResultTokenizerID(item, "TokenizerID", false)
		if err != nil {
			return zero, err
		}
		if err := add("tokenizer_implementation", version, "", "", source.versions.Tokenizer, source.tokenizerHash, encoding); err != nil {
			return zero, err
		}
	}
	if ctx.Err() != nil {
		return zero, ErrUnavailable
	}
	return out, nil
}

func snapshotResultMember(object map[string]json.RawMessage, source snapshotReferenceObservation) (snapshotResultSampleReference, bool, error) {
	var out snapshotResultSampleReference
	partial := false
	id, found, err := snapshotResultDecimal(object, "sample_id")
	if err != nil {
		return out, false, err
	}
	out.id = id
	if !found {
		partial = true
	}
	if !snapshotKeyExactNames(object, "ordinal") {
		return out, false, errSnapshotResultReferenceInvalid
	}
	if raw, present := object["ordinal"]; present {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &out.ordinal) != nil || out.ordinal < 0 {
			return out, false, errSnapshotResultReferenceInvalid
		}
		out.hasOrdinal = true
	} else {
		partial = true
	}
	out.memberID, found, err = snapshotResultString(object, "template_id", false, false)
	if err != nil {
		return out, false, err
	}
	if !found {
		partial = true
	}
	out.memberVersion, found, err = snapshotResultString(object, "template_version", false, false)
	if err != nil {
		return out, false, err
	}
	if !found {
		partial = true
	}
	if !source.legacy && out.hasOrdinal {
		if out.ordinal >= int64(len(source.members)) {
			return out, false, errSnapshotResultReferenceInvalid
		}
		expected := source.members[out.ordinal]
		if out.memberID != "" && out.memberID != expected.ID || out.memberVersion != "" && out.memberVersion != expected.Version {
			return out, false, errSnapshotResultReferenceInvalid
		}
	} else if len(source.members) > 0 && (out.memberID != "" || out.memberVersion != "") {
		matched := false
		for _, member := range source.members {
			if (out.memberID == "" || out.memberID == member.ID) && (out.memberVersion == "" || out.memberVersion == member.Version) {
				matched = true
				break
			}
		}
		if !matched {
			return out, false, errSnapshotResultReferenceInvalid
		}
	} else {
		partial = true
	}
	return out, partial, nil
}
