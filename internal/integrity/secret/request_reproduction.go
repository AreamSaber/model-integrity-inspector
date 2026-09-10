package secret

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/evidencedisplay"
)

var ErrRequestReproductionUnavailable = errors.New("MI_REQUEST_REPRODUCTION_UNAVAILABLE")

// RequestReproductionBinding must come from a future fenced persistence
// boundary. A valid binding authenticates bytes, not authorization or retention
// policy. All times are Unix UTC microseconds. No response receipt is required.
type RequestReproductionBinding struct {
	Scope            EvidenceScope
	ManifestHash     string
	CapturedAtMicros int64
	ExpiresAtMicros  int64
}

type RequestReproductionRecord struct {
	Version        int
	Policy         string
	KeyVersion     string
	Nonce          []byte
	Ciphertext     []byte
	PlaintextBytes int
	PayloadHash    string
}

func (RequestReproductionBinding) String() string               { return "[request reproduction binding]" }
func (v RequestReproductionBinding) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (RequestReproductionBinding) MarshalJSON() ([]byte, error) {
	return nil, evidencedisplay.ErrSensitive
}
func (v RequestReproductionBinding) LogValue() slog.Value      { return slog.StringValue(v.String()) }
func (RequestReproductionRecord) String() string               { return "[encrypted request reproduction]" }
func (v RequestReproductionRecord) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (RequestReproductionRecord) MarshalJSON() ([]byte, error) {
	return nil, evidencedisplay.ErrSensitive
}
func (v RequestReproductionRecord) LogValue() slog.Value { return slog.StringValue(v.String()) }

// These immutable capabilities copy only request-reproduction purpose keys;
// neither retains KeyRing nor permits raw/response-display/credential access.
type RequestReproductionSealer struct {
	version string
	key     [32]byte
	now     func() time.Time
}
type RequestReproductionOpener struct {
	keys map[string][32]byte
	now  func() time.Time
}

func (RequestReproductionSealer) String() string               { return "[request-only sealer]" }
func (v RequestReproductionSealer) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (RequestReproductionSealer) MarshalJSON() ([]byte, error) {
	return nil, evidencedisplay.ErrSensitive
}
func (v RequestReproductionSealer) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (RequestReproductionOpener) String() string               { return "[request-only opener]" }
func (v RequestReproductionOpener) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (RequestReproductionOpener) MarshalJSON() ([]byte, error) {
	return nil, evidencedisplay.ErrSensitive
}
func (v RequestReproductionOpener) LogValue() slog.Value { return slog.StringValue(v.String()) }

// NewRequestReproductionCapabilities is trusted startup composition only. A
// nil clock uses time.Now. HTTP callers may supply neither a clock nor KeyRing.
func (k *KeyRing) NewRequestReproductionCapabilities(now func() time.Time) (*RequestReproductionSealer, *RequestReproductionOpener, error) {
	if k == nil || !versionPattern.MatchString(k.active) {
		return nil, nil, ErrRequestReproductionUnavailable
	}
	if now == nil {
		now = time.Now
	}
	active, ok := k.keys[k.active]
	if !ok || len(active.requestReproduction) != 32 {
		return nil, nil, ErrRequestReproductionUnavailable
	}
	sealer := &RequestReproductionSealer{version: k.active, now: now}
	copy(sealer.key[:], active.requestReproduction)
	opener := &RequestReproductionOpener{keys: make(map[string][32]byte, len(k.keys)), now: now}
	for version, set := range k.keys {
		if !versionPattern.MatchString(version) || len(set.requestReproduction) != 32 {
			return nil, nil, ErrRequestReproductionUnavailable
		}
		var value [32]byte
		copy(value[:], set.requestReproduction)
		opener.keys[version] = value
	}
	return sealer, opener, nil
}

func validRequestReproductionBinding(binding RequestReproductionBinding, now time.Time) bool {
	if !validEvidenceScope(binding.Scope) || !evidenceHash.MatchString(binding.ManifestHash) || now.IsZero() {
		return false
	}
	current := now.UnixMicro()
	// Policy-agnostic ordering only: response 0/30/180-day rules are not request
	// S2 policy. A future repository must choose and recheck that policy.
	return binding.CapturedAtMicros > 0 && binding.CapturedAtMicros <= current && binding.ExpiresAtMicros > current && binding.ExpiresAtMicros > binding.CapturedAtMicros
}

func requestReproductionAAD(binding RequestReproductionBinding, record RequestReproductionRecord) ([]byte, error) {
	return json.Marshal(struct {
		Version        int           `json:"version"`
		Purpose        string        `json:"purpose"`
		Policy         string        `json:"policy"`
		Scope          EvidenceScope `json:"scope"`
		ManifestHash   string        `json:"manifest_hash"`
		CapturedAt     int64         `json:"captured_at_micros"`
		ExpiresAt      int64         `json:"expires_at_micros"`
		KeyVersion     string        `json:"key_version"`
		PlaintextBytes int           `json:"plaintext_bytes"`
		PayloadHash    string        `json:"payload_hash"`
	}{record.Version, "request-reproduction", record.Policy, binding.Scope, binding.ManifestHash, binding.CapturedAtMicros, binding.ExpiresAtMicros, record.KeyVersion, record.PlaintextBytes, record.PayloadHash})
}

func (s *RequestReproductionSealer) Seal(ctx context.Context, binding RequestReproductionBinding, prepared *evidencedisplay.PreparedRequestReproduction) (record RequestReproductionRecord, result error) {
	defer func() {
		if recover() != nil {
			clear(record.Ciphertext)
			record = RequestReproductionRecord{}
			result = ErrRequestReproductionUnavailable
		}
	}()
	if ctx == nil || s == nil || s.now == nil || prepared == nil || !versionPattern.MatchString(s.version) {
		return record, ErrRequestReproductionUnavailable
	}
	if ctx.Err() != nil {
		return record, evidencedisplay.ErrCancelled
	}
	if !validRequestReproductionBinding(binding, s.now()) {
		return record, ErrRequestReproductionUnavailable
	}
	manifest, request := prepared.BindingHashes()
	if binding.ManifestHash != manifest || binding.Scope.RequestHash != request {
		return record, ErrRequestReproductionUnavailable
	}
	err := prepared.WithCanonicalForSeal(ctx, func(data []byte) error {
		aead, err := gcm(s.key[:])
		if err != nil {
			return ErrRequestReproductionUnavailable
		}
		hash := sha256.Sum256(data)
		record = RequestReproductionRecord{Version: 1, Policy: evidencedisplay.RequestReproductionPolicyVersion, KeyVersion: s.version, Nonce: make([]byte, aead.NonceSize()), PlaintextBytes: len(data), PayloadHash: hex.EncodeToString(hash[:])}
		if _, err := rand.Read(record.Nonce); err != nil {
			return ErrRequestReproductionUnavailable
		}
		aad, err := requestReproductionAAD(binding, record)
		if err != nil {
			return ErrRequestReproductionUnavailable
		}
		record.Ciphertext = aead.Seal(nil, record.Nonce, data, aad)
		return nil
	})
	validAtCompletion := false
	if err == nil {
		validAtCompletion = validRequestReproductionBinding(binding, s.now())
	}
	if err != nil || ctx.Err() != nil || !validAtCompletion {
		clear(record.Ciphertext)
		if ctx.Err() != nil || errors.Is(err, evidencedisplay.ErrCancelled) {
			return RequestReproductionRecord{}, evidencedisplay.ErrCancelled
		}
		return RequestReproductionRecord{}, ErrRequestReproductionUnavailable
	}
	return record, nil
}

func (o *RequestReproductionOpener) Open(ctx context.Context, binding RequestReproductionBinding, record RequestReproductionRecord) (opened *evidencedisplay.OpenedRequestReproduction, result error) {
	defer func() {
		if recover() != nil {
			if opened != nil {
				opened.Close()
			}
			opened = nil
			result = ErrRequestReproductionUnavailable
		}
	}()
	if ctx == nil || o == nil || o.now == nil {
		return nil, ErrRequestReproductionUnavailable
	}
	if ctx.Err() != nil {
		return nil, evidencedisplay.ErrCancelled
	}
	if !validRequestReproductionBinding(binding, o.now()) || record.Version != 1 || record.Policy != evidencedisplay.RequestReproductionPolicyVersion || !versionPattern.MatchString(record.KeyVersion) || !evidenceHash.MatchString(record.PayloadHash) || len(record.Nonce) != 12 || record.PlaintextBytes < 1 || record.PlaintextBytes > evidencedisplay.MaxPayloadBytes || len(record.Ciphertext) != record.PlaintextBytes+16 {
		return nil, ErrRequestReproductionUnavailable
	}
	key, ok := o.keys[record.KeyVersion]
	if !ok {
		return nil, ErrRequestReproductionUnavailable
	}
	aead, err := gcm(key[:])
	clear(key[:])
	if err != nil {
		return nil, ErrRequestReproductionUnavailable
	}
	aad, err := requestReproductionAAD(binding, record)
	if err != nil {
		return nil, ErrRequestReproductionUnavailable
	}
	data, err := aead.Open(nil, record.Nonce, record.Ciphertext, aad)
	if err != nil {
		return nil, ErrRequestReproductionUnavailable
	}
	defer clear(data)
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) != record.PayloadHash {
		return nil, ErrRequestReproductionUnavailable
	}
	opened, err = evidencedisplay.DecodeAuthenticatedRequestReproduction(data, binding.ManifestHash, binding.Scope.RequestHash)
	if err != nil {
		return nil, ErrRequestReproductionUnavailable
	}
	validAtCompletion := validRequestReproductionBinding(binding, o.now())
	if ctx.Err() != nil || !validAtCompletion {
		opened.Close()
		if ctx.Err() != nil {
			return nil, evidencedisplay.ErrCancelled
		}
		return nil, ErrRequestReproductionUnavailable
	}
	return opened, nil
}
