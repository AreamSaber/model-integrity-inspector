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

var ErrDisplayUnavailable = errors.New("MI_DISPLAY_UNAVAILABLE")

// DisplayBinding contains immutable expected facts from the future fenced
// persistence boundary, never a caller-supplied authorization decision. Times
// are Unix UTC microseconds, not ambiguous local strings or float timestamps.
// SourceHash is evidencedisplay's domain-separated pre-redaction source digest,
// NOT response-evidence ContentHash or the original HTTP wire ResponseHash.
type DisplayBinding struct {
	Scope            EvidenceScope
	SourceHash       string
	CapturedAtMicros int64
	ExpiresAtMicros  int64
}

type DisplayRecord struct {
	Version        int
	Policy         string
	KeyVersion     string
	Nonce          []byte
	Ciphertext     []byte
	PlaintextBytes int
	PayloadHash    string
}

func (DisplayBinding) String() string               { return "[display evidence binding]" }
func (v DisplayBinding) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (DisplayBinding) MarshalJSON() ([]byte, error) { return nil, evidencedisplay.ErrSensitive }
func (v DisplayBinding) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (DisplayRecord) String() string                { return "[encrypted display evidence]" }
func (v DisplayRecord) Format(s fmt.State, _ rune)  { _, _ = io.WriteString(s, v.String()) }
func (DisplayRecord) MarshalJSON() ([]byte, error)  { return nil, evidencedisplay.ErrSensitive }
func (v DisplayRecord) LogValue() slog.Value        { return slog.StringValue(v.String()) }

// These capabilities own only copied display-purpose keys. Neither embeds a
// KeyRing nor exposes credentials, raw analysis decryption, or key bytes.
type DisplaySealer struct {
	version string
	key     [32]byte
	now     func() time.Time
}
type DisplayOpener struct {
	keys map[string][32]byte
	now  func() time.Time
}

func (DisplaySealer) String() string               { return "[display-only sealer]" }
func (v DisplaySealer) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (DisplaySealer) MarshalJSON() ([]byte, error) { return nil, evidencedisplay.ErrSensitive }
func (v DisplaySealer) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (DisplayOpener) String() string               { return "[display-only opener]" }
func (v DisplayOpener) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (DisplayOpener) MarshalJSON() ([]byte, error) { return nil, evidencedisplay.ErrSensitive }
func (v DisplayOpener) LogValue() slog.Value       { return slog.StringValue(v.String()) }

// NewDisplayCapabilities is for trusted startup composition. A nil clock uses
// time.Now; tests may supply a fixed clock. HTTP must never provide this clock
// or receive the KeyRing. Opening authenticates bytes, not repository authority.
func (k *KeyRing) NewDisplayCapabilities(now func() time.Time) (*DisplaySealer, *DisplayOpener, error) {
	if k == nil || !versionPattern.MatchString(k.active) {
		return nil, nil, ErrDisplayUnavailable
	}
	if now == nil {
		now = time.Now
	}
	active, ok := k.keys[k.active]
	if !ok || len(active.display) != 32 {
		return nil, nil, ErrDisplayUnavailable
	}
	sealer := &DisplaySealer{version: k.active, now: now}
	copy(sealer.key[:], active.display)
	opener := &DisplayOpener{keys: make(map[string][32]byte, len(k.keys)), now: now}
	for version, set := range k.keys {
		if !versionPattern.MatchString(version) || len(set.display) != 32 {
			return nil, nil, ErrDisplayUnavailable
		}
		var value [32]byte
		copy(value[:], set.display)
		opener.keys[version] = value
	}
	return sealer, opener, nil
}

func validDisplayBinding(binding DisplayBinding, now time.Time) bool {
	if !validEvidenceScope(binding.Scope) || !evidenceHash.MatchString(binding.SourceHash) || now.IsZero() {
		return false
	}
	current := now.UnixMicro()
	return binding.CapturedAtMicros > 0 && binding.CapturedAtMicros <= current && binding.ExpiresAtMicros > current && binding.ExpiresAtMicros > binding.CapturedAtMicros && binding.ExpiresAtMicros-binding.CapturedAtMicros <= int64(180*24*time.Hour/time.Microsecond)
}

func displayAAD(binding DisplayBinding, record DisplayRecord) ([]byte, error) {
	// Dedicated fixed DTO: ordinary binding/record serialization stays forbidden.
	return json.Marshal(struct {
		Version        int           `json:"version"`
		Purpose        string        `json:"purpose"`
		Policy         string        `json:"policy"`
		Scope          EvidenceScope `json:"scope"`
		SourceHash     string        `json:"source_hash"`
		CapturedAt     int64         `json:"captured_at_micros"`
		ExpiresAt      int64         `json:"expires_at_micros"`
		KeyVersion     string        `json:"key_version"`
		PlaintextBytes int           `json:"plaintext_bytes"`
		PayloadHash    string        `json:"payload_hash"`
	}{record.Version, "evidence-display", record.Policy, binding.Scope, binding.SourceHash, binding.CapturedAtMicros, binding.ExpiresAtMicros, record.KeyVersion, record.PlaintextBytes, record.PayloadHash})
}

func (s *DisplaySealer) Seal(ctx context.Context, binding DisplayBinding, prepared *evidencedisplay.Prepared) (record DisplayRecord, result error) {
	defer func() {
		if recover() != nil {
			record = DisplayRecord{}
			result = ErrDisplayUnavailable
		}
	}()
	if ctx == nil || s == nil || s.now == nil || prepared == nil || !versionPattern.MatchString(s.version) {
		return record, ErrDisplayUnavailable
	}
	if ctx.Err() != nil {
		return record, evidencedisplay.ErrCancelled
	}
	if !validDisplayBinding(binding, s.now()) {
		return record, ErrDisplayUnavailable
	}
	source, request := prepared.Hashes()
	if binding.SourceHash != source || binding.Scope.RequestHash != request {
		return record, ErrDisplayUnavailable
	}
	err := prepared.WithCanonicalForSeal(ctx, func(data []byte) error {
		aead, err := gcm(s.key[:])
		if err != nil {
			return ErrDisplayUnavailable
		}
		hash := sha256.Sum256(data)
		record = DisplayRecord{Version: 1, Policy: evidencedisplay.PolicyVersion, KeyVersion: s.version, Nonce: make([]byte, aead.NonceSize()), PlaintextBytes: len(data), PayloadHash: hex.EncodeToString(hash[:])}
		if _, err := rand.Read(record.Nonce); err != nil {
			return ErrDisplayUnavailable
		}
		aad, err := displayAAD(binding, record)
		if err != nil {
			return ErrDisplayUnavailable
		}
		record.Ciphertext = aead.Seal(nil, record.Nonce, data, aad)
		return nil
	})
	// The injected trusted clock can itself cross the request deadline. Check
	// cancellation after the final expiry observation, before releasing output.
	validAtCompletion := false
	if err == nil {
		validAtCompletion = validDisplayBinding(binding, s.now())
	}
	if err != nil || ctx.Err() != nil || !validAtCompletion {
		clear(record.Ciphertext)
		if ctx.Err() != nil || errors.Is(err, evidencedisplay.ErrCancelled) {
			return DisplayRecord{}, evidencedisplay.ErrCancelled
		}
		return DisplayRecord{}, ErrDisplayUnavailable
	}
	return record, nil
}

func (o *DisplayOpener) Open(ctx context.Context, binding DisplayBinding, record DisplayRecord) (opened *evidencedisplay.Opened, result error) {
	defer func() {
		if recover() != nil {
			if opened != nil {
				opened.Close()
			}
			opened = nil
			result = ErrDisplayUnavailable
		}
	}()
	if ctx == nil || o == nil || o.now == nil {
		return nil, ErrDisplayUnavailable
	}
	if ctx.Err() != nil {
		return nil, evidencedisplay.ErrCancelled
	}
	if !validDisplayBinding(binding, o.now()) || record.Version != 1 || record.Policy != evidencedisplay.PolicyVersion || !versionPattern.MatchString(record.KeyVersion) || !evidenceHash.MatchString(record.PayloadHash) || len(record.Nonce) != 12 || record.PlaintextBytes < 1 || record.PlaintextBytes > evidencedisplay.MaxPayloadBytes || len(record.Ciphertext) != record.PlaintextBytes+16 {
		return nil, ErrDisplayUnavailable
	}
	key, ok := o.keys[record.KeyVersion]
	if !ok {
		return nil, ErrDisplayUnavailable
	}
	aead, err := gcm(key[:])
	clear(key[:])
	if err != nil {
		return nil, ErrDisplayUnavailable
	}
	aad, err := displayAAD(binding, record)
	if err != nil {
		return nil, ErrDisplayUnavailable
	}
	data, err := aead.Open(nil, record.Nonce, record.Ciphertext, aad)
	if err != nil {
		return nil, ErrDisplayUnavailable
	}
	defer clear(data)
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) != record.PayloadHash {
		return nil, ErrDisplayUnavailable
	}
	opened, err = evidencedisplay.DecodeAuthenticatedCanonical(data, binding.SourceHash, binding.Scope.RequestHash)
	if err != nil {
		return nil, ErrDisplayUnavailable
	}
	validAtCompletion := validDisplayBinding(binding, o.now())
	if ctx.Err() != nil || !validAtCompletion {
		opened.Close()
		if ctx.Err() != nil {
			return nil, evidencedisplay.ErrCancelled
		}
		return nil, ErrDisplayUnavailable
	}
	return opened, nil
}
