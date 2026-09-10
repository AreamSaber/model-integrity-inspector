package features

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"regexp"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

const DerivedVersion = domain.AnalysisSourceDerivedV1
const MaxDerivedBytes = 32 << 10

// DerivedRecord is S1, not a trusted value until its independent-purpose MAC
// and complete scope have been checked. It carries no response ciphertext.
type DerivedRecord struct {
	Version    string `json:"version"`
	KeyVersion string `json:"key_version"`
	Payload    []byte `json:"payload"`
	MAC        []byte `json:"mac"`
}

// PreparedDerived can only be constructed by the actual feature extractor.
// It owns canonical S1 bytes; no caller-filled feature constructor is exposed.
type PreparedDerived struct{ canonical []byte }

type DerivedSealer struct {
	version       string
	authenticator DerivedAuthenticator
}
type DerivedVerifier struct{ authenticator DerivedAuthenticator }

// DerivedAuthenticator is a purpose-only capability supplied by trusted
// startup. It must not retain a general KeyRing or expose raw purpose keys.
// The input already contains features' full, versioned authentication domain.
type DerivedAuthenticator interface {
	DerivedMAC(version string, canonical []byte) ([]byte, error)
}

type derivedPurposeKeys struct{ keys map[string][32]byte }

func (k *derivedPurposeKeys) DerivedMAC(version string, canonical []byte) ([]byte, error) {
	if k == nil {
		return nil, ErrConfiguration
	}
	key, ok := k.keys[version]
	if !ok {
		return nil, ErrBinding
	}
	h := hmac.New(sha256.New, key[:])
	_, _ = h.Write(canonical)
	return h.Sum(nil), nil
}

var derivedKeyVersion = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

func NewDerivedCapabilitiesWithMAC(activeVersion string, authenticator DerivedAuthenticator) (*DerivedSealer, *DerivedVerifier, error) {
	if !derivedKeyVersion.MatchString(activeVersion) || authenticator == nil {
		return nil, nil, ErrConfiguration
	}
	return &DerivedSealer{activeVersion, authenticator}, &DerivedVerifier{authenticator}, nil
}

// NewDerivedCapabilities takes an already independently derived purpose key,
// NEVER a master/display/response-evidence key. Production KeyRing wiring must
// enforce that boundary. These capabilities have no other key-service methods.
func NewDerivedCapabilities(version string, purposeKey []byte) (*DerivedSealer, *DerivedVerifier, error) {
	verifier, err := NewDerivedVerifier(map[string][]byte{version: purposeKey})
	if err != nil {
		return nil, nil, err
	}
	return &DerivedSealer{version, verifier.authenticator}, verifier, nil
}

// NewDerivedVerifier receives a historical key window at trusted startup,
// never caller-selected keys on a request. Production uses the MAC capability.
func NewDerivedVerifier(keys map[string][]byte) (*DerivedVerifier, error) {
	if len(keys) == 0 {
		return nil, ErrConfiguration
	}
	out := &derivedPurposeKeys{keys: make(map[string][32]byte, len(keys))}
	for version, key := range keys {
		if !derivedKeyVersion.MatchString(version) || len(key) != 32 {
			return nil, ErrConfiguration
		}
		out.keys[version] = [32]byte(key)
	}
	return &DerivedVerifier{out}, nil
}

func derivedMAC(authenticator DerivedAuthenticator, version string, payload []byte) ([]byte, error) {
	if authenticator == nil {
		return nil, ErrConfiguration
	}
	data := append([]byte("mii/derived-s1/auth/v1\x00"+DerivedVersion+"\x00"+version+"\x00"), payload...)
	defer clear(data)
	mac, err := authenticator.DerivedMAC(version, data)
	if err != nil || len(mac) != sha256.Size {
		return nil, ErrBinding
	}
	return mac, nil
}

func (s *DerivedSealer) Seal(ctx context.Context, prepared *PreparedDerived) (DerivedRecord, error) {
	if s == nil || ctx == nil || !derivedKeyVersion.MatchString(s.version) || prepared == nil || len(prepared.canonical) == 0 || len(prepared.canonical) > MaxDerivedBytes {
		return DerivedRecord{}, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return DerivedRecord{}, err
	}
	mac, err := derivedMAC(s.authenticator, s.version, prepared.canonical)
	if err != nil {
		return DerivedRecord{}, err
	}
	r := DerivedRecord{DerivedVersion, s.version, bytes.Clone(prepared.canonical), mac}
	if err := ctx.Err(); err != nil {
		return DerivedRecord{}, err
	}
	return r, nil
}

func (v *DerivedVerifier) open(ctx context.Context, record DerivedRecord) (derivedPayload, error) {
	if v == nil || ctx == nil {
		return derivedPayload{}, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return derivedPayload{}, err
	}
	if !derivedKeyVersion.MatchString(record.KeyVersion) || record.Version != DerivedVersion || len(record.Payload) == 0 || len(record.Payload) > MaxDerivedBytes || len(record.MAC) != sha256.Size {
		return derivedPayload{}, ErrBinding
	}
	mac, err := derivedMAC(v.authenticator, record.KeyVersion, record.Payload)
	if err != nil || !hmac.Equal(record.MAC, mac) {
		return derivedPayload{}, ErrBinding
	}
	var payload derivedPayload
	d := json.NewDecoder(bytes.NewReader(record.Payload))
	d.DisallowUnknownFields()
	if d.Decode(&payload) != nil || d.Decode(new(any)) != io.EOF || payload.Version != DerivedVersion {
		return derivedPayload{}, ErrBinding
	}
	canonical, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(canonical, record.Payload) {
		return derivedPayload{}, ErrBinding
	}
	if err := ctx.Err(); err != nil {
		return derivedPayload{}, err
	}
	return payload, nil
}

func (PreparedDerived) String() string               { return redacted }
func (PreparedDerived) Format(w fmt.State, _ rune)   { _, _ = io.WriteString(w, redacted) }
func (PreparedDerived) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (DerivedSealer) String() string                 { return redacted }
func (DerivedSealer) Format(w fmt.State, _ rune)     { _, _ = io.WriteString(w, redacted) }
func (DerivedSealer) MarshalJSON() ([]byte, error)   { return []byte(`"` + redacted + `"`), nil }
func (DerivedVerifier) String() string               { return redacted }
func (DerivedVerifier) Format(w fmt.State, _ rune)   { _, _ = io.WriteString(w, redacted) }
func (DerivedVerifier) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
