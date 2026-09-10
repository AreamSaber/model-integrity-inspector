package localfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"unicode/utf8"
)

const (
	MaxTrustBytes      = 2048
	ManifestKeyVersion = "dev-replay-manifest-v1"
	publicSchema       = "mii.replay-development-capture-public-key.v1"
	manifestSchema     = "mii.replay-development-manifest-key.v1"
)

var (
	ErrTrust         = errors.New("MI_REPLAY_DEVELOPMENT_TRUST_INVALID")
	ErrSensitive     = errors.New("MI_REPLAY_TRUST_SERIALIZATION_FORBIDDEN")
	developmentKeyID = regexp.MustCompile(`^dev-[a-z0-9][a-z0-9.-]{0,47}$`)
)

// ManifestSigner is ONLY a synthetic development ProbeMAC key, not an application
// master key or a release credential. Its lifecycle must be confined to one run.
type ManifestSigner struct{ key []byte }

func NewManifestSigner() (*ManifestSigner, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		clear(key)
		return nil, ErrTrust
	}
	return &ManifestSigner{key: key}, nil
}
func (s *ManifestSigner) ActiveVersion() string { return ManifestKeyVersion }
func (s *ManifestSigner) ProbeMAC(version string, data []byte) ([]byte, error) {
	if s == nil || len(s.key) != 32 || version != ManifestKeyVersion {
		return nil, ErrTrust
	}
	h := hmac.New(sha256.New, s.key)
	_, _ = h.Write(data)
	return h.Sum(nil), nil
}
func (s *ManifestSigner) Destroy() {
	if s != nil {
		clear(s.key)
		s.key = nil
	}
}
func (s ManifestSigner) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, "[REDACTED development manifest signer]")
}
func (s ManifestSigner) String() string               { return "[REDACTED development manifest signer]" }
func (s ManifestSigner) LogValue() slog.Value         { return slog.StringValue(s.String()) }
func (s ManifestSigner) MarshalJSON() ([]byte, error) { return nil, ErrSensitive }

type publicDocument struct {
	SchemaVersion string `json:"schema_version"`
	Purpose       string `json:"purpose"`
	KeyID         string `json:"key_id"`
	PublicKey     []byte `json:"public_key"`
}
type manifestDocument struct {
	SchemaVersion string `json:"schema_version"`
	Purpose       string `json:"purpose"`
	KeyVersion    string `json:"key_version"`
	Key           []byte `json:"key"`
}

// EncodeDevelopmentManifestKey is the deliberately explicit export path. It can
// encode only this private synthetic signer, never secret.KeyRing/master bytes.
// The caller must protect and clear the returned S2 bytes after WriteNew.
func EncodeDevelopmentManifestKey(s *ManifestSigner) ([]byte, error) {
	if s == nil || len(s.key) != 32 {
		return nil, ErrTrust
	}
	return json.Marshal(manifestDocument{manifestSchema, "development-only-probe-mac", ManifestKeyVersion, s.key})
}
func EncodeDevelopmentCapturePublicKey(id string, key ed25519.PublicKey) ([]byte, error) {
	if !developmentKeyID.MatchString(id) || len(key) != ed25519.PublicKeySize {
		return nil, ErrTrust
	}
	return json.Marshal(publicDocument{publicSchema, "development-only-capture-signature", id, key})
}

func decodeCanonicalTrust(data []byte, dst any) error {
	if len(data) == 0 || len(data) > MaxTrustBytes || !utf8.Valid(data) {
		return ErrTrust
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(dst) != nil {
		return ErrTrust
	}
	canonical, err := json.Marshal(dst)
	defer clear(canonical)
	// Exact canonical equality rejects duplicate/case-aliased fields, omitted
	// fields, extra values and whitespace, even though encoding/json accepts them.
	if err != nil || !bytes.Equal(canonical, data) {
		return ErrTrust
	}
	return nil
}

func ParseDevelopmentManifestKey(data []byte) (*ManifestSigner, error) {
	var doc manifestDocument
	defer func() { clear(doc.Key) }()
	if decodeCanonicalTrust(data, &doc) != nil || doc.SchemaVersion != manifestSchema || doc.Purpose != "development-only-probe-mac" || doc.KeyVersion != ManifestKeyVersion || len(doc.Key) != 32 {
		return nil, ErrTrust
	}
	return &ManifestSigner{key: bytes.Clone(doc.Key)}, nil
}
func ParseDevelopmentCapturePublicKey(data []byte) (string, ed25519.PublicKey, error) {
	var doc publicDocument
	if decodeCanonicalTrust(data, &doc) != nil || doc.SchemaVersion != publicSchema || doc.Purpose != "development-only-capture-signature" || !developmentKeyID.MatchString(doc.KeyID) || len(doc.PublicKey) != ed25519.PublicKeySize {
		return "", nil, ErrTrust
	}
	return doc.KeyID, doc.PublicKey, nil
}
