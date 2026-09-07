package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

const MaxEvidencePlaintextBytes = 1 << 20

var (
	ErrEvidenceInvalid     = errors.New("MI_EVIDENCE_INVALID")
	ErrEvidenceUnavailable = errors.New("MI_EVIDENCE_UNAVAILABLE")
	ErrEvidenceLimit       = errors.New("MI_EVIDENCE_LIMIT")
	ErrEvidenceConsumer    = errors.New("MI_EVIDENCE_CONSUMER_FAILED")
	ErrEvidenceSensitive   = errors.New("MI_EVIDENCE_SERIALIZATION_FORBIDDEN")
)

type EvidenceScope struct {
	OrganizationID  int64  `json:"organization_id"`
	RunID           int64  `json:"run_id"`
	LogicalSampleID int64  `json:"logical_sample_id"`
	AttemptID       int64  `json:"attempt_id"`
	RequestHash     string `json:"request_hash"`
}

// EvidenceRecord is encrypted persistence data, never an HTTP DTO/log value.
// ContentHash hashes the entire versioned AES plaintext payload, not the raw
// upstream response body (NormalizedResponse.ResponseHash retains that meaning).
type EvidenceRecord struct {
	KeyVersion     string
	Nonce          []byte
	Ciphertext     []byte
	PlaintextBytes int
	ContentHash    string
}

func (EvidenceRecord) String() string               { return "[encrypted response evidence]" }
func (r EvidenceRecord) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, r.String()) }
func (EvidenceRecord) MarshalJSON() ([]byte, error) { return nil, ErrEvidenceSensitive }
func (r EvidenceRecord) LogValue() slog.Value       { return slog.StringValue(r.String()) }

type responseEvidencePayload struct {
	Version  int                       `json:"version"`
	Response domain.NormalizedResponse `json:"response"`
}

var evidenceHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

func validEvidenceScope(scope EvidenceScope) bool {
	return scope.OrganizationID > 0 && scope.RunID > 0 && scope.LogicalSampleID > 0 && scope.AttemptID > 0 && evidenceHash.MatchString(scope.RequestHash)
}

func evidenceAAD(scope EvidenceScope, record EvidenceRecord) ([]byte, error) {
	return json.Marshal(struct {
		Version        int           `json:"version"`
		Purpose        string        `json:"purpose"`
		Scope          EvidenceScope `json:"scope"`
		KeyVersion     string        `json:"key_version"`
		PlaintextBytes int           `json:"plaintext_bytes"`
		ContentHash    string        `json:"content_hash"`
	}{1, "response-evidence", scope, record.KeyVersion, record.PlaintextBytes, record.ContentHash})
}

func (k *KeyRing) EncryptResponseEvidence(scope EvidenceScope, response domain.NormalizedResponse) (EvidenceRecord, error) {
	if k == nil || !validEvidenceScope(scope) {
		return EvidenceRecord{}, ErrEvidenceInvalid
	}
	// Do not allocate an unbounded serialization just to discover its size.
	if len(response.Content) > MaxEvidencePlaintextBytes || len(response.Events) > 256 || len(response.HeaderSummary) > 32 || len(response.ParseWarnings) > 64 {
		return EvidenceRecord{}, ErrEvidenceLimit
	}
	total := len(response.Content)
	stringsToCheck := []string{response.ProviderRequestID, response.ModelReported, response.FinishReason, response.ContentType, response.ResponseHash, response.ParseStatus, response.EndCause}
	for key, value := range response.HeaderSummary {
		stringsToCheck = append(stringsToCheck, key, value)
	}
	stringsToCheck = append(stringsToCheck, response.ParseWarnings...)
	for _, event := range response.Events {
		stringsToCheck = append(stringsToCheck, event.Type)
	}
	for _, value := range stringsToCheck {
		if len(value) > MaxEvidencePlaintextBytes-total {
			return EvidenceRecord{}, ErrEvidenceLimit
		}
		total += len(value)
	}
	encoded, err := json.Marshal(responseEvidencePayload{1, response})
	if err != nil {
		return EvidenceRecord{}, ErrEvidenceInvalid
	}
	defer clear(encoded)
	if len(encoded) > MaxEvidencePlaintextBytes {
		return EvidenceRecord{}, ErrEvidenceLimit
	}
	keys, ok := k.keys[k.active]
	if !ok || len(keys.evidence) != 32 {
		return EvidenceRecord{}, ErrEvidenceUnavailable
	}
	aead, err := gcm(keys.evidence)
	if err != nil {
		return EvidenceRecord{}, ErrEvidenceUnavailable
	}
	digest := sha256.Sum256(encoded)
	record := EvidenceRecord{KeyVersion: k.active, Nonce: make([]byte, aead.NonceSize()), PlaintextBytes: len(encoded), ContentHash: hex.EncodeToString(digest[:])}
	if _, err := rand.Read(record.Nonce); err != nil {
		return EvidenceRecord{}, ErrEvidenceUnavailable
	}
	associated, err := evidenceAAD(scope, record)
	if err != nil {
		return EvidenceRecord{}, ErrEvidenceUnavailable
	}
	record.Ciphertext = aead.Seal(nil, record.Nonce, encoded, associated)
	return record, nil
}

// WithResponseEvidence is only for trusted Worker/analysis composition, never a
// credential read or HTTP export. Borrowed strings must not be retained/logged.
// The owned decoded byte buffer is cleared on all exits, including panics; Go
// strings copied by trusted analysis cannot generally be forcibly zeroized.
func (k *KeyRing) WithResponseEvidence(scope EvidenceScope, record EvidenceRecord, fn func(domain.NormalizedResponse) error) (result error) {
	defer func() {
		if recover() != nil {
			result = ErrEvidenceConsumer
		}
	}()
	if k == nil || fn == nil || !validEvidenceScope(scope) {
		return ErrEvidenceInvalid
	}
	if !versionPattern.MatchString(record.KeyVersion) || !evidenceHash.MatchString(record.ContentHash) || len(record.Nonce) != 12 || record.PlaintextBytes < 1 || record.PlaintextBytes > MaxEvidencePlaintextBytes || len(record.Ciphertext) != record.PlaintextBytes+16 {
		return ErrEvidenceUnavailable
	}
	keys, ok := k.keys[record.KeyVersion]
	if !ok || len(keys.evidence) != 32 {
		return ErrEvidenceUnavailable
	}
	aead, err := gcm(keys.evidence)
	if err != nil {
		return ErrEvidenceUnavailable
	}
	associated, err := evidenceAAD(scope, record)
	if err != nil {
		return ErrEvidenceUnavailable
	}
	plaintext, err := aead.Open(nil, record.Nonce, record.Ciphertext, associated)
	if err != nil {
		return ErrEvidenceUnavailable
	}
	defer clear(plaintext)
	digest := sha256.Sum256(plaintext)
	if hex.EncodeToString(digest[:]) != record.ContentHash {
		return ErrEvidenceUnavailable
	}
	var payload responseEvidencePayload
	if decode(plaintext, &payload) != nil || payload.Version != 1 {
		return ErrEvidenceUnavailable
	}
	if err := fn(payload.Response); err != nil {
		return ErrEvidenceConsumer
	}
	return nil
}
