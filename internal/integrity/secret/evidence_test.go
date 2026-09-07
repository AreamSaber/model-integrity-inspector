package secret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func evidenceFixture(t *testing.T) (*KeyRing, EvidenceScope, EvidenceRecord) {
	t.Helper()
	ring := testRing(t)
	scope := EvidenceScope{OrganizationID: 1, RunID: 2, LogicalSampleID: 3, AttemptID: 4, RequestHash: strings.Repeat("a", 64)}
	record, err := ring.EncryptResponseEvidence(scope, domain.NormalizedResponse{Content: canary, HTTPStatus: 200, ParseStatus: "valid", HeaderSummary: map[string]string{"x-request-id": "synthetic-evidence-id"}})
	if err != nil {
		t.Fatal(err)
	}
	return ring, scope, record
}

func TestResponseEvidenceEncryptionAndSafeFormatting(t *testing.T) {
	ring, scope, record := evidenceFixture(t)
	if bytes.Contains(record.Ciphertext, []byte(canary)) {
		t.Fatal("plaintext evidence persisted")
	}
	if err := ring.WithResponseEvidence(scope, record, func(response domain.NormalizedResponse) error {
		if response.Content != canary || response.HTTPStatus != 200 {
			t.Fatal("evidence mismatch")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	second, err := ring.EncryptResponseEvidence(scope, domain.NormalizedResponse{Content: canary})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(record.Nonce, second.Nonce) {
		t.Fatal("nonce reuse")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		text := fmt.Sprintf(format, record)
		if strings.Contains(text, canary) || strings.Contains(text, record.ContentHash) || strings.Contains(text, record.KeyVersion) {
			t.Fatal("record formatter leaked fields")
		}
	}
	if _, err := json.Marshal(record); !errors.Is(err, ErrEvidenceSensitive) {
		t.Fatal("record serialized")
	}
	var logs bytes.Buffer
	for _, handler := range []slog.Handler{slog.NewJSONHandler(&logs, nil), slog.NewTextHandler(&logs, nil)} {
		slog.New(handler).Info("safe", "record", record, "pointer", &record, slog.Group("nested", "record", record))
	}
	if strings.Contains(logs.String(), record.ContentHash) || strings.Contains(logs.String(), record.KeyVersion) || !strings.Contains(logs.String(), "encrypted response evidence") {
		t.Fatal("structured logger bypassed evidence redaction")
	}
	if err := ring.WithResponseEvidence(scope, record, func(domain.NormalizedResponse) error { return errors.New(canary) }); !errors.Is(err, ErrEvidenceConsumer) || strings.Contains(err.Error(), canary) {
		t.Fatal("consumer error leaked")
	}
	if err := ring.WithResponseEvidence(scope, record, func(domain.NormalizedResponse) error { panic(canary) }); !errors.Is(err, ErrEvidenceConsumer) {
		t.Fatal("consumer panic leaked")
	}
}

func TestResponseEvidenceAADAndPayloadTampering(t *testing.T) {
	ring, scope, record := evidenceFixture(t)
	for _, mutate := range []func(*EvidenceScope){func(v *EvidenceScope) { v.OrganizationID++ }, func(v *EvidenceScope) { v.RunID++ }, func(v *EvidenceScope) { v.LogicalSampleID++ }, func(v *EvidenceScope) { v.AttemptID++ }, func(v *EvidenceScope) { v.RequestHash = strings.Repeat("b", 64) }} {
		wrong := scope
		mutate(&wrong)
		if err := ring.WithResponseEvidence(wrong, record, func(domain.NormalizedResponse) error { t.Fatal("wrong scope decrypted"); return nil }); !errors.Is(err, ErrEvidenceUnavailable) {
			t.Fatal("AAD mismatch accepted")
		}
	}
	for _, mutate := range []func(*EvidenceRecord){func(v *EvidenceRecord) { v.Ciphertext[0] ^= 1 }, func(v *EvidenceRecord) { v.Nonce[0] ^= 1 }, func(v *EvidenceRecord) { v.KeyVersion = "two" }, func(v *EvidenceRecord) { v.ContentHash = strings.Repeat("c", 64) }, func(v *EvidenceRecord) { v.PlaintextBytes++ }} {
		wrong := record
		wrong.Nonce = bytes.Clone(record.Nonce)
		wrong.Ciphertext = bytes.Clone(record.Ciphertext)
		mutate(&wrong)
		if err := ring.WithResponseEvidence(scope, wrong, func(domain.NormalizedResponse) error { t.Fatal("tampered evidence decrypted"); return nil }); !errors.Is(err, ErrEvidenceUnavailable) {
			t.Fatal("tampering accepted")
		}
	}
	other, err := NewKeyRing("one", map[string][]byte{"one": bytes.Repeat([]byte{0x92}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.WithResponseEvidence(scope, record, func(domain.NormalizedResponse) error { return nil }); !errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatal("wrong master accepted")
	}
}

func TestResponseEvidenceLimitsAndVersionRetention(t *testing.T) {
	ring, scope, record := evidenceFixture(t)
	if _, err := ring.EncryptResponseEvidence(scope, domain.NormalizedResponse{Content: strings.Repeat("x", MaxEvidencePlaintextBytes)}); !errors.Is(err, ErrEvidenceLimit) {
		t.Fatal("serialized envelope overhead ignored")
	}
	rotated, err := NewKeyRing("two", map[string][]byte{"one": bytes.Repeat([]byte{0x17}, 32), "two": bytes.Repeat([]byte{0x91}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if err := rotated.WithResponseEvidence(scope, record, func(domain.NormalizedResponse) error { return nil }); err != nil {
		t.Fatal("retained old key unreadable")
	}
	retired, err := NewKeyRing("two", map[string][]byte{"two": bytes.Repeat([]byte{0x91}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if err := retired.WithResponseEvidence(scope, record, func(domain.NormalizedResponse) error { return nil }); !errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatal("missing historical key did not fail closed")
	}
	if _, err := ring.EncryptResponseEvidence(EvidenceScope{}, domain.NormalizedResponse{}); !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatal("invalid scope")
	}
}
