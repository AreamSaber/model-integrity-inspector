package secret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func preparedService(t *testing.T) *Service {
	t.Helper()
	store, err := repository.Open(t.Context(), repository.Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "secrets.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	service, err := NewService(store, testRing(t))
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestSecretServicePreparationScopesAndSafeMetadata(t *testing.T) {
	service := preparedService(t)
	input := Input{Type: "custom_header", HeaderName: "x-api-key", APIKey: []byte(canary), Headers: map[string]string{"X-Custom": "header-canary"}}
	auth, err := ValidateInput(input)
	if err != nil || auth.Type != "custom_header" || auth.HeaderName != "X-Api-Key" {
		t.Fatal("auth normalization")
	}
	prepared, err := service.PrepareCreate(1, input)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.ID <= 0 || prepared.OrganizationID != 1 || prepared.SecretVersion != 1 || len(prepared.Ciphertext) == 0 || bytes.Contains(prepared.Ciphertext, input.APIKey) || bytes.Contains(prepared.Ciphertext, []byte("header-canary")) {
		t.Fatal("invalid encrypted preparation")
	}
	// No table exists: preparation succeeds without any persistence operation.
	if err := service.ring.WithCredentialsForWorker(Scope{1, prepared.ID, 1}, Record{KeyVersion: prepared.KeyVersion, PayloadKeyVersion: prepared.PayloadKeyVersion, Fingerprint: prepared.Fingerprint, LastFour: prepared.LastFour, EncryptedDataKey: prepared.EncryptedDataKey, Nonce: prepared.Nonce, Ciphertext: prepared.Ciphertext}, func(credentials Credentials) error {
		return credentials.Use(func(key []byte, headers map[string][]byte) error {
			if string(key) != canary || string(headers["x-custom"]) != "header-canary" {
				t.Fatal("prepared payload mismatch")
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PrepareCreate(0, input); !errors.Is(err, repository.ErrOrganizationScope) {
		t.Fatal("missing org accepted")
	}
	for _, scope := range []Scope{{1, prepared.ID, 1}, {1, prepared.ID, math.MaxInt32 + 1}, {0, prepared.ID, 2}, {1, 0, 2}} {
		if _, err := service.PrepareReplacement(scope, input); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid replacement scope accepted")
		}
	}
	replacement, err := service.PrepareReplacement(Scope{1, prepared.ID, 2}, input)
	if err != nil || replacement.SecretVersion != 2 || bytes.Equal(prepared.Ciphertext, replacement.Ciphertext) || bytes.Equal(prepared.EncryptedDataKey, replacement.EncryptedDataKey) || bytes.Equal(prepared.Nonce, replacement.Nonce) {
		t.Fatal("replacement did not refresh encryption")
	}
	for _, sensitive := range []any{input, service, prepared} {
		if _, err := json.Marshal(sensitive); err == nil {
			t.Fatal("sensitive service value marshaled")
		}
		formatted := fmt.Sprintf("%v %+v %#v %s", sensitive, sensitive, sensitive, sensitive)
		for _, forbidden := range []string{canary, "header-canary", "x-api-key", prepared.Fingerprint} {
			if strings.Contains(formatted, forbidden) {
				t.Fatal("sensitive formatting leaked")
			}
		}
	}
	if string(input.APIKey) != canary || input.Headers["X-Custom"] != "header-canary" {
		t.Fatal("service mutated caller input")
	}
}

func TestSecretServiceFingerprintDomainSeparation(t *testing.T) {
	service := preparedService(t)
	first, err := service.EndpointFingerprint(1, "https://example.com/v1")
	if err != nil || len(first) != 64 {
		t.Fatal("fingerprint unavailable")
	}
	same, _ := service.EndpointFingerprint(1, "https://example.com/v1")
	otherTenant, _ := service.EndpointFingerprint(2, "https://example.com/v1")
	otherEndpoint, _ := service.EndpointFingerprint(1, "https://example.com/v2")
	if first != same || first == otherTenant || first == otherEndpoint {
		t.Fatal("endpoint fingerprint missing scope separation")
	}
	if _, err := service.EndpointFingerprint(0, "https://example.com/v1"); !errors.Is(err, ErrInvalid) {
		t.Fatal("fingerprint accepted missing org")
	}
	if _, err := service.EndpointFingerprint(1, ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("fingerprint accepted empty endpoint")
	}
	if _, err := NewService(nil, testRing(t)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil repository accepted")
	}
	if _, err := NewService(service.store, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil keyring accepted")
	}
}

func TestSecretInputRejectsReservedHeadersAndInvalidPayload(t *testing.T) {
	for _, header := range []string{"Authorization", "HOST", "Content-Type", "Accept", "User-Agent", "Content-Length", "Transfer-Encoding", "Connection", "Proxy-Authorization", "X-Forwarded-For", "Cookie", "X-Original-URL", "Idempotency-Key", "Accept-Encoding", "Bad Header", "X-CR\r\nLF"} {
		t.Run(header, func(t *testing.T) {
			for _, input := range []Input{{Type: "bearer", APIKey: []byte(canary), Headers: map[string]string{header: "value"}}, {Type: "custom_header", APIKey: []byte(canary), HeaderName: header}} {
				if _, err := ValidateInput(input); !errors.Is(err, ErrInvalid) {
					t.Fatal("reserved header accepted")
				}
			}
		})
	}
	for _, input := range []Input{{Type: "bearer", APIKey: []byte(canary), HeaderName: "X-Key"}, {Type: "custom_header", APIKey: []byte(canary)}, {Type: "bearer", APIKey: bytes.Repeat([]byte{'x'}, 8193)}, {Type: "bearer", APIKey: []byte{0xff}}, {Type: "bearer", APIKey: []byte(canary), Headers: map[string]string{"X-Value": "a\r\nb"}}} {
		if _, err := ValidateInput(input); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid input accepted")
		}
	}
	if _, err := ValidateInput(Input{Type: "bearer", APIKey: []byte(canary), Headers: map[string]string{"X-OK": "value"}}); err != nil {
		t.Fatal("allowed header rejected")
	}
}
