package secret

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/evidencedisplay"
)

func requestReproductionFixture(t testing.TB) (*KeyRing, *evidencedisplay.PreparedRequestReproduction, RequestReproductionBinding, time.Time) {
	t.Helper()
	seed := int64(9223372036854775807)
	r := domain.NormalizedRequest{Model: "test-model", Messages: []domain.NormalizedMessage{{Role: "user", Content: "Synthetic " + canary + " synthetic-private-header"}}, Seed: &seed, MaxOutputTokens: 64}
	a, err := openaichat.New(openaichat.Config{Endpoint: "https://analysis.invalid/v1", Doer: noDisplayNetwork{}})
	if err != nil {
		t.Fatal(err)
	}
	wire, snapshot, err := a.BuildRequest(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	_ = wire.Body.Close()
	credentials, err := NewCredentials([]byte(canary), map[string]string{"X-Ordinary": "synthetic-private-header"})
	if err != nil {
		t.Fatal(err)
	}
	defer credentials.Destroy()
	var prepared *evidencedisplay.PreparedRequestReproduction
	manifest := strings.Repeat("a", 64)
	if err := credentials.Use(func(key []byte, headers map[string][]byte) error {
		var e error
		prepared, e = evidencedisplay.PrepareRequestReproduction(context.Background(), evidencedisplay.RequestReproductionSource{Request: r, Snapshot: snapshot, ManifestHash: manifest}, key, headers)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 8, 10, 0, 0, 123456000, time.UTC)
	// Synthetic one-day expiry is a test input, not an organization default.
	b := RequestReproductionBinding{Scope: EvidenceScope{OrganizationID: 1, RunID: 2, LogicalSampleID: 3, AttemptID: 4, RequestHash: snapshot.RequestHash}, ManifestHash: manifest, CapturedAtMicros: now.UnixMicro(), ExpiresAtMicros: now.Add(24 * time.Hour).UnixMicro()}
	return testRing(t), prepared, b, now
}

func TestRequestReproductionPurposeRoundTripProtectedNarrowCapabilities(t *testing.T) {
	ring, prepared, binding, now := requestReproductionFixture(t)
	defer prepared.Close()
	sealer, opener, err := ring.NewRequestReproductionCapabilities(func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	record, err := sealer.Seal(context.Background(), binding, prepared)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sealer.Seal(context.Background(), binding, prepared)
	if err != nil || bytes.Equal(record.Nonce, second.Nonce) || bytes.Contains(record.Ciphertext, []byte(canary)) {
		t.Fatal("unsafe encrypted request record")
	}
	opened, err := opener.Open(context.Background(), binding, record)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	var borrowed []byte
	if err := opened.WithCanonicalForReproduction(context.Background(), func(data []byte) error {
		borrowed = data
		if bytes.Contains(data, []byte(canary)) || bytes.Contains(data, []byte("synthetic-private-header")) || !bytes.Contains(data, []byte("[REDACTED]")) || !bytes.Contains(data, []byte("9223372036854775807")) {
			t.Fatal("authenticated request not redacted/exact")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("borrowed plaintext not cleared")
	}
	for _, value := range []any{sealer, *sealer, opener, *opener, binding, &binding, record, &record} {
		if _, err := json.Marshal(value); !errors.Is(err, evidencedisplay.ErrSensitive) {
			t.Fatal("protected crypto wrapper serialized")
		}
		var log bytes.Buffer
		for _, handler := range []slog.Handler{slog.NewJSONHandler(&log, nil), slog.NewTextHandler(&log, nil)} {
			slog.New(handler).Info("safe", "value", value, slog.Group("nested", "value", value))
		}
		for _, text := range []string{fmt.Sprintf("%v %+v %#v %s", value, value, value, value), log.String()} {
			for _, absent := range []string{canary, record.PayloadHash, binding.ManifestHash, "one"} {
				if strings.Contains(text, absent) {
					t.Fatal("crypto wrapper logged protected data")
				}
			}
		}
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(sealer), reflect.TypeOf(opener)} {
		for _, method := range []string{"WithCredentialsForWorker", "WithResponseEvidence", "EncryptResponseEvidence", "NewDisplayCapabilities", "Rewrap", "Encrypt"} {
			if _, ok := typ.MethodByName(method); ok {
				t.Fatal("foreign capability exposed")
			}
		}
		for i := 0; i < typ.Elem().NumField(); i++ {
			if typ.Elem().Field(i).Type == reflect.TypeOf(ring) {
				t.Fatal("capability retains KeyRing")
			}
		}
	}
	ring.keys["one"].requestReproduction[0] ^= 1
	still, err := opener.Open(context.Background(), binding, record)
	if err != nil {
		t.Fatal("factory retained key alias")
	}
	still.Close()
}

func TestRequestReproductionAllAADEnvelopeAndLifetimeTampering(t *testing.T) {
	ring, prepared, binding, now := requestReproductionFixture(t)
	defer prepared.Close()
	sealer, opener, _ := ring.NewRequestReproductionCapabilities(func() time.Time { return now })
	record, err := sealer.Seal(context.Background(), binding, prepared)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*RequestReproductionBinding){
		func(b *RequestReproductionBinding) { b.Scope.OrganizationID++ }, func(b *RequestReproductionBinding) { b.Scope.RunID++ }, func(b *RequestReproductionBinding) { b.Scope.LogicalSampleID++ }, func(b *RequestReproductionBinding) { b.Scope.AttemptID++ }, func(b *RequestReproductionBinding) { b.Scope.RequestHash = strings.Repeat("b", 64) }, func(b *RequestReproductionBinding) { b.ManifestHash = strings.Repeat("c", 64) }, func(b *RequestReproductionBinding) { b.CapturedAtMicros-- }, func(b *RequestReproductionBinding) { b.ExpiresAtMicros++ }, func(b *RequestReproductionBinding) { b.CapturedAtMicros = 0 },
	} {
		bad := binding
		mutate(&bad)
		if value, err := opener.Open(context.Background(), bad, record); value != nil || !errors.Is(err, ErrRequestReproductionUnavailable) {
			t.Fatal("changed scope/manifest/time accepted")
		}
	}
	for _, mutate := range []func(*RequestReproductionRecord){
		func(r *RequestReproductionRecord) { r.Version++ }, func(r *RequestReproductionRecord) { r.Policy = evidencedisplay.PolicyVersion }, func(r *RequestReproductionRecord) { r.KeyVersion = "two" }, func(r *RequestReproductionRecord) { r.KeyVersion = "missing" }, func(r *RequestReproductionRecord) { r.PayloadHash = strings.Repeat("d", 64) }, func(r *RequestReproductionRecord) { r.PlaintextBytes++ }, func(r *RequestReproductionRecord) { r.PlaintextBytes = evidencedisplay.MaxPayloadBytes + 1 }, func(r *RequestReproductionRecord) { r.Nonce[0] ^= 1 }, func(r *RequestReproductionRecord) { r.Ciphertext[len(r.Ciphertext)-1] ^= 1 }, func(r *RequestReproductionRecord) { r.Nonce = r.Nonce[:11] },
	} {
		bad := record
		bad.Nonce = bytes.Clone(record.Nonce)
		bad.Ciphertext = bytes.Clone(record.Ciphertext)
		mutate(&bad)
		if value, err := opener.Open(context.Background(), binding, bad); value != nil || !errors.Is(err, ErrRequestReproductionUnavailable) {
			t.Fatal("changed envelope accepted")
		}
	}
	for _, offset := range []time.Duration{-time.Microsecond, 24 * time.Hour, 25 * time.Hour} {
		_, reader, _ := ring.NewRequestReproductionCapabilities(func() time.Time { return now.Add(offset) })
		if value, err := reader.Open(context.Background(), binding, record); value != nil || !errors.Is(err, ErrRequestReproductionUnavailable) {
			t.Fatal("future capture/expired boundary accepted")
		}
	}
	for _, mutate := range []func(*RequestReproductionBinding){func(b *RequestReproductionBinding) { b.ManifestHash = strings.Repeat("c", 64) }, func(b *RequestReproductionBinding) { b.Scope.RequestHash = strings.Repeat("d", 64) }, func(b *RequestReproductionBinding) { b.ExpiresAtMicros = b.CapturedAtMicros }} {
		bad := binding
		mutate(&bad)
		if value, err := sealer.Seal(context.Background(), bad, prepared); len(value.Ciphertext) != 0 || !errors.Is(err, ErrRequestReproductionUnavailable) {
			t.Fatal("invalid seal binding accepted")
		}
	}
	// No hidden response retention assumption (this is not policy approval).
	long := binding
	long.ExpiresAtMicros = now.Add(181 * 24 * time.Hour).UnixMicro()
	if _, err := sealer.Seal(context.Background(), long, prepared); err != nil {
		t.Fatal("crypto imposed an undocumented response-day policy")
	}
}

func TestRequestReproductionRejectsOtherPurposesAndRealKeyRotation(t *testing.T) {
	ring, prepared, binding, now := requestReproductionFixture(t)
	defer prepared.Close()
	sealer, opener, _ := ring.NewRequestReproductionCapabilities(func() time.Time { return now })
	record, err := sealer.Seal(context.Background(), binding, prepared)
	if err != nil {
		t.Fatal(err)
	}
	_, displayPrepared, displayBinding, _ := displayFixture(t)
	defer displayPrepared.Close()
	displayWriter, displayReader, _ := ring.NewDisplayCapabilities(func() time.Time { return now })
	displayRecord, err := displayWriter.Seal(context.Background(), displayBinding, displayPrepared)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ring.EncryptResponseEvidence(binding.Scope, domain.NormalizedResponse{Content: canary})
	if err != nil {
		t.Fatal(err)
	}
	for _, foreign := range []RequestReproductionRecord{
		{Version: 1, Policy: evidencedisplay.RequestReproductionPolicyVersion, KeyVersion: raw.KeyVersion, Nonce: raw.Nonce, Ciphertext: raw.Ciphertext, PlaintextBytes: raw.PlaintextBytes, PayloadHash: raw.ContentHash},
		{Version: 1, Policy: evidencedisplay.RequestReproductionPolicyVersion, KeyVersion: displayRecord.KeyVersion, Nonce: displayRecord.Nonce, Ciphertext: displayRecord.Ciphertext, PlaintextBytes: displayRecord.PlaintextBytes, PayloadHash: displayRecord.PayloadHash},
	} {
		if value, err := opener.Open(context.Background(), binding, foreign); value != nil || !errors.Is(err, ErrRequestReproductionUnavailable) {
			t.Fatal("another purpose opened as request")
		}
	}
	fakeDisplay := DisplayRecord{Version: 1, Policy: evidencedisplay.PolicyVersion, KeyVersion: record.KeyVersion, Nonce: record.Nonce, Ciphertext: record.Ciphertext, PlaintextBytes: record.PlaintextBytes, PayloadHash: record.PayloadHash}
	if value, err := displayReader.Open(context.Background(), displayBinding, fakeDisplay); value != nil || !errors.Is(err, ErrDisplayUnavailable) {
		t.Fatal("request opened as display")
	}
	fakeRaw := EvidenceRecord{KeyVersion: record.KeyVersion, Nonce: record.Nonce, Ciphertext: record.Ciphertext, PlaintextBytes: record.PlaintextBytes, ContentHash: record.PayloadHash}
	if err := ring.WithResponseEvidence(binding.Scope, fakeRaw, func(domain.NormalizedResponse) error { t.Fatal("request opened as raw"); return nil }); !errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatal("raw purpose isolation failed")
	}
	rotated, err := NewKeyRing("two", map[string][]byte{"one": bytes.Repeat([]byte{0x17}, 32), "two": bytes.Repeat([]byte{0x91}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	newWriter, reader, _ := rotated.NewRequestReproductionCapabilities(func() time.Time { return now })
	oldView, err := reader.Open(context.Background(), binding, record)
	if err != nil {
		t.Fatal(err)
	}
	oldView.Close()
	newRecord, err := newWriter.Seal(context.Background(), binding, prepared)
	if err != nil || newRecord.KeyVersion != "two" {
		t.Fatal("active rotation not used")
	}
	newView, err := reader.Open(context.Background(), binding, newRecord)
	if err != nil {
		t.Fatal(err)
	}
	newView.Close()
	retired, err := NewKeyRing("two", map[string][]byte{"two": bytes.Repeat([]byte{0x91}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	_, reader, _ = retired.NewRequestReproductionCapabilities(func() time.Time { return now })
	if value, err := reader.Open(context.Background(), binding, record); value != nil || !errors.Is(err, ErrRequestReproductionUnavailable) {
		t.Fatal("missing historical key fell back")
	}
	wrong, err := NewKeyRing("one", map[string][]byte{"one": bytes.Repeat([]byte{0x92}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	_, reader, _ = wrong.NewRequestReproductionCapabilities(func() time.Time { return now })
	if value, err := reader.Open(context.Background(), binding, record); value != nil || !errors.Is(err, ErrRequestReproductionUnavailable) {
		t.Fatal("changed master under same version accepted")
	}
}

func TestRequestReproductionCancellationExpiryPanicAndConcurrentReuse(t *testing.T) {
	ring, prepared, binding, now := requestReproductionFixture(t)
	defer prepared.Close()
	sealer, opener, _ := ring.NewRequestReproductionCapabilities(func() time.Time { return now })
	record, err := sealer.Seal(context.Background(), binding, prepared)
	if err != nil {
		t.Fatal(err)
	}
	for _, when := range []int{1, 2} {
		for _, action := range []string{"cancel", "expiry", "panic"} {
			for _, operation := range []string{"seal", "open"} {
				t.Run(fmt.Sprintf("%s-%s-%d", operation, action, when), func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					calls := 0
					writer, reader, err := ring.NewRequestReproductionCapabilities(func() time.Time {
						calls++
						if calls == when {
							switch action {
							case "cancel":
								cancel()
							case "expiry":
								return time.UnixMicro(binding.ExpiresAtMicros)
							case "panic":
								panic(canary)
							}
						}
						return now
					})
					if err != nil {
						t.Fatal(err)
					}
					want := ErrRequestReproductionUnavailable
					if action == "cancel" {
						want = evidencedisplay.ErrCancelled
					}
					if operation == "seal" {
						value, err := writer.Seal(ctx, binding, prepared)
						if len(value.Ciphertext) != 0 || !errors.Is(err, want) {
							t.Fatal("failed seal released output", err)
						}
					} else {
						value, err := reader.Open(ctx, binding, record)
						if value != nil || !errors.Is(err, want) {
							t.Fatal("failed open released plaintext", err)
						}
					}
				})
			}
		}
	}
	if _, _, err := (*KeyRing)(nil).NewRequestReproductionCapabilities(nil); !errors.Is(err, ErrRequestReproductionUnavailable) {
		t.Fatal("nil ring accepted")
	}
	if _, _, err := ring.NewRequestReproductionCapabilities(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := (&RequestReproductionSealer{}).Seal(context.Background(), binding, prepared); !errors.Is(err, ErrRequestReproductionUnavailable) {
		t.Fatal("zero sealer accepted")
	}
	if value, err := (&RequestReproductionOpener{}).Open(context.Background(), binding, record); value != nil || !errors.Is(err, ErrRequestReproductionUnavailable) {
		t.Fatal("zero opener accepted")
	}
	var wait sync.WaitGroup
	failures := make(chan error, 12)
	for range 12 {
		wait.Go(func() {
			record, err := sealer.Seal(context.Background(), binding, prepared)
			if err == nil {
				view, e := opener.Open(context.Background(), binding, record)
				err = e
				if view != nil {
					view.Close()
				}
			}
			if err != nil {
				failures <- err
			}
		})
	}
	wait.Wait()
	close(failures)
	for range failures {
		t.Fatal("immutable capabilities failed concurrent use")
	}
}

func TestRequestReproductionAuthenticatedInvalidPayloadAndPurposeGolden(t *testing.T) {
	ring, prepared, binding, now := requestReproductionFixture(t)
	defer prepared.Close()
	_, reader, _ := ring.NewRequestReproductionCapabilities(func() time.Time { return now })
	var original []byte
	if err := prepared.WithCanonicalForSeal(context.Background(), func(data []byte) error { original = bytes.Clone(data); return nil }); err != nil {
		t.Fatal(err)
	}
	defer clear(original)
	for _, data := range [][]byte{bytes.Replace(original, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(original, []byte(`"version":1`), []byte(`"version":1,"response":{}`), 1)} {
		hash := sha256.Sum256(data)
		record := RequestReproductionRecord{Version: 1, Policy: evidencedisplay.RequestReproductionPolicyVersion, KeyVersion: "one", Nonce: bytes.Repeat([]byte{0x53}, 12), PlaintextBytes: len(data), PayloadHash: hex.EncodeToString(hash[:])}
		aad, err := requestReproductionAAD(binding, record)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := gcm(ring.keys["one"].requestReproduction)
		if err != nil {
			t.Fatal(err)
		}
		record.Ciphertext = aead.Seal(nil, record.Nonce, data, aad)
		if value, err := reader.Open(context.Background(), binding, record); value != nil || !errors.Is(err, ErrRequestReproductionUnavailable) {
			t.Fatal("AEAD bypassed closed schema")
		}
	}
	// Independent .NET HMAC-SHA256 extract/expand vector, public synthetic
	// master=0x17*32, version=one; existing nine-purpose goldens stay untouched.
	keys := ring.keys["one"]
	if hex.EncodeToString(keys.requestReproduction) != "4ff0f738f5b6cbe6583bc1c2aed504134701b0b1f5e6c597a498b64913ef0377" {
		t.Fatal("request purpose golden changed")
	}
	mac := hmac.New(sha256.New, keys.requestReproduction)
	_, _ = mac.Write([]byte("synthetic-golden-event"))
	if hex.EncodeToString(mac.Sum(nil)) != "42eeda7aec5e4cb1849a6a276e5ba2f8af888468f7e8ab00ff6d755469082e30" {
		t.Fatal("request purpose output golden changed")
	}
	for _, key := range [][]byte{keys.wrap, keys.fingerprint, keys.audit, keys.cursor, keys.probe, keys.evidence, keys.baseline, keys.display, keys.derivedSource} {
		if bytes.Equal(key, keys.requestReproduction) {
			t.Fatal("request key reused an existing purpose")
		}
		// Hold every request AAD/payload field identical and change only the
		// actual purpose-derived key, so rejection is not merely a DTO mismatch.
		hash := sha256.Sum256(original)
		foreign := RequestReproductionRecord{Version: 1, Policy: evidencedisplay.RequestReproductionPolicyVersion, KeyVersion: "one", Nonce: bytes.Repeat([]byte{0x54}, 12), PlaintextBytes: len(original), PayloadHash: hex.EncodeToString(hash[:])}
		aad, err := requestReproductionAAD(binding, foreign)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := gcm(key)
		if err != nil {
			t.Fatal(err)
		}
		foreign.Ciphertext = aead.Seal(nil, foreign.Nonce, original, aad)
		if value, err := reader.Open(context.Background(), binding, foreign); value != nil || !errors.Is(err, ErrRequestReproductionUnavailable) {
			t.Fatal("foreign purpose key accepted with identical request AAD")
		}
	}
}

func FuzzRequestReproductionChangedTagFails(f *testing.F) {
	f.Add(byte(0), byte(1))
	f.Add(byte(15), byte(255))
	f.Fuzz(func(t *testing.T, position, mask byte) {
		if mask == 0 {
			mask = 1
		}
		ring, prepared, binding, now := requestReproductionFixture(t)
		defer prepared.Close()
		writer, reader, _ := ring.NewRequestReproductionCapabilities(func() time.Time { return now })
		record, err := writer.Seal(context.Background(), binding, prepared)
		if err != nil {
			t.Fatal(err)
		}
		record.Ciphertext[len(record.Ciphertext)-16+int(position)%16] ^= mask
		if value, err := reader.Open(context.Background(), binding, record); value != nil || !errors.Is(err, ErrRequestReproductionUnavailable) {
			t.Fatal("changed tag opened")
		}
	})
}
