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
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/evidencedisplay"
)

type noDisplayNetwork struct{}

func (noDisplayNetwork) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("synthetic-no-network")
}

func displayFixture(t testing.TB) (*KeyRing, *evidencedisplay.Prepared, DisplayBinding, time.Time) {
	t.Helper()
	ring := testRing(t)
	request := domain.NormalizedRequest{Model: "test-model", Messages: []domain.NormalizedMessage{{Role: "user", Content: "Synthetic " + canary}}, MaxOutputTokens: 64}
	adapter, err := openaichat.New(openaichat.Config{Endpoint: "https://analysis.invalid/v1", Doer: noDisplayNetwork{}})
	if err != nil {
		t.Fatal(err)
	}
	wire, snapshot, err := adapter.BuildRequest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	_ = wire.Body.Close()
	source := evidencedisplay.Source{Request: request, Snapshot: snapshot, Response: domain.NormalizedResponse{Content: "Synthetic " + canary, ModelReported: "test-model", HTTPStatus: 200, ParseStatus: "valid", FinishReason: "stop", DurationMs: 2}}
	credentials, err := NewCredentials([]byte(canary), map[string]string{"X-Ordinary": "synthetic-private-header"})
	if err != nil {
		t.Fatal(err)
	}
	defer credentials.Destroy()
	var prepared *evidencedisplay.Prepared
	if err := credentials.Use(func(key []byte, headers map[string][]byte) error {
		var e error
		prepared, e = evidencedisplay.Prepare(context.Background(), source, key, headers)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 7, 10, 0, 0, 123456000, time.UTC)
	sourceHash, requestHash := prepared.Hashes()
	binding := DisplayBinding{Scope: EvidenceScope{OrganizationID: 1, RunID: 2, LogicalSampleID: 3, AttemptID: 4, RequestHash: requestHash}, SourceHash: sourceHash, CapturedAtMicros: now.UnixMicro(), ExpiresAtMicros: now.Add(30 * 24 * time.Hour).UnixMicro()}
	return ring, prepared, binding, now
}

func TestDisplayPurposeRoundTripAndNarrowCapabilities(t *testing.T) {
	ring, prepared, binding, now := displayFixture(t)
	defer prepared.Close()
	sealer, opener, err := ring.NewDisplayCapabilities(func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	record, err := sealer.Seal(context.Background(), binding, prepared)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sealer.Seal(context.Background(), binding, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(record.Nonce, second.Nonce) || bytes.Contains(record.Ciphertext, []byte(canary)) {
		t.Fatal("unsafe encrypted display record")
	}
	opened, err := opener.Open(context.Background(), binding, record)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	var borrowed []byte
	if err := opened.WithCanonicalForDisplay(context.Background(), func(value []byte) error {
		borrowed = value
		if bytes.Contains(value, []byte(canary)) || !bytes.Contains(value, []byte("[REDACTED]")) {
			t.Fatal("authenticated display was not redacted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("display callback retained owned bytes")
	}
	for _, value := range []any{sealer, *sealer, opener, *opener, record, &record, binding, &binding} {
		if _, err := json.Marshal(value); !errors.Is(err, evidencedisplay.ErrSensitive) {
			t.Fatal("display capability/binding/record serialized")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			text := fmt.Sprintf(format, value)
			if strings.Contains(text, record.PayloadHash) || strings.Contains(text, "one") || strings.Contains(text, canary) || strings.Contains(text, binding.SourceHash) {
				t.Fatal("display wrapper exposed protected fields")
			}
		}
		var log bytes.Buffer
		for _, handler := range []slog.Handler{slog.NewJSONHandler(&log, nil), slog.NewTextHandler(&log, nil)} {
			slog.New(handler).Info("safe", "value", value, slog.Group("nested", "value", value))
		}
		if strings.Contains(log.String(), binding.SourceHash) || strings.Contains(log.String(), canary) || strings.Contains(log.String(), "one") {
			t.Fatal("structured logger bypassed redaction")
		}
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(sealer), reflect.TypeOf(opener)} {
		for _, name := range []string{"WithCredentialsForWorker", "WithResponseEvidence", "EncryptResponseEvidence", "Rewrap", "Encrypt"} {
			if _, ok := typ.MethodByName(name); ok {
				t.Fatal("display capability gained a different-purpose method")
			}
		}
		for i := 0; i < typ.Elem().NumField(); i++ {
			if typ.Elem().Field(i).Type == reflect.TypeOf(ring) {
				t.Fatal("display capability embeds KeyRing")
			}
		}
	}
	// Factories copy the purpose key, rather than retaining the parent key set.
	ring.keys["one"].display[0] ^= 1
	still, err := opener.Open(context.Background(), binding, record)
	if err != nil {
		t.Fatal("capability retained parent key alias")
	}
	still.Close()
}

func TestDisplayBindingCiphertextAndLifetimeTampering(t *testing.T) {
	ring, prepared, binding, now := displayFixture(t)
	defer prepared.Close()
	sealer, opener, _ := ring.NewDisplayCapabilities(func() time.Time { return now })
	record, err := sealer.Seal(context.Background(), binding, prepared)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*DisplayBinding){
		func(b *DisplayBinding) { b.Scope.OrganizationID++ }, func(b *DisplayBinding) { b.Scope.RunID++ }, func(b *DisplayBinding) { b.Scope.LogicalSampleID++ }, func(b *DisplayBinding) { b.Scope.AttemptID++ }, func(b *DisplayBinding) { b.Scope.RequestHash = strings.Repeat("b", 64) }, func(b *DisplayBinding) { b.SourceHash = strings.Repeat("c", 64) }, func(b *DisplayBinding) { b.CapturedAtMicros-- }, func(b *DisplayBinding) { b.ExpiresAtMicros++ }, func(b *DisplayBinding) { b.CapturedAtMicros = 0 },
	} {
		bad := binding
		change(&bad)
		if result, err := opener.Open(context.Background(), bad, record); result != nil || !errors.Is(err, ErrDisplayUnavailable) {
			t.Fatal("changed expected scope/time accepted")
		}
	}
	for _, change := range []func(*DisplayRecord){
		func(r *DisplayRecord) { r.Version++ }, func(r *DisplayRecord) { r.Policy = "legacy-unverified" }, func(r *DisplayRecord) { r.KeyVersion = "two" }, func(r *DisplayRecord) { r.KeyVersion = "missing" }, func(r *DisplayRecord) { r.PayloadHash = strings.Repeat("d", 64) }, func(r *DisplayRecord) { r.PlaintextBytes++ }, func(r *DisplayRecord) { r.PlaintextBytes = evidencedisplay.MaxPayloadBytes + 1 }, func(r *DisplayRecord) { r.Nonce[0] ^= 1 }, func(r *DisplayRecord) { r.Ciphertext[len(r.Ciphertext)-1] ^= 1 }, func(r *DisplayRecord) { r.Nonce = r.Nonce[:11] },
	} {
		bad := record
		bad.Nonce = bytes.Clone(record.Nonce)
		bad.Ciphertext = bytes.Clone(record.Ciphertext)
		change(&bad)
		if result, err := opener.Open(context.Background(), binding, bad); result != nil || !errors.Is(err, ErrDisplayUnavailable) {
			t.Fatal("changed display envelope accepted")
		}
	}
	for _, offset := range []time.Duration{-time.Microsecond, 30 * 24 * time.Hour, 31 * 24 * time.Hour} {
		at := now.Add(offset)
		_, reader, _ := ring.NewDisplayCapabilities(func() time.Time { return at })
		if result, err := reader.Open(context.Background(), binding, record); result != nil || !errors.Is(err, ErrDisplayUnavailable) {
			t.Fatal("future capture or expired boundary accepted")
		}
	}
	for _, change := range []func(*DisplayBinding){func(b *DisplayBinding) { b.ExpiresAtMicros = b.CapturedAtMicros }, func(b *DisplayBinding) {
		b.ExpiresAtMicros = b.CapturedAtMicros + int64(181*24*time.Hour/time.Microsecond)
	}, func(b *DisplayBinding) { b.Scope.RequestHash = strings.Repeat("b", 64) }, func(b *DisplayBinding) { b.SourceHash = strings.Repeat("c", 64) }} {
		bad := binding
		change(&bad)
		if _, err := sealer.Seal(context.Background(), bad, prepared); !errors.Is(err, ErrDisplayUnavailable) {
			t.Fatal("invalid seal binding accepted")
		}
	}
}

func TestDisplayPurposeCannotOpenAnalysisOrSurviveMissingHistoricalKey(t *testing.T) {
	ring, prepared, binding, now := displayFixture(t)
	defer prepared.Close()
	sealer, opener, _ := ring.NewDisplayCapabilities(func() time.Time { return now })
	record, err := sealer.Seal(context.Background(), binding, prepared)
	if err != nil {
		t.Fatal(err)
	}
	old, err := ring.EncryptResponseEvidence(binding.Scope, domain.NormalizedResponse{Content: canary})
	if err != nil {
		t.Fatal(err)
	}
	fake := DisplayRecord{Version: 1, Policy: evidencedisplay.PolicyVersion, KeyVersion: old.KeyVersion, Nonce: old.Nonce, Ciphertext: old.Ciphertext, PlaintextBytes: old.PlaintextBytes, PayloadHash: old.ContentHash}
	if result, err := opener.Open(context.Background(), binding, fake); result != nil || !errors.Is(err, ErrDisplayUnavailable) {
		t.Fatal("raw analysis evidence opened as display")
	}
	reverse := EvidenceRecord{KeyVersion: record.KeyVersion, Nonce: record.Nonce, Ciphertext: record.Ciphertext, PlaintextBytes: record.PlaintextBytes, ContentHash: record.PayloadHash}
	if err := ring.WithResponseEvidence(binding.Scope, reverse, func(domain.NormalizedResponse) error { t.Fatal("display opened as raw analysis"); return nil }); !errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatal("purpose isolation failed")
	}
	rotated, err := NewKeyRing("two", map[string][]byte{"one": bytes.Repeat([]byte{0x17}, 32), "two": bytes.Repeat([]byte{0x91}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	_, reader, _ := rotated.NewDisplayCapabilities(func() time.Time { return now })
	view, err := reader.Open(context.Background(), binding, record)
	if err != nil {
		t.Fatal(err)
	}
	view.Close()
	retired, err := NewKeyRing("two", map[string][]byte{"two": bytes.Repeat([]byte{0x91}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	_, reader, _ = retired.NewDisplayCapabilities(func() time.Time { return now })
	if view, err := reader.Open(context.Background(), binding, record); view != nil || !errors.Is(err, ErrDisplayUnavailable) {
		t.Fatal("retired key silently replaced")
	}
}

func TestDisplayCancellationInvalidCapabilitiesAndConcurrentReuse(t *testing.T) {
	ring, prepared, binding, now := displayFixture(t)
	defer prepared.Close()
	sealer, opener, _ := ring.NewDisplayCapabilities(func() time.Time { return now })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sealer.Seal(ctx, binding, prepared); !errors.Is(err, evidencedisplay.ErrCancelled) {
		t.Fatal("seal cancellation ignored")
	}
	if view, err := opener.Open(ctx, binding, DisplayRecord{}); view != nil || !errors.Is(err, evidencedisplay.ErrCancelled) {
		t.Fatal("open cancellation ignored")
	}
	if _, err := (&DisplaySealer{}).Seal(context.Background(), binding, prepared); !errors.Is(err, ErrDisplayUnavailable) {
		t.Fatal("zero sealer accepted")
	}
	if view, err := (&DisplayOpener{}).Open(context.Background(), binding, DisplayRecord{}); view != nil || !errors.Is(err, ErrDisplayUnavailable) {
		t.Fatal("zero opener accepted")
	}
	if _, _, err := (*KeyRing)(nil).NewDisplayCapabilities(nil); !errors.Is(err, ErrDisplayUnavailable) {
		t.Fatal("nil ring accepted")
	}
	if _, _, err := ring.NewDisplayCapabilities(nil); err != nil {
		t.Fatal(err)
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

func TestDisplayOpenerRejectsAuthenticatedButInvalidDocument(t *testing.T) {
	ring, prepared, binding, now := displayFixture(t)
	defer prepared.Close()
	_, opener, _ := ring.NewDisplayCapabilities(func() time.Time { return now })
	var original []byte
	if err := prepared.WithCanonicalForSeal(context.Background(), func(data []byte) error { original = bytes.Clone(data); return nil }); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{bytes.Replace(original, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(original, []byte(`"metadata_omitted":true`), []byte(`"metadata_omitted":false`), 1), bytes.Replace(original, []byte(`"version":1`), []byte(`"version":1,"extra":"unknown"`), 1)} {
		hash := sha256.Sum256(data)
		record := DisplayRecord{Version: 1, Policy: evidencedisplay.PolicyVersion, KeyVersion: "one", Nonce: bytes.Repeat([]byte{0x53}, 12), PlaintextBytes: len(data), PayloadHash: hex.EncodeToString(hash[:])}
		aad, err := displayAAD(binding, record)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := gcm(ring.keys["one"].display)
		if err != nil {
			t.Fatal(err)
		}
		record.Ciphertext = aead.Seal(nil, record.Nonce, data, aad)
		if value, err := opener.Open(context.Background(), binding, record); value != nil || !errors.Is(err, ErrDisplayUnavailable) {
			t.Fatal("AEAD authenticity bypassed closed payload schema")
		}
	}
}

func FuzzDisplayEnvelopeRejectsChangedAuthenticationTag(f *testing.F) {
	f.Add(byte(0), byte(1))
	f.Add(byte(12), byte(255))
	f.Fuzz(func(t *testing.T, position, mask byte) {
		if mask == 0 {
			mask = 1
		}
		ring, prepared, binding, now := displayFixture(t)
		defer prepared.Close()
		sealer, opener, _ := ring.NewDisplayCapabilities(func() time.Time { return now })
		record, err := sealer.Seal(context.Background(), binding, prepared)
		if err != nil {
			t.Fatal(err)
		}
		at := len(record.Ciphertext) - 16 + int(position)%16
		record.Ciphertext[at] ^= mask
		if view, err := opener.Open(context.Background(), binding, record); view != nil || !errors.Is(err, ErrDisplayUnavailable) {
			t.Fatal("changed tag opened")
		}
	})
}

func TestDisplayPurposeGoldenPreservesEveryPreviousKeyAndMAC(t *testing.T) {
	// Public synthetic compatibility vectors: master=0x17 repeated 32 times,
	// version=one, HKDF info=mii/v1/<purpose>/one. Independently computed with
	// HMAC-SHA256 extract/expand, not generated from the implementation in test.
	keys := testRing(t).keys["one"]
	for _, item := range []struct {
		name           string
		actual         []byte
		keyHex, macHex string
	}{
		{"secret-wrap", keys.wrap, "0a9ca4703e44065e840093c119b4b39ef470d98dbd904c12bed34afe7b76b3f4", "661209bc9ddbb90e90dd67603287626f140f6c5deb51bb45213375663ef895bf"},
		{"secret-fingerprint", keys.fingerprint, "34219f79a73476f275f2d02995475d908c625803b220fd00dd6934338a9ad302", "516ede9b72fe10b97f0d7a9071227652f8d0b84448c31db26310f27f6cfe9da0"},
		{"audit-integrity", keys.audit, "8e1c5c7707e3bf2fa481815ddaaab8fd0ccd97f22ff4024a2ff86567b18c6825", "51319a5cb24428a98ad1270f59c1ab7560be6bc88a907bd4f5fbcc1bcd43aab2"},
		{"pagination-cursor", keys.cursor, "0684de766af12e12e293d9c2270376f2709ff73ad40b5866637f72aa3a29ab45", "bcd13c96c7a64f911ed62382f26b3b8271b85800798c52201d04b10e2eb57b7d"},
		{"probe-reproduction", keys.probe, "8a62ec5bbc1c85ad45ca3e8c9918486567fedb6b68facf21cd88320ed6808a03", "f1212996618f4801360210e435c2a26cd5146f394b080449056eaf902064d903"},
		{"response-evidence", keys.evidence, "d5bda113511799d8880e8f0b5f81710c68c0bff501b9ae8c94bd90436c3b5cff", "218add7680194cfa857df6e6382c0142d607c9f2796ee817f48d4f160b8453bf"},
		{"baseline-approval", keys.baseline, "501ed9c664aece159f570567926eaa9d7d809b9330c9e8d99ff2c774f5e8edfa", "7e48ba87c1982460e1904a4beb5134fe2cecf17a6ff2e47750f16d8e97737012"},
		{"evidence-display", keys.display, "b0019d0619f558aab57fdfb34a1bbea883eb314ae253d8cb530f4009520687bf", "414d5cea96a530e93e6050cb7a30d1f0fdf307473e2e18029c1e95f1e59b0dcb"},
		{"derived-s1-authentication", keys.derivedSource, "0e4cd005fec43175bc8d846fcdaf7a9cb4f294d483dcb2542abe7d54eccf11e1", "d8cfce8dc0d5434be0ef8873178fac39021837d4868dbcd78c09f4b9c4171a19"},
	} {
		t.Run(item.name, func(t *testing.T) {
			if hex.EncodeToString(item.actual) != item.keyHex {
				t.Fatal("purpose key changed")
			}
			mac := hmac.New(sha256.New, item.actual)
			_, _ = mac.Write([]byte("synthetic-golden-event"))
			if hex.EncodeToString(mac.Sum(nil)) != item.macHex {
				t.Fatal("purpose output changed")
			}
			if item.name != "evidence-display" && bytes.Equal(item.actual, keys.display) {
				t.Fatal("display key reused another purpose")
			}
			if item.name != "derived-s1-authentication" && bytes.Equal(item.actual, keys.derivedSource) {
				t.Fatal("derived source key reused another purpose")
			}
		})
	}
}

func TestDisplayCancellationDuringFinalClockCheckDoesNotRelease(t *testing.T) {
	ring, prepared, binding, now := displayFixture(t)
	defer prepared.Close()
	sealer, _, _ := ring.NewDisplayCapabilities(func() time.Time { return now })
	record, err := sealer.Seal(context.Background(), binding, prepared)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"seal", "open"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			checks := 0
			writer, reader, e := ring.NewDisplayCapabilities(func() time.Time {
				checks++
				if checks == 2 {
					cancel()
				}
				return now
			})
			if e != nil {
				t.Fatal(e)
			}
			if operation == "seal" {
				value, e := writer.Seal(ctx, binding, prepared)
				if len(value.Ciphertext) != 0 || !errors.Is(e, evidencedisplay.ErrCancelled) {
					t.Fatal("cancelled seal released a record")
				}
			} else {
				value, e := reader.Open(ctx, binding, record)
				if value != nil {
					value.Close()
				}
				if value != nil || !errors.Is(e, evidencedisplay.ErrCancelled) {
					t.Fatal("cancelled open released a view")
				}
			}
		})
	}
}
