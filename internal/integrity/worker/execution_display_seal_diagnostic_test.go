package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/evidencedisplay"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

const sealDiagnosticCredential = "synthetic-display-seal-diagnostic-39170"

type sealDiagnosticNoNetwork struct{}

func (sealDiagnosticNoNetwork) Do(*http.Request) (*http.Response, error) {
	panic("display seal diagnostic must not perform network I/O")
}

func sealDiagnosticFixture(t *testing.T) (*secret.KeyRing, domain.NormalizedRequest, runCallResult, repository.DisplayEvidenceRecord) {
	t.Helper()
	master := bytes.Repeat([]byte{0x39}, 32)
	ring, err := secret.NewKeyRing("diagnostic-v1", map[string][]byte{"diagnostic-v1": master})
	clear(master)
	if err != nil {
		t.Fatal("construct synthetic display capability")
	}
	request := domain.NormalizedRequest{Model: "mock-model", Messages: []domain.NormalizedMessage{{Role: "user", Content: "synthetic display question"}}, MaxOutputTokens: 64}
	adapter, err := openaichat.New(openaichat.Config{Endpoint: "https://diagnostic.invalid/v1", Doer: sealDiagnosticNoNetwork{}})
	if err != nil {
		t.Fatal("construct no-network adapter")
	}
	wire, snapshot, err := adapter.BuildRequest(t.Context(), request)
	if err != nil {
		t.Fatal("construct actual bounded wire snapshot")
	}
	_ = wire.Body.Close()
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal("encode actual snapshot")
	}
	result := runCallResult{attempt: repository.AttemptRecord{OrganizationID: 1, RunID: 2, LogicalSampleID: 3, ID: 4, RequestHash: snapshot.RequestHash, RequestSnapshot: string(encoded)}, response: domain.NormalizedResponse{Content: "synthetic completion " + sealDiagnosticCredential, HTTPStatus: 200, ParseStatus: "valid", ModelReported: "mock-model", FinishReason: "stop"}, outcome: domain.AttemptOutcome{Validity: "VALID", HTTPStatus: 200}}
	stamp := time.Date(2026, 9, 8, 1, 0, 0, 123456000, time.UTC)
	bound := repository.DisplayEvidenceRecord{OrganizationID: 1, RunID: 2, LogicalSampleID: 3, AttemptID: 4, RequestHash: snapshot.RequestHash, Policy: repository.DisplayEvidencePolicy, State: repository.DisplayCaptured, CapturedAtMicros: stamp.UnixMicro(), ExpiresAtMicros: stamp.Add(30 * 24 * time.Hour).UnixMicro()}
	return ring, request, result, bound
}

func sealDiagnosticCapture(t *testing.T, ctx context.Context, sealer *secret.DisplaySealer, request domain.NormalizedRequest, result runCallResult, bound repository.DisplayEvidenceRecord) repository.DisplayEvidenceRecord {
	t.Helper()
	credentials, err := secret.NewCredentials([]byte(sealDiagnosticCredential), nil)
	if err != nil {
		t.Fatal("construct synthetic credentials")
	}
	defer credentials.Destroy()
	var captured repository.DisplayEvidenceRecord
	if err := credentials.Use(func(key []byte, headers map[string][]byte) error {
		// Supplied times/scope are test-only observations, not a minted DB
		// capability. This invokes real Prepare/Seal but never persistence.
		captured = captureRunDisplayUsingBinding(ctx, Execution{}, sealer, request, result, key, headers, &bound)
		return nil
	}); err != nil {
		t.Fatal("diagnostic credential scope failed")
	}
	return captured
}

func TestRunWorkerDisplaySealDiagnosticClosedCauses(t *testing.T) {
	for _, cause := range []string{"equal_clock", "capture_one_microsecond_ahead", "expired", "retention_over_limit", "zero_clock", "clock_panics", "clock_rewinds_at_completion", "cancel_at_clock", "invalid_capability", "request_binding_mismatch"} {
		t.Run(cause, func(t *testing.T) {
			ring, request, result, bound := sealDiagnosticFixture(t)
			original := result
			now := time.UnixMicro(bound.CapturedAtMicros).UTC()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			clockCalls := 0
			clock := func() time.Time {
				clockCalls++
				switch cause {
				case "zero_clock":
					return time.Time{}
				case "clock_panics":
					panic("synthetic clock fault")
				case "clock_rewinds_at_completion":
					if clockCalls == 2 {
						return now.Add(-time.Microsecond)
					}
				case "cancel_at_clock":
					cancel()
				}
				return now
			}
			sealer, _, err := ring.NewDisplayCapabilities(clock)
			if err != nil {
				t.Fatal("construct clock-scoped capability")
			}
			want := repository.DisplayUnavailableSeal
			switch cause {
			case "equal_clock":
				want = repository.DisplayCaptured
			case "capture_one_microsecond_ahead":
				bound.CapturedAtMicros++
			case "expired":
				bound.CapturedAtMicros--
				bound.ExpiresAtMicros = now.UnixMicro()
			case "retention_over_limit":
				bound.ExpiresAtMicros = bound.CapturedAtMicros + int64(180*24*time.Hour/time.Microsecond) + 1
			case "invalid_capability":
				sealer = &secret.DisplaySealer{}
			case "request_binding_mismatch":
				bound.RequestHash = string(bytes.Repeat([]byte{'b'}, 64))
			case "cancel_at_clock":
				want = repository.DisplayUnavailableCancelled
			}
			captured := sealDiagnosticCapture(t, ctx, sealer, request, result, bound)
			if captured.State != want {
				t.Fatal("real Worker/Prepare/Seal closed classification differs")
			}
			if want == repository.DisplayCaptured && (len(captured.Ciphertext) == 0 || len(captured.Nonce) != 12) {
				t.Fatal("valid equal-clock control did not actually seal")
			}
			if want != repository.DisplayCaptured && (len(captured.Ciphertext) != 0 || len(captured.Nonce) != 0 || captured.CapturedAtMicros != 0 || captured.ExpiresAtMicros != 0) {
				t.Fatal("unavailable result retained a partial envelope")
			}
			if cause == "clock_rewinds_at_completion" && clockCalls != 2 {
				t.Fatal("did not reach the real post-encryption clock check")
			}
			if !reflect.DeepEqual(original, result) {
				t.Fatal("display diagnostic changed actual response or outcome")
			}
		})
	}
}

func TestRunWorkerDisplaySealDiagnosticClosedPreparedIsNotTimeout(t *testing.T) {
	ring, request, result, bound := sealDiagnosticFixture(t)
	var snapshot domain.RequestSnapshot
	if err := json.Unmarshal([]byte(result.attempt.RequestSnapshot), &snapshot); err != nil {
		t.Fatal("decode diagnostic snapshot")
	}
	prepared, err := evidencedisplay.Prepare(t.Context(), evidencedisplay.Source{Request: request, Snapshot: snapshot, Response: result.response}, []byte(sealDiagnosticCredential), nil)
	if err != nil {
		t.Fatal("prepare diagnostic source")
	}
	sourceHash, requestHash := prepared.Hashes()
	prepared.Close()
	sealer, _, err := ring.NewDisplayCapabilities(func() time.Time { return time.UnixMicro(bound.CapturedAtMicros).UTC() })
	if err != nil {
		t.Fatal("construct diagnostic capability")
	}
	_, err = sealer.Seal(t.Context(), secret.DisplayBinding{Scope: secret.EvidenceScope{OrganizationID: 1, RunID: 2, LogicalSampleID: 3, AttemptID: 4, RequestHash: requestHash}, SourceHash: sourceHash, CapturedAtMicros: bound.CapturedAtMicros, ExpiresAtMicros: bound.ExpiresAtMicros}, prepared)
	if !errors.Is(err, secret.ErrDisplayUnavailable) || t.Context().Err() != nil {
		t.Fatal("closed Prepared classification differs from non-cancel unavailability")
	}
}
