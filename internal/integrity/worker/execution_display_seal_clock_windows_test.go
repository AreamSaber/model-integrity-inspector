package worker

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/evidencedisplay"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

// Observational, not a new machine-dependent CI requirement. A machine with no
// ahead-of-Go-clock samples reports that negative result and still passes.
// It changes neither clock, never queries a database, and has a fixed 1-second /
// 1024-sample ceiling. PostgreSQL's official Windows gettimeofday implementation
// uses the precise FILETIME API; this is not a claim about an actual DB query.
func TestRunWorkerDisplaySealDiagnosticWindowsNaturalClockObservation(t *testing.T) {
	ring, request, result, _ := sealDiagnosticFixture(t)
	var snapshot domain.RequestSnapshot
	if err := json.Unmarshal([]byte(result.attempt.RequestSnapshot), &snapshot); err != nil {
		t.Fatal("decode diagnostic snapshot")
	}
	prepared, err := evidencedisplay.Prepare(t.Context(), evidencedisplay.Source{Request: request, Snapshot: snapshot, Response: result.response}, []byte(sealDiagnosticCredential), nil)
	if err != nil {
		t.Fatal("prepare actual diagnostic source")
	}
	defer prepared.Close()
	sourceHash, requestHash := prepared.Hashes()
	var observed [2]int64
	var clockCalls int
	sealer, _, err := ring.NewDisplayCapabilities(func() time.Time {
		now := time.Now()
		if clockCalls < len(observed) {
			observed[clockCalls] = now.UnixMicro()
		}
		clockCalls++
		return now
	})
	if err != nil {
		t.Fatal("construct actual Go-clock sealer")
	}
	ctx, stop := context.WithTimeout(t.Context(), 2*time.Second)
	defer stop()
	start := time.Now()
	var samples, preciseAhead, captured, initialFutureRejected, finalFutureRejected, otherUnavailable, cancelled int
	var maximumLeadMicros int64
	for samples < 1024 && time.Since(start) < time.Second {
		var ft windows.Filetime
		windows.GetSystemTimePreciseAsFileTime(&ft)
		captureMicros := time.Unix(0, ft.Nanoseconds()).UnixMicro()
		after := time.Now().UnixMicro()
		if lead := captureMicros - after; lead > 0 {
			preciseAhead++
			if lead > maximumLeadMicros {
				maximumLeadMicros = lead
			}
		}
		observed, clockCalls = [2]int64{}, 0
		binding := secret.DisplayBinding{Scope: secret.EvidenceScope{OrganizationID: 1, RunID: 2, LogicalSampleID: 3, AttemptID: 4, RequestHash: requestHash}, SourceHash: sourceHash, CapturedAtMicros: captureMicros, ExpiresAtMicros: captureMicros + int64(30*24*time.Hour/time.Microsecond)}
		record, err := sealer.Seal(ctx, binding, prepared)
		samples++
		switch {
		case err == nil:
			if len(record.Nonce) != 12 || len(record.Ciphertext) == 0 {
				t.Fatal("successful real seal lacks its envelope")
			}
			captured++
		case errors.Is(err, evidencedisplay.ErrCancelled):
			cancelled++
		case errors.Is(err, secret.ErrDisplayUnavailable):
			switch {
			case clockCalls == 1 && captureMicros > observed[0]:
				initialFutureRejected++
			case clockCalls == 2 && captureMicros > observed[1]:
				finalFutureRejected++
			default:
				otherUnavailable++
			}
		default:
			t.Fatal("unexpected non-closed seal error category")
		}
		clear(record.Ciphertext)
		clear(record.Nonce)
		if ctx.Err() != nil {
			break
		}
	}
	// Only aggregate counts/differences: no absolute timestamps, source digests,
	// request/response bytes, keys, credentials, ciphertext or database strings.
	t.Logf("clock observation samples=%d precise_ahead=%d max_lead_us=%d captured=%d initial_future_rejected=%d final_future_rejected=%d other_unavailable=%d cancelled=%d", samples, preciseAhead, maximumLeadMicros, captured, initialFutureRejected, finalFutureRejected, otherUnavailable, cancelled)
}
