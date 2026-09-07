package worker

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func TestRunWorkerCircuitStopsFurtherActualRequests(t *testing.T) {
	for _, scenario := range []struct {
		name          string
		statuses      []int
		expectedCalls int64
		code          string
	}{
		{"authentication", []int{401, 403, 200}, 2, "MI_CIRCUIT_AUTH_FAILURES"},
		{"model", []int{404, 404, 200}, 2, "MI_CIRCUIT_MODEL_FAILURES"},
		{"protocol", []int{400, 400, 400, 400, 400, 200}, 5, "MI_CIRCUIT_PROTOCOL_FAILURES"},
		{"success-reset", []int{401, 200, 403, 200}, 4, ""},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				var calls atomic.Int64
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					n := int(calls.Add(1)) - 1
					w.Header().Set("Content-Type", "application/json")
					if n >= len(scenario.statuses) {
						t.Error("extra request after circuit")
						w.WriteHeader(500)
						return
					}
					status := scenario.statuses[n]
					w.WriteHeader(status)
					if status == 200 {
						_, _ = io.WriteString(w, `{"choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}]}`)
					} else {
						_, _ = io.WriteString(w, `{"error":{"message":"synthetic body must not be persisted"}}`)
					}
				})
				tenant, run, _ := f.createRun(t, make([]bool, len(scenario.statuses)))
				startRunWorker(t, f, runTLSConfig(t, f, handler), nil)
				finished := awaitRunClosed(t, tenant, run.ID)
				if calls.Load() != scenario.expectedCalls || finished.RequestCount != scenario.expectedCalls || finished.CircuitBreakerCode != scenario.code || finished.FinalizedSampleCount != int64(len(scenario.statuses)) || finished.CancelRequestedAt != nil || finished.ReservedTokens != 0 {
					t.Fatal("wrong actual circuit execution")
				}
			})
		})
	}
}

func TestRunWorkerCircuitCancelsInflightWithoutUserCancellation(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		started, stopped := make(chan struct{}, 1), make(chan struct{}, 1)
		authStarted := make(chan struct{}, 2)
		release := make(chan struct{})
		var calls atomic.Int64
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			if calls.Add(1) == 1 {
				started <- struct{}{}
				select {
				case <-r.Context().Done():
					stopped <- struct{}{}
				case <-time.After(5 * time.Second):
				}
				return
			}
			authStarted <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"error":{"message":"synthetic"}}`)
		})
		tenant, run, samples := f.createRun(t, []bool{false, false, false, false})
		config := runTLSConfig(t, f, handler)
		config.RequestTimeout = 10 * time.Second
		handlers, err := NewRunHandlers(config)
		if err != nil {
			t.Fatal(err)
		}
		runner, err := New(Config{Store: f.store, Handlers: handlers, PollInterval: 10 * time.Millisecond, HeartbeatInterval: 40 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		queue, err := f.store.OpenJobQueue(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = queue.Close(context.WithoutCancel(f.ctx)) }()
		planLease, err := queue.Claim(f.ctx)
		if err != nil || planLease == nil {
			t.Fatal(err)
		}
		if err := queue.CompleteWith(f.ctx, *planLease, func(tx *repository.TenantTransaction) error { return tx.StartRun(run.ID) }); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()
		done := make(chan error, 3)
		for i := 0; i < 3; i++ {
			lease, err := queue.Claim(f.ctx)
			if err != nil || lease == nil {
				t.Fatal(err)
			}
			go func() { done <- runner.execute(ctx, queue, *lease, handlers[repository.JobSampleExecute]) }()
			if i == 0 {
				select {
				case <-started:
				case <-time.After(5 * time.Second):
					t.Fatal("slow request not started")
				}
			}
		}
		for range 2 {
			select {
			case <-authStarted:
			case <-time.After(5 * time.Second):
				t.Fatal("auth requests not started")
			}
		}
		began := time.Now()
		close(release)
		select {
		case <-stopped:
			if time.Since(began) > 5*time.Second {
				t.Fatal("circuit stop exceeded bound")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("circuit did not stop in-flight request")
		}
		for range 3 {
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("circuit worker did not settle")
			}
		}
		finished := awaitRunClosed(t, tenant, run.ID)
		if calls.Load() != 3 || finished.RequestCount != 3 || finished.FinalizedSampleCount != 4 || finished.CancelRequestedAt != nil || finished.CircuitBreakerCode != "MI_CIRCUIT_AUTH_FAILURES" || finished.ReservedTokens != 0 {
			t.Fatal("inflight circuit accounting incorrect")
		}
		attempt, _ := evidenceFor(t, f, tenant, samples[0])
		if attempt.ErrorCode == nil || *attempt.ErrorCode != "MI_EXECUTION_CIRCUIT_OPEN" || attempt.Validity != "NOT_APPLICABLE" {
			t.Fatal("circuit interruption mislabelled as user cancellation or network failure")
		}
	})
}
