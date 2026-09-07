package worker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

// A bounded completion can legitimately take longer than an individual SQL
// pulse. On SQLite it owns the only pool connection. Waiting behind our own
// finalization is not evidence that the consumer lease or database was lost.
func TestRunWorkerCancellationSettlementDoesNotStarveConsumerHeartbeat(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		heartbeat   time.Duration
		hold        time.Duration
		maintenance func(context.Context, *repository.JobQueue) error
	}{
		{"heartbeat", 40 * time.Millisecond, 2200 * time.Millisecond, nil},
		{"maintenance", repository.JobHeartbeatEvery, 3200 * time.Millisecond, ReconcileRunJobs},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				started, stopped, settling := make(chan struct{}), make(chan struct{}), make(chan struct{})
				release := make(chan struct{})
				var calls atomic.Int64
				config := runTLSConfig(t, f, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					firstCall := calls.Add(1) == 1
					if firstCall {
						close(started)
					}
					<-r.Context().Done()
					if firstCall {
						close(stopped)
					}
				}))
				config.RequestTimeout = 10 * time.Second
				tenant, run, _ := f.createRun(t, []bool{false, false})
				handlers, err := NewRunHandlers(config)
				if err != nil {
					t.Fatal(err)
				}
				original := handlers[repository.JobSampleExecute]
				var first atomic.Bool
				handlers[repository.JobSampleExecute] = func(ctx context.Context, execution Execution) (Completion, error) {
					completion, err := original(ctx, execution)
					if err != nil || !first.CompareAndSwap(false, true) {
						return completion, err
					}
					return func(tx *repository.TenantTransaction) error {
						close(settling)
						select {
						case <-release:
							return completion(tx)
						case <-ctx.Done():
							return ctx.Err()
						}
					}, nil
				}
				var log executionLogBuffer
				runner, err := New(Config{Store: f.store, Handlers: handlers, Logger: slog.New(slog.NewTextHandler(&log, nil)), PollInterval: 10 * time.Millisecond, HeartbeatInterval: scenario.heartbeat, Maintenance: scenario.maintenance})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(f.ctx)
				done := make(chan error, 1)
				go func() { done <- runner.Run(ctx) }()
				t.Cleanup(func() {
					cancel()
					select {
					case err := <-done:
						if err != nil {
							t.Errorf("worker stopped during live cancellation settlement: %v", err)
						}
					case <-time.After(7 * time.Second):
						t.Error("worker shutdown exceeded bound")
					}
					if t.Failed() {
						t.Log(log.String())
					}
				})
				select {
				case <-started:
				case <-time.After(5 * time.Second):
					t.Fatal("outbound call not started")
				}
				began := time.Now()
				for {
					current, err := tenant.GetRun(run.ID)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = tenant.CancelRun(run.ID, current.Version); errors.Is(err, repository.ErrConflict) {
						continue
					} else if err != nil {
						t.Fatal(err)
					}
					break
				}
				select {
				case <-stopped:
					if time.Since(began) > 5*time.Second {
						t.Fatal("outbound cancellation exceeded five seconds")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("outbound cancellation exceeded five seconds")
				}
				select {
				case <-settling:
				case <-time.After(5 * time.Second):
					t.Fatal("cancellation settlement not reached")
				}
				// Deterministically overlap a consumer pulse with a healthy, bounded
				// completion (under the existing 10-second completion deadline).
				time.Sleep(scenario.hold)
				ready := runner.Ready()
				close(release)
				if !ready {
					t.Fatal("consumer stopped because its own completion held the SQLite connection")
				}
				finished := awaitRunClosed(t, tenant, run.ID)
				if finished.Status != "CANCELLED" || finished.RequestCount != 1 || finished.ValidSampleCount != 0 || calls.Load() != 1 {
					t.Fatal("cancellation did not preserve the one real request and close without dispatching again")
				}
			})
		})
	}
}
