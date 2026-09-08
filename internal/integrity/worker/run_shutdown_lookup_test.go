package worker

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

// Match the real circuit cleanup boundary: two actual 404 responses close the
// Run, but the third (already skipped) sample Job still needs a fenced no-op
// completion. Stop the actual Runner only after that completion owns its SQL
// transaction. A canceled query is not proof that another owner took its lease.
func TestRunWorkerCircuitClosedShutdownQueryIsNotLeaseLoss(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		var calls atomic.Int64
		config := runTLSConfig(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":{"message":"synthetic model unavailable"}}`)
		}))
		tenant, run, samples := f.createRun(t, []bool{false, false, false})
		handlers, err := NewRunHandlers(config)
		if err != nil {
			t.Fatal("create shutdown circuit handlers")
		}
		entered := make(chan repository.JobLease, 1)
		release := make(chan struct{})
		original := handlers[repository.JobSampleExecute]
		handlers[repository.JobSampleExecute] = func(ctx context.Context, execution Execution) (Completion, error) {
			completion, err := original(ctx, execution)
			if err != nil || execution.Lease.Job.ObjectID != samples[2].ID {
				return completion, err
			}
			return func(tx *repository.TenantTransaction) error {
				entered <- execution.Lease
				<-release
				return completion(tx)
			}, nil
		}
		var log executionLogBuffer
		runner, err := New(Config{Store: f.store, Handlers: handlers, Logger: slog.New(slog.NewTextHandler(&log, nil)), PollInterval: 10 * time.Millisecond, HeartbeatInterval: 40 * time.Millisecond})
		if err != nil {
			t.Fatal("create shutdown circuit runner")
		}
		ctx, cancel := context.WithCancel(f.ctx)
		done := make(chan error, 1)
		go func() { done <- runner.Run(ctx) }()
		stopped, released := false, false
		t.Cleanup(func() {
			if !released {
				close(release)
			}
			cancel()
			if !stopped {
				select {
				case <-done:
				case <-time.After(7 * time.Second):
					t.Error("shutdown circuit runner did not stop")
				}
			}
		})
		var lease repository.JobLease
		select {
		case lease = <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("closed circuit sample did not enter its fenced completion")
		}
		// The separate observer reads only committed state, so SQLite's one
		// application connection remains held at the exact completion barrier.
		var closed sql.NullTime
		var code string
		if err := f.db.QueryRowContext(f.ctx, "SELECT execution_closed_at,circuit_breaker_code FROM integrity_runs WHERE organization_id=$1 AND id=$2", f.orgID, run.ID).Scan(&closed, &code); err != nil || !closed.Valid || code != "MI_CIRCUIT_MODEL_FAILURES" || calls.Load() != 2 {
			t.Fatal("shutdown barrier did not follow two actual model failures and committed Run closure")
		}
		cancel()
		close(release)
		released = true
		var runnerErr error
		select {
		case runnerErr = <-done:
			stopped = true
		case <-time.After(5 * time.Second):
			t.Fatal("canceled completion exceeded shutdown grace")
		}
		job, err := tenant.GetJob(lease.Job.ID)
		if err != nil || job.Status != "running" || job.LeaseOwner == nil || lease.Job.LeaseOwner == nil || *job.LeaseOwner != *lease.Job.LeaseOwner || job.AttemptCount != lease.Generation || job.LeaseUntil == nil || !job.LeaseUntil.After(time.Now()) {
			t.Fatal("canceled completion unexpectedly changed the original unexpired fence")
		}
		if runnerErr != nil {
			t.Fatalf("canceled SQL misclassified: lease_lost=%t unavailable=%t parent_cancelled=%t fence_unchanged=true lease_unexpired=true complete_failure=%t", errors.Is(runnerErr, repository.ErrJobLeaseLost), errors.Is(runnerErr, repository.ErrUnavailable), ctx.Err() != nil, strings.Contains(log.String(), "operation=complete"))
		}
		if runner.Ready() || calls.Load() != 2 {
			t.Fatal("shutdown remained ready or dispatched after the circuit")
		}
	})
}
