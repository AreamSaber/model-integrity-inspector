package worker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func TestRunnerMaintenanceUsesExistingConsumerWhileJobRuns(t *testing.T) {
	eachWorkerDatabase(t, func(t *testing.T, f workerFixture) {
		target := f.createTarget(t, "auto")
		if _, err := f.service.EnqueuePrecheck(f.ctx, f.orgID, target.ID, target.Version, "maintenance"); err != nil {
			t.Fatal(err)
		}
		var first atomic.Pointer[repository.JobQueue]
		var pulses atomic.Int32
		entered := make(chan struct{})
		handler := func(ctx context.Context, e Execution) (Completion, error) {
			if first.Load() != e.Queue {
				return nil, ErrConfiguration
			}
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		runner, err := New(Config{Store: f.store, Handlers: map[repository.JobType]Handler{repository.JobTargetPrecheck: handler}, PollInterval: time.Millisecond, Maintenance: func(ctx context.Context, q *repository.JobQueue) error {
			if first.Load() == nil {
				first.Store(q)
			}
			if q != first.Load() {
				return ErrConfiguration
			}
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 2*time.Second {
				return ErrConfiguration
			}
			pulses.Add(1)
			return ReconcileRunJobs(ctx, q)
		}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- runner.Run(ctx) }()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("job did not start")
		}
		deadline := time.Now().Add(4 * time.Second)
		for pulses.Load() < 2 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if pulses.Load() < 2 || !runner.Ready() {
			t.Error("maintenance did not run during active job")
		}
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(7 * time.Second):
			t.Fatal("unbounded stop")
		}
	})
}

func TestRunnerMaintenanceFailureCannotReportReady(t *testing.T) {
	eachWorkerDatabase(t, func(t *testing.T, f workerFixture) {
		runner, err := New(Config{Store: f.store, Handlers: map[repository.JobType]Handler{repository.JobTargetPrecheck: func(context.Context, Execution) (Completion, error) { return nil, nil }}, Maintenance: func(context.Context, *repository.JobQueue) error { return repository.ErrUnavailable }})
		if err != nil {
			t.Fatal(err)
		}
		if err := runner.Run(f.ctx); !errors.Is(err, repository.ErrUnavailable) {
			t.Fatal("maintenance failure swallowed")
		}
		if runner.Ready() {
			t.Fatal("failed startup is ready")
		}
	})
}
