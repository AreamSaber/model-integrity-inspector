package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func TestRunnerCancellationDuringCommitRollsBackWithoutStorageFailure(t *testing.T) {
	eachWorkerDatabase(t, func(t *testing.T, f workerFixture) {
		target := f.createTarget(t, "auto")
		precheck, err := f.service.EnqueuePrecheck(f.ctx, f.orgID, target.ID, target.Version, "cancel-during-commit")
		if err != nil {
			t.Fatal(err)
		}
		entered := make(chan struct{})
		handler := func(ctx context.Context, _ Execution) (Completion, error) {
			return func(_ *repository.TenantTransaction) error { close(entered); <-ctx.Done(); return ctx.Err() }, nil
		}
		runner, err := New(Config{Store: f.store, Handlers: map[repository.JobType]Handler{repository.JobTargetPrecheck: handler}, PollInterval: time.Millisecond})
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
			t.Fatal("completion not reached")
		}
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("normal shutdown misclassified as storage outage: %v", err)
			}
		case <-time.After(7 * time.Second):
			t.Fatal("shutdown unbounded")
		}
		if runner.Ready() {
			t.Fatal("cancelled runner remains ready")
		}
		tenant, err := f.store.WithOrganization(f.ctx, f.orgID)
		if err != nil {
			t.Fatal(err)
		}
		job, err := tenant.GetJob(precheck.JobID)
		if err != nil {
			t.Fatal(err)
		}
		if job.Status == "completed" {
			t.Fatal("cancelled completion committed")
		}
	})
}

func TestRunnerActualStorageFailureStillFailsClosed(t *testing.T) {
	eachWorkerDatabase(t, func(t *testing.T, f workerFixture) {
		runner, err := New(Config{Store: f.store, Handlers: map[repository.JobType]Handler{repository.JobTargetPrecheck: func(context.Context, Execution) (Completion, error) { return nil, nil }}})
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.Close(); err != nil {
			t.Fatal(err)
		}
		if err := runner.Run(f.ctx); !errors.Is(err, repository.ErrSchemaMismatch) {
			t.Fatalf("genuine database outage concealed: %v", err)
		}
		if runner.Ready() {
			t.Fatal("unavailable database reported ready")
		}
	})
}
