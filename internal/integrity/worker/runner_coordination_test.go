package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func TestRunnerQueueGateCancellationNeverStartsWaitingOperation(t *testing.T) {
	runner := &Runner{queueGate: make(chan struct{}, 1)}
	runner.queueGate <- struct{}{}
	ctx, cancel := context.WithCancel(t.Context())
	called := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- runner.withQueueGate(ctx, func() error { called <- struct{}{}; return nil })
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("gate cancellation lost")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled operation waited for the gate holder")
	}
	<-runner.queueGate
	// Even when a free gate and cancellation are both selectable, a cancelled
	// operation must never receive authority to invoke a new database operation.
	for range 20 {
		if err := runner.withQueueGate(ctx, func() error { called <- struct{}{}; return nil }); !errors.Is(err, context.Canceled) {
			t.Fatal("already cancelled operation entered the gate")
		}
	}
	select {
	case <-called:
		t.Fatal("cancelled operation executed")
	default:
	}
	if err := runner.withQueueGate(t.Context(), func() error { return repository.ErrUnavailable }); !errors.Is(err, repository.ErrUnavailable) {
		t.Fatal("live database failure was concealed")
	}
	if err := runner.withQueueGate(t.Context(), func() error { return nil }); err != nil {
		t.Fatal("gate was not released after failure")
	}
}

func TestRunnerQueueGateCannotCommitAfterLeaseLostWhileWaiting(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		tenant, run, _ := f.createRun(t, []bool{false})
		queue, err := f.store.OpenJobQueue(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = queue.Close(context.WithoutCancel(f.ctx)) }()
		lease, err := queue.Claim(f.ctx)
		if err != nil || lease == nil {
			t.Fatal("plan not claimed")
		}
		runner, err := New(Config{Store: f.store, Handlers: map[repository.JobType]Handler{repository.JobRunPlan: func(context.Context, Execution) (Completion, error) { return nil, nil }}})
		if err != nil {
			t.Fatal(err)
		}
		runner.queueGate <- struct{}{}
		returned := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- runner.execute(f.ctx, queue, *lease, func(context.Context, Execution) (Completion, error) {
				close(returned)
				return func(tx *repository.TenantTransaction) error { return tx.StartRun(run.ID) }, nil
			})
		}()
		select {
		case <-returned:
		case <-time.After(5 * time.Second):
			t.Fatal("plan handler did not return")
		}
		// The coordinating gate is not a lease. A different owner can take over
		// before the final transaction starts, and the repository must reject it.
		if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_jobs SET lease_owner = $1 WHERE organization_id = $2 AND id = $3", "replacement-owner", f.orgID, lease.Job.ID); err != nil {
			t.Fatal("lease replacement failed")
		}
		<-runner.queueGate
		select {
		case err := <-done:
			if !errors.Is(err, repository.ErrJobLeaseLost) {
				t.Fatalf("gate bypassed lease authority: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("stale completion did not finish")
		}
		stored, err := tenant.GetRun(run.ID)
		if err != nil || stored.Status != "QUEUED" || stored.StartedAt != nil {
			t.Fatal("stale owner changed the run")
		}
		job, err := tenant.GetJob(lease.Job.ID)
		if err != nil || job.LeaseOwner == nil || *job.LeaseOwner != "replacement-owner" || job.Status != "running" {
			t.Fatal("stale owner changed the replacement job")
		}
	})
}
