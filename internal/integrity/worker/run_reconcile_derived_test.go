package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func TestDerivedRunReconcilerActualTerminalJobsNeedNoSecretsOrRedispatch(t *testing.T) {
	for _, status := range []string{"failed", "cancelled"} {
		t.Run(status, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				p := pendingDerivedTLSAttempt(t, f, 30)
				if status == "failed" {
					if err := p.queue.Fail(f.ctx, p.lease, "SYNTHETIC_PROCESS_LOSS"); err != nil {
						t.Fatal("fail actual abandoned job", err)
					}
				} else {
					if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_jobs SET available_at=$1 WHERE organization_id=$2 AND status='pending'", time.Now().UTC().Add(time.Hour), f.orgID); err != nil {
						t.Fatal("isolate cancelled abandoned job")
					}
					if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_jobs SET cancel_requested_at=$1,lease_until=$1 WHERE organization_id=$2 AND id=$3", time.Now().UTC().Add(-time.Second), f.orgID, p.lease.Job.ID); err != nil {
						t.Fatal("expire cancelled job")
					}
					if next, err := p.queue.Claim(f.ctx); err != nil || next != nil {
						t.Fatal("actual queue did not terminally reconcile cancelled job", err)
					}
				}
				if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_targets SET version=version+1 WHERE organization_id=$1 AND id=$2", f.orgID, p.run.TargetID); err != nil {
					t.Fatal("stale target before terminal recovery")
				}
				rejectDerivedBodyInserts(t, f)
				reconcile, err := NewRunReconciler(RunConfig{DerivedBuilder: p.builder, DerivedSealer: p.config.DerivedSealer})
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 2; i++ {
					ctx, stop := context.WithTimeout(f.ctx, 2*time.Second)
					err := reconcile(ctx, p.queue)
					stop()
					if err != nil {
						t.Fatal("bounded real terminal-job maintenance", err)
					}
				}
				derivedCounts(t, f, p.run.ID, 1, 0)
				verifySettledDerivedAttempt(t, f, p, "UNCERTAIN", "INVALID_RETRYABLE", "MI_UNCERTAIN_ATTEMPT")
				attempts, err := p.tenant.ListAttempts(p.lease.Job.ObjectID)
				if err != nil || len(attempts) != 1 || attempts[0].DerivedReceipt != repository.DerivedRecovered {
					t.Fatal("terminal recovery receipt missing")
				}
				run, err := p.tenant.GetRun(p.run.ID)
				if err != nil || run.ReservedTokens != 0 || run.RequestCount != 1 || p.requestCount() != 1 {
					t.Fatal("terminal maintenance redispatched or lost accounting")
				}
				if err := p.queue.CompleteWith(f.ctx, p.lease, p.completion); !errors.Is(err, repository.ErrJobLeaseLost) {
					t.Fatal("terminal maintenance revived original completion", err)
				}
			})
		})
	}
	if _, err := NewRunReconciler(RunConfig{}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("maintenance silently lacks derived capability")
	}
}
