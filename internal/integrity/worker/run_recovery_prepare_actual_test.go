package worker

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

// A real signed Run + TLS request has been reserved and executed. Its original
// completion remains uncommitted. This exercises the actual owned SQL source,
// narrow preparation, real purpose MAC and normal repository settlement; it is
// not a backup-maintenance/drain source or a whole-backup acceptance test.
func TestRunRecoveryPrepareActualTLSOwnedSourceAndMACSettlement(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		p := pendingDerivedTLSAttempt(t, f, 30)
		if err := p.queue.Fail(f.ctx, p.lease, "SYNTHETIC_PROCESS_LOSS"); err != nil {
			t.Fatal("terminalize the actual interrupted request job", err)
		}
		sources, err := p.queue.LoadExecutionReconciliations(f.ctx, 1)
		if err != nil || len(sources) != 1 {
			t.Fatal("load actual owned source", err)
		}
		if err := sources[0].Use(func(data repository.ExecutionReconciliationData) error {
			if data.Attempt == nil {
				t.Fatal("real source has no reserved attempt")
			}
			data.Plan.Manifest[0] ^= 1
			data.Plan.Probes[0].Samples[0].Request.Model = "mutated-borrow-only"
			data.Attempt.RequestHash = "mutated-borrow-only"
			*data.Sample.JobID = -1
			return nil
		}); err != nil {
			t.Fatal("borrow source for deep-clone mutation test", err)
		}
		if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_targets SET status='disabled',version=version+1 WHERE organization_id=$1 AND id=$2", f.orgID, p.run.TargetID); err != nil {
			t.Fatal("make current target unusable after actual request")
		}
		rejectDerivedBodyInserts(t, f)
		// Only the two narrow capabilities are provided; no RunConfig, Secret
		// service, response/display keys, HTTP client, queue or Store is captured.
		prepare, err := NewRunRecoveryPreparer(p.builder, p.config.DerivedSealer)
		if err != nil {
			t.Fatal(err)
		}
		beforeRun, err := p.tenant.GetRun(p.run.ID)
		if err != nil {
			t.Fatal(err)
		}
		beforeAttempts, err := p.tenant.ListAttempts(p.lease.Job.ObjectID)
		if err != nil || len(beforeAttempts) != 1 {
			t.Fatal("original persisted attempt unavailable", err)
		}
		ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
		defer cancel()
		failed, err := prepare(ctx, runRecoveryTestSource(func(fn func(repository.ExecutionReconciliationData) error) error {
			if err := sources[0].Use(fn); err != nil {
				return err
			}
			return errors.New("private-canary-after-real-source")
		}))
		if failed != nil || !errors.Is(err, repository.ErrAnalysisSource) {
			t.Fatal("late owned-source failure escaped its zero-result boundary", err)
		}
		prepared, err := prepare(ctx, sources[0])
		if err != nil || prepared == nil || len(prepared.Items) != 1 || prepared.Scope.RequestHash != beforeAttempts[0].RequestHash || prepared.Scope.JobID != p.lease.Job.ID || prepared.Scope.AttemptID != beforeAttempts[0].ID || prepared.Items[0].Record.KeyVersion != "worker-test" {
			t.Fatal("actual original identity was lost by narrow preparation", err)
		}
		afterRun, err := p.tenant.GetRun(p.run.ID)
		if err != nil {
			t.Fatal(err)
		}
		afterAttempts, err := p.tenant.ListAttempts(p.lease.Job.ObjectID)
		if err != nil || !reflect.DeepEqual(beforeRun, afterRun) || !reflect.DeepEqual(beforeAttempts, afterAttempts) || p.requestCount() != 1 {
			t.Fatal("preparation changed SQL facts or sent another request", err)
		}
		derivedCounts(t, f, p.run.ID, 0, 0)
		for _, want := range []repository.ExecutionReconciliationResult{repository.ReconciliationApplied, repository.ReconciliationAlreadyCompleted} {
			got, err := p.queue.ReconcileExecutionWithDerived(ctx, sources[0], prepared)
			if err != nil || got != want {
				t.Fatal("actual source did not settle exactly once", got, err)
			}
		}
		derivedCounts(t, f, p.run.ID, 1, 0)
		verifySettledDerivedAttempt(t, f, p, "UNCERTAIN", "INVALID_RETRYABLE", "MI_UNCERTAIN_ATTEMPT")
		attempts, err := p.tenant.ListAttempts(p.lease.Job.ObjectID)
		if err != nil || len(attempts) != 1 || attempts[0].RequestHash != beforeAttempts[0].RequestHash || attempts[0].RequestSnapshot != beforeAttempts[0].RequestSnapshot || attempts[0].LeaseGeneration != beforeAttempts[0].LeaseGeneration || attempts[0].DerivedReceipt != repository.DerivedRecovered || p.requestCount() != 1 {
			t.Fatal("settlement changed original request/generation or redispatched", err)
		}
		if err := p.queue.CompleteWith(ctx, p.lease, p.completion); !errors.Is(err, repository.ErrJobLeaseLost) {
			t.Fatal("old TLS completion revived the interrupted request", err)
		}
	})
}
