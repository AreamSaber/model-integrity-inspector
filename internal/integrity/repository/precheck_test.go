package repository

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func precheckFixture(t *testing.T, store *Store) (*Tenant, TargetState, PrecheckRecord, *JobQueue, JobLease) {
	t.Helper()
	_, tenant := targetFixture(t, store)
	target := mustCreateTarget(t, tenant)
	precheck, err := tenant.EnqueuePrecheck(PrecheckRecord{OrganizationID: tenant.orgID, TargetID: target.Target.ID, TargetVersion: 1, SecretID: target.Secret.ID, SecretVersion: 1, RequestKey: "test-request", SnapshotJSON: "{}"})
	if err != nil {
		t.Fatal(err)
	}
	queue, err := store.OpenJobQueue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queue.Close(t.Context()) })
	lease, err := queue.Claim(t.Context())
	if err != nil || lease == nil {
		t.Fatalf("claim precheck: %v", err)
	}
	return tenant, target, precheck, queue, *lease
}

func passedPrecheck() PrecheckOutcome {
	outcome := PrecheckOutcome{Status: "passed", MaxOutputParameter: "max_tokens", Checks: []PrecheckCheck{}}
	for _, name := range []string{"network", "authentication", "model", "parameters", "nonstream", "stream"} {
		outcome.Checks = append(outcome.Checks, PrecheckCheck{Name: name, Status: "passed"})
	}
	return outcome
}

func TestPrecheckAtomicEnqueueBudgetAndFencedCompletion(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, target, record, queue, lease := precheckFixture(t, store)
		same, err := tenant.EnqueuePrecheck(PrecheckRecord{OrganizationID: tenant.orgID, TargetID: target.Target.ID, TargetVersion: 1, SecretID: target.Secret.ID, SecretVersion: 1, RequestKey: "test-request", SnapshotJSON: "{}"})
		if err != nil || same.ID != record.ID || *same.JobID != *record.JobID {
			t.Fatal("idempotent enqueue duplicated work")
		}
		if err := tenant.DeleteTarget(target.Target.ID, 1); !errors.Is(err, ErrConflict) {
			t.Fatal("in-flight precheck did not protect credential")
		}
		if err := queue.WithLease(t.Context(), lease, func(tx *TenantTransaction) error { _, err := tx.BeginPrecheck(record.ID, lease.Job.ID); return err }); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			if err := queue.WithLease(t.Context(), lease, func(tx *TenantTransaction) error { return tx.ReservePrecheckRequest(record.ID, lease.Job.ID) }); err != nil {
				t.Fatal(err)
			}
		}
		if err := queue.WithLease(t.Context(), lease, func(tx *TenantTransaction) error { return tx.ReservePrecheckRequest(record.ID, lease.Job.ID) }); !errors.Is(err, ErrPrecheckBudget) {
			t.Fatalf("fourth request not denied: %v", err)
		}
		before, err := tenant.GetPrecheck(target.Target.ID, record.ID)
		if err != nil || before.RequestCount != 3 || before.Status != "running" {
			t.Fatal("request budget not durable")
		}
		foreign, _ := store.WithOrganization(t.Context(), tenant.orgID+1)
		if _, err := foreign.GetPrecheck(target.Target.ID, record.ID); !errors.Is(err, ErrNotFound) {
			t.Fatal("cross tenant precheck read")
		}
		if err := queue.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error { return tx.FinishPrecheck(record.ID, lease.Job.ID, passedPrecheck()) }); err != nil {
			t.Fatal(err)
		}
		finished, err := tenant.GetPrecheck(target.Target.ID, record.ID)
		if err != nil || finished.Status != "passed" || finished.FinishedAt == nil || finished.RequestCount != 3 {
			t.Fatal("precheck result not committed")
		}
		job, err := tenant.GetJob(lease.Job.ID)
		if err != nil || job.Status != "completed" {
			t.Fatal("job did not commit with result")
		}
		if err := queue.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error { return tx.FinishPrecheck(record.ID, lease.Job.ID, passedPrecheck()) }); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("stale completion accepted")
		}
		if err := tenant.DeleteTarget(target.Target.ID, 1); err != nil {
			t.Fatal("completed precheck blocked target deletion")
		}
		if _, err := tenant.GetPrecheck(target.Target.ID, record.ID); err != nil {
			t.Fatal("target deletion removed precheck history")
		}
	})
}

func TestPrecheckAuditFailureAndExpiredLeaseRollback(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, target, record, queue, lease := precheckFixture(t, store)
		if err := queue.WithLease(t.Context(), lease, func(tx *TenantTransaction) error { _, err := tx.BeginPrecheck(record.ID, lease.Job.ID); return err }); err != nil {
			t.Fatal(err)
		}
		signer := &switchAuditSigner{}
		signer.fail.Store(true)
		store.auditSigner = signer
		if err := queue.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error {
			return tx.FinishPrecheck(record.ID, lease.Job.ID, PrecheckOutcome{Status: "failed", ErrorCode: "MI_NETWORK_FAILED", Checks: []PrecheckCheck{}})
		}); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatalf("finish ignored audit failure: %v", err)
		}
		result, _ := tenant.GetPrecheck(target.Target.ID, record.ID)
		job, _ := tenant.GetJob(lease.Job.ID)
		if result.Status != "running" || result.FinishedAt != nil || job.Status != "running" {
			t.Fatal("audit failure partially committed")
		}
		signer.fail.Store(false)
		expireJob(t, store, lease.Job)
		if err := queue.WithLease(t.Context(), lease, func(tx *TenantTransaction) error { return tx.ReservePrecheckRequest(record.ID, lease.Job.ID) }); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("expired lease reserved request")
		}
		if err := queue.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error { return tx.FinishPrecheck(record.ID, lease.Job.ID, passedPrecheck()) }); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("expired lease wrote success")
		}
		result, _ = tenant.GetPrecheck(target.Target.ID, record.ID)
		if result.RequestCount != 0 || result.Status != "running" {
			t.Fatal("expired lease changed business state")
		}
	})
}

func TestPrecheckStaleExpiryCancellationAndResultVocabulary(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, target, record, queue, lease := precheckFixture(t, store)
		if err := queue.WithLease(t.Context(), lease, func(tx *TenantTransaction) error { _, err := tx.BeginPrecheck(record.ID, lease.Job.ID); return err }); err != nil {
			t.Fatal(err)
		}
		old := time.Now().UTC().Add(-16 * time.Minute)
		if err := store.db.Model(&PrecheckRecord{}).Where("organization_id = ? AND id = ?", tenant.orgID, record.ID).Update("created_at", old).Error; err != nil {
			t.Fatal(err)
		}
		if err := queue.WithLease(t.Context(), lease, func(tx *TenantTransaction) error { return tx.ReservePrecheckRequest(record.ID, lease.Job.ID) }); !errors.Is(err, ErrPrecheckExpired) {
			t.Fatal("expired snapshot issued request")
		}
		if err := store.db.Model(&PrecheckRecord{}).Where("organization_id = ? AND id = ?", tenant.orgID, record.ID).Update("created_at", time.Now().UTC()).Error; err != nil {
			t.Fatal(err)
		}
		replacement := target.Target
		replacement.Status = "disabled"
		if _, err := tenant.UpdateTarget(target.Target.ID, 1, replacement); err != nil {
			t.Fatal(err)
		}
		if err := queue.CheckLease(t.Context(), lease); !errors.Is(err, ErrPrecheckStale) {
			t.Fatalf("disabled target not detected: %v", err)
		}
		if err := queue.WithLease(t.Context(), lease, func(tx *TenantTransaction) error { return tx.ReservePrecheckRequest(record.ID, lease.Job.ID) }); !errors.Is(err, ErrPrecheckStale) {
			t.Fatal("stale configuration reserved request")
		}
		if err := queue.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error { return tx.FinishPrecheck(record.ID, lease.Job.ID, passedPrecheck()) }); err != nil {
			t.Fatal(err)
		}
		result, _ := tenant.GetPrecheck(target.Target.ID, record.ID)
		if result.Status != "failed" || result.ErrorCode != "MI_PRECHECK_STALE" {
			t.Fatal("disabled target committed passed result")
		}
		for _, outcome := range []PrecheckOutcome{{Status: "passed"}, {Status: "failed", ErrorCode: "private-upstream-body"}, {Status: "failed", ErrorCode: "MI_AUTH_FAILED", Checks: []PrecheckCheck{{Name: "header-secret", Status: "failed", ErrorCode: "MI_AUTH_FAILED"}}}} {
			if validPrecheckOutcome(outcome) {
				t.Fatal("untrusted result vocabulary accepted")
			}
		}
	})
}

func TestPrecheckRequiresMatchingLeaseAndCompletionCapability(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, target, record, queue, lease := precheckFixture(t, store)
		if err := queue.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error { return tx.FinishPrecheck(record.ID, lease.Job.ID, passedPrecheck()) }); !errors.Is(err, ErrConfiguration) {
			t.Fatal("claim alone was accepted as successful precheck")
		}
		if err := tenant.InTransaction(func(tx *TenantTransaction) error { _, err := tx.BeginPrecheck(record.ID, lease.Job.ID); return err }); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("ordinary transaction began precheck")
		}
		if err := tenant.InTransaction(func(tx *TenantTransaction) error { return tx.FinishPrecheck(record.ID, lease.Job.ID, passedPrecheck()) }); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("ordinary transaction finished precheck")
		}
		if err := queue.WithLease(t.Context(), lease, func(tx *TenantTransaction) error { return tx.FinishPrecheck(record.ID, lease.Job.ID, passedPrecheck()) }); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("non-completion capability finished precheck")
		}
		if err := queue.WithLease(t.Context(), lease, func(tx *TenantTransaction) error { _, err := tx.BeginPrecheck(record.ID, lease.Job.ID+1); return err }); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("wrong-job capability accepted")
		}
		if err := queue.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error { return tx.ReservePrecheckRequest(record.ID, lease.Job.ID) }); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("completion capability issued outbound reservation")
		}
		result, _ := tenant.GetPrecheck(target.Target.ID, record.ID)
		job, _ := tenant.GetJob(lease.Job.ID)
		if result.Status != "queued" || result.RequestCount != 0 || job.Status != "running" {
			t.Fatal("wrong capability changed state")
		}
	})
}

func TestPrecheckReconcileCancellationAuditRollbackAndOtherJobIsolation(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, target, record, queue, lease := precheckFixture(t, store)
		now := time.Now().UTC()
		if err := store.db.Model(&Job{}).Where("organization_id = ? AND id = ?", tenant.orgID, lease.Job.ID).Updates(map[string]any{"cancel_requested_at": now, "lease_until": now.Add(-time.Second)}).Error; err != nil {
			t.Fatal(err)
		}
		signer := &switchAuditSigner{}
		signer.fail.Store(true)
		store.auditSigner = signer
		if _, err := queue.Claim(t.Context()); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatalf("reconcile ignored audit failure: %v", err)
		}
		job, _ := tenant.GetJob(lease.Job.ID)
		result, _ := tenant.GetPrecheck(target.Target.ID, record.ID)
		if job.Status != "running" || result.Status != "queued" || result.FinishedAt != nil {
			t.Fatal("reconcile audit failure partially committed")
		}
		signer.fail.Store(false)
		retention, err := tenant.Enqueue(JobSpec{Type: JobRetentionDelete, ObjectID: tenant.orgID, IdempotencyKey: "unrelated-retention"})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.db.Model(&Job{}).Where("organization_id = ? AND id = ?", tenant.orgID, retention.ID).Update("cancel_requested_at", now).Error; err != nil {
			t.Fatal(err)
		}
		if claimed, err := queue.Claim(t.Context()); err != nil || claimed != nil {
			t.Fatalf("cancel reconcile: %v", err)
		}
		job, _ = tenant.GetJob(lease.Job.ID)
		result, _ = tenant.GetPrecheck(target.Target.ID, record.ID)
		other, _ := tenant.GetJob(retention.ID)
		if job.Status != "cancelled" || result.Status != "failed" || result.ErrorCode != "MI_PRECHECK_CANCELLED" || result.FinishedAt == nil || other.Status != "cancelled" {
			t.Fatal("reconcile did not preserve typed terminal outcomes")
		}
		verified, err := tenant.VerifyAuditFull()
		// Includes the real authenticated session created by targetFixture.
		if err != nil || verified.EventCount != 6 {
			t.Fatal("reconcile modified unrelated job audit behavior")
		}
	})
}

func TestPrecheckReconcileExhaustedAndUncertainAreDistinct(t *testing.T) {
	for _, count := range []int{0, 1} {
		t.Run(fmt.Sprintf("requests-%d", count), func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				tenant, target, record, queue, lease := precheckFixture(t, store)
				if err := store.db.Model(&PrecheckRecord{}).Where("organization_id = ? AND id = ?", tenant.orgID, record.ID).Update("request_count", count).Error; err != nil {
					t.Fatal(err)
				}
				if err := store.db.Model(&Job{}).Where("organization_id = ? AND id = ?", tenant.orgID, lease.Job.ID).Updates(map[string]any{"attempt_count": 2, "lease_until": time.Now().UTC().Add(-time.Second)}).Error; err != nil {
					t.Fatal(err)
				}
				if claimed, err := queue.Claim(t.Context()); err != nil || claimed != nil {
					t.Fatalf("exhaustion reconcile: %v", err)
				}
				result, _ := tenant.GetPrecheck(target.Target.ID, record.ID)
				expected := "MI_PRECHECK_ATTEMPTS_EXHAUSTED"
				if count > 0 {
					expected = "MI_UNCERTAIN_ATTEMPT"
				}
				if result.Status != "failed" || result.ErrorCode != expected || result.FinishedAt == nil {
					t.Fatalf("wrong recovery code: %s", result.ErrorCode)
				}
			})
		})
	}
}
