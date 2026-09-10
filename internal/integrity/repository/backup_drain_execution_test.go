package repository

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func backupDrainExecutionFixture(t *testing.T, s *Store, mode string, attempted bool) (*Tenant, *MaintenanceLease, *BackupDrainSource, JobLease, RunRecord, []LogicalSampleRecord) {
	t.Helper()
	tenant, _, plan, policy := executionFixture(t, s, 1)
	run, queue, samples := executionStart(t, tenant, plan, policy)
	job := mustClaim(t, queue)
	if attempted {
		reserveTestAttempt(t, tenant, queue, job, samples[0])
	}
	switch mode {
	case "pending":
		if err := queue.Retry(tenant.ctx, job, "JOB_TEST_PENDING", time.Hour); err != nil {
			t.Fatal(err)
		}
	case "failed":
		if err := queue.Fail(tenant.ctx, job, "JOB_TEST_ORIGINAL"); err != nil {
			t.Fatal(err)
		}
	case "cancelled":
		if err := queue.Fail(tenant.ctx, job, "JOB_TEST_ORIGINAL"); err != nil {
			t.Fatal(err)
		}
		if err := s.db.Model(&Job{}).Where("id=?", job.Job.ID).Updates(map[string]any{"status": "cancelled", "last_error_code": "JOB_CANCELLED"}).Error; err != nil {
			t.Fatal(err)
		}
	case "expired":
		if err := s.db.Model(&Job{}).Where("id=?", job.Job.ID).UpdateColumn("lease_until", time.Unix(1, 0).UTC()).Error; err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown fixture mode")
	}
	freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
	source, _, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
	if err != nil || source == nil {
		t.Fatal("actual candidate", err)
	}
	return tenant, freeze, source, job, run, samples
}

func TestBackupDrainExecutionActualLegacyDispatchedAtomicOnce(t *testing.T) {
	for _, mode := range []string{"pending", "expired", "failed", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				tenant, freeze, candidate, old, run, samples := backupDrainExecutionFixture(t, s, mode, true)
				before := reconciliationAtomicRows(t, s)
				source, err := freeze.LoadBackupExecutionSource(tenant.ctx, candidate)
				if err != nil || source == nil {
					t.Fatal("load actual intent", err)
				}
				if !reflect.DeepEqual(before, reconciliationAtomicRows(t, s)) {
					t.Fatal("load changed facts")
				}
				if err := freeze.Renew(tenant.ctx); err != nil {
					t.Fatal(err)
				}
				result, err := freeze.ApplyBackupExecutionSource(tenant.ctx, source, nil)
				if err != nil || result != ReconciliationApplied {
					t.Fatal("legacy intent not atomically drained", result, err)
				}
				var got Job
				if err := s.db.First(&got, old.Job.ID).Error; err != nil {
					t.Fatal(err)
				}
				if got.Status != "failed" && got.Status != "cancelled" || got.AttemptCount != old.Generation || got.LeaseOwner != nil || got.LeaseUntil != nil {
					t.Fatal("wrong original job fence")
				}
				wantCode := "JOB_BACKUP_UNCERTAIN"
				if mode == "failed" {
					wantCode = "JOB_TEST_ORIGINAL"
				}
				if mode == "cancelled" {
					wantCode = "JOB_CANCELLED"
				}
				if got.LastErrorCode == nil || *got.LastErrorCode != wantCode {
					t.Fatal("original terminal reason replaced")
				}
				attempts, err := tenant.ListAttempts(samples[0].ID)
				if err != nil || len(attempts) != 1 || attempts[0].Status != "UNCERTAIN" || attempts[0].Validity != "INVALID_RETRYABLE" || attempts[0].FinishedAt == nil {
					t.Fatal("intent not settled", err)
				}
				current, err := tenant.GetRun(run.ID)
				if err != nil || current.RequestCount != 1 || current.ReservedTokens != 0 || current.ReservedCostMicros != 0 || current.TokenCount != 38 {
					t.Fatal("original accounting not once", err)
				}
				var derived, executionJobs int64
				if err := s.db.Model(&AttemptDerivedRecord{}).Count(&derived).Error; err != nil {
					t.Fatal(err)
				}
				if err := s.db.Model(&Job{}).Where("type=?", string(JobSampleExecute)).Count(&executionJobs).Error; err != nil {
					t.Fatal(err)
				}
				if derived != 0 || executionJobs != 1 {
					t.Fatal("legacy gained S1 or retry")
				}
				after := reconciliationAtomicRows(t, s)
				if result, err := freeze.ApplyBackupExecutionSource(tenant.ctx, source, nil); !errors.Is(err, ErrBackupDrainStale) || result != "" {
					t.Fatal("old source replay", result, err)
				}
				if !reflect.DeepEqual(after, reconciliationAtomicRows(t, s)) {
					t.Fatal("replay changed accounting")
				}
				if err := s.VerifyAllAudit(tenant.ctx, true); err != nil {
					t.Fatal("authentic audit", err)
				}
			})
		})
	}
}

func TestBackupDrainExecutionUnattemptedAndPlan(t *testing.T) {
	for _, kind := range []JobType{JobRunPlan, JobSampleExecute} {
		t.Run(string(kind), func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				tenant, q, job := backupDrainRealProducer(t, s, kind)
				if err := q.Fail(tenant.ctx, job, "JOB_TEST_ORIGINAL"); err != nil {
					t.Fatal(err)
				}
				freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
				candidate, _, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
				if err != nil || candidate == nil {
					t.Fatal(err)
				}
				source, err := freeze.LoadBackupExecutionSource(tenant.ctx, candidate)
				if err != nil {
					t.Fatal(err)
				}
				if err := source.Use(func(data ExecutionReconciliationData) error {
					if data.Attempt != nil {
						t.Fatal("unattempted source gained intent")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if got, err := freeze.ApplyBackupExecutionSource(tenant.ctx, source, nil); err != nil || got != ReconciliationApplied {
					t.Fatal("unattempted projection", got, err)
				}
				var count int64
				if err := s.db.Model(&AttemptRecord{}).Count(&count).Error; err != nil || count != 0 {
					t.Fatal("invented attempt", err)
				}
				if err := s.db.Model(&AttemptDerivedRecord{}).Count(&count).Error; err != nil || count != 0 {
					t.Fatal("invented S1", err)
				}
				if err := s.VerifyAllAudit(tenant.ctx, true); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestBackupDrainExecutionPureDecisionPriority(t *testing.T) {
	job := backupDrainJob{Type: string(JobSampleExecute), Status: "running", Expired: true, AttemptCount: 3, MaxAttempts: 3, Inactive: true}
	data := ExecutionReconciliationData{Attempt: &AttemptRecord{Status: "DISPATCHED"}, Plan: domain.ExecutionPlan{}}
	for _, test := range []struct {
		cancel, lease bool
		count         int64
		inactive      bool
		status, code  string
	}{
		{true, false, 3, true, "cancelled", "JOB_CANCELLED"}, {false, false, 3, true, "failed", "JOB_LEASE_INVALID"},
		{false, true, 3, true, "failed", "JOB_ATTEMPTS_EXHAUSTED"}, {false, true, 1, true, "cancelled", "JOB_ORGANIZATION_INACTIVE"}, {false, true, 1, false, "failed", "JOB_BACKUP_UNCERTAIN"},
	} {
		job.CancelRequestedAt.Valid, job.LeaseUntil.Valid, job.AttemptCount, job.Inactive = test.cancel, test.lease, test.count, test.inactive
		status, code, _, err := backupDrainExecutionDecision(job, data)
		if err != nil || status != test.status || code != test.code {
			t.Fatal("original decision priority", err)
		}
	}
	if got, err := (*MaintenanceLease)(nil).ApplyBackupExecutionSource(context.Background(), nil, nil); got != "" || !errors.Is(err, ErrBackupDrainSource) {
		t.Fatal("nil authority", err)
	}
}
