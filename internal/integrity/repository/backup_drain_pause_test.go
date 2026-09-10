package repository

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func backupDrainTestAuthority(t *testing.T, s *Store, ctx context.Context) ManagementAuthority {
	t.Helper()
	actor, err := audit.ActorFromContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	user, err := s.GetUser(ctx, actor.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	return managementSession(t, s, user)
}

func TestBackupDrainPausePreservesRealSampleAndOriginalFence(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, s, 1)
		_, q, _ := executionStart(t, tenant, plan, policy)
		original := mustClaim(t, q)
		// Expire only the lease. GORM Update also writes host-local updated_at,
		// which PG's timestamp-without-time-zone stores as a different wall clock
		// from the real queue's UTC DB clock. That unrelated fixture mutation
		// would invalidate the exact UpdatedAt advancement proof below.
		if err := s.db.Model(&Job{}).Where("organization_id=? AND id=?", original.Job.OrganizationID, original.Job.ID).
			UpdateColumn("lease_until", time.Unix(1, 0).UTC()).Error; err != nil {
			t.Fatal(err)
		}
		auth := backupDrainTestAuthority(t, s, tenant.ctx)
		freeze := beginTestMaintenance(t, s, tenant.ctx, auth)
		if claimed, err := q.Claim(tenant.ctx); err != nil || claimed != nil {
			t.Fatal("frozen Claim admitted work", err)
		}
		beforeObservation, err := freeze.Observe(tenant.ctx)
		if err != nil || !beforeObservation.ExpiredJobPresent {
			t.Fatal("original missing progress not demonstrated", err)
		}
		var before Job
		if err := s.db.First(&before, original.Job.ID).Error; err != nil {
			t.Fatal(err)
		}
		source, observation, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
		if err != nil || source == nil || source.Kind() != BackupDrainPauseSafe || !observation.CandidatePresent {
			t.Fatal("actual sample candidate", source, observation, err)
		}
		// A normal maintenance renewal is not a change to the source's Job fence.
		if err := freeze.Renew(tenant.ctx); err != nil {
			t.Fatal(err)
		}
		result, err := freeze.PauseBackupDrainCandidate(tenant.ctx, source)
		if err != nil || !result.Applied {
			t.Fatal("safe expired sample was not paused", result, err)
		}
		var after Job
		if err := s.db.First(&after, original.Job.ID).Error; err != nil {
			t.Fatal(err)
		}
		if after.Status != "pending" || after.LeaseOwner != nil || after.LeaseUntil != nil || !after.UpdatedAt.After(before.UpdatedAt) {
			t.Fatalf("pause did not persist exact transition: pending=%t owner_null=%t lease_null=%t updated_delta=%s", after.Status == "pending", after.LeaseOwner == nil, after.LeaseUntil == nil, after.UpdatedAt.Sub(before.UpdatedAt))
		}
		after.Status, after.LeaseOwner, after.LeaseUntil, after.UpdatedAt = before.Status, before.LeaseOwner, before.LeaseUntil, before.UpdatedAt
		if !reflect.DeepEqual(before, after) {
			t.Fatal("pause rewrote unrelated original Job facts")
		}
		if result, err := freeze.PauseBackupDrainCandidate(tenant.ctx, source); !errors.Is(err, ErrBackupDrainStale) || result != (BackupDrainPauseResult{}) {
			t.Fatal("old source was applied twice", result, err)
		}
		for _, operation := range []func() error{
			func() error { return q.Complete(tenant.ctx, original) }, func() error { return q.Retry(tenant.ctx, original, "JOB_TEST", 0) }, func() error { _, err := q.Renew(tenant.ctx, original); return err },
		} {
			if err := operation(); !errors.Is(err, ErrJobLeaseLost) {
				t.Fatal("original Job fence survived pause", err)
			}
		}
		var attempts int64
		if err := s.db.Model(&AttemptRecord{}).Count(&attempts).Error; err != nil || attempts != 0 {
			t.Fatal("pause invented dispatch", err)
		}
		if err := s.VerifyAllAudit(tenant.ctx, true); err != nil {
			t.Fatal("pause audit", err)
		}
	})
}
