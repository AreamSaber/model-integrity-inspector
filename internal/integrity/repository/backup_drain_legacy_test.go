package repository

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBackupDrainLegacyActiveMissingPointerIsNotRepaired(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, job := backupDrainRealProducer(t, s, JobSampleExecute)
		expireJob(t, s, job.Job)
		freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
		// Historical nullable layout, not a current producer success fixture.
		if err := s.db.Model(&LogicalSampleRecord{}).Where("id=?", job.Job.ObjectID).Update("job_id", nil).Error; err != nil {
			t.Fatal(err)
		}
		backupDrainAssertBlocked(t, freeze, tenant.ctx, BackupDrainSourceUnsupported)
	})
}

func TestBackupDrainLegacyDispatchedGenerationRemainsUnsupported(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, s, 1)
		_, q, samples := executionStart(t, tenant, plan, policy)
		job := mustClaim(t, q)
		attempt := reserveTestAttempt(t, tenant, q, job, samples[0])
		if err := q.Retry(tenant.ctx, job, "JOB_TEST", time.Hour); err != nil {
			t.Fatal(err)
		}
		freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
		// Preserve a known old nullable/zero-generation layout; no replacement
		// generation, Run ID or MAC may be fabricated by this foundation.
		if err := s.db.Model(&AttemptRecord{}).Where("id=?", attempt.ID).Updates(map[string]any{"run_id": nil, "lease_generation": 0}).Error; err != nil {
			t.Fatal(err)
		}
		backupDrainAssertBlocked(t, freeze, tenant.ctx, BackupDrainSourceUnsupported)
		_, observation, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
		if err != nil || !observation.UnsupportedSourcePresent || !observation.UnsettledAttemptPresent {
			t.Fatal("active legacy not represented as a blocker", observation, err)
		}
		// Without the nullable old Job ID there is no join-selected candidate,
		// but the independent all-attempt observation must still block snapshot.
		if err := s.db.Model(&AttemptRecord{}).Where("id=?", attempt.ID).Update("job_id", nil).Error; err != nil {
			t.Fatal(err)
		}
		missing, observation, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
		if err != nil || missing != nil || !observation.UnsupportedSourcePresent || !observation.UnsettledAttemptPresent {
			t.Fatal("unmapped legacy dispatch disappeared behind job join", observation, err)
		}
	})
}

func TestBackupDrainStaticLegacyMetadataIsNotNewlyRestricted(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		initial, tenant, q := queueFixture(t, s)
		tenant.ctx = testActorContext(t, initial.User.ID)
		mustEnqueue(t, tenant, retentionJob(tenant.orgID, "legacy-sentinel"))
		job := mustClaim(t, q)
		if err := q.Fail(tenant.ctx, job, "JOB_TEST"); err != nil {
			t.Fatal(err)
		}
		freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
		// The historical schema does not cap this key. It is not a selected
		// active source, so imposing a new client-allocation cap would incorrectly
		// shrink the existing static snapshot compatibility. Never select its text.
		legacyKey := strings.Repeat("legacy-opaque-", 100000)
		if cfg.Driver == "postgres" {
			// Keep a storable historical key above the new 128-byte source cap;
			// a megabyte index key is rejected by PG before the drain can read it.
			legacyKey = strings.Repeat("legacy-opaque-", 14)
		}
		if err := s.db.Model(&Job{}).Where("id=?", job.Job.ID).Update("idempotency_key", legacyKey).Error; err != nil {
			t.Fatal(err)
		}
		var before Job
		if err := s.db.First(&before, job.Job.ID).Error; err != nil {
			t.Fatal(err)
		}
		source, observation, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
		if err != nil || source != nil || observation.CandidatePresent {
			t.Fatal("static legacy metadata got new allocation restrictions", source, observation, err)
		}
		var after Job
		if err := s.db.First(&after, job.Job.ID).Error; err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("static legacy rewritten", err)
		}
	})
}
