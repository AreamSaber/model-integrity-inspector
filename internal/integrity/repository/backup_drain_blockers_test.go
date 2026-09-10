package repository

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBackupDrainPendingDispatchedIsBlockedWithoutSettlement(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, s, 1)
		_, q, samples := executionStart(t, tenant, plan, policy)
		job := mustClaim(t, q)
		attempt := reserveTestAttempt(t, tenant, q, job, samples[0])
		if err := q.Retry(tenant.ctx, job, "JOB_TEST", time.Hour); err != nil {
			t.Fatal(err)
		}
		freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
		source := backupDrainAssertBlocked(t, freeze, tenant.ctx, BackupDrainExecutionRequired)
		if source.job.Status != "pending" || !source.job.Unsettled {
			t.Fatal("pending dispatched intent vanished")
		}
		var after AttemptRecord
		if err := s.db.First(&after, attempt.ID).Error; err != nil || after.Status != "DISPATCHED" || after.FinishedAt != nil {
			t.Fatal("foundation invented settlement", err)
		}
		_, observation, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
		if err != nil || !observation.UnsettledAttemptPresent || observation.RunningJobPresent {
			t.Fatal("pending-only blocker observation", observation, err)
		}
	})
}

func TestBackupDrainPendingPrecheckRequestIsBlocked(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, record, q, job := precheckFixture(t, s)
		if err := q.WithLease(tenant.ctx, job, func(tx *TenantTransaction) error {
			if _, err := tx.BeginPrecheck(record.ID, job.Job.ID); err != nil {
				return err
			}
			return tx.ReservePrecheckRequest(record.ID, job.Job.ID)
		}); err != nil {
			t.Fatal(err)
		}
		if err := q.Retry(tenant.ctx, job, "JOB_TEST", time.Hour); err != nil {
			t.Fatal(err)
		}
		freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
		backupDrainAssertBlocked(t, freeze, tenant.ctx, BackupDrainPrecheckRequired)
	})
}

func backupDrainTerminalProducer(t *testing.T, typ JobType, want BackupDrainKind) {
	t.Helper()
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, q, job := backupDrainRealProducer(t, s, typ)
		if err := q.Fail(tenant.ctx, job, "JOB_TEST"); err != nil {
			t.Fatal(err)
		}
		freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
		backupDrainAssertBlocked(t, freeze, tenant.ctx, want)
	})
}
func TestBackupDrainTerminalPlanProjection(t *testing.T) {
	backupDrainTerminalProducer(t, JobRunPlan, BackupDrainExecutionRequired)
}
func TestBackupDrainTerminalSampleProjection(t *testing.T) {
	backupDrainTerminalProducer(t, JobSampleExecute, BackupDrainExecutionRequired)
}
func TestBackupDrainTerminalAnalyzeProjection(t *testing.T) {
	backupDrainTerminalProducer(t, JobRunAnalyze, BackupDrainAnalysisRequired)
}
func TestBackupDrainTerminalReportProjection(t *testing.T) {
	backupDrainTerminalProducer(t, JobReportGenerate, BackupDrainReportRequired)
}
func TestBackupDrainTerminalPrecheckProjection(t *testing.T) {
	backupDrainTerminalProducer(t, JobTargetPrecheck, BackupDrainPrecheckRequired)
}

func TestBackupDrainTerminalPredicatesDoNotBecomePause(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, job := backupDrainRealProducer(t, s, JobSampleExecute)
		expireJob(t, s, job.Job)
		freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
		// Controlled malformed/terminal queue metadata, distinct from real producer positives.
		for _, item := range []struct {
			name    string
			updates map[string]any
		}{
			{"cancel", map[string]any{"cancel_requested_at": time.Now().UTC()}},
			{"exhausted", map[string]any{"attempt_count": job.Job.MaxAttempts}},
			{"missing-lease", map[string]any{"lease_until": nil}},
			{"pending-cancel", map[string]any{"status": "pending", "cancel_requested_at": time.Now().UTC(), "lease_owner": nil, "lease_until": nil}},
		} {
			t.Run(item.name, func(t *testing.T) {
				if err := s.db.Model(&Job{}).Where("id=?", job.Job.ID).Updates(item.updates).Error; err != nil {
					t.Fatal(err)
				}
				backupDrainAssertBlocked(t, freeze, tenant.ctx, BackupDrainTerminalRequired)
				if err := s.db.Model(&Job{}).Where("id=?", job.Job.ID).Updates(map[string]any{"status": "running", "cancel_requested_at": nil, "attempt_count": job.Generation, "lease_owner": job.Job.LeaseOwner, "lease_until": time.Unix(1, 0).UTC()}).Error; err != nil {
					t.Fatal(err)
				}
			})
		}
		if err := s.db.Model(&Organization{}).Where("id=?", tenant.orgID).Update("status", "disabled").Error; err != nil {
			t.Fatal(err)
		}
		backupDrainAssertBlocked(t, freeze, tenant.ctx, BackupDrainTerminalRequired)
	})
}

func TestBackupDrainDisabledModernRetentionStillPauses(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, job := backupDrainRealProducer(t, s, JobRetentionDelete)
		expireJob(t, s, job.Job)
		freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
		if err := s.db.Model(&Organization{}).Where("id=?", tenant.orgID).Update("status", "disabled").Error; err != nil {
			t.Fatal(err)
		}
		source, _, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
		if err != nil || source == nil || source.Kind() != BackupDrainPauseSafe || source.job.Inactive {
			t.Fatal("lost existing retention exception", source, err)
		}
		if result, err := freeze.PauseBackupDrainCandidate(tenant.ctx, source); err != nil || !result.Applied {
			t.Fatal("modern disabled retention pause", result, err)
		}
	})
}

func TestBackupDrainLegacyRetentionActiveUnsupportedStaticRetained(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, tenant, q := queueFixture(t, s)
		tenant.ctx = testActorContext(t, initial.User.ID)
		mustEnqueue(t, tenant, retentionJob(tenant.orgID, "legacy-sentinel"))
		job := mustClaim(t, q)
		expireJob(t, s, job.Job)
		freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
		backupDrainAssertBlocked(t, freeze, tenant.ctx, BackupDrainSourceUnsupported)
		// A retained terminal historical sentinel is not a modern batch and must
		// not be rewritten into one merely to make a candidate disappear.
		if err := s.db.Model(&Job{}).Where("id=?", job.Job.ID).Updates(map[string]any{"status": "failed", "lease_owner": nil, "lease_until": nil, "completed_at": time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
		before := backupDrainDomainRows(t, s)
		source, observation, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
		if err != nil || source != nil || observation.CandidatePresent || !reflect.DeepEqual(before, backupDrainDomainRows(t, s)) {
			t.Fatal("static legacy sentinel rejected or rewritten", source, observation, err)
		}
	})
}

func TestBackupDrainNotificationUnknownDeliveryIsVisible(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, tenant, q := queueFixture(t, s)
		tenant.ctx = testActorContext(t, initial.User.ID)
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		// There is currently no production notification producer/Handler. This
		// is explicitly a retained historical schema fixture, not a delivery proof.
		if err := s.db.Exec("INSERT INTO integrity_outbox(id,organization_id,event_type,object_id,idempotency_key,status,available_at,created_at) VALUES(?,?,?,?,?,?,?,?)", id, tenant.orgID, "retained.event", tenant.orgID, "retained-notification", "pending", time.Now().UTC(), time.Now().UTC()).Error; err != nil {
			t.Fatal(err)
		}
		mustEnqueue(t, tenant, JobSpec{Type: JobNotificationSend, ObjectID: id, IdempotencyKey: "retained-notification"})
		job := mustClaim(t, q)
		if err := q.Retry(tenant.ctx, job, "JOB_TEST", time.Hour); err != nil {
			t.Fatal(err)
		}
		freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
		backupDrainAssertBlocked(t, freeze, tenant.ctx, BackupDrainNotificationRequired)
	})
}

func TestBackupDrainLiveIsNotAnExpiredPermit(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, job := backupDrainRealProducer(t, s, JobSampleExecute)
		freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
		source, observation, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
		if err != nil || source != nil || !observation.RunningJobPresent || observation.CandidatePresent || observation.ExpiredJobPresent {
			t.Fatal("live job became candidate", source, observation, err)
		}
		var got Job
		if err := s.db.First(&got, job.Job.ID).Error; err != nil || got.Status != "running" {
			t.Fatal("live state changed", err)
		}
	})
}

func TestBackupDrainSourceBoundsAndCorruptRelationshipAreClosed(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, _, job := backupDrainRealProducer(t, s, JobSampleExecute)
		expireJob(t, s, job.Job)
		freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
		oversizeKey := strings.Repeat("private-canary-", 100000)
		if cfg.Driver == "postgres" {
			// Above the source's 128-byte bound but below PostgreSQL's physical
			// B-tree row limit, so the intended source check is actually reached.
			oversizeKey = strings.Repeat("private-canary-", 14)
		}
		for _, item := range []struct {
			name    string
			updates map[string]any
		}{
			{"oversize-key", map[string]any{"idempotency_key": oversizeKey}},
			{"wrong-object", map[string]any{"object_id": tenant.orgID}},
			{"unknown-type", map[string]any{"type": "private-canary-unknown"}},
		} {
			t.Run(item.name, func(t *testing.T) {
				if err := s.db.Model(&Job{}).Where("id=?", job.Job.ID).Updates(item.updates).Error; err != nil {
					t.Fatal(err)
				}
				source, observation, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
				if !errors.Is(err, ErrBackupDrainSource) || source != nil || observation != (BackupDrainObservation{}) || strings.Contains(err.Error(), "private-canary") {
					t.Fatal("invalid source accepted or leaked", err)
				}
				if err := s.db.Model(&Job{}).Where("id=?", job.Job.ID).Updates(map[string]any{"idempotency_key": job.Job.IdempotencyKey, "object_id": job.Job.ObjectID, "type": job.Job.Type}).Error; err != nil {
					t.Fatal(err)
				}
			})
		}
	})
}
