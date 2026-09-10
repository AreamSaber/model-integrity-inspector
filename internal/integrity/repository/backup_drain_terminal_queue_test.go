package repository

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestBackupDrainTerminalApplyPendingPrecheckUncertain(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		f := newBackupDomainFixture(t, s, JobTargetPrecheck, 1)
		if err := f.queue.Retry(f.tenant.ctx, f.lease, "JOB_TEST", time.Hour); err != nil {
			t.Fatal(err)
		}
		freeze := beginTestMaintenance(t, s, f.tenant.ctx, backupDrainTestAuthority(t, s, f.tenant.ctx))
		source := backupDrainTerminalLoad(t, freeze, f.tenant.ctx, f.lease.Job.ID)
		if source.Kind() != BackupDrainPrecheckRequired || source.job.Status != "pending" {
			t.Fatal("actual pending request disappeared")
		}
		proof := backupDomainPreservationProof(t, s, JobTargetPrecheck, f.lease.Job.ObjectID)
		if result, err := freeze.ApplyBackupTerminalCandidate(f.tenant.ctx, source); err != nil || !result.Applied {
			t.Fatal("pending precheck not conservatively terminal", err)
		}
		var job Job
		if err := s.db.First(&job, f.lease.Job.ID).Error; err != nil || job.Status != "failed" || job.LastErrorCode == nil || *job.LastErrorCode != "JOB_BACKUP_UNCERTAIN" || job.CompletedAt == nil {
			t.Fatal("wrong pending precheck queue outcome", err)
		}
		proof(*job.CompletedAt)
		backupDrainTerminalAssertAudit(t, s, source, freeze, "precheck_uncertain", f.actor, "target.precheck.reconcile")
	})
}

func TestBackupDrainTerminalApplyRetentionPreservesReceipts(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, original := backupDrainRealProducer(t, s, JobRetentionDelete)
		backupDrainTerminalExpire(t, s, original.Job.ID)
		if err := s.db.Model(&Job{}).Where("id=?", original.Job.ID).UpdateColumn("cancel_requested_at", time.Now().UTC()).Error; err != nil {
			t.Fatal(err)
		}
		freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
		source := backupDrainTerminalLoad(t, freeze, tenant.ctx, original.Job.ID)
		before := backupDrainDomainRows(t, s)
		if result, err := freeze.ApplyBackupTerminalCandidate(tenant.ctx, source); err != nil || !result.Applied {
			t.Fatal("real planned retention cancellation", err)
		}
		if !reflect.DeepEqual(before, backupDrainDomainRows(t, s)) {
			t.Fatal("terminal retention changed batch, receipts or retained evidence")
		}
		var job Job
		if err := s.db.First(&job, original.Job.ID).Error; err != nil || job.Status != "cancelled" || job.LastErrorCode == nil || *job.LastErrorCode != "JOB_CANCELLED" {
			t.Fatal("retention cancellation priority", err)
		}
		backupDrainTerminalAssertAudit(t, s, source, freeze, "terminalize", 0, "")
		if next, observation, err := freeze.LoadBackupDrainCandidate(tenant.ctx); err != nil || next != nil || observation.CandidatePresent {
			t.Fatal("terminal retention reselected", err)
		}
	})
}

func TestBackupDrainTerminalApplyLegacyRetentionNotModernized(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, tenant, q := queueFixture(t, s)
		tenant.ctx = testActorContext(t, initial.User.ID)
		mustEnqueue(t, tenant, retentionJob(tenant.orgID, "legacy-terminal-drain"))
		original := mustClaim(t, q)
		backupDrainTerminalExpire(t, s, original.Job.ID)
		freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
		source := backupDrainTerminalLoad(t, freeze, tenant.ctx, original.Job.ID)
		if source.Kind() != BackupDrainSourceUnsupported {
			t.Fatal("retryable legacy sentinel became routable")
		}
		before := backupDrainTerminalRows(t, s)
		if result, err := freeze.ApplyBackupTerminalCandidate(tenant.ctx, source); !errors.Is(err, ErrBackupDrainUnsupported) || result != (BackupDrainTerminalResult{}) || !reflect.DeepEqual(before, backupDrainTerminalRows(t, s)) {
			t.Fatal("legacy retryable sentinel acquired terminal authority", err)
		}
		if err := s.db.Model(&Job{}).Where("id=?", original.Job.ID).UpdateColumn("lease_until", nil).Error; err != nil {
			t.Fatal(err)
		}
		source = backupDrainTerminalLoad(t, freeze, tenant.ctx, original.Job.ID)
		beforeDomain := backupDrainDomainRows(t, s)
		// The coordinator routes only the closed Kind; it never probes Apply as
		// a decoder for SourceUnsupported. Keep the original legacy identity but
		// expose this proven original terminal predicate through the real Load.
		if !source.domain.Legacy || source.Kind() != BackupDrainTerminalRequired {
			t.Fatal("original terminal sentinel is not reachable through its Kind")
		}
		if result, err := freeze.ApplyBackupTerminalCandidate(tenant.ctx, source); err != nil || !result.Applied {
			t.Fatal("original null lease terminal predicate rejected", err)
		}
		if !reflect.DeepEqual(beforeDomain, backupDrainDomainRows(t, s)) {
			t.Fatal("legacy sentinel fabricated a batch or changed evidence")
		}
		var job Job
		if err := s.db.First(&job, original.Job.ID).Error; err != nil || job.Status != "failed" || job.LastErrorCode == nil || *job.LastErrorCode != "JOB_LEASE_INVALID" || job.ObjectID != tenant.orgID {
			t.Fatal("legacy null lease outcome", err)
		}
		backupDrainTerminalAssertAudit(t, s, source, freeze, "terminalize", 0, "")
		after := backupDrainTerminalRows(t, s)
		if result, err := freeze.ApplyBackupTerminalCandidate(tenant.ctx, source); !errors.Is(err, ErrBackupDrainStale) || result != (BackupDrainTerminalResult{}) || !reflect.DeepEqual(after, backupDrainTerminalRows(t, s)) {
			t.Fatal("routed original sentinel was replayed", err)
		}
		if next, observation, err := freeze.LoadBackupDrainCandidate(tenant.ctx); err != nil || next != nil || observation.CandidatePresent {
			t.Fatal("routed terminal sentinel remained an active candidate", err)
		}
	})
}

func TestBackupDrainTerminalApplyNotificationNoDeliveryClaim(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, tenant, q := queueFixture(t, s)
		tenant.ctx = testActorContext(t, initial.User.ID)
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		// Explicit retained schema fixture: no production notification handler or
		// producer currently exists. Actual enqueue/claim/retry are exercised.
		if err := s.db.Exec("INSERT INTO integrity_outbox(id,organization_id,event_type,object_id,idempotency_key,status,available_at,created_at) VALUES(?,?,?,?,?,?,?,?)", id, tenant.orgID, "retained.event", tenant.orgID, "retained-terminal-notification", "pending", time.Now().UTC(), time.Now().UTC()).Error; err != nil {
			t.Fatal(err)
		}
		mustEnqueue(t, tenant, JobSpec{Type: JobNotificationSend, ObjectID: id, IdempotencyKey: "retained-terminal-notification"})
		job := mustClaim(t, q)
		if err := q.Retry(tenant.ctx, job, "JOB_TEST", time.Hour); err != nil {
			t.Fatal(err)
		}
		freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
		source := backupDrainTerminalLoad(t, freeze, tenant.ctx, job.Job.ID)
		before := backupDrainDomainRows(t, s)
		if result, err := freeze.ApplyBackupTerminalCandidate(tenant.ctx, source); err != nil || !result.Applied {
			t.Fatal("notification uncertain terminal", err)
		}
		if !reflect.DeepEqual(before, backupDrainDomainRows(t, s)) {
			t.Fatal("terminal queue changed original delivery facts")
		}
		var after Job
		if err := s.db.First(&after, job.Job.ID).Error; err != nil || after.Status != "failed" || after.LastErrorCode == nil || *after.LastErrorCode != "JOB_DELIVERY_UNCERTAIN" {
			t.Fatal("unknown notification presented as certain", err)
		}
		backupDrainTerminalAssertAudit(t, s, source, freeze, "notification_uncertain", 0, "")
	})
}

func TestBackupDrainTerminalApplyRejectsSafeAndExecution(t *testing.T) {
	for _, kind := range []JobType{JobRunPlan, JobSampleExecute, JobRunAnalyze, JobReportGenerate, JobTargetPrecheck, JobRetentionDelete} {
		t.Run(string(kind), func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				tenant, _, job := backupDrainRealProducer(t, s, kind)
				backupDrainTerminalExpire(t, s, job.Job.ID)
				freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
				source := backupDrainTerminalLoad(t, freeze, tenant.ctx, job.Job.ID)
				before := backupDrainTerminalRows(t, s)
				if result, err := freeze.ApplyBackupTerminalCandidate(tenant.ctx, source); !errors.Is(err, ErrBackupDrainUnsupported) || result != (BackupDrainTerminalResult{}) || !reflect.DeepEqual(before, backupDrainTerminalRows(t, s)) {
					t.Fatal("safe/unsupported source gained terminal authority", err)
				}
			})
		})
	}
}
