package repository

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSystemMaintenanceFreezeKeepsInFlightFencesAndDependentJobs(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, _, plan, policy := executionFixture(t, s, 1)
		run, q, samples := executionStart(t, tenant, plan, policy)
		job := mustClaim(t, q)
		auth := tenant.ctx.Value(controlAuthorityKey{}).(controlAuthority).identity
		freeze := beginTestMaintenance(t, s, tenant.ctx, auth)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		otherCtx := bindTargetTestSession(t, other, testActorContext(t, auth.UserID), auth.SessionID, tenant.orgID)
		otherTenant, _ := other.WithOrganization(otherCtx, tenant.orgID)
		if _, err := otherTenant.CreateRun(plan, policy, "blocked-during-freeze"); !errors.Is(err, ErrSystemMaintenance) {
			t.Fatal("second API instance created Run", err)
		}
		if _, err := otherTenant.Enqueue(JobSpec{Type: JobRunAnalyze, ObjectID: run.ID, IdempotencyKey: "blocked-generic"}); !errors.Is(err, ErrSystemMaintenance) {
			t.Fatal("generic enqueue bypass", err)
		}
		if cfg.Driver == "postgres" {
			otherQueue, err := other.OpenJobQueue(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = otherQueue.Close(t.Context()) }()
			if claimed, err := otherQueue.Claim(t.Context()); err != nil || claimed != nil {
				t.Fatal("second PostgreSQL consumer claimed during freeze", err)
			}
		}
		if _, err := q.Renew(t.Context(), job); err != nil {
			t.Fatal("freeze prevented in-flight renewal", err)
		}
		if err := q.CheckLease(t.Context(), job); err != nil {
			t.Fatal("freeze became job cancellation", err)
		}
		// The Job was admitted before freeze; its original pre-call bookkeeping
		// and later settlement keep exactly the original live lease requirements.
		attempt := reserveTestAttempt(t, tenant, q, job, samples[0])
		observation, err := freeze.Observe(tenant.ctx)
		if err != nil || !observation.RunningJobPresent || !observation.UnsettledAttemptPresent {
			t.Fatal("active work called drained", observation, err)
		}
		if err := q.CompleteWith(t.Context(), job, func(tx *TenantTransaction) error {
			return tx.FinishAttempt(samples[0].ID, attempt.ID, successOutcome(), 0)
		}); err != nil {
			t.Fatal("freeze prevented settlement or internal analysis enqueue", err)
		}
		if err := q.Complete(t.Context(), job); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("old Job generation completed twice", err)
		}
		if claimed, err := q.Claim(t.Context()); err != nil || claimed != nil {
			t.Fatal("pending dependency claimed during freeze", err)
		}
		if err := q.ExpireRunEstimates(t.Context()); err != nil {
			t.Fatal("paused draft cleanup failed", err)
		}
		if err := q.ScheduleResponseRetention(t.Context()); err != nil {
			t.Fatal("paused retention scheduler failed", err)
		}
		var schedules int64
		if err := s.db.Table("integrity_response_retention_schedule").Count(&schedules).Error; err != nil || schedules != 0 {
			t.Fatal("freeze scheduler mutated state", schedules, err)
		}
		if err := freeze.Abort(tenant.ctx); err != nil {
			t.Fatal(err)
		}
		analysis := mustClaim(t, q)
		if JobType(analysis.Job.Type) != JobRunAnalyze {
			t.Fatal("internal dependent Job lost")
		}
	})
}

func TestSystemMaintenanceCancelAndPrecheckAdmission(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, record, q, job := precheckFixture(t, s)
		auth := tenant.ctx.Value(controlAuthorityKey{}).(controlAuthority).identity
		freeze := beginTestMaintenance(t, s, tenant.ctx, auth)
		if _, err := tenant.EnqueuePrecheck(record); !errors.Is(err, ErrSystemMaintenance) {
			t.Fatal("new precheck admitted", err)
		}
		if _, err := q.Renew(t.Context(), job); err != nil {
			t.Fatal("active precheck cannot renew", err)
		}
		if err := freeze.Abort(tenant.ctx); err != nil {
			t.Fatal(err)
		}
	})
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, s, 1)
		run, _, _ := executionStart(t, tenant, plan, policy)
		auth := tenant.ctx.Value(controlAuthorityKey{}).(controlAuthority).identity
		freeze := beginTestMaintenance(t, s, tenant.ctx, auth)
		cancelled, err := tenant.CancelRun(run.ID, run.Version)
		if err != nil || cancelled.Status != "CANCELLING" {
			t.Fatal("freeze prevented business cancellation", err)
		}
		if err := freeze.Abort(tenant.ctx); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSystemMaintenanceExpiredJobStillBlocksWithoutInventedRecovery(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, s, 1)
		_, queue, samples := executionStart(t, tenant, plan, policy)
		job := mustClaim(t, queue)
		attempt := reserveTestAttempt(t, tenant, queue, job, samples[0])
		auth := tenant.ctx.Value(controlAuthorityKey{}).(controlAuthority).identity
		freeze := beginTestMaintenance(t, s, tenant.ctx, auth)
		// Synthetic expired Job fact, not proof that a remote request stopped.
		// The observation must preserve both running and unresolved blockers.
		expiredAt := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Second)
		changed := s.db.Model(&Job{}).Where("id=?", job.Job.ID).Update("lease_until", expiredAt)
		if changed.Error != nil || changed.RowsAffected != 1 {
			t.Fatal("prepare canonical UTC synthetic expiry", changed.Error)
		}
		var persisted Job
		if err := s.db.Where("id=?", job.Job.ID).Take(&persisted).Error; err != nil || persisted.LeaseUntil == nil {
			t.Fatal("read persisted synthetic expiry", err)
		}
		now, err := queueTime(s.db, s.driver)
		if err != nil {
			t.Fatal(err)
		}
		_, writtenOffset := expiredAt.Zone()
		if writtenOffset != 0 || !persisted.LeaseUntil.Before(now) || !errors.Is(queue.CheckLease(t.Context(), job), ErrJobLeaseLost) {
			t.Fatal("fixture did not persist an actually expired canonical UTC Job")
		}
		observation, err := freeze.Observe(tenant.ctx)
		if err != nil || !observation.RunningJobPresent || !observation.ExpiredJobPresent || !observation.UnsettledAttemptPresent {
			t.Fatal("expired running Job was treated as drained", observation, err)
		}
		if err := queue.CheckLease(t.Context(), job); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("expired Job still authorized work", err)
		}
		var unresolved int64
		if err := s.db.Model(&AttemptRecord{}).Where("id=? AND status='DISPATCHED' AND finished_at IS NULL", attempt.ID).Count(&unresolved).Error; err != nil || unresolved != 1 {
			t.Fatal("maintenance observation invented attempt recovery", err)
		}
		if err := freeze.Abort(tenant.ctx); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSystemMaintenanceHistoricalReportDownloadAuditRemainsAvailable(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, q, run := reportFixture(t, s)
		row, err := tenant.CreateReport(ReportInput{RunID: run.ID, AnalysisRevision: 1, Format: "json", IdempotencyKey: "before-maintenance"})
		if err != nil {
			t.Fatal(err)
		}
		job := mustClaim(t, q)
		source, err := q.LoadReportSource(t.Context(), job)
		if err != nil {
			t.Fatal(err)
		}
		encoded := []byte(`{"synthetic_s1":true}`)
		if err := q.FreezeReportSource(t.Context(), job, source, encoded); err != nil {
			t.Fatal(err)
		}
		frozen, err := q.LoadReportSource(t.Context(), job)
		if err != nil {
			t.Fatal(err)
		}
		auth := tenant.ctx.Value(controlAuthorityKey{}).(controlAuthority).identity
		freeze := beginTestMaintenance(t, s, tenant.ctx, auth)
		publication := ReportPublication{ContentHash: "sha256:" + strings.Repeat("a", 64), FileHash: strings.Repeat("b", 64), FileSize: 128}
		if err := q.CompleteWith(t.Context(), job, func(tx *TenantTransaction) error { return tx.PublishReport(frozen, reportDigest(encoded), publication) }); err != nil {
			t.Fatal("in-flight report did not publish", err)
		}
		if err := tenant.AuditReportDownload(row.ID, publication.FileHash, publication.FileSize); err != nil {
			t.Fatal("freeze blocked historical download audit", err)
		}
		if _, err := tenant.CreateReport(ReportInput{RunID: run.ID, AnalysisRevision: 1, Format: "html", IdempotencyKey: "after-maintenance"}); !errors.Is(err, ErrSystemMaintenance) {
			t.Fatal("report creation shared download bypass", err)
		}
		if err := freeze.Abort(tenant.ctx); err != nil {
			t.Fatal(err)
		}
		// Synthetic isolated destination state only. This is NOT a restore or
		// activation implementation, and no source/live database is copied here.
		if err := s.db.Model(&maintenanceState{}).Where("id=1").Updates(map[string]any{"mode": MaintenanceRestoreIsolated, "version": 4}).Error; err != nil {
			t.Fatal(err)
		}
		if err := tenant.AuditReportDownload(row.ID, publication.FileHash, publication.FileSize); err != nil {
			t.Fatal("isolation blocked historical report audit", err)
		}
	})
}

func TestSystemMaintenanceRestoreIsolationPersistsAcrossStoreRestart(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		initial, auth, ctx := managementFixture(t, s)
		if err := s.db.Model(&maintenanceState{}).Where("id=1").Updates(map[string]any{"mode": MaintenanceRestoreIsolated, "version": 2, "updated_at_micros": time.Now().Add(-365 * 24 * time.Hour).UnixMicro()}).Error; err != nil {
			t.Fatal(err)
		}
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		state, err := other.ReadMaintenanceState(ctx)
		if err != nil || state.Mode != MaintenanceRestoreIsolated {
			t.Fatal("restart or old timestamp unlocked restore", state, err)
		}
		if _, err := other.BeginBackupMaintenance(ctx, auth, BackupMaintenanceRequest{ExpectedVersion: 2, ReasonCode: "backup.manual", MaxDuration: time.Hour}); !errors.Is(err, ErrRestoreIsolated) {
			t.Fatal("backup begin bypassed restore quarantine", err)
		}
		if _, err := other.TakeOverExpiredBackup(ctx, auth, BackupMaintenanceRequest{ExpectedVersion: 2, ReasonCode: "backup.recovery", MaxDuration: time.Hour}); !errors.Is(err, ErrRestoreIsolated) {
			t.Fatal("lease takeover unlocked restore quarantine", err)
		}
		if _, err := other.ManageCreateUser(ctx, auth, ManagedUserCreate{Username: "blocked", PasswordHash: "synthetic"}); !errors.Is(err, ErrRestoreIsolated) {
			t.Fatal("restored admin sensitive mutation accepted", err)
		}
		if err := other.ChangePassword(ctx, initial.User.ID, initial.User.PasswordHash, "replacement", time.Now()); !errors.Is(err, ErrRestoreIsolated) {
			t.Fatal("password mutation bypassed isolation", err)
		}
		_ = managementSession(t, other, initial.User) // Actual login session/audit path is retained.
		queue, err := other.OpenJobQueue(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = queue.Close(t.Context()) }()
		if claimed, err := queue.Claim(t.Context()); err != nil || claimed != nil {
			t.Fatal("restored consumer issued work", err)
		}
		if err := queue.ReconcileExecution(ctx, initial.Organization.ID); err != nil {
			t.Fatal("isolated recovery should pause", err)
		}
		if err := queue.ReconcileReports(ctx); err != nil {
			t.Fatal(err)
		}
		if err := queue.ExpireRunEstimates(ctx); err != nil {
			t.Fatal(err)
		}
		if err := queue.ScheduleResponseRetention(ctx); err != nil {
			t.Fatal(err)
		}
	})
}
