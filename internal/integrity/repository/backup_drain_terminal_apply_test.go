package repository

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func backupDrainTerminalRows(t *testing.T, s *Store) map[string][]map[string]any {
	t.Helper()
	rows := backupDomainRows(t, s)
	for table, values := range backupDrainDomainRows(t, s) {
		rows[table] = values
	}
	return rows
}

func backupDrainTerminalLoad(t *testing.T, freeze *MaintenanceLease, ctx context.Context, id int64) *BackupDrainSource {
	t.Helper()
	source, observation, err := freeze.LoadBackupDrainCandidate(ctx)
	if err != nil || source == nil || source.job.ID != id || !observation.CandidatePresent {
		t.Fatal("real terminal source missing", err)
	}
	return source
}

func backupDrainTerminalExpire(t *testing.T, s *Store, id int64) {
	t.Helper()
	// Only the original lease is fault-injected; never alter the Job's wall-clock
	// updated_at through the host timezone or shorten a production lease policy.
	if err := s.db.Model(&Job{}).Where("id=?", id).UpdateColumn("lease_until", time.Unix(1, 0).UTC()).Error; err != nil {
		t.Fatal(err)
	}
}

func backupDrainTerminalAssertAudit(t *testing.T, s *Store, source *BackupDrainSource, freeze *MaintenanceLease, action string, creator int64, domainAction string) {
	t.Helper()
	var system []audit.Event
	if err := s.db.Where("action=?", "system.backup.drain."+action).Find(&system).Error; err != nil || len(system) != 1 || system[0].ActorID == nil || *system[0].ActorID != freeze.auth.UserID || system[0].ObjectID != backupDrainTerminalIdentity(maintenanceOperation{ID: freeze.operationID, Generation: freeze.generation}, source.job) {
		t.Fatal("current maintenance actor or exact source audit missing", err)
	}
	if domainAction != "" {
		var domainEvents []audit.Event
		if err := s.db.Where("organization_id=? AND action=? AND object_id=?", source.job.OrganizationID, domainAction, strconv.FormatInt(source.job.ObjectID, 10)).Find(&domainEvents).Error; err != nil || len(domainEvents) != 1 || domainEvents[0].ActorID == nil || *domainEvents[0].ActorID != creator || domainEvents[0].IPSummary != "" {
			t.Fatal("original creator audit changed or replayed", err)
		}
	}
	if err := s.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal("real complete audit chains", err)
	}
}

func backupDrainTerminalApplyDomain(t *testing.T, kind JobType, terminalAlready bool) {
	t.Helper()
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		f := newBackupDomainFixture(t, s, kind, 1)
		if terminalAlready {
			if err := f.queue.Fail(f.tenant.ctx, f.lease, "JOB_ORIGINAL_FAILURE"); err != nil {
				t.Fatal(err)
			}
		} else {
			backupDrainTerminalExpire(t, s, f.lease.Job.ID)
			if err := s.db.Model(&Job{}).Where("id=?", f.lease.Job.ID).UpdateColumn("attempt_count", f.lease.Job.MaxAttempts).Error; err != nil {
				t.Fatal(err)
			}
		}
		// This nonmember maintenance administrator is distinct from the original
		// domain creator. Disabling that creator must not erase historical audit.
		auth := backupDrainTestAuthority(t, s, f.tenant.ctx)
		operator := managementFixtureUser(t, s, f.tenant.ctx, auth, "drain-operator")
		if err := s.db.Model(&User{}).Where("id=?", operator.ID).UpdateColumn("is_system_admin", true).Error; err != nil {
			t.Fatal(err)
		}
		operatorAuth := managementSession(t, s, operator)
		ctx := testActorContext(t, operator.ID)
		if err := s.db.Model(&User{}).Where("id=?", f.actor).UpdateColumn("status", "disabled").Error; err != nil {
			t.Fatal(err)
		}
		freeze := beginTestMaintenance(t, s, ctx, operatorAuth)
		source := backupDrainTerminalLoad(t, freeze, ctx, f.lease.Job.ID)
		before := backupDrainTerminalRows(t, s)
		var oldJob Job
		if err := s.db.First(&oldJob, f.lease.Job.ID).Error; err != nil {
			t.Fatal(err)
		}
		if claimed, err := f.queue.Claim(ctx); err != nil || claimed != nil || !reflect.DeepEqual(before, backupDrainTerminalRows(t, s)) {
			t.Fatal("frozen ordinary Claim performed drain work", err)
		}
		proof := backupDomainPreservationProof(t, s, kind, oldJob.ObjectID)
		if err := freeze.Renew(ctx); err != nil {
			t.Fatal(err)
		}
		if result, err := freeze.ApplyBackupTerminalCandidate(ctx, source); err != nil || !result.Applied {
			t.Fatal("real maintenance terminal application", result, err)
		}
		var afterJob Job
		if err := s.db.First(&afterJob, oldJob.ID).Error; err != nil {
			t.Fatal(err)
		}
		if terminalAlready && !reflect.DeepEqual(oldJob, afterJob) {
			t.Fatal("domain projection rewrote original terminal Job")
		}
		if !terminalAlready {
			if afterJob.Status != "failed" || afterJob.LastErrorCode == nil || *afterJob.LastErrorCode != "JOB_ATTEMPTS_EXHAUSTED" || afterJob.CompletedAt == nil || afterJob.LeaseOwner != nil || afterJob.LeaseUntil != nil {
				t.Fatal("original terminal priority/fence not retained")
			}
			normalized := afterJob
			normalized.Status, normalized.LastErrorCode, normalized.CompletedAt, normalized.LeaseOwner, normalized.LeaseUntil, normalized.UpdatedAt = oldJob.Status, oldJob.LastErrorCode, oldJob.CompletedAt, oldJob.LeaseOwner, oldJob.LeaseUntil, oldJob.UpdatedAt
			if !reflect.DeepEqual(oldJob, normalized) {
				t.Fatal("terminal Job changed unrelated original fields")
			}
		}
		var stamp time.Time
		table, action := "", ""
		switch kind {
		case JobRunAnalyze:
			var row RunRecord
			if err := s.db.First(&row, oldJob.ObjectID).Error; err != nil || row.FinishedAt == nil {
				t.Fatal("analysis time", err)
			}
			stamp, table, action = *row.FinishedAt, "integrity_runs", "run.analysis.fail"
		case JobReportGenerate:
			var row ReportRecord
			if err := s.db.First(&row, oldJob.ObjectID).Error; err != nil || row.CompletedAt == nil {
				t.Fatal("report time", err)
			}
			stamp, table, action = *row.CompletedAt, "integrity_reports", "report.fail"
		case JobTargetPrecheck:
			var row PrecheckRecord
			if err := s.db.First(&row, oldJob.ObjectID).Error; err != nil || row.FinishedAt == nil {
				t.Fatal("precheck time", err)
			}
			stamp, table, action = *row.FinishedAt, "integrity_target_prechecks", "target.precheck.reconcile"
		}
		proof(stamp)
		if !terminalAlready && !stamp.Equal(*afterJob.CompletedAt) {
			t.Fatal("Job and projection use different transaction clocks")
		}
		after := backupDrainTerminalRows(t, s)
		for name, values := range before {
			if name != table && name != "integrity_jobs" && name != "integrity_audit_logs" && name != "integrity_audit_chain_heads" && !reflect.DeepEqual(values, after[name]) {
				t.Fatal("unrelated domain or retained evidence changed")
			}
		}
		if result, err := freeze.ApplyBackupTerminalCandidate(ctx, source); !errors.Is(err, ErrBackupDrainStale) || result != (BackupDrainTerminalResult{}) || !reflect.DeepEqual(after, backupDrainTerminalRows(t, s)) {
			t.Fatal("old terminal source replayed or failed without rollback", result, err)
		}
		systemAction := "terminalize"
		if terminalAlready {
			systemAction = "project_terminal"
		}
		backupDrainTerminalAssertAudit(t, s, source, freeze, systemAction, f.actor, action)
		next, observation, err := freeze.LoadBackupDrainCandidate(ctx)
		if err != nil || next != nil || observation.CandidatePresent || observation.RunningJobPresent || observation.UnsettledAttemptPresent {
			t.Fatal("completed projection remains active", err)
		}
	})
}

func TestBackupDrainTerminalApplyAnalysis(t *testing.T) {
	backupDrainTerminalApplyDomain(t, JobRunAnalyze, false)
}
func TestBackupDrainTerminalApplyReport(t *testing.T) {
	backupDrainTerminalApplyDomain(t, JobReportGenerate, false)
}
func TestBackupDrainTerminalApplyPrecheck(t *testing.T) {
	backupDrainTerminalApplyDomain(t, JobTargetPrecheck, false)
}
func TestBackupDrainTerminalApplyOldAnalysis(t *testing.T) {
	backupDrainTerminalApplyDomain(t, JobRunAnalyze, true)
}
func TestBackupDrainTerminalApplyOldReport(t *testing.T) {
	backupDrainTerminalApplyDomain(t, JobReportGenerate, true)
}
func TestBackupDrainTerminalApplyOldPrecheck(t *testing.T) {
	backupDrainTerminalApplyDomain(t, JobTargetPrecheck, true)
}
