package repository

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

type backupDomainFixture struct {
	tenant *Tenant
	queue  *JobQueue
	lease  JobLease
	actor  int64
}

func newBackupDomainFixture(t *testing.T, s *Store, kind JobType, requests int) backupDomainFixture {
	t.Helper()
	var fixture backupDomainFixture
	switch kind {
	case JobRunAnalyze:
		tenant, queue, run, _, lease := analysisReadyFixture(t, s, 1)
		fixture = backupDomainFixture{tenant, queue, lease, run.CreatedBy}
	case JobReportGenerate:
		tenant, queue, run := reportFixture(t, s)
		if _, err := tenant.CreateReport(ReportInput{run.ID, 1, "json", "backup-domain-report"}); err != nil {
			t.Fatal(err)
		}
		lease := mustClaim(t, queue)
		source, err := queue.LoadReportSource(t.Context(), lease)
		if err != nil {
			t.Fatal(err)
		}
		// Existing repository-level opaque fixture, not a real report artifact.
		if err := queue.FreezeReportSource(t.Context(), lease, source, []byte(`{"synthetic_s1":true}`)); err != nil {
			t.Fatal(err)
		}
		fixture = backupDomainFixture{tenant, queue, lease, run.CreatedBy}
	case JobTargetPrecheck:
		tenant, _, record, queue, lease := precheckFixture(t, s)
		if err := queue.WithLease(t.Context(), lease, func(tx *TenantTransaction) error { _, err := tx.BeginPrecheck(record.ID, lease.Job.ID); return err }); err != nil {
			t.Fatal(err)
		}
		for range requests {
			if err := queue.WithLease(t.Context(), lease, func(tx *TenantTransaction) error { return tx.ReservePrecheckRequest(record.ID, lease.Job.ID) }); err != nil {
				t.Fatal(err)
			}
		}
		fixture = backupDomainFixture{tenant, queue, lease, record.CreatedBy}
	default:
		t.Fatal("unknown fixed domain fixture")
	}
	return fixture
}

func backupDomainInvoke(s *Store, db *gorm.DB, job Job, status, code string, now time.Time) (domainProjectionResult, error) {
	switch JobType(job.Type) {
	case JobRunAnalyze:
		job.Status = status
		return s.reconcileAnalysisDomain(db, job, now)
	case JobReportGenerate:
		job.Status = status
		return s.reconcileReportDomain(db, job, now)
	case JobTargetPrecheck:
		// Deliberately retain the caller's pre-update Job.Status for this core.
		return s.reconcilePrecheckDomain(db, job, status, code, now)
	default:
		return "", ErrJobInvalid
	}
}

// Test-only trusted caller: real admission/consumer/Job lock, then optional Job
// transition and shared domain work in one transaction. It is not full drain.
func backupDomainTransaction(f backupDomainFixture, ctx context.Context, terminalize bool, status, code string) (domainProjectionResult, time.Time, error) {
	s := f.queue.store
	var result domainProjectionResult
	var now time.Time
	err := s.db.WithContext(ctx).Transaction(func(db *gorm.DB) error {
		allowed, err := s.maintenanceAdmission(db, maintenanceRecovery)
		if err != nil {
			return err
		}
		if !allowed {
			return ErrJobInvalid
		}
		now, err = queueTime(db, s.driver)
		if err != nil {
			return err
		}
		if err := f.queue.guardConsumer(db, now, false); err != nil {
			return err
		}
		var job Job
		if err := db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("organization_id=? AND id=?", f.lease.Job.OrganizationID, f.lease.Job.ID).First(&job).Error; err != nil {
			return err
		}
		if terminalize {
			changed := db.Model(&Job{}).Where("organization_id=? AND id=? AND status='running' AND lease_owner=? AND attempt_count=?", job.OrganizationID, job.ID, f.queue.owner, f.lease.Generation).
				Updates(map[string]any{"status": status, "last_error_code": code, "lease_owner": nil, "lease_until": nil, "completed_at": now, "updated_at": now})
			if changed.Error != nil {
				return changed.Error
			}
			if changed.RowsAffected != 1 {
				return ErrJobLeaseLost
			}
		}
		result, err = backupDomainInvoke(s, db, job, status, code, now)
		return err
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return result, now, nil
}

func backupDomainRows(t *testing.T, s *Store) map[string][]map[string]any {
	t.Helper()
	rows := map[string][]map[string]any{}
	for _, table := range []string{"integrity_runs", "integrity_run_results", "integrity_logical_samples", "integrity_sample_attempts", "integrity_reports", "integrity_target_prechecks", "integrity_jobs", "integrity_audit_logs", "integrity_audit_chain_heads"} {
		var values []map[string]any
		order := "id"
		switch table {
		case "integrity_audit_chain_heads":
			order = "organization_id"
		case "integrity_run_results":
			order = "organization_id,run_id,analysis_revision"
		}
		if err := s.db.Table(table).Order(order).Find(&values).Error; err != nil {
			t.Fatal("observe fixed private fixture rows", err)
		}
		rows[table] = values
	}
	return rows
}

func TestBackupDomainAnalysisAtomicRollback(t *testing.T) {
	backupDomainAtomicRollback(t, JobRunAnalyze, "integrity_runs", "OLD.status='ANALYZING' AND NEW.status='FAILED'", "run.analysis.fail")
}
func TestBackupDomainReportAtomicRollback(t *testing.T) {
	backupDomainAtomicRollback(t, JobReportGenerate, "integrity_reports", "OLD.status='generating' AND NEW.status='failed'", "report.fail")
}
func TestBackupDomainPrecheckAtomicRollback(t *testing.T) {
	backupDomainAtomicRollback(t, JobTargetPrecheck, "integrity_target_prechecks", "OLD.status='running' AND NEW.status='failed'", "target.precheck.reconcile")
}

func backupDomainAtomicRollback(t *testing.T, kind JobType, table, predicate, action string) {
	t.Helper()
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		fixture := newBackupDomainFixture(t, s, kind, 1)
		// A departed/disabled creator remains the original failure-audit actor.
		if err := s.db.Model(&User{}).Where("id=?", fixture.actor).UpdateColumn("status", "disabled").Error; err != nil {
			t.Fatal(err)
		}
		before := backupDomainRows(t, s)
		checkPreserved := backupDomainPreservationProof(t, s, kind, fixture.lease.Job.ObjectID)
		for _, fault := range []string{"suppressed_update", "late_audit_sql", "late_cancel"} {
			t.Run(fault, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				entered := false
				switch fault {
				case "suppressed_update":
					t.Cleanup(backupDomainIgnoreUpdate(t, s, cfg, table, predicate))
				case "late_audit_sql":
					t.Cleanup(backupDomainAuditSQLFault(t, s, cfg, action))
				case "late_cancel":
					const callback = "backup_domain_cancel_after_actual_audit"
					if err := s.db.Callback().Create().After("gorm:create").Register(callback, func(db *gorm.DB) {
						event, ok := db.Statement.Dest.(*audit.Event)
						if ok && event.Action == action && db.Error == nil {
							entered = true
							cancel()
						}
					}); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = s.db.Callback().Create().Remove(callback) })
				}
				result, _, err := backupDomainTransaction(fixture, ctx, true, "failed", "JOB_ATTEMPTS_EXHAUSTED")
				if err == nil || result != "" || (fault == "late_cancel" && !entered) {
					t.Fatal("failed domain transaction reported progress", result, err)
				}
				if !reflect.DeepEqual(before, backupDomainRows(t, s)) {
					t.Fatal("failed core left partial Job/domain/audit facts")
				}
			})
		}
		spoof := audit.WithActor(t.Context(), audit.Actor{ActorID: fixture.actor + 1, ReasonCode: "forged.domain", IPSummary: "forged"})
		result, stamp, err := backupDomainTransaction(fixture, spoof, true, "failed", "JOB_ATTEMPTS_EXHAUSTED")
		if err != nil || result != domainProjectionApplied || stamp.IsZero() {
			t.Fatal("real source did not apply after removing faults", result, err)
		}
		checkPreserved(stamp)
		after := backupDomainRows(t, s)
		for originalTable, values := range before {
			if originalTable != table && originalTable != "integrity_jobs" && originalTable != "integrity_audit_logs" && originalTable != "integrity_audit_chain_heads" && !reflect.DeepEqual(values, after[originalTable]) {
				t.Fatal("projection modified an unrelated domain table")
			}
		}
		result, _, err = backupDomainTransaction(fixture, spoof, false, "failed", "JOB_ATTEMPTS_EXHAUSTED")
		if err != nil || result != domainProjectionNone || !reflect.DeepEqual(after, backupDomainRows(t, s)) {
			t.Fatal("completed domain was not an exact no-op", result, err)
		}
		var events []audit.Event
		if err := s.db.Where("organization_id=? AND action=? AND object_id=?", fixture.tenant.orgID, action, strconv.FormatInt(fixture.lease.Job.ObjectID, 10)).Find(&events).Error; err != nil || len(events) != 1 || events[0].ActorID == nil || *events[0].ActorID != fixture.actor || strings.Contains(events[0].DiffSummary, "forged") || events[0].IPSummary != "" {
			t.Fatal("original creator failure audit missing/forged/duplicated", err)
		}
		if err := s.VerifyAllAudit(t.Context(), true); err != nil {
			t.Fatal("domain failure chain verification", err)
		}
	})
}

func backupDomainAuditSQLFault(t *testing.T, s *Store, cfg Config, action string) func() {
	t.Helper()
	statements := []string{"CREATE TRIGGER backup_domain_audit_fault AFTER INSERT ON integrity_audit_logs WHEN NEW.action='" + action + "' BEGIN SELECT RAISE(ABORT,'domain-fault'); END"}
	if cfg.Driver == "postgres" {
		statements = []string{"CREATE FUNCTION backup_domain_audit_fault_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'domain-fault'; END $$", "CREATE TRIGGER backup_domain_audit_fault AFTER INSERT ON integrity_audit_logs FOR EACH ROW WHEN (NEW.action='" + action + "') EXECUTE FUNCTION backup_domain_audit_fault_fn()"}
	}
	for _, statement := range statements {
		if err := s.db.Exec(statement).Error; err != nil {
			t.Fatal("install actual late domain audit fault", err)
		}
	}
	return func() {
		drop := "DROP TRIGGER backup_domain_audit_fault"
		if cfg.Driver == "postgres" {
			drop += " ON integrity_audit_logs"
		}
		if err := s.db.Exec(drop).Error; err != nil {
			t.Fatal("remove exact late audit fault", err)
		}
		if cfg.Driver == "postgres" {
			if err := s.db.Exec("DROP FUNCTION backup_domain_audit_fault_fn()").Error; err != nil {
				t.Fatal("remove exact late audit function", err)
			}
		}
	}
}

func TestBackupDomainPrecheckPriorityAndPreservedFields(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		fixture := newBackupDomainFixture(t, s, JobTargetPrecheck, 1)
		var before PrecheckRecord
		if err := s.db.First(&before, fixture.lease.Job.ObjectID).Error; err != nil {
			t.Fatal(err)
		}
		for _, item := range []struct {
			name, status, code, expected string
			requests                     int
		}{
			{"cancel-with-request", "cancelled", "JOB_ATTEMPTS_EXHAUSTED", "MI_PRECHECK_CANCELLED", 1},
			{"cancel-no-request", "cancelled", "JOB_LEASE_INVALID", "MI_PRECHECK_CANCELLED", 0},
			{"uncertain-before-exhaustion", "failed", "JOB_ATTEMPTS_EXHAUSTED", "MI_UNCERTAIN_ATTEMPT", 1},
			{"exhausted-no-request", "failed", "JOB_ATTEMPTS_EXHAUSTED", "MI_PRECHECK_ATTEMPTS_EXHAUSTED", 0},
			{"unavailable-no-request", "failed", "JOB_LEASE_INVALID", "MI_SERVICE_UNAVAILABLE", 0},
		} {
			t.Run(item.name, func(t *testing.T) {
				rollback := errors.New("fixed-test-rollback")
				err := s.db.WithContext(t.Context()).Transaction(func(db *gorm.DB) error {
					// Original request-count variants are explicit fault fixtures;
					// the positive one-request case came through actual Reserve.
					if err := db.Model(&PrecheckRecord{}).Where("id=?", before.ID).UpdateColumn("request_count", item.requests).Error; err != nil {
						return err
					}
					now, err := queueTime(db, s.driver)
					if err != nil {
						return err
					}
					changed := db.Model(&Job{}).Where("organization_id=? AND id=? AND status='running'", fixture.lease.Job.OrganizationID, fixture.lease.Job.ID).
						Updates(map[string]any{"status": item.status, "last_error_code": item.code, "lease_owner": nil, "lease_until": nil, "completed_at": now, "updated_at": now})
					if changed.Error != nil {
						return changed.Error
					}
					if changed.RowsAffected != 1 {
						return ErrJobLeaseLost
					}
					got, err := s.reconcilePrecheckDomain(db, fixture.lease.Job, item.status, item.code, now)
					if err != nil || got != domainProjectionApplied {
						t.Fatal("original terminal decision was rejected", got, err)
					}
					var after PrecheckRecord
					if err := db.First(&after, before.ID).Error; err != nil || after.Status != "failed" || after.ErrorCode != item.expected || after.ResultJSON != "[]" || after.Version != before.Version+1 || after.FinishedAt == nil || !after.FinishedAt.Equal(now) || after.RequestCount != item.requests {
						t.Fatal("wrong precheck priority/time/request count", err)
					}
					after.Status, after.ErrorCode, after.ResultJSON, after.Version, after.FinishedAt, after.RequestCount = before.Status, before.ErrorCode, before.ResultJSON, before.Version, before.FinishedAt, before.RequestCount
					if !reflect.DeepEqual(before, after) {
						t.Fatal("projection rewrote unrelated precheck fields")
					}
					return rollback
				})
				if !errors.Is(err, rollback) {
					t.Fatal("priority test transaction failed", err)
				}
			})
		}
	})
}
