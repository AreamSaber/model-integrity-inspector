package repository

import (
	"strconv"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

type domainProjectionResult string

const (
	domainProjectionApplied domainProjectionResult = "applied"
	domainProjectionNone    domainProjectionResult = "no_projection"
)

// These PRIVATE cores share only the existing transaction-local domain work.
// The caller owns the transaction, admission/authority, original Job lock and
// fence, database clock, audit-head ordering and final authority check. A future
// maintenance caller must terminalize the original Job in THIS transaction;
// committing it first and deferring projection to a Worker is not sufficient.
// They do not grant authorization, open/commit a transaction, claim/renew work,
// read frozen bodies, or generate files/analysis/HTTP requests. Applied is not
// permission to commit without the caller's remaining checks.
func (s *Store) reconcileAnalysisDomain(db *gorm.DB, job Job, now time.Time) (domainProjectionResult, error) {
	if !validDomainProjectionCall(s, db, job, now) || JobType(job.Type) != JobRunAnalyze || (job.Status != "failed" && job.Status != "cancelled") {
		return "", ErrJobInvalid
	}
	if job.IdempotencyKey != "analyze:"+strconv.FormatInt(job.ObjectID, 10)+":1" {
		return domainProjectionNone, nil
	}
	var run struct {
		ID, Version int64
		Eligible    bool
	}
	// The original frozen JSON may itself be broken. Select only fixed numeric
	// metadata and an SQL boolean, not its body or a newly constrained old label.
	if err := db.Model(&RunRecord{}).Select("id,version,(status='ANALYZING' AND execution_closed_at IS NOT NULL) AS eligible").
		Clauses(clause.Locking{Strength: "UPDATE"}).Where("organization_id=? AND id=?", job.OrganizationID, job.ObjectID).First(&run).Error; err != nil {
		return "", err
	}
	if !run.Eligible {
		return domainProjectionNone, nil
	}
	var published int64
	if err := db.Model(&RunResultRecord{}).Where("organization_id=? AND run_id=? AND is_published=?", job.OrganizationID, run.ID, true).Count(&published).Error; err != nil {
		return "", err
	}
	if published != 0 {
		return "", ErrAnalysisSource
	}
	ctx, err := workerAuditContext(db.Statement.Context, db, job)
	if err != nil {
		return "", err
	}
	changed := db.Model(&RunRecord{}).Where("organization_id=? AND id=? AND version=? AND status='ANALYZING' AND execution_closed_at IS NOT NULL", job.OrganizationID, run.ID, run.Version).
		Updates(map[string]any{"status": "FAILED", "finished_at": now, "version": run.Version + 1, "error_summary": "MI_ANALYSIS_FAILED"})
	if changed.Error != nil {
		return "", changed.Error
	}
	if changed.RowsAffected != 1 {
		return "", ErrAnalysisSource
	}
	if err := s.appendAudit(ctx, db, job.OrganizationID, auditObject("run.analysis.fail", "run", run.ID), nil); err != nil {
		return "", err
	}
	return domainProjectionApplied, nil
}

func (s *Store) reconcileReportDomain(db *gorm.DB, job Job, now time.Time) (domainProjectionResult, error) {
	if !validDomainProjectionCall(s, db, job, now) || JobType(job.Type) != JobReportGenerate || (job.Status != "failed" && job.Status != "cancelled") {
		return "", ErrJobInvalid
	}
	if job.IdempotencyKey != "report:"+strconv.FormatInt(job.ObjectID, 10) {
		return domainProjectionNone, nil
	}
	var report struct{ ID int64 }
	query := db.Model(&ReportRecord{}).Select("id").Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("organization_id=? AND id=? AND job_id=? AND status IN ('queued','generating')", job.OrganizationID, job.ObjectID, job.ID)
	found := query.Find(&report)
	if found.Error != nil {
		return "", found.Error
	}
	if found.RowsAffected == 0 {
		return domainProjectionNone, nil
	}
	if found.RowsAffected != 1 {
		return "", ErrReportInvalid
	}
	ctx, err := workerAuditContext(db.Statement.Context, db, job)
	if err != nil {
		return "", err
	}
	changed := db.Model(&ReportRecord{}).Where("organization_id=? AND id=? AND job_id=? AND status IN ('queued','generating')", job.OrganizationID, job.ObjectID, job.ID).
		Updates(map[string]any{"status": "failed", "error_code": "MI_REPORT_GENERATION_FAILED", "completed_at": now})
	if changed.Error != nil {
		return "", changed.Error
	}
	if changed.RowsAffected != 1 {
		return "", ErrReportInvalid
	}
	if err := s.appendAudit(ctx, db, job.OrganizationID, auditObject("report.fail", "report", job.ObjectID), nil); err != nil {
		return "", err
	}
	return domainProjectionApplied, nil
}

// terminalStatus is the caller's original queue decision, not job.Status: the
// ordinary queue passes its pre-update in-memory Job after the SQL transition.
func (s *Store) reconcilePrecheckDomain(db *gorm.DB, job Job, terminalStatus, jobError string, now time.Time) (domainProjectionResult, error) {
	if JobType(job.Type) != JobTargetPrecheck {
		return domainProjectionNone, nil
	}
	if !validDomainProjectionCall(s, db, job, now) || (terminalStatus != "failed" && terminalStatus != "cancelled") {
		return "", ErrJobInvalid
	}
	var record PrecheckRecord
	found := db.Select("id,version,request_count,created_by").Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("organization_id=? AND id=? AND job_id=? AND status IN ('queued','running')", job.OrganizationID, job.ObjectID, job.ID).Find(&record)
	if found.Error != nil {
		return "", found.Error
	}
	if found.RowsAffected == 0 {
		return domainProjectionNone, nil
	}
	if found.RowsAffected != 1 {
		return "", ErrConflict
	}
	code := "MI_SERVICE_UNAVAILABLE"
	if terminalStatus == "cancelled" {
		code = "MI_PRECHECK_CANCELLED"
	} else if record.RequestCount > 0 {
		code = "MI_UNCERTAIN_ATTEMPT"
	} else if jobError == "JOB_ATTEMPTS_EXHAUSTED" {
		code = "MI_PRECHECK_ATTEMPTS_EXHAUSTED"
	}
	changed := db.Model(&PrecheckRecord{}).Where("organization_id=? AND id=? AND job_id=? AND version=? AND status IN ('queued','running')", job.OrganizationID, record.ID, job.ID, record.Version).
		Updates(map[string]any{"status": "failed", "error_code": code, "result_json": "[]", "finished_at": now, "version": record.Version + 1})
	if changed.Error != nil {
		return "", changed.Error
	}
	if changed.RowsAffected != 1 {
		return "", ErrConflict
	}
	ctx := audit.WithActor(db.Statement.Context, audit.Actor{ActorID: record.CreatedBy, ReasonCode: "target.precheck.reconcile"})
	if err := s.appendAudit(ctx, db, job.OrganizationID, auditObject("target.precheck.reconcile", "target_precheck", record.ID), nil); err != nil {
		return "", err
	}
	return domainProjectionApplied, nil
}

func validDomainProjectionCall(s *Store, db *gorm.DB, job Job, now time.Time) bool {
	return s != nil && db != nil && db.Statement != nil && db.Statement.Context != nil && job.ID > 0 && job.OrganizationID > 0 && job.ObjectID > 0 && !now.IsZero()
}
