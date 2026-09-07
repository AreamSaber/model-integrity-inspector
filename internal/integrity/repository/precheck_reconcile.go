package repository

import (
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

// Reconciliation is a queue recovery action, not a successful upstream call.
// This runs only after the existing queue predicate permits terminal recovery,
// in the exact transaction that marks the job cancelled/failed.
func (q *JobQueue) reconcilePrecheck(tx *gorm.DB, job Job, status, errorCode string, now time.Time) error {
	if JobType(job.Type) != JobTargetPrecheck {
		return nil
	}
	var record PrecheckRecord
	found := tx.Where("organization_id = ? AND id = ? AND job_id = ? AND status IN ('queued', 'running')", job.OrganizationID, job.ObjectID, job.ID).Find(&record)
	if found.Error != nil {
		return found.Error
	}
	if found.RowsAffected == 0 {
		return nil
	}
	code := "MI_SERVICE_UNAVAILABLE"
	if status == "cancelled" {
		code = "MI_PRECHECK_CANCELLED"
	} else if record.RequestCount > 0 {
		code = "MI_UNCERTAIN_ATTEMPT"
	} else if errorCode == "JOB_ATTEMPTS_EXHAUSTED" {
		code = "MI_PRECHECK_ATTEMPTS_EXHAUSTED"
	}
	changed := tx.Model(&PrecheckRecord{}).Where("organization_id = ? AND id = ? AND version = ?", job.OrganizationID, record.ID, record.Version).
		Updates(map[string]any{"status": "failed", "error_code": code, "result_json": "[]", "finished_at": now, "version": record.Version + 1})
	if changed.Error != nil {
		return changed.Error
	}
	if changed.RowsAffected != 1 {
		return ErrConflict
	}
	ctx := audit.WithActor(tx.Statement.Context, audit.Actor{ActorID: record.CreatedBy, ReasonCode: "target.precheck.reconcile"})
	return q.store.appendAudit(ctx, tx, job.OrganizationID, auditObject("target.precheck.reconcile", "target_precheck", record.ID), nil)
}
