package repository

import (
	"context"
	"strconv"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ReconcileReports projects failed/exhausted Jobs to truthful report failure.
// It neither deletes orphaned files nor changes any Run/Result/evidence rows.
func (q *JobQueue) ReconcileReports(ctx context.Context) error {
	if q == nil || q.store == nil {
		return ErrJobInvalid
	}
	return reportError(q.store.db.WithContext(ctx).Transaction(func(db *gorm.DB) error {
		now, err := queueTime(db, q.store.driver)
		if err != nil {
			return err
		}
		if err := q.guardConsumer(db, now, false); err != nil {
			return err
		}
		var jobs []Job
		columns := "id,organization_id,object_id," + readBoundedText(db, "type", "type", 64) + "," + readBoundedText(db, "idempotency_key", "idempotency_key", 128)
		if err := db.Select(columns).Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).Where("type=? AND status IN ('failed','cancelled')", string(JobReportGenerate)).Where("EXISTS (SELECT 1 FROM integrity_reports r WHERE r.organization_id=integrity_jobs.organization_id AND r.id=integrity_jobs.object_id AND r.job_id=integrity_jobs.id AND r.status IN ('queued','generating'))").Order("organization_id,id").Limit(50).Find(&jobs).Error; err != nil {
			return err
		}
		for _, job := range jobs {
			if job.IdempotencyKey != "report:"+strconv.FormatInt(job.ObjectID, 10) {
				continue
			}
			actorCtx, err := workerAuditContext(ctx, db, job)
			if err != nil {
				return err
			}
			result := db.Model(&ReportRecord{}).Where("organization_id=? AND id=? AND job_id=? AND status IN ('queued','generating')", job.OrganizationID, job.ObjectID, job.ID).Updates(map[string]any{"status": "failed", "error_code": "MI_REPORT_GENERATION_FAILED", "completed_at": now})
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return ErrReportInvalid
			}
			if err := q.store.appendAudit(actorCtx, db, job.OrganizationID, auditObject("report.fail", "report", job.ObjectID), nil); err != nil {
				return err
			}
		}
		return nil
	}))
}
