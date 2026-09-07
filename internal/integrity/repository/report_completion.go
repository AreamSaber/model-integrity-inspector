package repository

import (
	"context"
	"strconv"

	"gorm.io/gorm"
)

// FailReportGeneration records a rejected final authorization after the
// publication transaction has rolled back. Failure needs the exact live Job
// fence and persisted initiator, not a current export grant: requiring that
// revoked grant here would make truthful failure impossible. This capability
// can only fail a report; it cannot publish, return a path or disclose a file.
// Report + Job + audit commit atomically, without changing machine results.
func (q *JobQueue) FailReportGeneration(ctx context.Context, lease JobLease) error {
	if q == nil || q.store == nil || ctx == nil || JobType(lease.Job.Type) != JobReportGenerate {
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
		locked := q.fenced(db, lease, now).Update("updated_at", now)
		if locked.Error != nil {
			return locked.Error
		}
		if locked.RowsAffected != 1 {
			return ErrJobLeaseLost
		}
		var job Job
		if err := db.Where("organization_id=? AND id=?", lease.Job.OrganizationID, lease.Job.ID).Take(&job).Error; err != nil {
			return err
		}
		if job.Type != string(JobReportGenerate) || job.ObjectID != lease.Job.ObjectID || job.IdempotencyKey != "report:"+strconv.FormatInt(job.ObjectID, 10) {
			return ErrJobInvalid
		}
		row, err := reportRow(db, job.OrganizationID, job.ObjectID)
		if err != nil {
			return err
		}
		if *row.JobID != job.ID || row.Status != "generating" {
			return ErrReportInvalid
		}
		actorCtx, err := workerAuditContext(ctx, db, job)
		if err != nil {
			return err
		}
		changed := db.Model(&ReportRecord{}).Where("organization_id=? AND id=? AND job_id=? AND status='generating'", job.OrganizationID, row.ID, job.ID).Updates(map[string]any{"status": "failed", "error_code": "MI_REPORT_GENERATION_FAILED", "completed_at": now})
		if changed.Error != nil {
			return changed.Error
		}
		if changed.RowsAffected != 1 {
			return ErrReportInvalid
		}
		if err := q.store.appendAudit(actorCtx, db, job.OrganizationID, auditObject("report.fail", "report", row.ID), nil); err != nil {
			return err
		}
		now, err = queueTime(db, q.store.driver)
		if err != nil {
			return err
		}
		if err := q.guardConsumer(db, now, false); err != nil {
			return err
		}
		finished := q.fenced(db, lease, now).Updates(map[string]any{"status": "failed", "last_error_code": "WORKER_REPORT_PERMISSION_DENIED", "lease_owner": nil, "lease_until": nil, "completed_at": now, "updated_at": now})
		if finished.Error != nil {
			return finished.Error
		}
		if finished.RowsAffected != 1 {
			return ErrJobLeaseLost
		}
		return nil
	}))
}
