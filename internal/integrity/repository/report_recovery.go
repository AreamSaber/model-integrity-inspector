package repository

import (
	"context"

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
		allowed, err := q.store.maintenanceAdmission(db, maintenanceRecovery)
		if err != nil || !allowed {
			return err
		}
		now, err := queueTime(db, q.store.driver)
		if err != nil {
			return err
		}
		if err := q.guardConsumer(db, now, false); err != nil {
			return err
		}
		var jobs []Job
		columns := "id,organization_id,object_id,status," + readBoundedText(db, "type", "type", 64) + "," + readBoundedText(db, "idempotency_key", "idempotency_key", 128)
		if err := db.Select(columns).Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).Where("type=? AND status IN ('failed','cancelled')", string(JobReportGenerate)).Where("EXISTS (SELECT 1 FROM integrity_reports r WHERE r.organization_id=integrity_jobs.organization_id AND r.id=integrity_jobs.object_id AND r.job_id=integrity_jobs.id AND r.status IN ('queued','generating'))").Order("organization_id,id").Limit(50).Find(&jobs).Error; err != nil {
			return err
		}
		for _, job := range jobs {
			if _, err := q.store.reconcileReportDomain(db, job, now); err != nil {
				return err
			}
		}
		return nil
	}))
}
