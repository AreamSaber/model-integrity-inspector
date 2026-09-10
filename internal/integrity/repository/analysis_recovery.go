package repository

import (
	"context"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ReconcileAnalyses records exhausted/cancelled analysis jobs without inventing
// a score or altering execution evidence. Live or reclaimable leases are not
// terminal. The existing consumer capability is required, including on SQLite.
func (q *JobQueue) ReconcileAnalyses(ctx context.Context) error {
	if q == nil || q.store == nil {
		return ErrJobInvalid
	}
	return executionError(q.store.db.WithContext(ctx).Transaction(func(db *gorm.DB) error {
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
		if err := db.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).Where("type = ? AND status IN ('failed','cancelled')", string(JobRunAnalyze)).Where("EXISTS (SELECT 1 FROM integrity_runs r WHERE r.organization_id = integrity_jobs.organization_id AND r.id = integrity_jobs.object_id AND r.status = 'ANALYZING' AND r.execution_closed_at IS NOT NULL)").Order("organization_id,id").Limit(50).Find(&jobs).Error; err != nil {
			return err
		}
		for _, job := range jobs {
			if _, err := q.store.reconcileAnalysisDomain(db, job, now); err != nil {
				return err
			}
		}
		return nil
	}))
}
