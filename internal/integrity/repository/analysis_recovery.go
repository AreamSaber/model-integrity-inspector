package repository

import (
	"context"
	"strconv"

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
			if job.IdempotencyKey != "analyze:"+strconv.FormatInt(job.ObjectID, 10)+":1" {
				continue
			}
			var run RunRecord
			// A broken frozen JSON may be the reason analysis failed. Do not parse
			// it merely to persist a truthful failure and make it visible to users.
			if err := db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("organization_id = ? AND id = ?", job.OrganizationID, job.ObjectID).First(&run).Error; err != nil {
				return err
			}
			if run.Status != "ANALYZING" || run.ExecutionClosedAt == nil {
				continue
			}
			var published int64
			if err := db.Model(&RunResultRecord{}).Where("organization_id = ? AND run_id = ? AND is_published = ?", job.OrganizationID, run.ID, true).Count(&published).Error; err != nil {
				return err
			}
			if published != 0 {
				return ErrAnalysisSource
			}
			actorCtx, err := workerAuditContext(ctx, db, job)
			if err != nil {
				return err
			}
			if err := db.Model(&RunRecord{}).Where("organization_id = ? AND id = ?", job.OrganizationID, run.ID).Updates(map[string]any{"status": "FAILED", "finished_at": now, "version": run.Version + 1, "error_summary": "MI_ANALYSIS_FAILED"}).Error; err != nil {
				return err
			}
			if err := q.store.appendAudit(actorCtx, db, job.OrganizationID, auditObject("run.analysis.fail", "run", run.ID), nil); err != nil {
				return err
			}
		}
		return nil
	}))
}
