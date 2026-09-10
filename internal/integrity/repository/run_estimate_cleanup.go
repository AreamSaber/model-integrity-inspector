package repository

import (
	"context"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

// ExpireRunEstimates is bounded maintenance on the existing consumer. Expired
// preparation snapshots are disposable; confirmed Runs retain their immutable
// plan and owner/hash-bound request identity independently of these rows.
func (q *JobQueue) ExpireRunEstimates(ctx context.Context) error {
	if q == nil || q.store == nil || q.closed.Load() {
		return ErrJobLeaseLost
	}
	return queueError(q.store.db.WithContext(ctx).Transaction(func(db *gorm.DB) error {
		allowed, err := q.store.maintenanceAdmission(db, maintenanceScheduled)
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
		return q.store.pruneRunEstimates(ctx, db, 0, 0)
	}))
}

func (s *Store) pruneRunEstimates(ctx context.Context, db *gorm.DB, org, creator int64) error {
	now, err := queueTime(db, s.driver)
	if err != nil {
		return err
	}
	query := db.Select("id", "organization_id", "created_by").Where("expires_at <= ?", now).Order("organization_id, id").Limit(100)
	if org > 0 {
		query = query.Where("organization_id = ? AND created_by = ?", org, creator)
	}
	if s.driver == "postgres" {
		query = query.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"})
	}
	var expired []RunEstimateRecord
	if err := query.Find(&expired).Error; err != nil {
		return err
	}
	for _, draft := range expired {
		result := db.Where("organization_id = ? AND id = ? AND expires_at <= ?", draft.OrganizationID, draft.ID, now).Delete(&RunEstimateRecord{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrConflict
		}
		// This denotes automatic expiry of storage requested by this creator,
		// not a human approval or an interactive deletion action.
		actorCtx := audit.WithActor(ctx, audit.Actor{ActorID: draft.CreatedBy, ReasonCode: "run.estimate.expiry"})
		if err := s.appendAudit(actorCtx, db, draft.OrganizationID, auditObject("run.estimate.expire", "run_estimate", draft.ID), nil); err != nil {
			return err
		}
	}
	return nil
}
