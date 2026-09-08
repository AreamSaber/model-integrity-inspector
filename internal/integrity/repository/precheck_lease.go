package repository

import (
	"context"

	"gorm.io/gorm"
)

// CheckLease is an advisory read-only liveness/cancellation check between
// heartbeats. It deliberately does not open a transaction: SQLite transactions
// use BEGIN IMMEDIATE, which would turn every poll into a competing writer.
// Each statement may see a newer committed state. This never grants dispatch or
// commit authority: WithLease/CompleteWith revalidate all fences transactionally.
func (q *JobQueue) CheckLease(ctx context.Context, lease JobLease) error {
	if q == nil || q.store == nil {
		return ErrJobInvalid
	}
	db := q.store.db.WithContext(ctx)
	return precheckError(func(tx *gorm.DB) error {
		now, err := queueTime(tx, q.store.driver)
		if err != nil {
			return err
		}
		if err := q.guardConsumer(tx, now, false); err != nil {
			return err
		}
		var job Job
		found := q.fenced(tx, lease, now).Find(&job)
		if found.Error != nil {
			return found.Error
		}
		if found.RowsAffected != 1 {
			return ErrJobLeaseLost
		}
		if job.CancelRequestedAt != nil {
			return ErrJobCancelled
		}
		var active int64
		if err := tx.Table("organizations").Where("id = ? AND status = 'active'", lease.Job.OrganizationID).Count(&active).Error; err != nil {
			return err
		}
		if active != 1 {
			return ErrJobCancelled
		}
		if JobType(job.Type) == JobTargetPrecheck {
			var record PrecheckRecord
			if err := tx.Where("organization_id = ? AND id = ?", job.OrganizationID, job.ObjectID).First(&record).Error; err != nil {
				return err
			}
			capability := &TenantTransaction{store: q.store, db: tx, ctx: ctx, orgID: job.OrganizationID}
			if err := capability.precheckTargetCurrent(record); err != nil {
				return err
			}
		}
		return nil
	}(db))
}

// WithLease permits short, typed pre-call bookkeeping under the exact same
// owner/generation/expiry predicate as CompleteWith. It does not complete a job.
func (q *JobQueue) WithLease(ctx context.Context, lease JobLease, fn func(*TenantTransaction) error) error {
	if fn == nil {
		return ErrConfiguration
	}
	return precheckError(q.store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := q.store.maintenanceAdmission(tx, maintenanceSettlement); err != nil {
			return err
		}
		now, err := queueTime(tx, q.store.driver)
		if err != nil {
			return err
		}
		if err := q.guardConsumer(tx, now, false); err != nil {
			return err
		}
		locked := q.fenced(tx, lease, now).Where("cancel_requested_at IS NULL").Update("updated_at", now)
		if locked.Error != nil {
			return locked.Error
		}
		if locked.RowsAffected != 1 {
			return ErrJobLeaseLost
		}
		var active int64
		if err := tx.Table("organizations").Where("id = ? AND status = 'active'", lease.Job.OrganizationID).Count(&active).Error; err != nil {
			return err
		}
		if active != 1 {
			return ErrJobCancelled
		}
		actorCtx, err := q.leasedAuditContext(ctx, tx, lease)
		if err != nil {
			return err
		}
		capability := &TenantTransaction{store: q.store, db: tx, ctx: actorCtx, orgID: lease.Job.OrganizationID, leaseJobID: lease.Job.ID, leaseGeneration: lease.Generation, enqueueAdmitted: true}
		defer capability.closed.Store(true)
		if err := fn(capability); err != nil {
			return err
		}
		now, err = queueTime(tx, q.store.driver)
		if err != nil {
			return err
		}
		checked := q.fenced(tx, lease, now).Where("cancel_requested_at IS NULL").Update("updated_at", now)
		if checked.Error != nil {
			return checked.Error
		}
		if checked.RowsAffected != 1 {
			return ErrJobLeaseLost
		}
		return nil
	}))
}
