package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"regexp"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
)

const (
	JobLeaseDuration    = 60 * time.Second
	JobHeartbeatEvery   = 15 * time.Second
	queueConsumerName   = "sqlite-primary"
	claimPoisonBatchMax = 20
)

// JobQueue is one process's consumer capability. PostgreSQL supports many queues;
// SQLite grants only one active consumer capability across all processes.
type JobQueue struct {
	store  *Store
	owner  string
	closed atomic.Bool
}

// JobLease must be retained unchanged by the handler. Generation fences every
// renewal/completion/retry against a later recovery of the same persistent Job.
type JobLease struct {
	Job        Job
	Generation int
	ExpiresAt  time.Time
}

func (s *Store) OpenJobQueue(ctx context.Context) (*JobQueue, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, ErrUnavailable
	}
	queue := &JobQueue{store: s, owner: "worker-" + hex.EncodeToString(nonce[:])}
	if err := s.CheckSchema(ctx); err != nil {
		return nil, err
	}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := s.maintenanceAdmission(tx, maintenanceSettlement); err != nil {
			return err
		}
		if s.driver != "sqlite" {
			return nil
		}
		now, err := queueTime(tx, s.driver)
		if err != nil {
			return err
		}
		result := tx.Exec(`INSERT INTO integrity_queue_consumer_leases (lock_name, owner, lease_until)
 VALUES (?, ?, ?) ON CONFLICT (lock_name) DO UPDATE SET owner = excluded.owner, lease_until = excluded.lease_until
 WHERE integrity_queue_consumer_leases.lease_until <= ?`, queueConsumerName, queue.owner, now.Add(JobLeaseDuration), now)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrConsumerActive
		}
		return nil
	})
	if err != nil {
		return nil, queueError(err)
	}
	return queue, nil
}

// HeartbeatConsumer keeps an otherwise idle SQLite claimant exclusive. The
// Worker must call this every 15 seconds, including while handlers are running.
func (q *JobQueue) HeartbeatConsumer(ctx context.Context) error {
	if q.closed.Load() {
		return ErrConsumerLost
	}
	return queueError(q.store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := q.store.maintenanceAdmission(tx, maintenanceSettlement); err != nil {
			return err
		}
		now, err := queueTime(tx, q.store.driver)
		if err != nil {
			return err
		}
		return q.guardConsumer(tx, now, true)
	}))
}

func (q *JobQueue) guardConsumer(tx *gorm.DB, now time.Time, renew bool) error {
	if q.closed.Load() {
		return ErrConsumerLost
	}
	if q.store.driver != "sqlite" {
		return nil
	}
	if renew {
		result := tx.Table("integrity_queue_consumer_leases").Where("lock_name = ? AND owner = ? AND lease_until > ?", queueConsumerName, q.owner, now).Update("lease_until", now.Add(JobLeaseDuration))
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrConsumerLost
		}
		return nil
	}
	var count int64
	if err := tx.Table("integrity_queue_consumer_leases").Where("lock_name = ? AND owner = ? AND lease_until > ?", queueConsumerName, q.owner, now).Count(&count).Error; err != nil {
		return err
	}
	if count != 1 {
		return ErrConsumerLost
	}
	return nil
}

// Close releases only this consumer guard. It never claims running jobs finished;
// outstanding job leases must complete or expire normally for crash recovery.
func (q *JobQueue) Close(ctx context.Context) error {
	if q.closed.Swap(true) {
		return nil
	}
	if q.store.driver != "sqlite" {
		return nil
	}
	return queueError(q.store.db.WithContext(ctx).Exec("DELETE FROM integrity_queue_consumer_leases WHERE lock_name = ? AND owner = ?", queueConsumerName, q.owner).Error)
}

// Claim returns nil,nil when no eligible job exists. It revalidates the typed
// object's organization before exposing it to any handler. Poison jobs become
// failed and are skipped in bounded batches, rather than leaking into consumers.
func (q *JobQueue) Claim(ctx context.Context) (*JobLease, error) {
	if q.closed.Load() {
		return nil, ErrConsumerLost
	}
	var lease *JobLease
	err := q.store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		allowed, err := q.store.maintenanceAdmission(tx, maintenanceScheduled)
		if err != nil || !allowed {
			return err
		}
		now, err := queueTime(tx, q.store.driver)
		if err != nil {
			return err
		}
		if err := q.guardConsumer(tx, now, true); err != nil {
			return err
		}
		if err := q.reconcile(tx, now); err != nil {
			return err
		}
		for range claimPoisonBatchMax {
			var job Job
			query := `SELECT j.* FROM integrity_jobs j
 JOIN integrity_queue_fairness f ON f.organization_id = j.organization_id
 JOIN organizations o ON o.id = j.organization_id
 WHERE (o.status = 'active' OR (` + retentionDisabledJobSQL + `)) AND j.cancel_requested_at IS NULL AND j.attempt_count < j.max_attempts
 AND ((j.status = 'pending' AND j.available_at <= ?) OR (j.status = 'running' AND j.lease_until <= ?))
 ORDER BY f.last_claimed_at ASC, j.priority DESC, j.available_at ASC, j.id ASC LIMIT 1`
			if q.store.driver == "postgres" {
				query += " FOR UPDATE OF j, f SKIP LOCKED"
			}
			result := tx.Raw(query, now, now).Scan(&job)
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected == 0 {
				return nil
			}
			if err := validateJobObject(tx, job.OrganizationID, JobType(job.Type), job.ObjectID); err != nil {
				if !errors.Is(err, ErrJobInvalid) {
					return err
				}
				if err := tx.Model(&Job{}).Where("organization_id = ? AND id = ?", job.OrganizationID, job.ID).
					Updates(map[string]any{"status": "failed", "last_error_code": "JOB_PAYLOAD_INVALID", "lease_owner": nil, "lease_until": nil, "completed_at": now, "updated_at": now}).Error; err != nil {
					return err
				}
				continue
			}
			until := now.Add(JobLeaseDuration)
			result = tx.Model(&Job{}).Where("organization_id = ? AND id = ? AND attempt_count = ?", job.OrganizationID, job.ID, job.AttemptCount).
				Where("(status = 'pending' AND available_at <= ?) OR (status = 'running' AND lease_until <= ?)", now, now).
				Updates(map[string]any{"status": "running", "lease_owner": q.owner, "lease_until": until, "attempt_count": job.AttemptCount + 1, "updated_at": now})
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return ErrJobLeaseLost
			}
			if err := tx.Table("integrity_queue_fairness").Where("organization_id = ?", job.OrganizationID).Update("last_claimed_at", now).Error; err != nil {
				return err
			}
			owner := q.owner // Do not expose a pointer to the consumer's private owner.
			job.Status, job.LeaseOwner, job.LeaseUntil = "running", &owner, &until
			job.AttemptCount++
			job.UpdatedAt = now
			lease = &JobLease{Job: job, Generation: job.AttemptCount, ExpiresAt: until}
			return nil
		}
		return nil
	})
	if err != nil {
		return nil, queueError(err)
	}
	return lease, nil
}

func (q *JobQueue) reconcile(tx *gorm.DB, now time.Time) error {
	// Bound maintenance work and skip other transactions' locked jobs. Active
	// leases are never reclaimed; cancelled running work must first yield/expire.
	var jobs []Job
	query := `SELECT j.* FROM integrity_jobs j JOIN organizations o ON o.id = j.organization_id
 WHERE (j.status = 'pending' OR (j.status = 'running' AND (j.lease_until <= ? OR j.lease_until IS NULL)))
 AND (j.cancel_requested_at IS NOT NULL OR j.attempt_count >= j.max_attempts OR (o.status != 'active' AND NOT (` + retentionDisabledJobSQL + `)) OR (j.status = 'running' AND j.lease_until IS NULL))
 ORDER BY j.id LIMIT 100`
	if q.store.driver == "postgres" {
		query += " FOR UPDATE OF j SKIP LOCKED"
	}
	if err := tx.Raw(query, now).Scan(&jobs).Error; err != nil {
		return err
	}
	for _, job := range jobs {
		status, errorCode := "failed", "JOB_ATTEMPTS_EXHAUSTED"
		if job.CancelRequestedAt != nil {
			status, errorCode = "cancelled", "JOB_CANCELLED"
		} else if job.Status == "running" && job.LeaseUntil == nil {
			errorCode = "JOB_LEASE_INVALID"
		} else if job.AttemptCount < job.MaxAttempts {
			status, errorCode = "cancelled", "JOB_ORGANIZATION_INACTIVE"
		}
		if err := tx.Model(&Job{}).Where("organization_id = ? AND id = ?", job.OrganizationID, job.ID).
			Updates(map[string]any{"status": status, "last_error_code": errorCode, "lease_owner": nil, "lease_until": nil, "completed_at": now, "updated_at": now}).Error; err != nil {
			return err
		}
		if err := q.reconcilePrecheck(tx, job, status, errorCode, now); err != nil {
			return err
		}
	}
	return nil
}

func (q *JobQueue) Renew(ctx context.Context, lease JobLease) (JobLease, error) {
	var renewed JobLease
	err := q.store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := q.store.maintenanceAdmission(tx, maintenanceSettlement); err != nil {
			return err
		}
		now, err := queueTime(tx, q.store.driver)
		if err != nil {
			return err
		}
		if err := q.guardConsumer(tx, now, true); err != nil {
			return err
		}
		until := now.Add(JobLeaseDuration)
		result := q.fenced(tx, lease, now).Updates(map[string]any{"lease_until": until, "updated_at": now})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrJobLeaseLost
		}
		renewed = lease
		renewed.ExpiresAt, renewed.Job.LeaseUntil = until, &until
		return nil
	})
	return renewed, queueError(err)
}

func (q *JobQueue) fenced(tx *gorm.DB, lease JobLease, now time.Time) *gorm.DB {
	return tx.Model(&Job{}).Where("organization_id = ? AND id = ? AND status = 'running' AND lease_owner = ? AND attempt_count = ? AND lease_until > ?", lease.Job.OrganizationID, lease.Job.ID, q.owner, lease.Generation, now)
}

func (q *JobQueue) Complete(ctx context.Context, lease JobLease) error {
	return q.CompleteWith(ctx, lease, nil)
}

// CompleteWith lets a handler persist typed business state/dependent jobs in the
// same transaction as fenced completion. The callback must perform short DB-only
// operations, never network calls. Expiry is checked again after the callback.
func (q *JobQueue) CompleteWith(ctx context.Context, lease JobLease, fn func(*TenantTransaction) error) error {
	err := q.store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
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
		// Conditional no-op UPDATE locks the matching row before business writes.
		locked := q.fenced(tx, lease, now).Update("updated_at", now)
		if locked.Error != nil {
			return locked.Error
		}
		if locked.RowsAffected != 1 {
			return ErrJobLeaseLost
		}
		actorCtx, err := q.leasedAuditContext(ctx, tx, lease)
		if err != nil {
			return err
		}
		capability := &TenantTransaction{store: q.store, db: tx, ctx: actorCtx, orgID: lease.Job.OrganizationID, leaseJobID: lease.Job.ID, leaseGeneration: lease.Generation, completing: true, enqueueAdmitted: true}
		defer capability.closed.Store(true)
		if fn != nil {
			if err := fn(capability); err != nil {
				return err
			}
		}
		now, err = queueTime(tx, q.store.driver)
		if err != nil {
			return err
		}
		result := q.fenced(tx, lease, now).Updates(map[string]any{"status": "completed", "lease_owner": nil, "lease_until": nil, "completed_at": now, "updated_at": now})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrJobLeaseLost
		}
		return nil
	})
	// A final, typed authorization rejection is not a storage outage. Preserve
	// only this fixed sentinel so the trusted Worker can terminally fail its
	// report Job; unknown/SQL/audit/fencing errors keep their existing handling.
	if errors.Is(err, ErrManagementPermission) {
		return ErrManagementPermission
	}
	return queueError(err)
}

var jobErrorCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

func (q *JobQueue) Retry(ctx context.Context, lease JobLease, errorCode string, delay time.Duration) error {
	if delay < 0 || delay > 24*time.Hour {
		return ErrConfiguration
	}
	return q.finishFailed(ctx, lease, errorCode, delay, false)
}

func (q *JobQueue) Fail(ctx context.Context, lease JobLease, errorCode string) error {
	return q.finishFailed(ctx, lease, errorCode, 0, true)
}

func (q *JobQueue) finishFailed(ctx context.Context, lease JobLease, errorCode string, delay time.Duration, permanent bool) error {
	if !jobErrorCodePattern.MatchString(errorCode) {
		return ErrConfiguration
	}
	err := q.store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
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
		updates := map[string]any{"status": "pending", "lease_owner": nil, "lease_until": nil, "last_error_code": errorCode, "updated_at": now, "available_at": now.Add(delay)}
		if permanent || lease.Generation >= lease.Job.MaxAttempts {
			updates["status"], updates["completed_at"] = "failed", now
		}
		result := q.fenced(tx, lease, now).Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrJobLeaseLost
		}
		return nil
	})
	return queueError(err)
}
