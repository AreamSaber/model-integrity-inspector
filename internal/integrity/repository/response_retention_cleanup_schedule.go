package repository

import (
	"context"
	"errors"
	"strconv"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ScheduleResponseRetention advances at most one organization's one-Run cursor.
// Daily progress, active batch, and round-robin observation survive restarts.
// It uses the existing consumer and never opens a second SQLite consumer.
func (q *JobQueue) ScheduleResponseRetention(ctx context.Context) error {
	if q == nil || q.store == nil || ctx == nil || q.closed.Load() {
		return ErrConsumerLost
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
		operation := func() error {
			// Bounded discovery includes disabled organizations: account availability
			// does not suspend an already established data-retention obligation.
			var missing []int64
			if err := db.Raw("SELECT o.id FROM organizations o LEFT JOIN integrity_response_retention_schedule s ON s.organization_id=o.id WHERE s.organization_id IS NULL ORDER BY o.id LIMIT 16").Scan(&missing).Error; err != nil {
				return err
			}
			for _, id := range missing {
				row := responseRetentionSchedule{OrganizationID: id, NextDueAt: time.Unix(0, 0).UTC(), LastCheckedAt: time.Unix(0, 0).UTC()}
				if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
					return err
				}
			}
			var selected responseRetentionSchedule
			eligible := "next_due_at<=? AND (active_batch_id IS NULL OR EXISTS (SELECT 1 FROM integrity_response_retention_batches b JOIN integrity_jobs j ON j.organization_id=b.organization_id AND j.id=b.job_id WHERE b.organization_id=integrity_response_retention_schedule.organization_id AND b.id=integrity_response_retention_schedule.active_batch_id AND j.status IN ('failed','cancelled')))"
			err = db.Select("organization_id").Where(eligible, now).Order("last_checked_at,organization_id").Take(&selected).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			if err != nil {
				return err
			}
			organization, err := loadResponseRetentionOrganization(db, q.store.driver, selected.OrganizationID, true)
			if err != nil {
				return err
			}
			policy, err := responseRetentionObservation(organization, db, q.store.driver)
			if err != nil {
				return err
			}
			now = time.UnixMicro(policy.ObservedAtMicros()).UTC()
			query := db.Where("organization_id=?", selected.OrganizationID)
			if q.store.driver == "postgres" {
				query = query.Clauses(clause.Locking{Strength: "UPDATE"})
			}
			var schedule responseRetentionSchedule
			if err := query.Take(&schedule).Error; err != nil {
				return err
			}
			if schedule.NextDueAt.After(now) {
				return nil
			}
			if schedule.ActiveBatchID != nil {
				var job Job
				if err := db.Select("j.*").Table("integrity_jobs j").Joins("JOIN integrity_response_retention_batches b ON b.organization_id=j.organization_id AND b.job_id=j.id").Where("b.organization_id=? AND b.id=?", schedule.OrganizationID, *schedule.ActiveBatchID).Take(&job).Error; err != nil {
					return err
				}
				if job.Status != "failed" && job.Status != "cancelled" {
					return nil
				}
				batch, err := retentionJobBatch(db, job)
				if err != nil {
					return err
				}
				// Keep the failed Job and advance only past its Run for this daily
				// sweep. A permanently bad first Run must not starve healthy later
				// Runs in the same organization. Tomorrow resets the cursor and
				// retries the bad Run; no tick-level retry storm or permanent skip.
				changed := db.Model(&responseRetentionSchedule{}).Where("organization_id=? AND active_batch_id=?", schedule.OrganizationID, *schedule.ActiveBatchID).Updates(map[string]any{"active_batch_id": nil, "cursor_run_id": batch.RunID, "sweep_day": now.Unix() / 86400, "next_due_at": now, "last_checked_at": now})
				if changed.Error != nil {
					return changed.Error
				}
				if changed.RowsAffected != 1 {
					return ErrRetentionSource
				}
				return nil
			}
			day := now.Unix() / 86400
			if schedule.SweepDay != day {
				schedule.CursorRunID = 0
				schedule.SweepDay = day
			}
			// Min Run uses the existing organization/Run indexes; no S2 projection.
			var candidates []int64
			if err := db.Raw("SELECT run_id FROM (SELECT run_id FROM integrity_response_evidence WHERE organization_id=? AND run_id>? UNION SELECT run_id FROM integrity_display_evidence WHERE organization_id=? AND run_id>? AND state='captured') r ORDER BY run_id LIMIT 1", schedule.OrganizationID, schedule.CursorRunID, schedule.OrganizationID, schedule.CursorRunID).Scan(&candidates).Error; err != nil {
				return err
			}
			updates := map[string]any{"last_checked_at": now, "sweep_day": day, "cursor_run_id": schedule.CursorRunID}
			if len(candidates) == 0 {
				updates["next_due_at"] = nextRetentionDay(now)
			} else {
				runID := candidates[0]
				has, err := hasExpiredResponseObjects(db, schedule.OrganizationID, runID, policy)
				if err != nil {
					return err
				}
				if !has {
					updates["cursor_run_id"] = runID
				} else {
					var run RunRecord
					if err := db.Select("id,organization_id,created_by").Where("organization_id=? AND id=?", schedule.OrganizationID, runID).Take(&run).Error; err != nil {
						return err
					}
					if run.CreatedBy <= 0 {
						return ErrRetentionSource
					}
					batchID, err := NewID()
					if err != nil {
						return err
					}
					if batchID == schedule.OrganizationID {
						return ErrConflict
					}
					batch := responseRetentionBatch{ID: batchID, OrganizationID: schedule.OrganizationID, RunID: runID, CreatedBy: run.CreatedBy, State: "planned", CreatedAt: now}
					if err := db.Create(&batch).Error; err != nil {
						return err
					}
					capability := &TenantTransaction{store: q.store, db: db, ctx: ctx, orgID: schedule.OrganizationID, enqueueAdmitted: true}
					defer capability.closed.Store(true)
					job, err := capability.Enqueue(JobSpec{Type: JobRetentionDelete, ObjectID: batchID, IdempotencyKey: "response-retention:" + strconv.FormatInt(batchID, 10), Priority: -10, MaxAttempts: 3})
					if err != nil {
						return err
					}
					bound := db.Model(&responseRetentionBatch{}).Where("organization_id=? AND id=? AND job_id IS NULL AND state='planned'", batch.OrganizationID, batch.ID).Update("job_id", job.ID)
					if bound.Error != nil {
						return bound.Error
					}
					if bound.RowsAffected != 1 {
						return ErrRetentionSource
					}
					updates["active_batch_id"] = batch.ID
				}
			}
			changed := db.Model(&responseRetentionSchedule{}).Where("organization_id=? AND active_batch_id IS NULL", schedule.OrganizationID).Updates(updates)
			if changed.Error != nil {
				return changed.Error
			}
			if changed.RowsAffected != 1 {
				return ErrRetentionSource
			}
			return nil
		}
		if err := operation(); err != nil {
			return err
		}
		now, err = queueTime(db, q.store.driver)
		if err != nil {
			return err
		}
		return q.guardConsumer(db, now, false)
	}))
}

func nextRetentionDay(now time.Time) time.Time { return time.Unix((now.Unix()/86400+1)*86400, 0).UTC() }

func expiredResponseQuery(db *gorm.DB, orgID, runID int64, source string, policy ResponseRetentionPolicy) *gorm.DB {
	if source == retentionRawSource {
		q := db.Model(&ResponseEvidenceRecord{}).Where("organization_id=? AND run_id=?", orgID, runID)
		if policy.days == 0 {
			return q
		}
		now := time.UnixMicro(policy.observedAtMicros).UTC()
		cutoff := time.UnixMicro(max(policy.notBeforeMicros, policy.observedAtMicros-int64(policy.days)*responseRetentionDayMicros)).UTC()
		return q.Where("expires_at<=? OR created_at<=?", now, cutoff)
	}
	q := db.Model(&DisplayEvidenceRecord{}).Where("organization_id=? AND run_id=? AND state='captured'", orgID, runID)
	if policy.days == 0 {
		return q
	}
	return q.Where("expires_at_micros<=? OR captured_at_micros<=?", policy.observedAtMicros, max(policy.notBeforeMicros, policy.observedAtMicros-int64(policy.days)*responseRetentionDayMicros))
}

func hasExpiredResponseObjects(db *gorm.DB, orgID, runID int64, policy ResponseRetentionPolicy) (bool, error) {
	for _, source := range []string{retentionRawSource, retentionDisplaySource} {
		var rows []int64
		if err := expiredResponseQuery(db, orgID, runID, source, policy).Select("attempt_id").Limit(1).Find(&rows).Error; err != nil {
			return false, err
		}
		if len(rows) > 0 {
			return true, nil
		}
	}
	return false, nil
}
