package repository

import (
	"context"
	"errors"
	"strconv"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

// RecoverInterruptedSample runs when the same Job is reclaimed with a newer
// generation. It never retries a possibly billed request automatically.
func (tx *TenantTransaction) RecoverInterruptedSample(sampleID int64) error {
	return tx.recoverInterruptedSample(sampleID, 0, nil)
}

// RecoverInterruptedSampleWithDerived records the unavailable result of the
// OLD real Attempt. It never reopens a Secret, checks current target validity,
// reissues HTTP, or rewrites the old request/job identity.
func (tx *TenantTransaction) RecoverInterruptedSampleWithDerived(sampleID, attemptID int64, candidates AttemptDerivedCandidates) error {
	if attemptID <= 0 {
		return ErrAnalysisSource
	}
	return tx.recoverInterruptedSample(sampleID, attemptID, &candidates)
}

func (tx *TenantTransaction) recoverInterruptedSample(sampleID, attemptID int64, candidates *AttemptDerivedCandidates) error {
	var err error
	if candidates == nil {
		_, err = tx.executionJob(JobSampleExecute, sampleID, true)
	} else {
		_, err = tx.derivedCompletionJob(sampleID)
	}
	if err != nil {
		return err
	}
	if _, err := tx.LockResponseRetentionPolicy(); err != nil {
		return err
	}
	if err := tx.serializeReservations(); err != nil {
		return err
	}
	sample, plan, err := tx.lockedExecutionSample(sampleID)
	if err != nil {
		return err
	}
	run, frozen, err := tx.lockRun(sample.RunID)
	if err != nil {
		return err
	}
	if (run.AnalysisSourceVersion == domain.AnalysisSourceDerivedV1) != (candidates != nil) {
		return ErrAnalysisSource
	}
	var attempt AttemptRecord
	query := tx.db.Where("organization_id = ? AND logical_sample_id = ? AND job_id = ? AND lease_generation < ? AND status = 'DISPATCHED'", tx.orgID, sample.ID, tx.leaseJobID, tx.leaseGeneration)
	if candidates != nil {
		query = query.Where("id = ?", attemptID)
	}
	if err := query.First(&attempt).Error; err != nil {
		return ErrJobLeaseLost
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return err
	}
	outcome := domain.AttemptOutcome{Validity: "INVALID_RETRYABLE", ErrorCode: "MI_UNCERTAIN_ATTEMPT"}
	if candidates != nil {
		if err := tx.insertSelectedDerived(run, frozen.Plan, sample, attempt, outcome, outcome, now, true, *candidates); err != nil {
			return err
		}
	}
	if err := tx.settleAttempt(run, frozen, sample, plan, attempt, outcome, now, 0, true); err != nil {
		return err
	}
	return tx.closeExecutionIfFinished(run.ID, now)
}

// FinishUnattemptedSample closes a skipped sample only for a proven cancellation,
// exhausted budget/deadline, or stale target. Concurrency/RPM contention is not a
// sample failure and must instead defer the Job without creating an Attempt.
func (tx *TenantTransaction) FinishUnattemptedSample(sampleID int64) error {
	if _, err := tx.executionJob(JobSampleExecute, sampleID, true); err != nil {
		return err
	}
	if err := tx.serializeReservations(); err != nil {
		return err
	}
	sample, plan, err := tx.lockedExecutionSample(sampleID)
	if err != nil {
		return err
	}
	if sample.CompletedAt != nil {
		now, err := queueTime(tx.db, tx.store.driver)
		if err != nil {
			return err
		}
		return tx.closeExecutionIfFinished(sample.RunID, now)
	}
	var active int64
	if err := tx.db.Model(&AttemptRecord{}).Where("organization_id = ? AND logical_sample_id = ? AND status = 'DISPATCHED'", tx.orgID, sample.ID).Count(&active).Error; err != nil {
		return err
	}
	if active != 0 {
		return ErrAttemptUncertain
	}
	run, frozen, err := tx.lockRun(sample.RunID)
	if err != nil {
		return err
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return err
	}
	blocked := executionOpen(run, now) != nil
	if !blocked {
		err = tx.executionTargetCurrent(frozen.Plan.Target)
		if err != nil && !errors.Is(err, ErrExecutionStale) {
			return err
		}
		blocked = err != nil
	}
	if !blocked {
		tokens, cost, err := sampleReservation(plan, frozen.Plan.Pricing)
		if err != nil {
			return err
		}
		blocked = budgetAvailable(run, tokens, cost) != nil
	}
	if !blocked {
		return ErrConflict
	}
	if err := tx.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND id = ? AND completed_at IS NULL", tx.orgID, sample.ID).Updates(map[string]any{"validity": "NOT_APPLICABLE", "completed_at": now}).Error; err != nil {
		return err
	}
	return tx.closeExecutionIfFinished(run.ID, now)
}

func (tx *TenantTransaction) closeExecutionIfFinished(runID int64, now time.Time) error {
	if err := tx.advanceExecutionBreaker(runID, now); err != nil {
		return err
	}
	var remaining int64
	if err := tx.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND run_id = ? AND completed_at IS NULL", tx.orgID, runID).Count(&remaining).Error; err != nil {
		return err
	}
	if remaining != 0 {
		return nil
	}
	run, _, err := tx.lockRun(runID)
	if err != nil {
		return err
	}
	if run.ExecutionClosedAt != nil {
		return nil
	}
	if run.ReservedTokens != 0 || run.ReservedCostMicros != 0 {
		return ErrConflict
	}
	status := "ANALYZING"
	var finished *time.Time
	if run.CancelRequestedAt != nil {
		status = "CANCELLED"
		finished = &now
	}
	if err := tx.db.Model(&RunRecord{}).Where("organization_id = ? AND id = ? AND execution_closed_at IS NULL", tx.orgID, runID).Updates(map[string]any{"status": status, "execution_closed_at": now, "finished_at": finished, "version": run.Version + 1}).Error; err != nil {
		return err
	}
	if err := tx.db.Model(&ProbeRecord{}).Where("organization_id = ? AND run_id = ?", tx.orgID, runID).Updates(map[string]any{"status": "COMPLETED", "finished_at": now}).Error; err != nil {
		return err
	}
	if status == "ANALYZING" {
		if _, err := tx.Enqueue(JobSpec{Type: JobRunAnalyze, ObjectID: runID, IdempotencyKey: "analyze:" + strconv.FormatInt(runID, 10) + ":1", MaxAttempts: 3}); err != nil {
			return err
		}
	}
	return tx.store.appendAudit(tx.ctx, tx.db, tx.orgID, auditObject("run.execution.close", "run", runID), nil)
}

// ReconcileExecution is an explicit bounded maintenance step for exhausted or
// cancelled terminal Jobs. It settles only proven terminal Jobs; live/expired
// but reclaimable jobs remain fenced through RecoverInterruptedSample. The
// consumer capability and transaction exclude an unprivileged control caller.
func (q *JobQueue) ReconcileExecution(ctx context.Context, organizationID int64) error {
	if organizationID <= 0 {
		return ErrOrganizationScope
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
		query := db.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).Where("organization_id = ? AND type IN (?,?) AND status IN ('failed','cancelled')", organizationID, string(JobSampleExecute), string(JobRunPlan)).Where("EXISTS (SELECT 1 FROM integrity_logical_samples s WHERE s.organization_id = integrity_jobs.organization_id AND s.job_id = integrity_jobs.id AND s.completed_at IS NULL) OR EXISTS (SELECT 1 FROM integrity_runs r WHERE r.organization_id = integrity_jobs.organization_id AND r.plan_job_id = integrity_jobs.id AND r.execution_closed_at IS NULL)").Order("id").Limit(100)
		if err := query.Find(&jobs).Error; err != nil {
			return err
		}
		capability := &TenantTransaction{store: q.store, db: db, ctx: ctx, orgID: organizationID, completing: true}
		defer capability.closed.Store(true)
		if _, err := capability.LockResponseRetentionPolicy(); err != nil {
			return err
		}
		if err := capability.serializeReservations(); err != nil {
			return err
		}
		for _, job := range jobs {
			actorCtx, err := workerAuditContext(ctx, db, job)
			if err != nil {
				return err
			}
			capability.ctx = actorCtx
			capability.leaseJobID = job.ID
			if JobType(job.Type) == JobRunPlan {
				if err := capability.reconcileUnstartedRun(job, now); err != nil {
					return err
				}
				continue
			}
			sample, plan, err := capability.lockedExecutionSample(job.ObjectID)
			if err != nil {
				return err
			}
			run, frozen, err := capability.lockRun(sample.RunID)
			if err != nil {
				return err
			}
			var attempt AttemptRecord
			found := db.Where("organization_id = ? AND logical_sample_id = ? AND status = 'DISPATCHED'", organizationID, sample.ID).Find(&attempt)
			if found.Error != nil {
				return found.Error
			}
			if found.RowsAffected > 0 {
				if err := capability.settleAttempt(run, frozen, sample, plan, attempt, domain.AttemptOutcome{Validity: "INVALID_RETRYABLE", ErrorCode: "MI_UNCERTAIN_ATTEMPT"}, now, 0, true); err != nil {
					return err
				}
			} else {
				if err := db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND id = ?", organizationID, sample.ID).Updates(map[string]any{"validity": "NOT_APPLICABLE", "completed_at": now}).Error; err != nil {
					return err
				}
				if err := capability.store.appendAudit(capability.ctx, db, organizationID, auditObject("run.sample.reconcile", "logical_sample", sample.ID), nil); err != nil {
					return err
				}
			}
			if err := capability.closeExecutionIfFinished(run.ID, now); err != nil {
				return err
			}
		}
		return nil
	}))
}

func (tx *TenantTransaction) reconcileUnstartedRun(job Job, now time.Time) error {
	run, _, err := tx.lockRun(job.ObjectID)
	if err != nil {
		return err
	}
	if run.PlanJobID == nil || *run.PlanJobID != job.ID || (run.Status != "QUEUED" && run.Status != "CANCELLING") || run.RequestCount != 0 || run.ReservedTokens != 0 || run.ReservedCostMicros != 0 {
		return ErrConflict
	}
	status, code := "FAILED", "MI_EXECUTION_PLAN_FAILED"
	if run.CancelRequestedAt != nil || job.Status == "cancelled" {
		status = "CANCELLED"
		code = "MI_EXECUTION_CANCELLED"
	}
	if err := tx.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND run_id = ? AND completed_at IS NULL", tx.orgID, run.ID).Updates(map[string]any{"validity": "NOT_APPLICABLE", "completed_at": now}).Error; err != nil {
		return err
	}
	if _, _, err := tx.sequenceFinalSamples(run.ID); err != nil {
		return err
	}
	if err := tx.db.Model(&ProbeRecord{}).Where("organization_id = ? AND run_id = ?", tx.orgID, run.ID).Updates(map[string]any{"status": "COMPLETED", "finished_at": now}).Error; err != nil {
		return err
	}
	if err := tx.db.Model(&RunRecord{}).Where("organization_id = ? AND id = ?", tx.orgID, run.ID).Updates(map[string]any{"status": status, "error_summary": code, "execution_closed_at": now, "finished_at": now, "version": run.Version + 1}).Error; err != nil {
		return err
	}
	return tx.store.appendAudit(tx.ctx, tx.db, tx.orgID, auditObject("run.execution.close", "run", run.ID), nil)
}
