package repository

import (
	"encoding/json"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

// reconcileExecutionData is the shared PRIVATE domain settlement core, not a
// new consumer or maintenance authorization. Its caller must own the enclosing
// transaction, validate its live authority and original source binding, lock
// the exact terminal Job, then the organization retention policy and global
// reservation mutex, and read reconciliationData under those locks. A backup
// caller must terminalize an expired/pending intent in that SAME transaction;
// it cannot commit the Job first and defer this core to a normal Worker.
//
// This core does not renew/check a consumer, validate a maintenance lease, sign
// candidates, load credentials, read response bodies or perform outbound work.
// The caller retains its own final fresh-clock/fence check and audit ordering.
// In particular, returning Applied is not permission to commit without them.
func (tx *TenantTransaction) reconcileExecutionData(job Job, data ExecutionReconciliationData, candidates *AttemptDerivedCandidates) (ExecutionReconciliationResult, error) {
	if tx == nil || tx.store == nil || tx.db == nil || tx.ctx == nil || tx.closed.Load() || !tx.completing || !tx.enqueueAdmitted || tx.orgID != job.OrganizationID || tx.leaseJobID != job.ID || tx.leaseGeneration != job.AttemptCount || job.ID <= 0 || job.OrganizationID <= 0 || (job.Status != "failed" && job.Status != "cancelled") || (JobType(job.Type) != JobRunPlan && JobType(job.Type) != JobSampleExecute) || data.Job.ID != job.ID || data.Job.OrganizationID != job.OrganizationID || data.Job.Type != job.Type || data.Job.ObjectID != job.ObjectID || data.Job.AttemptCount != job.AttemptCount || data.Job.Status != job.Status {
		return "", ErrAnalysisSource
	}
	requiresDerived := data.Attempt != nil && data.Run.AnalysisSourceVersion == domain.AnalysisSourceDerivedV1
	if requiresDerived != (candidates != nil) {
		return "", ErrAnalysisSource
	}
	if data.Run.ExecutionClosedAt != nil || (data.Sample.ID != 0 && data.Sample.CompletedAt != nil) {
		if requiresDerived {
			var record AttemptDerivedRecord
			if tx.db.Where("organization_id = ? AND attempt_id = ?", job.OrganizationID, data.Attempt.ID).First(&record).Error != nil || !completedReconciliationMatches(data, record, *candidates) {
				return "", ErrAnalysisSource
			}
		}
		return ReconciliationAlreadyCompleted, nil
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return "", err
	}
	if JobType(job.Type) == JobRunPlan {
		if err := tx.reconcileUnstartedRun(job, now); err != nil {
			return "", err
		}
	} else if data.Attempt == nil {
		changed := tx.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND id = ? AND completed_at IS NULL", job.OrganizationID, data.Sample.ID).Updates(map[string]any{"validity": "NOT_APPLICABLE", "completed_at": now})
		if changed.Error != nil {
			return "", changed.Error
		}
		if changed.RowsAffected != 1 {
			return "", ErrAnalysisSource
		}
		if err := tx.store.appendAudit(tx.ctx, tx.db, job.OrganizationID, auditObject("run.sample.reconcile", "logical_sample", data.Sample.ID), nil); err != nil {
			return "", err
		}
		if err := tx.closeExecutionIfFinished(data.Run.ID, now); err != nil {
			return "", err
		}
	} else {
		if data.Attempt.Status != "DISPATCHED" {
			return "", ErrAnalysisSource
		}
		outcome := domain.AttemptOutcome{Validity: "INVALID_RETRYABLE", ErrorCode: "MI_UNCERTAIN_ATTEMPT"}
		if requiresDerived {
			if err := tx.insertSelectedDerived(data.Run, data.Plan, data.Sample, *data.Attempt, outcome, outcome, now, true, *candidates); err != nil {
				return "", err
			}
		}
		var plan domain.SamplePlan
		if json.Unmarshal([]byte(data.Sample.RequestPlan), &plan) != nil {
			return "", ErrAnalysisSource
		}
		var frozen executionSnapshot
		if json.Unmarshal([]byte(data.Run.ConfigSnapshot), &frozen) != nil {
			return "", ErrAnalysisSource
		}
		if err := tx.settleAttempt(data.Run, frozen, data.Sample, plan, *data.Attempt, outcome, now, 0, true); err != nil {
			return "", err
		}
		if err := tx.closeExecutionIfFinished(data.Run.ID, now); err != nil {
			return "", err
		}
	}
	return ReconciliationApplied, nil
}
