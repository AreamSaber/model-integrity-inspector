package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

type ExecutionReconciliationResult string

const (
	ReconciliationApplied          ExecutionReconciliationResult = "applied"
	ReconciliationAlreadyCompleted ExecutionReconciliationResult = "already_completed"
	ReconciliationStale            ExecutionReconciliationResult = "stale"
)

// ExecutionReconciliationData is a bounded frozen input, never response data or
// a user/HTTP authorization. A nil Attempt means no request needs recovering.
type ExecutionReconciliationData struct {
	Job     Job
	Run     RunRecord
	Plan    domain.ExecutionPlan
	Sample  LogicalSampleRecord
	Attempt *AttemptRecord
}

type ExecutionReconciliationSource struct {
	store                 *Store
	owner                 string
	organizationID, jobID int64
	generation            int
	status                string
	binding               [32]byte
	data                  ExecutionReconciliationData
}

func (*ExecutionReconciliationSource) String() string { return "[protected execution recovery source]" }
func (s *ExecutionReconciliationSource) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, s.String())
}
func (*ExecutionReconciliationSource) MarshalJSON() ([]byte, error) { return nil, ErrAnalysisSensitive }
func (*ExecutionReconciliationSource) UnmarshalJSON([]byte) error   { return ErrAnalysisSensitive }
func (s *ExecutionReconciliationSource) LogValue() slog.Value       { return slog.StringValue(s.String()) }
func (ExecutionReconciliationData) String() string                  { return "[protected execution recovery input]" }
func (d ExecutionReconciliationData) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, d.String())
}
func (ExecutionReconciliationData) MarshalJSON() ([]byte, error) { return nil, ErrAnalysisSensitive }
func (d ExecutionReconciliationData) LogValue() slog.Value       { return slog.StringValue(d.String()) }

func (s *ExecutionReconciliationSource) Use(fn func(ExecutionReconciliationData) error) error {
	if s == nil || s.store == nil || fn == nil {
		return ErrAnalysisSource
	}
	// A local alias bypasses only this internal type's deliberate serialization
	// rejection. Deep cloning all pointer/slice fields prevents a borrower from
	// changing a later Use. Never expose or retain the temporary S2 encoding.
	type cloneData ExecutionReconciliationData
	encoded, err := json.Marshal(cloneData(s.data))
	if err != nil {
		return ErrAnalysisSource
	}
	defer clear(encoded)
	var cloned cloneData
	if json.Unmarshal(encoded, &cloned) != nil {
		return ErrAnalysisSource
	}
	data := ExecutionReconciliationData(cloned)
	// These protected immutable strings are intentionally omitted by each
	// persistence model's JSON tags, so restore them without mutable aliases.
	data.Run.ConfigSnapshot, data.Run.RequestKey = s.data.Run.ConfigSnapshot, s.data.Run.RequestKey
	data.Sample.RequestPlan = s.data.Sample.RequestPlan
	if data.Attempt != nil {
		data.Attempt.RequestSnapshot, data.Attempt.ResponseMeta = s.data.Attempt.RequestSnapshot, s.data.Attempt.ResponseMeta
	}
	return fn(data)
}

func reconciliationBinding(data ExecutionReconciliationData) ([32]byte, error) {
	// Mutable Run progress, cancellation and final timestamps are deliberately
	// not frozen: another sample finishing must not invalidate an old intent.
	var attempt any
	if data.Attempt != nil {
		a := data.Attempt
		attempt = []any{a.ID, a.OrganizationID, a.RunID, a.LogicalSampleID, a.JobID, a.LeaseGeneration, a.AttemptNo, a.RequestSnapshot, a.RequestHash, a.StartedAt, a.ReservedTokens, a.ReservedCostMicros}
	}
	row := data.Sample
	encoded, err := json.Marshal([]any{data.Job.ID, data.Job.OrganizationID, data.Job.Type, data.Job.ObjectID, data.Job.AttemptCount, data.Job.Status, data.Run.ID, data.Run.OrganizationID, data.Run.AnalysisSourceVersion, data.Run.ManifestHash, data.Run.ConfigSnapshot, row.ID, row.RunID, row.OrganizationID, row.ProbeInstanceID, row.Ordinal, row.ExecutionOrdinal, row.PairID, row.RequestPlan, row.JobID, attempt})
	if err != nil {
		return [32]byte{}, ErrAnalysisSource
	}
	defer clear(encoded)
	return sha256.Sum256(encoded), nil
}

func (tx *TenantTransaction) reconciliationData(job Job, oldAttemptID int64) (ExecutionReconciliationData, error) {
	data := ExecutionReconciliationData{Job: job}
	runID := job.ObjectID
	if JobType(job.Type) == JobSampleExecute {
		if err := analysisBoundedRows(tx.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND id = ? AND job_id = ?", tx.orgID, job.ObjectID, job.ID), tx.store.driver, "request_plan", 1, 2<<20); err != nil {
			return data, err
		}
		row, _, err := tx.lockedExecutionSample(job.ObjectID)
		if err != nil {
			return data, err
		}
		data.Sample, runID = row, row.RunID
	} else if JobType(job.Type) != JobRunPlan {
		return data, ErrJobInvalid
	}
	if err := analysisBoundedRows(tx.db.Model(&RunRecord{}).Where("organization_id = ? AND id = ?", tx.orgID, runID), tx.store.driver, "config_snapshot", 1, 8<<20); err != nil {
		return data, err
	}
	run, frozen, err := tx.lockRun(runID)
	if err != nil {
		return data, err
	}
	data.Run, data.Plan = run, frozen.Plan
	if data.Sample.ID != 0 {
		query := tx.db.Model(&AttemptRecord{}).Where("organization_id = ? AND run_id = ? AND logical_sample_id = ? AND job_id = ?", tx.orgID, runID, data.Sample.ID, job.ID)
		if oldAttemptID > 0 {
			query = query.Where("id = ?", oldAttemptID)
		} else {
			query = query.Where("status = 'DISPATCHED'")
		}
		if err := analysisBoundedRows(query, tx.store.driver, "request_snapshot", 1, 2<<20); err != nil {
			return data, err
		}
		var attempts []AttemptRecord
		if err := query.Omit("response_meta").Limit(2).Find(&attempts).Error; err != nil {
			return data, err
		}
		if len(attempts) > 1 || (oldAttemptID > 0 && len(attempts) != 1) {
			return data, ErrAnalysisSource
		}
		if len(attempts) == 1 {
			data.Attempt = &attempts[0]
			if data.Attempt.LeaseGeneration < 1 || data.Attempt.LeaseGeneration > job.AttemptCount {
				return data, ErrAnalysisSource
			}
			if run.AnalysisSourceVersion == domain.AnalysisSourceDerivedV1 && !validDerivedAttemptSource(run, frozen.Plan, data.Sample, *data.Attempt) {
				return data, ErrAnalysisSource
			}
		}
	}
	return data, nil
}

// LoadExecutionReconciliations prepares a small bounded batch on the Runner's
// existing consumer. No feature extraction, crypto callback or Secret is used.
func (q *JobQueue) LoadExecutionReconciliations(ctx context.Context, limit int) ([]*ExecutionReconciliationSource, error) {
	if q == nil || q.store == nil || ctx == nil || limit < 1 || limit > 8 {
		return nil, ErrConfiguration
	}
	var sources []*ExecutionReconciliationSource
	err := q.store.db.WithContext(ctx).Transaction(func(db *gorm.DB) error {
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
		query := db.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).Where("type IN (?,?) AND status IN ('failed','cancelled')", string(JobRunPlan), string(JobSampleExecute)).Where("EXISTS (SELECT 1 FROM integrity_logical_samples s WHERE s.organization_id = integrity_jobs.organization_id AND s.job_id = integrity_jobs.id AND s.completed_at IS NULL) OR EXISTS (SELECT 1 FROM integrity_runs r WHERE r.organization_id = integrity_jobs.organization_id AND r.plan_job_id = integrity_jobs.id AND r.execution_closed_at IS NULL)").Order("organization_id, id").Limit(limit)
		if err := query.Find(&jobs).Error; err != nil {
			return err
		}
		if len(jobs) == 0 {
			return nil
		}
		capability := &TenantTransaction{store: q.store, db: db, ctx: ctx}
		defer capability.closed.Store(true)
		// All organization locks precede the global execution mutex. Taking a
		// second organization after the mutex would invert a normal Worker lock.
		var previousOrg int64
		for _, job := range jobs {
			if job.OrganizationID != previousOrg {
				capability.orgID = job.OrganizationID
				if _, err := capability.LockResponseRetentionPolicy(); err != nil {
					return err
				}
				previousOrg = job.OrganizationID
			}
		}
		if err := capability.serializeReservations(); err != nil {
			return err
		}
		totalBytes := 0
		for _, job := range jobs {
			capability.orgID, capability.leaseJobID = job.OrganizationID, job.ID
			data, err := capability.reconciliationData(job, 0)
			if err != nil {
				return err
			}
			totalBytes += len(data.Run.ConfigSnapshot) + len(data.Sample.RequestPlan)
			if data.Attempt != nil {
				totalBytes += len(data.Attempt.RequestSnapshot)
			}
			if totalBytes > 8<<20 {
				return ErrAnalysisLimit
			}
			binding, err := reconciliationBinding(data)
			if err != nil {
				return err
			}
			sources = append(sources, &ExecutionReconciliationSource{store: q.store, owner: q.owner, organizationID: job.OrganizationID, jobID: job.ID, generation: job.AttemptCount, status: job.Status, binding: binding, data: data})
		}
		return nil
	})
	if err != nil {
		return nil, executionError(err)
	}
	return sources, nil
}

// ReconcileExecutionWithDerived submits ONE prepared source in a short DB-only
// transaction. Stale sources are progress outcomes; integrity/SQL errors remain
// visible. Terminal Jobs are never reclaimed, retried or made running here.
func (q *JobQueue) ReconcileExecutionWithDerived(ctx context.Context, source *ExecutionReconciliationSource, candidates *AttemptDerivedCandidates) (ExecutionReconciliationResult, error) {
	if q == nil || q.store == nil || source == nil || source.store != q.store || source.owner != q.owner {
		return "", ErrAnalysisSource
	}
	result := ReconciliationStale
	err := q.store.db.WithContext(ctx).Transaction(func(db *gorm.DB) error {
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
		var job Job
		if err := db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("organization_id = ? AND id = ?", source.organizationID, source.jobID).First(&job).Error; err != nil {
			return err
		}
		if job.Status != source.status || job.AttemptCount != source.generation || (job.Status != "failed" && job.Status != "cancelled") {
			return nil
		}
		actorCtx, err := workerAuditContext(ctx, db, job)
		if err != nil {
			return err
		}
		capability := &TenantTransaction{store: q.store, db: db, ctx: actorCtx, orgID: job.OrganizationID, leaseJobID: job.ID, leaseGeneration: job.AttemptCount, completing: true, enqueueAdmitted: true}
		defer capability.closed.Store(true)
		if _, err := capability.LockResponseRetentionPolicy(); err != nil {
			return err
		}
		if err := capability.serializeReservations(); err != nil {
			return err
		}
		var attemptID int64
		if source.data.Attempt != nil {
			attemptID = source.data.Attempt.ID
		}
		data, err := capability.reconciliationData(job, attemptID)
		if err != nil {
			return err
		}
		binding, err := reconciliationBinding(data)
		if err != nil || binding != source.binding {
			return ErrAnalysisSource
		}
		requiresDerived := data.Attempt != nil && data.Run.AnalysisSourceVersion == domain.AnalysisSourceDerivedV1
		if requiresDerived != (candidates != nil) {
			return ErrAnalysisSource
		}
		if data.Run.ExecutionClosedAt != nil || (data.Sample.ID != 0 && data.Sample.CompletedAt != nil) {
			if requiresDerived {
				var record AttemptDerivedRecord
				if db.Where("organization_id = ? AND attempt_id = ?", job.OrganizationID, attemptID).First(&record).Error != nil || !completedReconciliationMatches(data, record, *candidates) {
					return ErrAnalysisSource
				}
			}
			result = ReconciliationAlreadyCompleted
			return nil
		}
		now, err = queueTime(db, q.store.driver)
		if err != nil {
			return err
		}
		if JobType(job.Type) == JobRunPlan {
			if err := capability.reconcileUnstartedRun(job, now); err != nil {
				return err
			}
		} else if data.Attempt == nil {
			if err := db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND id = ? AND completed_at IS NULL", job.OrganizationID, data.Sample.ID).Updates(map[string]any{"validity": "NOT_APPLICABLE", "completed_at": now}).Error; err != nil {
				return err
			}
			if err := q.store.appendAudit(actorCtx, db, job.OrganizationID, auditObject("run.sample.reconcile", "logical_sample", data.Sample.ID), nil); err != nil {
				return err
			}
			if err := capability.closeExecutionIfFinished(data.Run.ID, now); err != nil {
				return err
			}
		} else {
			if data.Attempt.Status != "DISPATCHED" {
				return ErrAnalysisSource
			}
			outcome := domain.AttemptOutcome{Validity: "INVALID_RETRYABLE", ErrorCode: "MI_UNCERTAIN_ATTEMPT"}
			if requiresDerived {
				if err := capability.insertSelectedDerived(data.Run, data.Plan, data.Sample, *data.Attempt, outcome, outcome, now, true, *candidates); err != nil {
					return err
				}
			}
			var plan domain.SamplePlan
			if json.Unmarshal([]byte(data.Sample.RequestPlan), &plan) != nil {
				return ErrAnalysisSource
			}
			var frozen executionSnapshot
			if json.Unmarshal([]byte(data.Run.ConfigSnapshot), &frozen) != nil {
				return ErrAnalysisSource
			}
			if err := capability.settleAttempt(data.Run, frozen, data.Sample, plan, *data.Attempt, outcome, now, 0, true); err != nil {
				return err
			}
			if err := capability.closeExecutionIfFinished(data.Run.ID, now); err != nil {
				return err
			}
		}
		now, err = queueTime(db, q.store.driver)
		if err != nil {
			return err
		}
		if err := q.guardConsumer(db, now, false); err != nil {
			return err
		}
		result = ReconciliationApplied
		return nil
	})
	if err != nil {
		return "", executionError(err)
	}
	return result, nil
}

func completedReconciliationMatches(data ExecutionReconciliationData, record AttemptDerivedRecord, candidates AttemptDerivedCandidates) bool {
	if data.Attempt == nil || data.Attempt.DerivedReceipt != DerivedRecovered || data.Attempt.Status != "UNCERTAIN" || data.Attempt.Validity != "INVALID_RETRYABLE" || data.Attempt.ErrorCode == nil || *data.Attempt.ErrorCode != "MI_UNCERTAIN_ATTEMPT" || data.Attempt.FinishedAt == nil || len(candidates.Items) != 1 || candidates.Scope != derivedScopeFor(data.Run, data.Sample, *data.Attempt) {
		return false
	}
	candidate := candidates.Items[0]
	return validDerivedRecord(candidate.Record) && candidate.Status == "UNCERTAIN" && validDerivedOutcomeKey(candidate) && record.OrganizationID == data.Run.OrganizationID && record.RunID == data.Run.ID && record.LogicalSampleID == data.Sample.ID && record.AttemptID == data.Attempt.ID && record.RequestHash == data.Attempt.RequestHash && record.Status == candidate.Status && record.Validity == candidate.Validity && record.ErrorCode == candidate.ErrorCode && record.Version == candidate.Record.Version && record.KeyVersion == candidate.Record.KeyVersion && record.CreatedAt.Equal(*data.Attempt.FinishedAt) && bytes.Equal(record.Payload, candidate.Record.Payload) && bytes.Equal(record.MAC, candidate.Record.MAC)
}
