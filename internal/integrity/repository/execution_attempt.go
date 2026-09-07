package repository

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
)

// serializeReservations is a tiny DB-wide mutex for exact hierarchical quotas.
// It never covers network I/O. Fixed acquisition order (job, mutex, sample, run,
// target) avoids cross-organization oversubscription on PostgreSQL.
func (tx *TenantTransaction) serializeReservations() error {
	result := tx.db.Exec("UPDATE integrity_execution_mutex SET touched = 0 WHERE lock_name = 'global-reservation'")
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrUnavailable
	}
	return nil
}

func (tx *TenantTransaction) lockedExecutionSample(id int64) (LogicalSampleRecord, domain.SamplePlan, error) {
	var record LogicalSampleRecord
	var plan domain.SamplePlan
	err := tx.db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("organization_id = ? AND id = ? AND job_id = ?", tx.orgID, id, tx.leaseJobID).First(&record).Error
	if err != nil {
		return record, plan, ErrJobLeaseLost
	}
	if json.Unmarshal([]byte(record.RequestPlan), &plan) != nil {
		return record, plan, ErrConfiguration
	}
	return record, plan, nil
}

// validDispatchSnapshot verifies the actual wire snapshot, not merely its
// self-reported hash: only the frozen normalized request's fields are permitted.
// Both token parameter spellings are accounted as independent Attempts.
func validDispatchSnapshot(plan domain.SamplePlan, snapshot domain.RequestSnapshot) bool {
	r := plan.Request
	if snapshot.Model != r.Model || snapshot.Stream != r.Stream || snapshot.MaxOutputTokens != r.MaxOutputTokens || snapshot.PayloadBytes != len(snapshot.Payload) || len(snapshot.Payload) > 1<<20 || (snapshot.MaxOutputParameter != "max_tokens" && snapshot.MaxOutputParameter != "max_completion_tokens") {
		return false
	}
	hash := sha256.Sum256(snapshot.Payload)
	if hex.EncodeToString(hash[:]) != snapshot.RequestHash {
		return false
	}
	expected := map[string]any{"model": r.Model, "messages": r.Messages, "stream": r.Stream, snapshot.MaxOutputParameter: r.MaxOutputTokens}
	if r.Temperature != nil {
		expected["temperature"] = *r.Temperature
	}
	if r.TopP != nil {
		expected["top_p"] = *r.TopP
	}
	if r.Seed != nil {
		expected["seed"] = *r.Seed
	}
	if len(r.Stop) > 0 {
		expected["stop"] = r.Stop
	}
	if r.ResponseFormat != nil {
		expected["response_format"] = r.ResponseFormat
	}
	if r.Stream {
		expected["stream_options"] = map[string]bool{"include_usage": true}
	}
	for k, v := range r.ExtraAllowedParams {
		if k != "frequency_penalty" && k != "presence_penalty" {
			return false
		}
		expected[k] = v
	}
	encoded, err := json.Marshal(expected)
	if err != nil {
		return false
	}
	// Adapter uses this canonical JSON encoding. Exact bytes also reject
	// duplicate JSON keys and avoid float-decoding collisions for large seeds.
	return bytes.Equal(encoded, snapshot.Payload)
}

// ReserveAttempt is committed immediately before one actual Do (including an
// adapter parameter fallback). This durable intent counts against the request
// budget even if the process dies before it can prove whether bytes were sent.
func (tx *TenantTransaction) ReserveAttempt(sampleID int64, snapshot domain.RequestSnapshot) (AttemptRecord, error) {
	if _, err := tx.executionJob(JobSampleExecute, sampleID, false); err != nil {
		return AttemptRecord{}, err
	}
	if err := tx.serializeReservations(); err != nil {
		return AttemptRecord{}, err
	}
	sample, plan, err := tx.lockedExecutionSample(sampleID)
	if err != nil {
		return AttemptRecord{}, err
	}
	if sample.CompletedAt != nil {
		return AttemptRecord{}, ErrExecutionClosed
	}
	if !validDispatchSnapshot(plan, snapshot) {
		return AttemptRecord{}, ErrConfiguration
	}
	run, frozen, err := tx.lockRun(sample.RunID)
	if err != nil {
		return AttemptRecord{}, err
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return AttemptRecord{}, err
	}
	if err := executionOpen(run, now); err != nil {
		return AttemptRecord{}, err
	}
	if err := tx.executionTargetCurrent(frozen.Plan.Target); err != nil {
		return AttemptRecord{}, err
	}
	var unfinished int64
	if err := tx.db.Model(&AttemptRecord{}).Where("organization_id = ? AND logical_sample_id = ? AND status = 'DISPATCHED'", tx.orgID, sample.ID).Count(&unfinished).Error; err != nil {
		return AttemptRecord{}, err
	}
	if unfinished > 0 {
		return AttemptRecord{}, ErrAttemptUncertain
	}
	if sample.AttemptCount >= 1+frozen.Plan.MaxRetries {
		return AttemptRecord{}, ErrExecutionBudget
	}
	tokens, err := scheduler.Add(plan.EstimatedInputTokens, int64(plan.Request.MaxOutputTokens))
	if err != nil {
		return AttemptRecord{}, err
	}
	cost, err := scheduler.Cost(frozen.Plan.Pricing, plan.EstimatedInputTokens, int64(plan.Request.MaxOutputTokens))
	if err != nil {
		return AttemptRecord{}, err
	}
	if err := budgetAvailable(run, tokens, cost); err != nil {
		return AttemptRecord{}, err
	}
	if err := tx.executionCapacity(run, frozen, now); err != nil {
		return AttemptRecord{}, err
	}
	id, err := NewID()
	if err != nil {
		return AttemptRecord{}, err
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return AttemptRecord{}, ErrConfiguration
	}
	attempt := AttemptRecord{ID: id, OrganizationID: tx.orgID, LogicalSampleID: sample.ID, RunID: run.ID, JobID: tx.leaseJobID, LeaseGeneration: tx.leaseGeneration, AttemptNo: sample.AttemptCount + 1, Status: "DISPATCHED", Validity: "PENDING", RequestSnapshot: string(encoded), RequestHash: snapshot.RequestHash, ResponseMeta: "{}", ReservedTokens: tokens, CostKnown: cost != nil, StartedAt: &now}
	if cost != nil {
		attempt.ReservedCostMicros = *cost
	}
	if err := tx.db.Create(&attempt).Error; err != nil {
		return AttemptRecord{}, err
	}
	if err := tx.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND id = ?", tx.orgID, sample.ID).Update("attempt_count", attempt.AttemptNo).Error; err != nil {
		return AttemptRecord{}, err
	}
	if err := tx.db.Model(&RunRecord{}).Where("organization_id = ? AND id = ?", tx.orgID, run.ID).Updates(map[string]any{"request_count": run.RequestCount + 1, "reserved_tokens": run.ReservedTokens + tokens, "reserved_cost_micros": run.ReservedCostMicros + attempt.ReservedCostMicros, "version": run.Version + 1}).Error; err != nil {
		return AttemptRecord{}, err
	}
	return attempt, nil
}

func budgetAvailable(run RunRecord, tokens int64, cost *int64) error {
	used, err := scheduler.Add(run.TokenCount, run.ReservedTokens)
	if err != nil {
		return err
	}
	total, err := scheduler.Add(used, tokens)
	if err != nil {
		return err
	}
	if run.RequestCount >= run.RequestBudget || total > run.TokenBudget {
		return ErrExecutionBudget
	}
	if cost != nil {
		used, err = scheduler.Add(run.EstimatedCostMicros, run.ReservedCostMicros)
		if err != nil {
			return err
		}
		total, err = scheduler.Add(used, *cost)
		if err != nil {
			return err
		}
		if run.MoneyBudgetMicros != nil && total > *run.MoneyBudgetMicros {
			return ErrExecutionBudget
		}
	} else if run.MoneyBudgetMicros != nil {
		return scheduler.ErrUnknownPrice
	}
	return nil
}

func sampleReservation(plan domain.SamplePlan, pricing domain.ExecutionPricing) (int64, *int64, error) {
	tokens, err := scheduler.Add(plan.EstimatedInputTokens, int64(plan.Request.MaxOutputTokens))
	if err != nil {
		return 0, nil, err
	}
	cost, err := scheduler.Cost(pricing, plan.EstimatedInputTokens, int64(plan.Request.MaxOutputTokens))
	return tokens, cost, err
}

func executionOpen(run RunRecord, now time.Time) error {
	if run.CancelRequestedAt != nil {
		return ErrExecutionCancelled
	}
	if run.ExecutionClosedAt != nil || run.Status != "RUNNING" {
		return ErrExecutionClosed
	}
	if run.DeadlineAt == nil || !run.DeadlineAt.After(now) {
		return ErrExecutionBudget
	}
	return nil
}

func (tx *TenantTransaction) executionCapacity(run RunRecord, frozen executionSnapshot, now time.Time) error {
	// Counts are internal aggregates only, never cross-tenant rows returned to a
	// caller. All processes acquire the same mutex before testing/inserting.
	base := tx.db.Table("integrity_sample_attempts a").Joins("JOIN integrity_jobs j ON j.organization_id = a.organization_id AND j.id = a.job_id").Joins("JOIN integrity_runs r ON r.organization_id = a.organization_id AND r.id = a.run_id").Where("a.status = 'DISPATCHED' AND j.status = 'running' AND j.attempt_count = a.lease_generation AND j.lease_until > ?", now)
	limits := frozen.Limits
	for _, scope := range []struct {
		predicate string
		args      []any
		limit     int
	}{{"1 = 1", nil, limits.Global}, {"a.organization_id = ?", []any{tx.orgID}, limits.Organization}, {"a.organization_id = ? AND r.target_id = ?", []any{tx.orgID, run.TargetID}, limits.Target}, {"a.organization_id = ? AND a.run_id = ?", []any{tx.orgID, run.ID}, min(limits.Run, frozen.Plan.Concurrency)}} {
		var count int64
		if err := base.Session(&gorm.Session{}).Where(scope.predicate, scope.args...).Count(&count).Error; err != nil {
			return err
		}
		if count >= int64(scope.limit) {
			return ErrExecutionLimit
		}
	}
	var count int64
	if err := tx.db.Table("integrity_sample_attempts a").Joins("JOIN integrity_runs r ON r.organization_id = a.organization_id AND r.id = a.run_id").Where("a.organization_id = ? AND r.target_id = ? AND a.started_at > ?", tx.orgID, run.TargetID, now.Add(-time.Minute)).Count(&count).Error; err != nil {
		return err
	}
	if count >= int64(limits.TargetRPM) {
		return ErrExecutionRPM
	}
	return nil
}

// CheckExecution is a read-only Run/target cancellation boundary for the Worker
// alongside Queue.CheckLease. It neither renews nor bypasses the Job lease.
func (t *Tenant) CheckExecution(runID int64) error {
	run, err := t.GetRun(runID)
	if err != nil {
		return err
	}
	now, err := queueTime(t.store.db.WithContext(t.ctx), t.store.driver)
	if err != nil {
		return err
	}
	if err := executionOpen(run, now); err != nil {
		return err
	}
	var snapshot executionSnapshot
	if json.Unmarshal([]byte(run.ConfigSnapshot), &snapshot) != nil {
		return ErrConfiguration
	}
	tx := &TenantTransaction{store: t.store, db: t.store.db.WithContext(t.ctx), ctx: t.ctx, orgID: t.orgID}
	return executionError(tx.executionTargetCurrent(snapshot.Plan.Target))
}

var outcomeCodes = map[string]bool{"": true, "MI_NETWORK_TEMPORARY": true, "MI_CONNECTION_RESET": true, "MI_TIMEOUT": true, "MI_RATE_LIMITED": true, "MI_SERVICE_UNAVAILABLE": true, "MI_AUTH_FAILED": true, "MI_MODEL_NOT_FOUND": true, "MI_PROTOCOL_UNSUPPORTED": true, "MI_CLIENT_SAFETY_LIMIT": true, "MI_SAFETY_REFUSAL": true, "MI_EXECUTION_CANCELLED": true, "MI_EXECUTION_TARGET_STALE": true, "MI_UNCERTAIN_ATTEMPT": true, "MI_EXECUTION_BUDGET_EXCEEDED": true}

func validAttemptOutcome(outcome domain.AttemptOutcome) bool {
	switch outcome.Validity {
	case "VALID", "VALID_WITH_WARNING", "INVALID_RETRYABLE", "INVALID_PROTOCOL", "INVALID_SAFETY_LIMIT", "NOT_APPLICABLE":
	default:
		return false
	}
	valid := outcome.Validity == "VALID" || outcome.Validity == "VALID_WITH_WARNING"
	if !outcomeCodes[outcome.ErrorCode] || (valid && (outcome.ErrorCode != "" || outcome.HTTPStatus != 200)) || (!valid && outcome.ErrorCode == "") || outcome.HTTPStatus < 0 || outcome.HTTPStatus > 599 || outcome.LocalCompletionTokens < 0 || outcome.LocalCompletionTokens > 1_000_000_000 || outcome.DurationMillis < 0 || outcome.DurationMillis > 86400000 || outcome.RetryAfterSeconds < 0 || outcome.RetryAfterSeconds > 3600 {
		return false
	}
	for _, v := range []*int64{outcome.PromptTokens, outcome.CompletionTokens} {
		if v != nil && (*v < 0 || *v > 1_000_000_000_000) {
			return false
		}
	}
	if outcome.Validity == "INVALID_RETRYABLE" {
		switch outcome.ErrorCode {
		case "MI_NETWORK_TEMPORARY", "MI_CONNECTION_RESET":
			if outcome.HTTPStatus != 0 {
				return false
			}
		case "MI_TIMEOUT":
			if outcome.HTTPStatus != 0 && outcome.HTTPStatus != 408 {
				return false
			}
		case "MI_RATE_LIMITED":
			if outcome.HTTPStatus != 429 {
				return false
			}
		case "MI_SERVICE_UNAVAILABLE":
			if outcome.HTTPStatus != 500 && outcome.HTTPStatus != 502 && outcome.HTTPStatus != 503 && outcome.HTTPStatus != 504 {
				return false
			}
		case "MI_UNCERTAIN_ATTEMPT":
			if outcome.HTTPStatus != 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// FinishAttempt, final sample selection and retry Job enqueue must share the
// same CompleteWith transaction. A retry retains the exact frozen nonce/request.
func (tx *TenantTransaction) FinishAttempt(sampleID, attemptID int64, outcome domain.AttemptOutcome, jitter int) error {
	if !validAttemptOutcome(outcome) || jitter < 0 || jitter > 1000 {
		return ErrConfiguration
	}
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
	run, frozen, err := tx.lockRun(sample.RunID)
	if err != nil {
		return err
	}
	var attempt AttemptRecord
	if err := tx.db.Where("organization_id = ? AND id = ? AND logical_sample_id = ? AND job_id = ? AND lease_generation = ? AND status = 'DISPATCHED'", tx.orgID, attemptID, sampleID, tx.leaseJobID, tx.leaseGeneration).First(&attempt).Error; err != nil {
		return ErrJobLeaseLost
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return err
	}
	if run.CancelRequestedAt != nil {
		outcome.Validity = "NOT_APPLICABLE"
		outcome.ErrorCode = "MI_EXECUTION_CANCELLED"
	} else if err := tx.executionTargetCurrent(frozen.Plan.Target); err != nil {
		if !errors.Is(err, ErrExecutionStale) {
			return err
		}
		outcome.Validity = "NOT_APPLICABLE"
		outcome.ErrorCode = "MI_EXECUTION_TARGET_STALE"
	}
	if run.CancelRequestedAt == nil && run.DeadlineAt != nil && !run.DeadlineAt.After(now) {
		outcome.Validity = "NOT_APPLICABLE"
		outcome.ErrorCode = "MI_EXECUTION_BUDGET_EXCEEDED"
	}
	if err := tx.settleAttempt(run, frozen, sample, plan, attempt, outcome, now, jitter, false); err != nil {
		return err
	}
	return tx.closeExecutionIfFinished(run.ID, now)
}

func (tx *TenantTransaction) settleAttempt(run RunRecord, frozen executionSnapshot, sample LogicalSampleRecord, plan domain.SamplePlan, attempt AttemptRecord, outcome domain.AttemptOutcome, now time.Time, jitter int, uncertain bool) error {
	input := plan.EstimatedInputTokens
	output := outcome.LocalCompletionTokens
	if outcome.PromptTokens != nil {
		input = max(input, *outcome.PromptTokens)
	}
	if outcome.CompletionTokens != nil {
		output = max(output, *outcome.CompletionTokens)
	}
	if uncertain {
		output = int64(plan.Request.MaxOutputTokens)
	}
	if uncertain || outcome.PromptTokens == nil || outcome.CompletionTokens == nil {
		var err error
		input, err = scheduler.UncertainTokens(input)
		if err != nil {
			return err
		}
		output, err = scheduler.UncertainTokens(output)
		if err != nil {
			return err
		}
	}
	tokens, err := scheduler.Add(input, output)
	if err != nil {
		return err
	}
	cost, err := scheduler.Cost(frozen.Plan.Pricing, input, output)
	if err != nil {
		return err
	}
	costValue := int64(0)
	if cost != nil {
		costValue = *cost
	}
	totalTokens, err := scheduler.Add(run.TokenCount, tokens)
	if err != nil {
		return err
	}
	totalCost, err := scheduler.Add(run.EstimatedCostMicros, costValue)
	if err != nil {
		return err
	}
	if run.ReservedTokens < attempt.ReservedTokens || run.ReservedCostMicros < attempt.ReservedCostMicros {
		return ErrConfiguration
	}
	status := "COMPLETED"
	if uncertain {
		status = "UNCERTAIN"
	}
	if err := tx.db.Model(&AttemptRecord{}).Where("organization_id = ? AND id = ? AND status = 'DISPATCHED'", tx.orgID, attempt.ID).Updates(map[string]any{"status": status, "validity": outcome.Validity, "error_code": outcome.ErrorCode, "http_status": outcome.HTTPStatus, "prompt_tokens": outcome.PromptTokens, "completion_tokens": outcome.CompletionTokens, "total_tokens": tokens, "local_completion_tokens": outcome.LocalCompletionTokens, "duration_ms": outcome.DurationMillis, "billed_estimate_micros": costValue, "finished_at": now}).Error; err != nil {
		return err
	}
	valid := outcome.Validity == "VALID" || outcome.Validity == "VALID_WITH_WARNING"
	delay, retry := scheduler.RetryDelay(outcome.ErrorCode, attempt.AttemptNo, frozen.Plan.MaxRetries, outcome.RetryAfterSeconds, jitter)
	retry = retry && outcome.Validity == "INVALID_RETRYABLE" && !uncertain && run.CancelRequestedAt == nil && run.ExecutionClosedAt == nil && run.DeadlineAt != nil && run.DeadlineAt.After(now.Add(delay))
	run.TokenCount = totalTokens
	run.EstimatedCostMicros = totalCost
	run.ReservedTokens -= attempt.ReservedTokens
	run.ReservedCostMicros -= attempt.ReservedCostMicros
	if retry {
		minimumTokens, e := scheduler.Add(plan.EstimatedInputTokens, int64(plan.Request.MaxOutputTokens))
		if e != nil {
			return e
		}
		minimumCost, e := scheduler.Cost(frozen.Plan.Pricing, plan.EstimatedInputTokens, int64(plan.Request.MaxOutputTokens))
		if e != nil {
			return e
		}
		retry = budgetAvailable(run, minimumTokens, minimumCost) == nil
	}
	if retry {
		if _, err := tx.enqueueSample(sample, attempt.AttemptNo+1, now.Add(delay)); err != nil {
			return err
		}
	} else {
		if err := tx.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND id = ? AND completed_at IS NULL", tx.orgID, sample.ID).Updates(map[string]any{"final_attempt_id": attempt.ID, "validity": outcome.Validity, "completed_at": now}).Error; err != nil {
			return err
		}
		if valid {
			run.ValidSampleCount++
			if err := tx.db.Model(&ProbeRecord{}).Where("organization_id = ? AND id = ?", tx.orgID, sample.ProbeInstanceID).Update("valid_samples", clause.Expr{SQL: "valid_samples + 1"}).Error; err != nil {
				return err
			}
		}
	}
	if err := tx.db.Model(&RunRecord{}).Where("organization_id = ? AND id = ?", tx.orgID, run.ID).Updates(map[string]any{"token_count": run.TokenCount, "estimated_cost_micros": run.EstimatedCostMicros, "reserved_tokens": run.ReservedTokens, "reserved_cost_micros": run.ReservedCostMicros, "valid_sample_count": run.ValidSampleCount, "version": run.Version + 1}).Error; err != nil {
		return err
	}
	return tx.store.appendAudit(tx.ctx, tx.db, tx.orgID, auditObject("run.attempt.finish", "sample_attempt", attempt.ID), nil)
}
