package repository

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strconv"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

var ErrEvidenceSerialization = errors.New("MI_EVIDENCE_SERIALIZATION_FORBIDDEN")

// ResponseEvidenceRecord contains only encrypted S2 payload and safe bindings.
// It is intentionally independent of secret.KeyRing (avoids repository->secret).
type ResponseEvidenceRecord struct {
	OrganizationID  int64 `gorm:"primaryKey"`
	RunID           int64
	LogicalSampleID int64
	AttemptID       int64 `gorm:"primaryKey"`
	RequestHash     string
	KeyVersion      string
	Nonce           []byte
	Ciphertext      []byte
	PlaintextBytes  int
	ContentHash     string
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

func (ResponseEvidenceRecord) TableName() string            { return "integrity_response_evidence" }
func (ResponseEvidenceRecord) String() string               { return "[encrypted response evidence]" }
func (r ResponseEvidenceRecord) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, r.String()) }
func (ResponseEvidenceRecord) MarshalJSON() ([]byte, error) { return nil, ErrEvidenceSerialization }
func (r ResponseEvidenceRecord) LogValue() slog.Value       { return slog.StringValue(r.String()) }

var responseEvidenceVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// FinishAttemptWithEvidence must be called only by a real sample handler through
// CompleteWith. Result, encrypted evidence, final sample, dependent Job and audit
// either all commit or none do. Historical request fields are never rewritten.
func (tx *TenantTransaction) FinishAttemptWithEvidence(sampleID, attemptID int64, outcome domain.AttemptOutcome, jitter int, evidence ResponseEvidenceRecord) error {
	if tx.closed.Load() {
		return ErrTransactionClosed
	}
	if evidence.OrganizationID != tx.orgID || evidence.LogicalSampleID != sampleID || evidence.AttemptID != attemptID || evidence.RunID <= 0 || !executionHash.MatchString(evidence.RequestHash) || !executionHash.MatchString(evidence.ContentHash) || !responseEvidenceVersion.MatchString(evidence.KeyVersion) || len(evidence.Nonce) != 12 || evidence.PlaintextBytes < 1 || evidence.PlaintextBytes > 1<<20 || len(evidence.Ciphertext) != evidence.PlaintextBytes+16 {
		return ErrConfiguration
	}
	var attempt AttemptRecord
	if err := tx.db.Where("organization_id = ? AND id = ? AND logical_sample_id = ? AND run_id = ? AND request_hash = ?", tx.orgID, attemptID, sampleID, evidence.RunID, evidence.RequestHash).First(&attempt).Error; err != nil {
		return ErrJobLeaseLost
	}
	if err := tx.FinishAttempt(sampleID, attemptID, outcome, jitter); err != nil {
		return err
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return err
	}
	// Development policy is fixed at 30 days until the retention service binds
	// the organization policy. Callers cannot silently extend this deadline.
	evidence.CreatedAt = now
	evidence.ExpiresAt = now.Add(30 * 24 * time.Hour)
	evidence.Nonce = bytes.Clone(evidence.Nonce)
	evidence.Ciphertext = bytes.Clone(evidence.Ciphertext)
	return tx.db.Create(&evidence).Error
}

// GetResponseEvidenceForAnalysis does not depend on a live target or Secret.
// No HTTP handler may expose this record; trusted Worker/analysis decrypts under
// the exact scope. Expired full evidence is not returned even before cleanup.
func (t *Tenant) GetResponseEvidenceForAnalysis(runID, sampleID, attemptID int64) (ResponseEvidenceRecord, error) {
	now, err := queueTime(t.store.db.WithContext(t.ctx), t.store.driver)
	if err != nil {
		return ResponseEvidenceRecord{}, err
	}
	var record ResponseEvidenceRecord
	err = t.scoped().Where("run_id = ? AND logical_sample_id = ? AND attempt_id = ? AND expires_at > ?", runID, sampleID, attemptID, now).First(&record).Error
	return record, executionError(err)
}

// FailUnattemptedSample records a local pre-dispatch failure without inventing
// an HTTP request/Attempt or charging a provider. Validity is non-statistical.
func (tx *TenantTransaction) FailUnattemptedSample(sampleID int64, code string) error {
	switch code {
	case "MI_SECRET_UNAVAILABLE", "MI_PROTOCOL_UNSUPPORTED", "MI_EVIDENCE_UNAVAILABLE", "MI_TARGET_BLOCKED_ADDRESS":
	default:
		return ErrConfiguration
	}
	if _, err := tx.executionJob(JobSampleExecute, sampleID, true); err != nil {
		return err
	}
	if err := tx.serializeReservations(); err != nil {
		return err
	}
	sample, _, err := tx.lockedExecutionSample(sampleID)
	if err != nil {
		return err
	}
	if sample.CompletedAt != nil {
		return ErrExecutionClosed
	}
	var active int64
	if err := tx.db.Model(&AttemptRecord{}).Where("organization_id = ? AND logical_sample_id = ? AND status = 'DISPATCHED'", tx.orgID, sampleID).Count(&active).Error; err != nil {
		return err
	}
	if active != 0 {
		return ErrAttemptUncertain
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return err
	}
	if err := tx.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND id = ?", tx.orgID, sampleID).Updates(map[string]any{"validity": "NOT_APPLICABLE", "failure_code": code, "completed_at": now}).Error; err != nil {
		return err
	}
	if err := tx.store.appendAudit(tx.ctx, tx.db, tx.orgID, auditObject("run.sample.local_failure", "logical_sample", sampleID), nil); err != nil {
		return err
	}
	return tx.closeExecutionIfFinished(sample.RunID, now)
}

// GetExecutionSampleForWorker is a scoped internal read, never a default list
// response. The immutable request/nonce remains excluded from model JSON.
func (t *Tenant) GetExecutionSampleForWorker(id int64) (LogicalSampleRecord, error) {
	var sample LogicalSampleRecord
	err := t.scoped().Where("id = ?", id).First(&sample).Error
	return sample, executionError(err)
}

// DeferExecutionSample releases a contended job without burning an HTTP Attempt
// or retry. Its replacement is still bound to this exact sample and completion.
func (tx *TenantTransaction) DeferExecutionSample(sampleID int64) error {
	if _, err := tx.executionJob(JobSampleExecute, sampleID, true); err != nil {
		return err
	}
	if err := tx.serializeReservations(); err != nil {
		return err
	}
	sample, _, err := tx.lockedExecutionSample(sampleID)
	if err != nil {
		return err
	}
	if sample.CompletedAt != nil {
		return ErrExecutionClosed
	}
	run, frozen, err := tx.lockRun(sample.RunID)
	if err != nil {
		return err
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return err
	}
	if executionOpen(run, now) != nil {
		return tx.FinishUnattemptedSample(sampleID)
	}
	var active int64
	if err := tx.db.Model(&AttemptRecord{}).Where("organization_id = ? AND logical_sample_id = ? AND status = 'DISPATCHED'", tx.orgID, sampleID).Count(&active).Error; err != nil {
		return err
	}
	if active != 0 {
		return ErrAttemptUncertain
	}
	// Capacity may have become free since the handler returned. Deferring one
	// second is still safe; never start network work inside this transaction.
	if err := tx.executionCapacity(run, frozen, now); err != nil && !errors.Is(err, ErrExecutionLimit) && !errors.Is(err, ErrExecutionRPM) {
		return err
	}
	job, err := tx.Enqueue(JobSpec{Type: JobSampleExecute, ObjectID: sampleID, IdempotencyKey: "defer:" + strconv.FormatInt(sampleID, 10) + ":" + strconv.FormatInt(tx.leaseJobID, 10), AvailableAt: now.Add(time.Second), MaxAttempts: 3})
	if err != nil {
		return err
	}
	return tx.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND id = ?", tx.orgID, sampleID).Update("job_id", job.ID).Error
}

// ReconcileRunJobs is called with the Runner's existing consumer capability.
// Opening another SQLite consumer for maintenance would violate exclusivity.
func (q *JobQueue) ReconcileRunJobs(ctx context.Context) error {
	now, err := queueTime(q.store.db.WithContext(ctx), q.store.driver)
	if err != nil {
		return err
	}
	if err := q.guardConsumer(q.store.db.WithContext(ctx), now, false); err != nil {
		return executionError(err)
	}
	var organizations []int64
	err = q.store.db.WithContext(ctx).Model(&Job{}).Distinct("organization_id").Where("type IN (?,?) AND status IN ('failed','cancelled')", string(JobRunPlan), string(JobSampleExecute)).Where("EXISTS (SELECT 1 FROM integrity_logical_samples s WHERE s.organization_id = integrity_jobs.organization_id AND s.job_id = integrity_jobs.id AND s.completed_at IS NULL) OR EXISTS (SELECT 1 FROM integrity_runs r WHERE r.organization_id = integrity_jobs.organization_id AND r.plan_job_id = integrity_jobs.id AND r.execution_closed_at IS NULL)").Order("organization_id").Limit(50).Pluck("organization_id", &organizations).Error
	if err != nil {
		return executionError(err)
	}
	for _, organizationID := range organizations {
		if err := q.ReconcileExecution(ctx, organizationID); err != nil {
			return err
		}
	}
	return nil
}
