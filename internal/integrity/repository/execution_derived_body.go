package repository

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

// AttemptBodyCapture is a store-minted observation, never a request DTO. Its
// scope, original expiry and DB clock are private and remain unchanged when
// ciphertext is attached. It grants no lease, user, or plaintext-read authority.
type AttemptBodyCapture struct {
	store             *Store
	scope             AttemptDerivedScope
	sourceMode        string
	generation        int
	captured, expires int64
	disabled          bool
	raw               *ResponseEvidenceRecord
	display           *DisplayEvidenceRecord
}

func (*AttemptBodyCapture) String() string               { return "[protected attempt body capture]" }
func (c *AttemptBodyCapture) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, c.String()) }
func (*AttemptBodyCapture) MarshalJSON() ([]byte, error) { return nil, ErrEvidenceSerialization }
func (*AttemptBodyCapture) UnmarshalJSON([]byte) error   { return ErrEvidenceSerialization }
func (c *AttemptBodyCapture) LogValue() slog.Value       { return slog.StringValue(c.String()) }

func (c *AttemptBodyCapture) CapturedAtMicros() int64 {
	if c == nil {
		return 0
	}
	return c.captured
}
func (c *AttemptBodyCapture) ExpiresAtMicros() int64 {
	if c == nil {
		return 0
	}
	return c.expires
}

func (c *AttemptBodyCapture) DisplayBinding() DisplayEvidenceRecord {
	if c == nil || c.store == nil {
		return DisplayEvidenceRecord{}
	}
	v := DisplayEvidenceRecord{OrganizationID: c.scope.OrganizationID, RunID: c.scope.RunID, LogicalSampleID: c.scope.LogicalSampleID, AttemptID: c.scope.AttemptID, RequestHash: c.scope.RequestHash, Policy: DisplayEvidencePolicy, State: DisplayCaptured, CapturedAtMicros: c.captured, ExpiresAtMicros: c.expires}
	if c.disabled {
		v.State, v.CapturedAtMicros, v.ExpiresAtMicros = DisplayUnavailableCapture, 0, 0
	}
	return v
}

func (c *AttemptBodyCapture) WithRecords(raw ResponseEvidenceRecord, display DisplayEvidenceRecord) (*AttemptBodyCapture, error) {
	if c == nil || c.store == nil {
		return nil, ErrConfiguration
	}
	copy := *c
	if c.disabled {
		copy.raw, copy.display = nil, nil
		return &copy, nil
	}
	if !validResponseEvidence(raw) || raw.OrganizationID != c.scope.OrganizationID || raw.RunID != c.scope.RunID || raw.LogicalSampleID != c.scope.LogicalSampleID || raw.AttemptID != c.scope.AttemptID || raw.RequestHash != c.scope.RequestHash || !validDisplayRecord(display) || display.OrganizationID != raw.OrganizationID || display.RunID != raw.RunID || display.LogicalSampleID != raw.LogicalSampleID || display.AttemptID != raw.AttemptID || display.RequestHash != raw.RequestHash {
		return nil, ErrAnalysisSource
	}
	if display.State == DisplayCaptured && (display.CapturedAtMicros != c.captured || display.ExpiresAtMicros != c.expires) {
		return nil, ErrAnalysisSource
	}
	raw.CreatedAt, raw.ExpiresAt = time.UnixMicro(c.captured).UTC(), time.UnixMicro(c.expires).UTC()
	raw.Nonce, raw.Ciphertext = bytes.Clone(raw.Nonce), bytes.Clone(raw.Ciphertext)
	display.Nonce, display.Ciphertext = bytes.Clone(display.Nonce), bytes.Clone(display.Ciphertext)
	if len(display.Nonce) == 0 {
		display.Nonce = nil
	}
	if len(display.Ciphertext) == 0 {
		display.Ciphertext = nil
	}
	copy.raw, copy.display = &raw, &display
	return &copy, nil
}

func validResponseEvidence(v ResponseEvidenceRecord) bool {
	return v.OrganizationID > 0 && v.RunID > 0 && v.LogicalSampleID > 0 && v.AttemptID > 0 && executionHash.MatchString(v.RequestHash) && executionHash.MatchString(v.ContentHash) && responseEvidenceVersion.MatchString(v.KeyVersion) && len(v.Nonce) == 12 && v.PlaintextBytes > 0 && v.PlaintextBytes <= 1<<20 && len(v.Ciphertext) == v.PlaintextBytes+16
}

func (tx *TenantTransaction) BindAttemptResponseCapture(sampleID, attemptID int64, requestHash string) (*AttemptBodyCapture, error) {
	if _, err := tx.executionJob(JobSampleExecute, sampleID, false); err != nil {
		return nil, err
	}
	policy, err := tx.LockResponseRetentionPolicy()
	if err != nil {
		return nil, err
	}
	var attempt AttemptRecord
	if err := tx.db.Where("organization_id = ? AND id = ? AND logical_sample_id = ? AND request_hash = ? AND job_id = ? AND lease_generation = ? AND status = 'DISPATCHED'", tx.orgID, attemptID, sampleID, requestHash, tx.leaseJobID, tx.leaseGeneration).First(&attempt).Error; err != nil {
		return nil, ErrJobLeaseLost
	}
	var sample LogicalSampleRecord
	if err := tx.db.Where("organization_id = ? AND id = ? AND run_id = ?", tx.orgID, sampleID, attempt.RunID).First(&sample).Error; err != nil {
		return nil, ErrAnalysisSource
	}
	run, _, err := tx.lockRun(attempt.RunID)
	if err != nil {
		return nil, err
	}
	validMode := run.AnalysisSourceVersion == domain.AnalysisSourceDerivedV1 && attempt.DerivedReceipt == DerivedPending || run.AnalysisSourceVersion == AnalysisSourceLegacyV1 && attempt.DerivedReceipt == DerivedLegacy
	if !validMode || attempt.StartedAt == nil {
		return nil, ErrAnalysisSource
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil || attempt.StartedAt.After(now) {
		return nil, ErrAnalysisSource
	}
	c := &AttemptBodyCapture{store: tx.store, scope: derivedScopeFor(run, sample, attempt), sourceMode: run.AnalysisSourceVersion, generation: tx.leaseGeneration, captured: now.UnixMicro(), disabled: policy.Days() == 0}
	if !c.disabled {
		c.expires = c.captured + int64(policy.Days())*responseRetentionDayMicros
	}
	return c, nil
}

// FinishLegacyAttemptWithCapture retains the already-signed legacy source mode.
// A nil capture explicitly records not_captured; no S1 is invented. Only this
// private capture can authorize new legacy bodies under the fresh policy.
func (tx *TenantTransaction) FinishLegacyAttemptWithCapture(sampleID, attemptID int64, outcome domain.AttemptOutcome, jitter int, bodies *AttemptBodyCapture) error {
	return tx.finishAttempt(sampleID, attemptID, outcome, jitter, nil, bodies, true)
}

func (tx *TenantTransaction) persistAttemptBodies(run RunRecord, sample LogicalSampleRecord, attempt AttemptRecord, policy ResponseRetentionPolicy, capture *AttemptBodyCapture) error {
	// settleAttempt may have waited on an audit head. Observe again after that
	// wait; no new policy lock is acquired after audit locks.
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return err
	}
	state := BodyNotCaptured
	if capture != nil {
		if capture.store != tx.store || capture.sourceMode != run.AnalysisSourceVersion || capture.scope != derivedScopeFor(run, sample, attempt) || capture.generation != tx.leaseGeneration || capture.captured <= 0 || capture.captured > now.UnixMicro() || attempt.StartedAt == nil || capture.captured < attempt.StartedAt.UnixMicro() {
			return ErrAnalysisSource
		}
		// Reobserve the clock after all lock waits, without reacquiring org after
		// audit locks. The policy row is still held throughout this transaction.
		policy.observedAtMicros = now.UnixMicro()
		if capture.disabled || !policy.EligibleAtObservation(capture.captured, capture.expires, false) {
			state = BodyNotRetained
		} else if capture.raw != nil && capture.display != nil {
			raw, display := *capture.raw, *capture.display
			display.CreatedAt = now
			if err := tx.db.Create(&raw).Error; err != nil {
				return err
			}
			if err := tx.db.Create(&display).Error; err != nil {
				return err
			}
			state = BodyRecorded
		}
	}
	receipt := DerivedLegacy
	if run.AnalysisSourceVersion == domain.AnalysisSourceDerivedV1 {
		receipt = DerivedRecorded
	}
	result := tx.db.Model(&AttemptRecord{}).Where("organization_id = ? AND id = ? AND status = 'COMPLETED' AND derived_receipt = ?", tx.orgID, attempt.ID, receipt).Update("response_body_receipt", state)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrAnalysisSource
	}
	return nil
}
