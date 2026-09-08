package repository

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

// These persistence constants are independent of crypto/analysis packages.
// The trusted Worker binds them to the display codec in its integration tests.
const DisplayEvidencePolicy = "display-redaction-v1"

const (
	DisplayCaptured             = "captured"
	DisplayUnavailablePolicy    = "unavailable_redaction_policy"
	DisplayUnavailableLimit     = "unavailable_safety_limit"
	DisplayUnavailableSource    = "unavailable_source_invalid"
	DisplayUnavailableCancelled = "unavailable_cancelled"
	DisplayUnavailableCapture   = "unavailable_capture"
	DisplayUnavailableSeal      = "unavailable_seal"
)

const displayRetentionMicros = int64(30 * 24 * time.Hour / time.Microsecond)

// DisplayEvidenceRecord is a separate S2 envelope, never an HTTP DTO. SourceHash
// is the display codec's original normalized-response/wire-request digest, not
// the analysis ContentHash. Failure states contain no envelope or source hash.
// There is deliberately no public repository read/decrypt capability here.
type DisplayEvidenceRecord struct {
	OrganizationID   int64 `gorm:"primaryKey"`
	RunID            int64
	LogicalSampleID  int64
	AttemptID        int64 `gorm:"primaryKey"`
	RequestHash      string
	Policy           string `gorm:"primaryKey"`
	State            string
	SourceHash       string
	Version          int
	KeyVersion       string
	Nonce            []byte
	Ciphertext       []byte
	PlaintextBytes   int
	PayloadHash      string
	CapturedAtMicros int64
	ExpiresAtMicros  int64
	CreatedAt        time.Time
}

func (DisplayEvidenceRecord) TableName() string            { return "integrity_display_evidence" }
func (DisplayEvidenceRecord) String() string               { return "[encrypted display evidence]" }
func (v DisplayEvidenceRecord) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (DisplayEvidenceRecord) MarshalJSON() ([]byte, error) { return nil, ErrEvidenceSerialization }
func (v DisplayEvidenceRecord) LogValue() slog.Value       { return slog.StringValue(v.String()) }

// BindAttemptDisplayCapture runs in a short WithLease transaction after the
// actual response was received. It supplies authoritative database time and a
// fenced, persistent Attempt identity. Prepare/Seal/network work never runs in
// this transaction. The fixed development policy cannot be caller-extended.
func (tx *TenantTransaction) BindAttemptDisplayCapture(sampleID, attemptID int64, requestHash string) (DisplayEvidenceRecord, error) {
	if tx.closed.Load() {
		return DisplayEvidenceRecord{}, ErrTransactionClosed
	}
	if !executionHash.MatchString(requestHash) {
		return DisplayEvidenceRecord{}, ErrConfiguration
	}
	if _, err := tx.executionJob(JobSampleExecute, sampleID, false); err != nil {
		return DisplayEvidenceRecord{}, err
	}
	var attempt AttemptRecord
	if err := tx.db.Where("organization_id = ? AND id = ? AND logical_sample_id = ? AND request_hash = ? AND job_id = ? AND lease_generation = ? AND status = 'DISPATCHED'", tx.orgID, attemptID, sampleID, requestHash, tx.leaseJobID, tx.leaseGeneration).First(&attempt).Error; err != nil {
		return DisplayEvidenceRecord{}, ErrJobLeaseLost
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return DisplayEvidenceRecord{}, err
	}
	if attempt.StartedAt == nil || attempt.StartedAt.After(now) {
		return DisplayEvidenceRecord{}, ErrConfiguration
	}
	return DisplayEvidenceRecord{OrganizationID: tx.orgID, RunID: attempt.RunID, LogicalSampleID: sampleID, AttemptID: attemptID, RequestHash: requestHash, Policy: DisplayEvidencePolicy, State: DisplayCaptured, CapturedAtMicros: now.UnixMicro(), ExpiresAtMicros: now.UnixMicro() + displayRetentionMicros}, nil
}

func validDisplayRecord(v DisplayEvidenceRecord) bool {
	if v.OrganizationID <= 0 || v.RunID <= 0 || v.LogicalSampleID <= 0 || v.AttemptID <= 0 || !executionHash.MatchString(v.RequestHash) || v.Policy != DisplayEvidencePolicy {
		return false
	}
	if v.State == DisplayCaptured {
		return executionHash.MatchString(v.SourceHash) && v.Version == 1 && responseEvidenceVersion.MatchString(v.KeyVersion) && len(v.Nonce) == 12 && v.PlaintextBytes > 0 && v.PlaintextBytes <= 4<<20 && len(v.Ciphertext) == v.PlaintextBytes+16 && executionHash.MatchString(v.PayloadHash) && v.CapturedAtMicros > 0 && v.CapturedAtMicros <= 1<<62 && v.ExpiresAtMicros-v.CapturedAtMicros == displayRetentionMicros
	}
	switch v.State {
	case DisplayUnavailablePolicy, DisplayUnavailableLimit, DisplayUnavailableSource, DisplayUnavailableCancelled, DisplayUnavailableCapture, DisplayUnavailableSeal:
	default:
		return false
	}
	return v.SourceHash == "" && v.Version == 0 && v.KeyVersion == "" && len(v.Nonce) == 0 && len(v.Ciphertext) == 0 && v.PlaintextBytes == 0 && v.PayloadHash == "" && v.CapturedAtMicros == 0 && v.ExpiresAtMicros == 0
}

// FinishAttemptWithEvidenceAndDisplay extends the existing fenced settlement.
// All Attempt/Job/audit/raw/display changes commit together. The old method is
// intentionally not retrofitted: legacy evidence never acquires a fake proof.
func (tx *TenantTransaction) FinishAttemptWithEvidenceAndDisplay(sampleID, attemptID int64, outcome domain.AttemptOutcome, jitter int, evidence ResponseEvidenceRecord, display DisplayEvidenceRecord) error {
	if tx.closed.Load() {
		return ErrTransactionClosed
	}
	if !validDisplayRecord(display) || display.OrganizationID != tx.orgID || display.OrganizationID != evidence.OrganizationID || display.RunID != evidence.RunID || display.LogicalSampleID != sampleID || display.LogicalSampleID != evidence.LogicalSampleID || display.AttemptID != attemptID || display.AttemptID != evidence.AttemptID || display.RequestHash != evidence.RequestHash {
		return ErrConfiguration
	}
	if err := tx.FinishAttemptWithEvidence(sampleID, attemptID, outcome, jitter, evidence); err != nil {
		return err
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return err
	}
	if display.State == DisplayCaptured {
		var attempt AttemptRecord
		if err := tx.db.Where("organization_id = ? AND id = ? AND run_id = ? AND logical_sample_id = ? AND request_hash = ? AND job_id = ? AND lease_generation = ? AND status = 'COMPLETED'", tx.orgID, attemptID, display.RunID, sampleID, display.RequestHash, tx.leaseJobID, tx.leaseGeneration).First(&attempt).Error; err != nil {
			return ErrJobLeaseLost
		}
		if attempt.StartedAt == nil || display.CapturedAtMicros < attempt.StartedAt.UnixMicro() || display.CapturedAtMicros > now.UnixMicro() || display.ExpiresAtMicros <= now.UnixMicro() {
			return ErrConfiguration
		}
	}
	display.CreatedAt = now
	display.Nonce = bytes.Clone(display.Nonce)
	display.Ciphertext = bytes.Clone(display.Ciphertext)
	if len(display.Nonce) == 0 {
		display.Nonce = nil
	}
	if len(display.Ciphertext) == 0 {
		display.Ciphertext = nil
	}
	return tx.db.Create(&display).Error
}
