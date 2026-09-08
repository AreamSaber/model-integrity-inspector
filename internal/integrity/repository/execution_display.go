package repository

import (
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

// BindAttemptDisplayCapture is compatibility metadata only, not a private body
// capture or permission to persist either envelope. Its old public AAD shape
// remains fixed at 30 days; both public-envelope finish methods now reject it.
// New Workers must use BindAttemptResponseCapture and its DisplayBinding.
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
		return executionHash.MatchString(v.SourceHash) && v.Version == 1 && responseEvidenceVersion.MatchString(v.KeyVersion) && len(v.Nonce) == 12 && v.PlaintextBytes > 0 && v.PlaintextBytes <= 4<<20 && len(v.Ciphertext) == v.PlaintextBytes+16 && executionHash.MatchString(v.PayloadHash) && v.CapturedAtMicros > 0 && v.CapturedAtMicros <= 1<<62 && v.ExpiresAtMicros >= v.CapturedAtMicros+responseRetentionDayMicros && v.ExpiresAtMicros <= v.CapturedAtMicros+180*responseRetentionDayMicros && (v.ExpiresAtMicros-v.CapturedAtMicros)%responseRetentionDayMicros == 0
	}
	switch v.State {
	case DisplayUnavailablePolicy, DisplayUnavailableLimit, DisplayUnavailableSource, DisplayUnavailableCancelled, DisplayUnavailableCapture, DisplayUnavailableSeal:
	default:
		return false
	}
	return v.SourceHash == "" && v.Version == 0 && v.KeyVersion == "" && len(v.Nonce) == 0 && len(v.Ciphertext) == 0 && v.PlaintextBytes == 0 && v.PayloadHash == "" && v.CapturedAtMicros == 0 && v.ExpiresAtMicros == 0
}

// FinishAttemptWithEvidenceAndDisplay rejects envelopes without a private
// capture. Public display AAD fields are not a retention capability. Call the
// mode-specific typed finish with a prior BindAttemptResponseCapture instead.
func (tx *TenantTransaction) FinishAttemptWithEvidenceAndDisplay(_, _ int64, _ domain.AttemptOutcome, _ int, _ ResponseEvidenceRecord, _ DisplayEvidenceRecord) error {
	if tx == nil || tx.closed.Load() {
		return ErrTransactionClosed
	}
	return ErrAnalysisSource
}
