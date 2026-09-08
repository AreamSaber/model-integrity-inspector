package repository

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

const (
	AnalysisSourceLegacyV1 = "legacy_response_v1"
	DerivedLegacy          = "legacy_not_recorded"
	DerivedPending         = "derived_pending"
	DerivedRecorded        = "derived_recorded"
	DerivedRecovered       = "derived_recovered_unavailable"
	BodyNotCaptured        = "not_captured"
	BodyNotRetained        = "not_retained"
	BodyRecorded           = "recorded"
	MaxAttemptDerivedBytes = 32 << 10
)

// DerivedRecord contains opaque S1, not authenticated features. Only the real
// analysis worker verifies its purpose MAC and complete signed source binding.
type DerivedRecord struct {
	Version, KeyVersion string
	Payload, MAC        []byte
}

type AttemptDerivedScope struct {
	OrganizationID, RunID, LogicalSampleID int64
	ProbeInstanceID, AttemptID, JobID      int64
	AttemptNo, Ordinal                     int
	ManifestHash, RequestHash              string
}

type AttemptDerivedCandidate struct {
	Status, Validity, ErrorCode string
	Record                      DerivedRecord
}

type AttemptDerivedCandidates struct {
	Scope AttemptDerivedScope
	Items []AttemptDerivedCandidate
}

// AttemptDerivedRecord is the all-attempt source projection. No expiry or body
// cleanup field exists: retention applies to S2 bodies, never authenticated S1.
type AttemptDerivedRecord struct {
	OrganizationID  int64 `gorm:"primaryKey"`
	RunID           int64
	LogicalSampleID int64
	AttemptID       int64 `gorm:"primaryKey"`
	RequestHash     string
	Status          string
	Validity        string
	ErrorCode       string
	Version         string
	KeyVersion      string
	Payload         []byte
	MAC             []byte
	CreatedAt       time.Time
}

func (AttemptDerivedRecord) TableName() string            { return "integrity_attempt_derived" }
func (AttemptDerivedRecord) String() string               { return "[protected derived evidence]" }
func (r AttemptDerivedRecord) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, r.String()) }
func (AttemptDerivedRecord) MarshalJSON() ([]byte, error) { return nil, ErrAnalysisSensitive }
func (r AttemptDerivedRecord) LogValue() slog.Value       { return slog.StringValue(r.String()) }

func planAnalysisSource(plan domain.ExecutionPlan) (string, error) {
	switch plan.AnalysisSourceVersion {
	case "":
		return AnalysisSourceLegacyV1, nil
	case domain.AnalysisSourceDerivedV1:
		return domain.AnalysisSourceDerivedV1, nil
	default:
		return "", ErrAnalysisSource
	}
}

func validRunAnalysisSource(run RunRecord, plan domain.ExecutionPlan) bool {
	mode, err := planAnalysisSource(plan)
	return err == nil && run.AnalysisSourceVersion == mode
}

func derivedScopeFor(run RunRecord, sample LogicalSampleRecord, attempt AttemptRecord) AttemptDerivedScope {
	return AttemptDerivedScope{OrganizationID: run.OrganizationID, RunID: run.ID, LogicalSampleID: sample.ID, ProbeInstanceID: sample.ProbeInstanceID, AttemptID: attempt.ID, JobID: attempt.JobID, AttemptNo: attempt.AttemptNo, Ordinal: sample.ExecutionOrdinal, ManifestHash: run.ManifestHash, RequestHash: attempt.RequestHash}
}

func validDerivedRecord(record DerivedRecord) bool {
	return record.Version == domain.AnalysisSourceDerivedV1 && responseEvidenceVersion.MatchString(record.KeyVersion) && len(record.Payload) > 0 && len(record.Payload) <= MaxAttemptDerivedBytes && len(record.MAC) == 32
}

func validDerivedOutcomeKey(candidate AttemptDerivedCandidate) bool {
	if candidate.Status == "UNCERTAIN" {
		return candidate.Validity == "INVALID_RETRYABLE" && candidate.ErrorCode == "MI_UNCERTAIN_ATTEMPT"
	}
	if candidate.Status != "COMPLETED" || !outcomeCodes[candidate.ErrorCode] {
		return false
	}
	switch candidate.Validity {
	case "VALID", "VALID_WITH_WARNING":
		return candidate.ErrorCode == ""
	case "INVALID_RETRYABLE", "INVALID_PROTOCOL", "INVALID_SAFETY_LIMIT", "NOT_APPLICABLE":
		return candidate.ErrorCode != ""
	default:
		return false
	}
}

func validDerivedAttemptSource(run RunRecord, frozen domain.ExecutionPlan, sample LogicalSampleRecord, attempt AttemptRecord) bool {
	if !validRunAnalysisSource(run, frozen) || len(frozen.Manifest) == 0 || len(frozen.Manifest) > 2<<20 || frozen.ManifestHash != run.ManifestHash || !validateExecutionPlan(frozen) || attempt.RunID != run.ID || attempt.LogicalSampleID != sample.ID || attempt.OrganizationID != run.OrganizationID || sample.RunID != run.ID || sample.OrganizationID != run.OrganizationID || len(attempt.RequestSnapshot) > 2<<20 {
		return false
	}
	ordinal := 0
	var expected *domain.SamplePlan
	for _, probe := range frozen.Probes {
		for _, row := range probe.Samples {
			if ordinal == sample.ExecutionOrdinal {
				copy := row
				expected = &copy
			}
			ordinal++
		}
	}
	if expected == nil {
		return false
	}
	encoded, err := json.Marshal(expected)
	if err != nil || !bytes.Equal(encoded, []byte(sample.RequestPlan)) {
		return false
	}
	var snapshot domain.RequestSnapshot
	d := json.NewDecoder(bytes.NewBufferString(attempt.RequestSnapshot))
	d.DisallowUnknownFields()
	return d.Decode(&snapshot) == nil && d.Decode(new(any)) == io.EOF && snapshot.RequestHash == attempt.RequestHash && validDispatchSnapshot(*expected, snapshot)
}

func (tx *TenantTransaction) insertSelectedDerived(run RunRecord, frozen domain.ExecutionPlan, sample LogicalSampleRecord, attempt AttemptRecord, original, outcome domain.AttemptOutcome, now time.Time, recovered bool, candidates AttemptDerivedCandidates) error {
	if run.AnalysisSourceVersion != domain.AnalysisSourceDerivedV1 || attempt.DerivedReceipt != DerivedPending || candidates.Scope != derivedScopeFor(run, sample, attempt) || len(candidates.Items) < 1 || len(candidates.Items) > 4 || (recovered && len(candidates.Items) != 1) {
		return ErrAnalysisSource
	}
	if !validDerivedAttemptSource(run, frozen, sample, attempt) {
		return ErrAnalysisSource
	}
	status := "COMPLETED"
	if recovered {
		status = "UNCERTAIN"
	}
	var selected *AttemptDerivedCandidate
	seen := make(map[[3]string]bool, len(candidates.Items))
	for i := range candidates.Items {
		candidate := &candidates.Items[i]
		key := [3]string{candidate.Status, candidate.Validity, candidate.ErrorCode}
		if seen[key] || !validDerivedRecord(candidate.Record) || !validDerivedOutcomeKey(*candidate) || (recovered != (candidate.Status == "UNCERTAIN")) {
			return ErrAnalysisSource
		}
		if !recovered && (candidate.Validity != original.Validity || candidate.ErrorCode != original.ErrorCode) && (candidate.Validity != "NOT_APPLICABLE" || (candidate.ErrorCode != "MI_EXECUTION_CANCELLED" && candidate.ErrorCode != "MI_EXECUTION_TARGET_STALE" && candidate.ErrorCode != "MI_EXECUTION_BUDGET_EXCEEDED")) {
			return ErrAnalysisSource
		}
		seen[key] = true
		if candidate.Status == status && candidate.Validity == outcome.Validity && candidate.ErrorCode == outcome.ErrorCode {
			selected = candidate
		}
	}
	if selected == nil {
		return ErrAnalysisSource
	}
	return tx.db.Create(&AttemptDerivedRecord{OrganizationID: tx.orgID, RunID: run.ID, LogicalSampleID: sample.ID, AttemptID: attempt.ID, RequestHash: attempt.RequestHash, Status: status, Validity: outcome.Validity, ErrorCode: outcome.ErrorCode, Version: selected.Record.Version, KeyVersion: selected.Record.KeyVersion, Payload: bytes.Clone(selected.Record.Payload), MAC: bytes.Clone(selected.Record.MAC), CreatedAt: now}).Error
}

// This only widens the completing business-cancellation classification. The
// private transaction still comes from CompleteWith's exact owner/gen/expiry
// fence, checked again after writes. Reserve/WithLease/network checks are intact.
func (tx *TenantTransaction) derivedCompletionJob(sampleID int64) (Job, error) {
	if tx == nil || tx.closed.Load() {
		return Job{}, ErrTransactionClosed
	}
	if !tx.completing || tx.leaseJobID <= 0 || tx.leaseGeneration <= 0 {
		return Job{}, ErrJobLeaseLost
	}
	var job Job
	if err := tx.db.Where("organization_id = ? AND id = ? AND type = ? AND object_id = ? AND status = 'running' AND attempt_count = ?", tx.orgID, tx.leaseJobID, string(JobSampleExecute), sampleID, tx.leaseGeneration).First(&job).Error; err != nil {
		return Job{}, ErrJobLeaseLost
	}
	return job, nil
}

func (tx *TenantTransaction) FinishAttemptWithDerived(sampleID, attemptID int64, outcome domain.AttemptOutcome, jitter int, candidates AttemptDerivedCandidates, bodies *AttemptBodyCapture) error {
	return tx.finishAttempt(sampleID, attemptID, outcome, jitter, &candidates, bodies, true)
}
