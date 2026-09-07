package repository

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"

	"gorm.io/gorm"
)

var (
	ErrAnalysisSource    = errors.New("MI_ANALYSIS_SOURCE_INVALID")
	ErrAnalysisLimit     = errors.New("MI_ANALYSIS_RESOURCE_LIMIT")
	ErrAnalysisSensitive = errors.New("MI_ANALYSIS_SERIALIZATION_FORBIDDEN")
)

// AnalysisData is internal S2, never an API or log DTO. Evidence contains only
// final-attempt, unexpired ciphertext. All retry metadata is retained so that
// the feature builder can reject a fabricated final pointer or best-of-retry.
type AnalysisData struct {
	Run      RunRecord
	Samples  []LogicalSampleRecord
	Attempts []AttemptRecord
	Evidence []ResponseEvidenceRecord
}

func (AnalysisData) String() string               { return "[protected analysis source]" }
func (d AnalysisData) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, d.String()) }
func (AnalysisData) MarshalJSON() ([]byte, error) { return nil, ErrAnalysisSensitive }
func (d AnalysisData) LogValue() slog.Value       { return slog.StringValue(d.String()) }

// AnalysisSource is minted only by the persisted Run-analysis lease. Its private
// receipt binds eventual publication to this store, Run version and job fence.
// It does not attest algorithm correctness or grant an HTTP caller authority.
type AnalysisSource struct {
	store                                    *Store
	organizationID, runID, runVersion, jobID int64
	generation                               int
	manifestHash                             string
	data                                     AnalysisData
}

func (*AnalysisSource) String() string               { return "[protected analysis source]" }
func (d *AnalysisSource) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, d.String()) }
func (*AnalysisSource) MarshalJSON() ([]byte, error) { return nil, ErrAnalysisSensitive }
func (d *AnalysisSource) LogValue() slog.Value       { return slog.StringValue(d.String()) }

// Use lends the authoritative projections to trusted Worker composition, which
// must not retain or log raw fields. No decryption, HMAC verification or scoring
// runs inside the short database transaction that minted this source.
func (s *AnalysisSource) Use(fn func(AnalysisData) error) error {
	if s == nil || s.store == nil || fn == nil {
		return ErrAnalysisSource
	}
	return fn(s.data)
}

// LoadRunAnalysis reads a consistent, bounded source under the existing queue
// consumer and exact organization/owner/generation fence. There is deliberately
// no equivalent unfenced Tenant method or caller-provided final-attempt flag.
func (q *JobQueue) LoadRunAnalysis(ctx context.Context, lease JobLease) (*AnalysisSource, error) {
	if q == nil || q.store == nil || JobType(lease.Job.Type) != JobRunAnalyze {
		return nil, ErrJobInvalid
	}
	var source *AnalysisSource
	err := q.WithLease(ctx, lease, func(tx *TenantTransaction) error {
		var err error
		source, err = tx.loadRunAnalysis(lease.Job.ObjectID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return source, nil
}

func (tx *TenantTransaction) loadRunAnalysis(runID int64) (*AnalysisSource, error) {
	job, err := tx.executionJob(JobRunAnalyze, runID, false)
	if err != nil {
		return nil, err
	}
	// Revision 1 is the execution-created job. Reanalysis will use an explicit
	// persisted revision capability; arbitrary queue object IDs cannot publish.
	if job.IdempotencyKey != "analyze:"+strconv.FormatInt(runID, 10)+":1" {
		return nil, ErrAnalysisSource
	}
	// Guard text sizes BEFORE fetching or decoding S2 columns, including damaged
	// rows. SQL byte length differs between PostgreSQL TEXT and SQLite TEXT.
	if err := analysisBoundedRows(tx.db.Model(&RunRecord{}).Where("organization_id = ? AND id = ?", tx.orgID, runID), tx.store.driver, "config_snapshot", 1, 8<<20); err != nil {
		return nil, err
	}
	run, _, err := tx.lockRun(runID)
	if err != nil {
		return nil, err
	}
	if run.Status != "ANALYZING" || run.ExecutionClosedAt == nil || run.CancelRequestedAt != nil || run.ReservedTokens != 0 || run.ReservedCostMicros != 0 || !executionHash.MatchString(run.ManifestHash) {
		return nil, ErrAnalysisSource
	}
	samplesQuery := tx.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND run_id = ?", tx.orgID, runID)
	if err := analysisBoundedRows(samplesQuery, tx.store.driver, "request_plan", 1000, 8<<20); err != nil {
		return nil, err
	}
	attemptsQuery := tx.db.Model(&AttemptRecord{}).Where("organization_id = ? AND run_id = ?", tx.orgID, runID)
	if err := analysisBoundedRows(attemptsQuery, tx.store.driver, "request_snapshot", 3000, 24<<20); err != nil {
		return nil, err
	}
	data := AnalysisData{Run: run}
	if err := tx.db.Where("organization_id = ? AND run_id = ?", tx.orgID, runID).Order("execution_ordinal, id").Find(&data.Samples).Error; err != nil {
		return nil, err
	}
	// response_meta is not needed for analysis: only exact-AAD decrypted evidence
	// may supply protocol/body features. Do not load an unbounded duplicate blob.
	if err := tx.db.Omit("response_meta").Where("organization_id = ? AND run_id = ?", tx.orgID, runID).Order("logical_sample_id, attempt_no").Find(&data.Attempts).Error; err != nil {
		return nil, err
	}
	if len(data.Samples) == 0 {
		return nil, ErrAnalysisSource
	}
	samples := make(map[int64]LogicalSampleRecord, len(data.Samples))
	attempts := make(map[int64]AttemptRecord, len(data.Attempts))
	counts := make(map[int64]int, len(data.Samples))
	for _, sample := range data.Samples {
		if sample.CompletedAt == nil || sample.CompletedAt.After(*run.ExecutionClosedAt) || sample.AttemptCount < 0 || sample.AttemptCount > 3 {
			return nil, ErrAnalysisSource
		}
		samples[sample.ID] = sample
	}
	for _, attempt := range data.Attempts {
		sample, found := samples[attempt.LogicalSampleID]
		if !found || attempt.StartedAt == nil || attempt.FinishedAt == nil || attempt.FinishedAt.Before(*attempt.StartedAt) || attempt.FinishedAt.After(*sample.CompletedAt) || (attempt.Status != "COMPLETED" && attempt.Status != "UNCERTAIN") || attempt.AttemptNo < 1 || attempt.AttemptNo > sample.AttemptCount {
			return nil, ErrAnalysisSource
		}
		counts[sample.ID]++
		attempts[attempt.ID] = attempt
	}
	for _, sample := range data.Samples {
		if counts[sample.ID] != sample.AttemptCount {
			return nil, ErrAnalysisSource
		}
		if sample.FinalAttemptID == nil {
			if sample.Validity != "NOT_APPLICABLE" {
				return nil, ErrAnalysisSource
			}
			continue
		}
		last, found := attempts[*sample.FinalAttemptID]
		if !found || last.LogicalSampleID != sample.ID || last.AttemptNo != sample.AttemptCount || last.Validity != sample.Validity {
			return nil, ErrAnalysisSource
		}
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return nil, err
	}
	evidenceQuery := tx.db.Model(&ResponseEvidenceRecord{}).Where("organization_id = ? AND run_id = ? AND expires_at > ?", tx.orgID, runID, now).Where("EXISTS (SELECT 1 FROM integrity_logical_samples s WHERE s.organization_id = integrity_response_evidence.organization_id AND s.run_id = integrity_response_evidence.run_id AND s.id = integrity_response_evidence.logical_sample_id AND s.final_attempt_id = integrity_response_evidence.attempt_id)")
	if err := analysisBoundedRows(evidenceQuery, tx.store.driver, "ciphertext", 1000, (8<<20)+16000); err != nil {
		return nil, err
	}
	if err := evidenceQuery.Order("attempt_id").Find(&data.Evidence).Error; err != nil {
		return nil, err
	}
	for _, evidence := range data.Evidence {
		attempt, found := attempts[evidence.AttemptID]
		if !found || attempt.LogicalSampleID != evidence.LogicalSampleID || attempt.RequestHash != evidence.RequestHash || !executionHash.MatchString(evidence.ContentHash) || evidence.PlaintextBytes < 1 || evidence.PlaintextBytes > 1<<20 || len(evidence.Ciphertext) != evidence.PlaintextBytes+16 || len(evidence.Nonce) != 12 || !responseEvidenceVersion.MatchString(evidence.KeyVersion) {
			return nil, ErrAnalysisSource
		}
	}
	return &AnalysisSource{store: tx.store, organizationID: tx.orgID, runID: runID, runVersion: run.Version, jobID: job.ID, generation: tx.leaseGeneration, manifestHash: run.ManifestHash, data: data}, nil
}

func analysisBoundedRows(query *gorm.DB, driver, column string, maxRows, maxBytes int64) error {
	// column is a fixed internal identifier, never accepted from an API.
	length := "LENGTH(CAST(" + column + " AS BLOB))"
	if driver == "postgres" {
		length = "OCTET_LENGTH(" + column + ")"
	}
	var size struct {
		Rows  int64
		Bytes int64
	}
	if err := query.Session(&gorm.Session{}).Select("COUNT(*) AS rows, COALESCE(SUM(" + length + "), 0) AS bytes").Scan(&size).Error; err != nil {
		return err
	}
	if size.Rows > maxRows || size.Bytes > maxBytes {
		return ErrAnalysisLimit
	}
	return nil
}
