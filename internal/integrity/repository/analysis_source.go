package repository

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

var (
	ErrAnalysisSource    = errors.New("MI_ANALYSIS_SOURCE_INVALID")
	ErrAnalysisLimit     = errors.New("MI_ANALYSIS_RESOURCE_LIMIT")
	ErrAnalysisSensitive = errors.New("MI_ANALYSIS_SERIALIZATION_FORBIDDEN")
)

// Match the existing feature batch (Manifest + wire Payload + S1 Payload), not
// the duplicated persistence JSON representations. Tests pin these constants
// to the feature/adapter contracts without a repository -> analysis dependency.
const analysisDerivedBatchBytes int64 = 8 << 20
const analysisDerivedRequestBytes int64 = 1 << 20
const analysisDerivedEnvelopeBytes int64 = 2 << 10

// AnalysisData is internal S2, never an API or log DTO. Legacy Evidence contains
// only policy-eligible final-attempt ciphertext; derived mode loads no bodies.
// All retry metadata and all required signed S1 records are retained so that
// the feature builder can reject a fabricated final pointer or best-of-retry.
type AnalysisData struct {
	Run      RunRecord
	Samples  []LogicalSampleRecord
	Attempts []AttemptRecord
	Evidence []ResponseEvidenceRecord
	Derived  []AttemptDerivedRecord
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
	sourceVersion                            string
	sourceDigest                             [sha256.Size]byte
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
	return tx.loadRunAnalysisMode(runID, "")
}

func (tx *TenantTransaction) loadRunAnalysisMode(runID int64, requiredMode string) (*AnalysisSource, error) {
	job, err := tx.executionJob(JobRunAnalyze, runID, tx.completing)
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
	// Inspect only the bounded SQL mode before locking the Run. Legacy needs
	// policy authority in Job -> organization -> Run order; derived never
	// acquires that policy lock or reads body tables. lockRun rechecks the mode
	// against the frozen Plan, and the signed Manifest is verified outside SQL.
	var stored struct{ AnalysisSourceVersion string }
	if err := tx.db.Model(&RunRecord{}).Select("analysis_source_version").Where("organization_id = ? AND id = ?", tx.orgID, runID).Take(&stored).Error; err != nil {
		return nil, err
	}
	mode := stored.AnalysisSourceVersion
	if requiredMode != "" && mode != requiredMode {
		return nil, ErrAnalysisSource
	}
	var policy ResponseRetentionPolicy
	switch mode {
	case AnalysisSourceLegacyV1:
		policy, err = tx.LockResponseRetentionPolicy()
		if err != nil {
			return nil, err
		}
	case domain.AnalysisSourceDerivedV1:
		if err := tx.boundAnalysisDerivedSource(runID); err != nil {
			return nil, err
		}
	default:
		return nil, ErrAnalysisSource
	}
	run, _, err := tx.lockRun(runID)
	if err != nil {
		return nil, err
	}
	if run.AnalysisSourceVersion != mode || run.Status != "ANALYZING" || run.ExecutionClosedAt == nil || run.CancelRequestedAt != nil || run.ReservedTokens != 0 || run.ReservedCostMicros != 0 || !executionHash.MatchString(run.ManifestHash) {
		return nil, ErrAnalysisSource
	}
	samplesQuery := tx.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND run_id = ?", tx.orgID, runID)
	maxSamples, maxAttempts := int64(1000), int64(3000)
	if mode == domain.AnalysisSourceDerivedV1 {
		maxSamples, maxAttempts = 150, 450
	}
	if err := analysisBoundedRows(samplesQuery, tx.store.driver, "request_plan", maxSamples, 8<<20); err != nil {
		return nil, err
	}
	attemptsQuery := tx.db.Model(&AttemptRecord{}).Where("organization_id = ? AND run_id = ?", tx.orgID, runID)
	if err := analysisBoundedRows(attemptsQuery, tx.store.driver, "request_snapshot", maxAttempts, 24<<20); err != nil {
		return nil, err
	}
	data := AnalysisData{Run: run}
	if err := tx.db.Where("organization_id = ? AND run_id = ?", tx.orgID, runID).Order("execution_ordinal, id").Limit(int(maxSamples) + 1).Find(&data.Samples).Error; err != nil {
		return nil, err
	}
	// response_meta is not needed for analysis: only exact-AAD decrypted evidence
	// may supply protocol/body features. Do not load an unbounded duplicate blob.
	if err := tx.db.Omit("response_meta").Where("organization_id = ? AND run_id = ?", tx.orgID, runID).Order("logical_sample_id, attempt_no").Limit(int(maxAttempts) + 1).Find(&data.Attempts).Error; err != nil {
		return nil, err
	}
	if int64(len(data.Samples)) > maxSamples || int64(len(data.Attempts)) > maxAttempts {
		return nil, ErrAnalysisLimit
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
	if mode == domain.AnalysisSourceDerivedV1 {
		if err := tx.loadAnalysisDerived(&data, attempts); err != nil {
			return nil, err
		}
	} else if err := tx.loadAnalysisLegacy(&data, attempts, policy); err != nil {
		return nil, err
	}
	source := &AnalysisSource{store: tx.store, organizationID: tx.orgID, runID: runID, runVersion: run.Version, jobID: job.ID, generation: tx.leaseGeneration, manifestHash: run.ManifestHash, sourceVersion: mode, data: data}
	if mode == domain.AnalysisSourceDerivedV1 {
		source.sourceDigest, err = analysisDerivedDigest(data)
		if err != nil {
			return nil, err
		}
	}
	return source, nil
}

func (tx *TenantTransaction) loadAnalysisLegacy(data *AnalysisData, attempts map[int64]AttemptRecord, policy ResponseRetentionPolicy) error {
	for _, a := range data.Attempts {
		if a.DerivedReceipt != DerivedLegacy {
			return ErrAnalysisSource
		}
	}
	// An injected S1 row must not silently select a mode or be hidden in a
	// legacy Run. Count it without fetching its opaque payload.
	var count int64
	if err := tx.db.Model(&AttemptDerivedRecord{}).Where("organization_id = ? AND run_id = ?", tx.orgID, data.Run.ID).Count(&count).Error; err != nil {
		return err
	}
	if count != 0 {
		return ErrAnalysisSource
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return err
	}
	policy.observedAtMicros = now.UnixMicro()
	if policy.days == 0 || !policy.active {
		return nil
	}
	cutoff := time.UnixMicro(max(policy.notBeforeMicros, now.UnixMicro()-int64(policy.days)*responseRetentionDayMicros)).UTC()
	evidenceQuery := tx.db.Model(&ResponseEvidenceRecord{}).Where("organization_id = ? AND run_id = ? AND expires_at > ? AND created_at > ? AND created_at <= ?", tx.orgID, data.Run.ID, now, cutoff, now).Where("EXISTS (SELECT 1 FROM integrity_logical_samples s WHERE s.organization_id = integrity_response_evidence.organization_id AND s.run_id = integrity_response_evidence.run_id AND s.id = integrity_response_evidence.logical_sample_id AND s.final_attempt_id = integrity_response_evidence.attempt_id)")
	if err := analysisBoundedRows(evidenceQuery, tx.store.driver, "ciphertext", 1000, (8<<20)+16000); err != nil {
		return err
	}
	if err := evidenceQuery.Order("attempt_id").Find(&data.Evidence).Error; err != nil {
		return err
	}
	for _, evidence := range data.Evidence {
		attempt, found := attempts[evidence.AttemptID]
		if !found || attempt.LogicalSampleID != evidence.LogicalSampleID || attempt.RequestHash != evidence.RequestHash || !executionHash.MatchString(evidence.ContentHash) || evidence.PlaintextBytes < 1 || evidence.PlaintextBytes > 1<<20 || len(evidence.Ciphertext) != evidence.PlaintextBytes+16 || len(evidence.Nonce) != 12 || !responseEvidenceVersion.MatchString(evidence.KeyVersion) {
			return ErrAnalysisSource
		}
	}
	return nil
}

func (tx *TenantTransaction) loadAnalysisDerived(data *AnalysisData, attempts map[int64]AttemptRecord) error {
	query := tx.db.Model(&AttemptDerivedRecord{}).Where("organization_id = ? AND run_id = ?", tx.orgID, data.Run.ID)
	if err := query.Order("attempt_id").Limit(451).Find(&data.Derived).Error; err != nil {
		return err
	}
	if len(data.Derived) > 450 {
		return ErrAnalysisLimit
	}
	if len(data.Derived) != len(data.Attempts) {
		return ErrAnalysisSource
	}
	seen := make(map[int64]bool, len(data.Derived))
	for _, row := range data.Derived {
		a, found := attempts[row.AttemptID]
		code := ""
		if a.ErrorCode != nil {
			code = *a.ErrorCode
		}
		if !found || seen[row.AttemptID] || row.OrganizationID != tx.orgID || row.RunID != data.Run.ID || row.LogicalSampleID != a.LogicalSampleID || row.RequestHash != a.RequestHash || row.Status != a.Status || row.Validity != a.Validity || row.ErrorCode != code || a.FinishedAt == nil || !row.CreatedAt.Equal(*a.FinishedAt) || !validDerivedRecord(DerivedRecord{Version: row.Version, KeyVersion: row.KeyVersion, Payload: row.Payload, MAC: row.MAC}) {
			return ErrAnalysisSource
		}
		switch a.DerivedReceipt {
		case DerivedRecorded:
			if a.Status != "COMPLETED" {
				return ErrAnalysisSource
			}
		case DerivedRecovered:
			if a.Status != "UNCERTAIN" || a.Validity != "INVALID_RETRYABLE" || code != "MI_UNCERTAIN_ATTEMPT" {
				return ErrAnalysisSource
			}
		default:
			return ErrAnalysisSource
		}
		seen[row.AttemptID] = true
	}
	return nil
}

// Pin the fixed Run identifier before fetching any S2/S1 columns. Application
// graph writers obey this Run lock; direct administrator graph rewrites are not
// an authenticated concurrency protocol. S1 has explicit shared row locks too.
func (tx *TenantTransaction) boundAnalysisDerivedSource(runID int64) error {
	runs := tx.db.Model(&RunRecord{}).Where("organization_id = ? AND id = ?", tx.orgID, runID)
	var lockedRun struct{ ID int64 }
	if err := runs.Session(&gorm.Session{}).Select("id").Clauses(clause.Locking{Strength: "UPDATE"}).Take(&lockedRun).Error; err != nil {
		return err
	}
	query := tx.db.Model(&AttemptDerivedRecord{}).Where("organization_id = ? AND run_id = ?", tx.orgID, runID)
	// Pin only fixed-size identifiers before byte guards or payload reads.
	// Holding these locks through publication closes the guard->fetch and
	// digest->commit S1 mutation windows. The Run is already locked; do not add
	// reverse Run->Sample/Attempt locks to the execution protocol.
	if tx.store.driver == "postgres" {
		var locked []struct{ AttemptID int64 }
		if err := query.Session(&gorm.Session{}).Select("attempt_id").Clauses(clause.Locking{Strength: "SHARE"}).Order("attempt_id").Limit(451).Find(&locked).Error; err != nil {
			return err
		}
		if len(locked) > 450 {
			return ErrAnalysisLimit
		}
	}
	samples := tx.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND run_id = ?", tx.orgID, runID)
	attempts := tx.db.Model(&AttemptRecord{}).Where("organization_id = ? AND run_id = ?", tx.orgID, runID)
	// These are representation bounds, not independently spendable source
	// budgets. The canonical SamplePlan adds <2 KiB of fixed fields/128-byte
	// labels to a <=1 MiB adapter request. RequestSnapshot adds <2 KiB of fixed
	// fields/model/hash. The Run snapshot retains its existing 8 MiB contract.
	for _, check := range []struct {
		query               *gorm.DB
		column              string
		rows, total, single int64
	}{{runs, "config_snapshot", 1, 8 << 20, 8 << 20}, {samples, "request_plan", 150, 8 << 20, analysisDerivedRequestBytes + analysisDerivedEnvelopeBytes}, {attempts, "request_snapshot", 450, analysisDerivedBatchBytes + 450*analysisDerivedEnvelopeBytes, analysisDerivedRequestBytes + analysisDerivedEnvelopeBytes}, {query, "payload", 450, analysisDerivedBatchBytes, MaxAttemptDerivedBytes}} {
		if err := analysisBoundedRowSizes(check.query, tx.store.driver, check.column, check.rows, check.total, check.single); err != nil {
			return err
		}
	}
	manifestBytes, err := analysisJSONPayloadBytes(runs, tx.store.driver, "config_snapshot", []string{"plan", "manifest"}, 2<<20)
	if err != nil {
		return err
	}
	wireBytes, err := analysisJSONPayloadBytes(attempts, tx.store.driver, "request_snapshot", []string{"payload"}, analysisDerivedRequestBytes)
	if err != nil {
		return err
	}
	derivedBytes, err := analysisRowByteSize(query, tx.store.driver, "payload")
	if err != nil {
		return err
	}
	if manifestBytes+wireBytes+derivedBytes.Bytes > analysisDerivedBatchBytes {
		return ErrAnalysisLimit
	}
	// Guard ancillary variable bytes before fetching, even if a damaged row
	// predates or bypasses a CHECK. Never filter malformed rows out of the set.
	for _, field := range []struct {
		column string
		bytes  int64
	}{{"mac", 32}, {"key_version", 64}, {"version", 64}, {"error_code", 128}, {"request_hash", 64}, {"status", 16}, {"validity", 32}} {
		if err := analysisBoundedRowSizes(query, tx.store.driver, field.column, 450, 450*field.bytes, field.bytes); err != nil {
			return err
		}
	}
	return nil
}

// Measure the exact object bytes that encoding/json gives a RawMessage. SQLite
// JSON extraction compacts whitespace, so require the persisted outer encoding
// to already be compact. Every traversed key must occur exactly once; otherwise
// SQLite's first-key and Go's last-key behavior could undercount the source.
// These are fixed internal identifiers, never caller-provided JSON paths.
func analysisJSONPayloadBytes(query *gorm.DB, driver, column string, keys []string, maxSingle int64) (int64, error) {
	value, valid := column, "json("+column+") = "+column
	if driver == "postgres" {
		value, valid = column+"::json", "TRUE"
	}
	for _, key := range keys {
		if driver == "postgres" {
			valid += " AND json_typeof(" + value + ") = 'object' AND (SELECT COUNT(*) FROM json_each(" + value + ") WHERE key = '" + key + "') = 1"
			value = "(" + value + " -> '" + key + "')"
		} else {
			valid += " AND json_type(" + value + ") = 'object' AND (SELECT COUNT(*) FROM json_each(" + value + ") WHERE key = '" + key + "') = 1"
			value = "(" + value + " -> '$." + key + "')"
		}
	}
	length := "LENGTH(CAST(" + value + " AS BLOB))"
	if driver == "postgres" {
		length = "OCTET_LENGTH(" + value + "::text)"
		valid += " AND json_typeof(" + value + ") = 'object'"
	} else {
		valid += " AND json_type(" + value + ") = 'object'"
	}
	var size struct{ Bytes, Largest, Invalid int64 }
	if err := query.Session(&gorm.Session{}).Select("COALESCE(SUM(" + length + "), 0) AS bytes, COALESCE(MAX(" + length + "), 0) AS largest, COALESCE(SUM(CASE WHEN " + valid + " THEN 0 ELSE 1 END), 0) AS invalid").Scan(&size).Error; err != nil {
		return 0, ErrAnalysisSource
	}
	if size.Invalid != 0 {
		return 0, ErrAnalysisSource
	}
	if size.Largest > maxSingle {
		return 0, ErrAnalysisLimit
	}
	return size.Bytes, nil
}

// The digest is a private in-process read receipt, NOT a signature or durable
// rollback anchor. Include the complete analysis graph, every derived receipt
// and every S1 byte. Body retention/cleanup is independent and never changes a
// derived analysis source. No JSON bytes are retained, logged or returned.
func analysisDerivedDigest(data AnalysisData) ([sha256.Size]byte, error) {
	h := sha256.New()
	encoder := json.NewEncoder(h)
	if err := encoder.Encode(struct {
		Domain   string
		Run      RunRecord
		Snapshot string
	}{"mii/analysis-source-receipt/v1", data.Run, data.Run.ConfigSnapshot}); err != nil {
		return [sha256.Size]byte{}, ErrAnalysisSource
	}
	for _, row := range data.Samples {
		if err := encoder.Encode(struct {
			Row  LogicalSampleRecord
			Plan string
		}{row, row.RequestPlan}); err != nil {
			return [sha256.Size]byte{}, ErrAnalysisSource
		}
	}
	for _, row := range data.Attempts {
		row.ResponseMeta, row.ResponseBodyReceipt = "", ""
		if err := encoder.Encode(struct {
			Row      AttemptRecord
			Snapshot string
		}{row, row.RequestSnapshot}); err != nil {
			return [sha256.Size]byte{}, ErrAnalysisSource
		}
	}
	// This local alias removes only the defensive MarshalJSON method so the
	// complete fixed S1 record may be hashed directly into the private receipt.
	type digestRow AttemptDerivedRecord
	for _, row := range data.Derived {
		if err := encoder.Encode(digestRow(row)); err != nil {
			return [sha256.Size]byte{}, ErrAnalysisSource
		}
	}
	return [sha256.Size]byte(h.Sum(nil)), nil
}

// Called only inside fenced PublishRunAnalysis before any publication SQL. The
// derived branch takes no organization/policy lock, including on this second
// read after the caller has locked the Run. Legacy remains the legacy source.
func (tx *TenantTransaction) validateRunAnalysisSource(source *AnalysisSource) error {
	if source == nil || source.store != tx.store || source.organizationID != tx.orgID || source.jobID != tx.leaseJobID || source.generation != tx.leaseGeneration {
		return ErrAnalysisSource
	}
	if source.sourceVersion == AnalysisSourceLegacyV1 {
		return nil
	}
	if source.sourceVersion != domain.AnalysisSourceDerivedV1 {
		return ErrAnalysisSource
	}
	// The required mode is checked before the loader can acquire any policy
	// lock. Even a changed SQL mirror cannot invert the established lock order.
	current, err := tx.loadRunAnalysisMode(source.runID, domain.AnalysisSourceDerivedV1)
	if err != nil {
		return err
	}
	if current.sourceVersion != source.sourceVersion || current.sourceDigest != source.sourceDigest {
		return ErrAnalysisSource
	}
	return nil
}

func analysisBoundedRows(query *gorm.DB, driver, column string, maxRows, maxBytes int64) error {
	return analysisBoundedRowSizes(query, driver, column, maxRows, maxBytes, maxBytes)
}

func analysisBoundedRowSizes(query *gorm.DB, driver, column string, maxRows, maxBytes, maxRowBytes int64) error {
	size, err := analysisRowByteSize(query, driver, column)
	if err != nil {
		return err
	}
	if size.Rows > maxRows || size.Bytes > maxBytes || size.Largest > maxRowBytes {
		return ErrAnalysisLimit
	}
	return nil
}

type analysisByteSize struct{ Rows, Bytes, Largest int64 }

func analysisRowByteSize(query *gorm.DB, driver, column string) (analysisByteSize, error) {
	// column is a fixed internal identifier, never accepted from an API.
	length := "LENGTH(CAST(" + column + " AS BLOB))"
	if driver == "postgres" {
		length = "OCTET_LENGTH(" + column + ")"
	}
	var size analysisByteSize
	if err := query.Session(&gorm.Session{}).Select("COUNT(*) AS rows, COALESCE(SUM(" + length + "), 0) AS bytes, COALESCE(MAX(" + length + "), 0) AS largest").Scan(&size).Error; err != nil {
		return size, err
	}
	return size, nil
}
