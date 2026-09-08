package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

type displayReadFacts struct {
	OrganizationID                 int64
	Selection                      DisplaySelection
	ManifestHash, AnalysisSource   string
	ResultCreatedAt                time.Time
	ProbeID, FinalAttemptID, JobID int64
	Ordinal, AttemptNo             int
	SampleCompletedAt, StartedAt   time.Time
	FinishedAt                     time.Time
	RequestHash, AttemptStatus     string
	DerivedReceipt, BodyReceipt    string
}

type displayReadSnapshot struct {
	metadata               DisplayReadMetadata
	facts                  displayReadFacts
	record                 DisplayEvidenceRecord
	present                bool
	metadataDigest, digest string
}

func displayBoundedColumns(db *gorm.DB, fixed string, fields ...struct {
	column string
	size   int
}) string {
	for _, field := range fields {
		fixed += "," + readBoundedText(db, field.column, field.column, field.size)
	}
	return fixed
}

func loadDisplayReadSnapshot(db *gorm.DB, orgID int64, selection DisplaySelection, policy ResponseRetentionPolicy, lock, envelope bool) (displayReadSnapshot, error) {
	var out displayReadSnapshot
	var run RunRecord
	q := db.Select(displayBoundedColumns(db, "id,organization_id,execution_closed_at",
		struct {
			column string
			size   int
		}{"manifest_hash", 64}, struct {
			column string
			size   int
		}{"analysis_source_version", 32})).Where("organization_id=? AND id=?", orgID, selection.RunID)
	if lock && db.Name() == "postgres" {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	if err := q.Take(&run).Error; err != nil {
		return out, err
	}
	if !executionHash.MatchString(run.ManifestHash) || run.ExecutionClosedAt == nil || (run.AnalysisSourceVersion != AnalysisSourceLegacyV1 && run.AnalysisSourceVersion != domain.AnalysisSourceDerivedV1) {
		return out, ErrDisplaySource
	}
	var result RunResultRecord
	if err := db.Select("organization_id,run_id,analysis_revision,created_at").Where("organization_id=? AND run_id=? AND analysis_revision=? AND is_published=?", orgID, selection.RunID, selection.AnalysisRevision, true).Take(&result).Error; err != nil {
		return out, err
	}
	if result.CreatedAt.IsZero() {
		return out, ErrDisplaySource
	}
	var sample LogicalSampleRecord
	if err := db.Select("id,organization_id,run_id,probe_instance_id,execution_ordinal,final_attempt_id,completed_at").Where("organization_id=? AND run_id=? AND id=?", orgID, selection.RunID, selection.SampleID).Take(&sample).Error; err != nil {
		return out, err
	}
	if sample.CompletedAt == nil || sample.ProbeInstanceID <= 0 || sample.ExecutionOrdinal < 0 {
		return out, ErrDisplaySource
	}
	if selection.AttemptID == 0 {
		if sample.FinalAttemptID == nil || *sample.FinalAttemptID <= 0 {
			return out, ErrNotFound
		}
		selection.AttemptID = *sample.FinalAttemptID
	}
	var attempt AttemptRecord
	columns := displayBoundedColumns(db, "id,organization_id,run_id,logical_sample_id,job_id,attempt_no,started_at,finished_at",
		struct {
			column string
			size   int
		}{"request_hash", 64}, struct {
			column string
			size   int
		}{"status", 16}, struct {
			column string
			size   int
		}{"derived_receipt", 40}, struct {
			column string
			size   int
		}{"response_body_receipt", 32})
	if err := db.Select(columns).Where("organization_id=? AND run_id=? AND logical_sample_id=? AND id=?", orgID, selection.RunID, selection.SampleID, selection.AttemptID).Take(&attempt).Error; err != nil {
		return out, err
	}
	if attempt.AttemptNo < 1 || attempt.JobID <= 0 || !executionHash.MatchString(attempt.RequestHash) || attempt.StartedAt == nil || attempt.FinishedAt == nil || attempt.FinishedAt.Before(*attempt.StartedAt) || (attempt.Status != "COMPLETED" && attempt.Status != "UNCERTAIN") {
		return out, ErrDisplaySource
	}
	if run.AnalysisSourceVersion == AnalysisSourceLegacyV1 && attempt.DerivedReceipt != DerivedLegacy || run.AnalysisSourceVersion == domain.AnalysisSourceDerivedV1 && (attempt.Status == "COMPLETED" && attempt.DerivedReceipt != DerivedRecorded || attempt.Status == "UNCERTAIN" && attempt.DerivedReceipt != DerivedRecovered) {
		return out, ErrDisplaySource
	}
	switch attempt.ResponseBodyReceipt {
	case DerivedLegacy, BodyNotCaptured, BodyNotRetained, BodyRecorded:
	default:
		return out, ErrDisplaySource
	}
	facts := displayReadFacts{OrganizationID: orgID, Selection: selection, ManifestHash: run.ManifestHash, AnalysisSource: run.AnalysisSourceVersion, ResultCreatedAt: result.CreatedAt, ProbeID: sample.ProbeInstanceID, JobID: attempt.JobID, Ordinal: sample.ExecutionOrdinal, AttemptNo: attempt.AttemptNo, SampleCompletedAt: *sample.CompletedAt, StartedAt: *attempt.StartedAt, FinishedAt: *attempt.FinishedAt, RequestHash: attempt.RequestHash, AttemptStatus: attempt.Status, DerivedReceipt: attempt.DerivedReceipt, BodyReceipt: attempt.ResponseBodyReceipt}
	if sample.FinalAttemptID != nil {
		facts.FinalAttemptID = *sample.FinalAttemptID
	}
	out.facts = facts
	out.metadata = DisplayReadMetadata{Selection: selection, IsFinal: facts.FinalAttemptID == attempt.ID}
	query := db.Model(&DisplayEvidenceRecord{}).Where("organization_id=? AND attempt_id=?", orgID, attempt.ID)
	if err := analysisBoundedRows(query, db.Name(), "ciphertext", 1, (4<<20)+16); err != nil {
		if errors.Is(err, ErrAnalysisLimit) {
			return out, ErrDisplaySource
		}
		return out, err
	}
	if err := analysisBoundedRows(query, db.Name(), "nonce", 1, 12); err != nil {
		if errors.Is(err, ErrAnalysisLimit) {
			return out, ErrDisplaySource
		}
		return out, err
	}
	type displayRow struct {
		DisplayEvidenceRecord
		NonceBytes, CipherBytes int64
	}
	var rows []displayRow
	columns = "organization_id,run_id,logical_sample_id,attempt_id,version,plaintext_bytes,captured_at_micros,expires_at_micros,created_at,COALESCE(length(nonce),0) AS nonce_bytes,COALESCE(length(ciphertext),0) AS cipher_bytes"
	for _, field := range []struct {
		column string
		size   int
	}{{"request_hash", 64}, {"policy", 64}, {"state", 64}, {"source_hash", 64}, {"key_version", 64}, {"payload_hash", 64}} {
		columns += "," + readBoundedText(db, field.column, field.column, field.size)
	}
	q = query.Select(columns).Limit(2)
	if lock && db.Name() == "postgres" {
		q = q.Clauses(clause.Locking{Strength: "SHARE"})
	}
	if err := q.Find(&rows).Error; err != nil {
		return out, err
	}
	if len(rows) > 1 {
		return out, ErrDisplaySource
	}
	if len(rows) == 1 {
		row := rows[0]
		out.present, out.record = true, row.DisplayEvidenceRecord
		if !validDisplayReadRow(row.DisplayEvidenceRecord, row.NonceBytes, row.CipherBytes, facts) {
			clear(out.record.Ciphertext)
			return displayReadSnapshot{}, ErrDisplaySource
		}
		if attempt.ResponseBodyReceipt == BodyNotCaptured || attempt.ResponseBodyReceipt == BodyNotRetained || attempt.Status == "UNCERTAIN" {
			clear(out.record.Ciphertext)
			return displayReadSnapshot{}, ErrDisplaySource
		}
		if envelope {
			// On the final READ COMMITTED path, metadata was locked FOR SHARE
			// before allocating cipher bytes. Initial reads use one repeatable
			// snapshot. Keep all real scope and receipt predicates on this read.
			var encrypted struct{ Nonce, Ciphertext []byte }
			fetched := db.Model(&DisplayEvidenceRecord{}).Select("nonce,ciphertext").Where("organization_id=? AND run_id=? AND logical_sample_id=? AND attempt_id=? AND policy=? AND state=? AND request_hash=? AND source_hash=? AND payload_hash=? AND key_version=? AND version=? AND plaintext_bytes=? AND captured_at_micros=? AND expires_at_micros=? AND COALESCE(length(nonce),0)<=12 AND COALESCE(length(ciphertext),0)<=?", orgID, selection.RunID, selection.SampleID, selection.AttemptID, out.record.Policy, out.record.State, out.record.RequestHash, out.record.SourceHash, out.record.PayloadHash, out.record.KeyVersion, out.record.Version, out.record.PlaintextBytes, out.record.CapturedAtMicros, out.record.ExpiresAtMicros, (4<<20)+16).Take(&encrypted)
			if fetched.Error != nil || fetched.RowsAffected != 1 {
				return displayReadSnapshot{}, ErrDisplaySource
			}
			out.record.Nonce, out.record.Ciphertext = encrypted.Nonce, encrypted.Ciphertext
			if !validDisplayRecord(out.record) {
				clear(out.record.Ciphertext)
				return displayReadSnapshot{}, ErrDisplaySource
			}
		}
	} else if attempt.ResponseBodyReceipt == BodyRecorded {
		return out, ErrDisplaySource
	}
	status, err := displayReadStatus(facts, out.record, out.present, policy)
	if err != nil {
		clear(out.record.Ciphertext)
		return displayReadSnapshot{}, err
	}
	out.metadata.Status, out.metadata.PayloadHash = status, out.record.PayloadHash
	type metadataRecord DisplayEvidenceRecord
	meta := metadataRecord(out.record)
	meta.Nonce, meta.Ciphertext = nil, nil
	out.metadataDigest, err = hashDisplayJSON([]any{facts, out.metadata, out.present, meta})
	if err != nil {
		clear(out.record.Ciphertext)
		return displayReadSnapshot{}, err
	}
	nonceHash, cipherHash := sha256.Sum256(out.record.Nonce), sha256.Sum256(out.record.Ciphertext)
	out.digest, err = hashDisplayJSON([]string{out.metadataDigest, hex.EncodeToString(nonceHash[:]), hex.EncodeToString(cipherHash[:])})
	return out, err
}

func validDisplayReadRow(row DisplayEvidenceRecord, nonceBytes, cipherBytes int64, facts displayReadFacts) bool {
	if row.OrganizationID != facts.OrganizationID || row.RunID != facts.Selection.RunID || row.LogicalSampleID != facts.Selection.SampleID || row.AttemptID != facts.Selection.AttemptID || row.RequestHash != facts.RequestHash || row.Policy != DisplayEvidencePolicy || row.CreatedAt.IsZero() || row.CreatedAt.Before(facts.FinishedAt) {
		return false
	}
	if row.State != DisplayCaptured {
		return nonceBytes == 0 && cipherBytes == 0 && validDisplayRecord(row)
	}
	return nonceBytes == 12 && row.PlaintextBytes > 0 && row.PlaintextBytes <= 4<<20 && cipherBytes == int64(row.PlaintextBytes)+16 && executionHash.MatchString(row.SourceHash) && executionHash.MatchString(row.PayloadHash) && row.Version == 1 && responseEvidenceVersion.MatchString(row.KeyVersion) && row.CapturedAtMicros >= facts.StartedAt.UnixMicro() && row.CapturedAtMicros <= facts.FinishedAt.UnixMicro() && row.CapturedAtMicros > 0 && row.CapturedAtMicros <= 1<<62 && row.ExpiresAtMicros >= row.CapturedAtMicros+responseRetentionDayMicros && row.ExpiresAtMicros <= row.CapturedAtMicros+180*responseRetentionDayMicros && (row.ExpiresAtMicros-row.CapturedAtMicros)%responseRetentionDayMicros == 0
}

func displayReadStatus(facts displayReadFacts, record DisplayEvidenceRecord, present bool, policy ResponseRetentionPolicy) (string, error) {
	if policy.OrganizationID() != facts.OrganizationID {
		return "", ErrDisplaySource
	}
	if policy.Days() == 0 {
		return DisplayReadPolicyZero, nil
	}
	if !present {
		if facts.AttemptStatus == "UNCERTAIN" {
			return DisplayReadUncertain, nil
		}
		switch facts.BodyReceipt {
		case DerivedLegacy:
			return DisplayReadLegacyUnverified, nil
		case BodyNotCaptured:
			return DisplayReadNotCaptured, nil
		case BodyNotRetained:
			return DisplayReadNotRetained, nil
		default:
			return "", ErrDisplaySource
		}
	}
	if record.State != DisplayCaptured {
		return record.State, nil
	}
	if !policy.EligibleAtObservation(record.CapturedAtMicros, record.ExpiresAtMicros, false) {
		return DisplayReadExpired, nil
	}
	return DisplayReadAvailable, nil
}
