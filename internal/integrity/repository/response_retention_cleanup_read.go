package repository

import (
	"errors"
	"strconv"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func deletionColumns(db *gorm.DB) string {
	columns := "organization_id,run_id,logical_sample_id,attempt_id,batch_id,captured_at_micros,expires_at_micros,deleted_at_micros,ciphertext_bytes"
	for _, f := range []struct {
		name string
		size int
	}{{"source_kind", 32}, {"policy", 64}, {"request_hash", 64}, {"content_hash", 64}, {"source_hash", 64}, {"reason", 32}} {
		columns += "," + readBoundedText(db, f.name, f.name, f.size)
	}
	return columns
}

func verifyResponseRetentionBatch(store *Store, db *gorm.DB, orgID, batchID int64) (responseRetentionBatch, []evidenceDeletion, error) {
	var batch responseRetentionBatch
	if store == nil || store.auditSigner == nil || orgID <= 0 || batchID <= 0 {
		return batch, nil, ErrRetentionSource
	}
	columns := "id,organization_id,run_id,job_id,created_by,created_at,completed_at,policy_days,policy_version,policy_cutoff_micros,observed_at_micros,deleted_rows,deleted_bytes," + readBoundedText(db, "state", "state", 16) + "," + readBoundedText(db, "receipt_hash", "receipt_hash", 64)
	if err := db.Select(columns).Where("organization_id=? AND id=?", orgID, batchID).Take(&batch).Error; err != nil {
		return batch, nil, err
	}
	var items []evidenceDeletion
	if err := db.Select(deletionColumns(db)).Where("organization_id=? AND batch_id=?", orgID, batchID).Order("attempt_id,source_kind").Limit(retentionBatchRows + 1).Find(&items).Error; err != nil {
		return batch, nil, err
	}
	hash, err := responseRetentionReceiptHash(batch, items)
	if err != nil || hash != batch.ReceiptHash || !executionHash.MatchString(hash) {
		return batch, nil, ErrRetentionSource
	}
	var count int64
	if err := db.Model(&Job{}).Where("organization_id=? AND id=? AND type=? AND object_id=? AND idempotency_key=? AND status='completed'", orgID, *batch.JobID, string(JobRetentionDelete), batch.ID, "response-retention:"+strconv.FormatInt(batch.ID, 10)).Count(&count).Error; err != nil {
		return batch, nil, err
	}
	if count != 1 {
		return batch, nil, ErrRetentionSource
	}
	// Verify the actual signed event, not a caller-supplied/plain SQL hash. Event
	// canonicalization and historical audit key versions remain unchanged.
	var events []audit.Event
	eventColumns := "id,organization_id,sequence,actor_id,created_at"
	for _, f := range []struct {
		name string
		size int
	}{{"action", 128}, {"object_type", 128}, {"object_id", 128}, {"result", 128}, {"ip_summary", 128}, {"user_agent_summary", 128}, {"diff_summary", 1024}, {"previous_hash", 64}, {"event_hmac", 64}, {"canonicalization_version", 64}, {"key_version", 128}} {
		eventColumns += "," + readBoundedText(db, f.name, f.name, f.size)
	}
	if err := db.Select(eventColumns).Where("organization_id=? AND action=? AND object_type=? AND object_id=?", orgID, retentionAuditAction, retentionAuditObject, strconv.FormatInt(batch.ID, 10)+":"+hash).Limit(2).Find(&events).Error; err != nil {
		return batch, nil, err
	}
	if len(events) != 1 || events[0].ActorID == nil || *events[0].ActorID != batch.CreatedBy || events[0].Result != "success" || events[0].CreatedAt.Before(*batch.CompletedAt) || audit.Verify(events[0], store.auditSigner) != nil {
		return batch, nil, ErrRetentionSource
	}
	return batch, items, nil
}

func loadVerifiedEvidenceDeletion(store *Store, db *gorm.DB, orgID, attemptID int64, source string) (*evidenceDeletion, error) {
	var rows []evidenceDeletion
	if err := db.Select(deletionColumns(db)).Where("organization_id=? AND attempt_id=? AND source_kind=?", orgID, attemptID, source).Limit(2).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	if len(rows) != 1 {
		return nil, ErrRetentionSource
	}
	_, items, err := verifyResponseRetentionBatch(store, db, orgID, rows[0].BatchID)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if item.AttemptID == attemptID && item.SourceKind == source {
			if item != rows[0] {
				return nil, ErrRetentionSource
			}
			copy := item
			return &copy, nil
		}
	}
	return nil, ErrRetentionSource
}

// ReadResponseRetentionSummary supplies only live S1 storage observations for
// an authorized published Run. It does not mutate immutable report artifacts,
// assert successful decryption, or claim that other retention classes are done.
func (t *Tenant) ReadResponseRetentionSummary(runID int64) (ResponseRetentionSummary, error) {
	var out ResponseRetentionSummary
	if t == nil || t.store == nil || t.ctx == nil || t.orgID <= 0 || runID <= 0 {
		return out, ErrNotFound
	}
	var businessErr error
	err := t.resultReadTransaction(true, func(db *gorm.DB) error {
		businessErr = func() error {
			if err := publishedReviewScope(db, t.orgID, runID, 1); err != nil {
				return err
			}
			org, err := loadResponseRetentionOrganization(db, t.store.driver, t.orgID, false)
			if err != nil {
				return err
			}
			policy, err := responseRetentionObservation(org, db, t.store.driver)
			if err != nil {
				return err
			}
			out.ObservedAt = time.UnixMicro(policy.observedAtMicros).UTC()
			out.PolicyDays = policy.days
			out.PolicyVersion = policy.version
			var attempts int64
			if err := db.Model(&AttemptRecord{}).Where("organization_id=? AND run_id=?", t.orgID, runID).Count(&attempts).Error; err != nil {
				return err
			}
			if attempts < 0 || attempts > 1536 {
				return ErrRetentionSource
			}
			out.AttemptCount = int(attempts)
			var items []evidenceDeletion
			if err := db.Select(deletionColumns(db)).Where("organization_id=? AND run_id=?", t.orgID, runID).Order("batch_id,attempt_id,source_kind").Limit(3073).Find(&items).Error; err != nil {
				return err
			}
			if len(items) > 3072 {
				return ErrRetentionSource
			}
			var inconsistent int64
			if err := db.Raw("SELECT COUNT(*) FROM integrity_evidence_deletions d WHERE d.organization_id=? AND d.run_id=? AND ((d.source_kind='analysis-response' AND EXISTS (SELECT 1 FROM integrity_response_evidence r WHERE r.organization_id=d.organization_id AND r.attempt_id=d.attempt_id)) OR (d.source_kind='response-display' AND EXISTS (SELECT 1 FROM integrity_display_evidence e WHERE e.organization_id=d.organization_id AND e.attempt_id=d.attempt_id)))", t.orgID, runID).Scan(&inconsistent).Error; err != nil {
				return err
			}
			if inconsistent != 0 {
				return ErrRetentionSource
			}
			if err := db.Raw("SELECT COUNT(*) FROM integrity_evidence_deletions d LEFT JOIN integrity_sample_attempts a ON a.organization_id=d.organization_id AND a.id=d.attempt_id WHERE d.organization_id=? AND d.run_id=? AND (a.id IS NULL OR a.run_id<>d.run_id OR a.logical_sample_id<>d.logical_sample_id OR a.request_hash<>d.request_hash OR a.status<>'COMPLETED' OR a.response_body_receipt NOT IN ('legacy_not_recorded','recorded'))", t.orgID, runID).Scan(&inconsistent).Error; err != nil {
				return err
			}
			if inconsistent != 0 {
				return ErrRetentionSource
			}
			if err := db.Raw("SELECT COUNT(*) FROM integrity_sample_attempts a WHERE a.organization_id=? AND a.run_id=? AND a.response_body_receipt='recorded' AND ((NOT EXISTS (SELECT 1 FROM integrity_response_evidence r WHERE r.organization_id=a.organization_id AND r.attempt_id=a.id) AND NOT EXISTS (SELECT 1 FROM integrity_evidence_deletions d WHERE d.organization_id=a.organization_id AND d.attempt_id=a.id AND d.source_kind='analysis-response')) OR (NOT EXISTS (SELECT 1 FROM integrity_display_evidence e WHERE e.organization_id=a.organization_id AND e.attempt_id=a.id) AND NOT EXISTS (SELECT 1 FROM integrity_evidence_deletions d WHERE d.organization_id=a.organization_id AND d.attempt_id=a.id AND d.source_kind='response-display')))", t.orgID, runID).Scan(&inconsistent).Error; err != nil {
				return err
			}
			if inconsistent != 0 {
				return ErrRetentionSource
			}
			verified := map[int64]map[[2]string]evidenceDeletion{}
			for _, item := range items {
				known, ok := verified[item.BatchID]
				if !ok {
					_, members, err := verifyResponseRetentionBatch(t.store, db, t.orgID, item.BatchID)
					if err != nil {
						return err
					}
					known = map[[2]string]evidenceDeletion{}
					for _, member := range members {
						known[[2]string{strconv.FormatInt(member.AttemptID, 10), member.SourceKind}] = member
					}
					verified[item.BatchID] = known
				}
				if known[[2]string{strconv.FormatInt(item.AttemptID, 10), item.SourceKind}] != item {
					return ErrRetentionSource
				}
				if item.SourceKind == retentionRawSource {
					out.RawDeletedCount++
				} else {
					out.DisplayDeletedCount++
				}
				deleted := time.UnixMicro(item.DeletedAtMicros).UTC()
				if out.LastDeletedAt == nil || deleted.After(*out.LastDeletedAt) {
					out.LastDeletedAt = &deleted
				}
			}
			retained, expired, err := responseRetentionDisplayCounts(db, t.orgID, runID, attempts, policy)
			if err != nil {
				return err
			}
			if retained < 0 || retained > attempts || expired < 0 || expired > retained || int64(out.RawDeletedCount) > attempts || int64(out.DisplayDeletedCount)+retained > attempts {
				return ErrRetentionSource
			}
			out.DisplayExpiredCount = int(expired)
			out.DisplayRetainedCount = int(retained - expired)
			return nil
		}()
		return businessErr
	})
	if err != nil {
		if errors.Is(businessErr, ErrRetentionSource) {
			return ResponseRetentionSummary{}, ErrRetentionSource
		}
		return ResponseRetentionSummary{}, err
	}
	return out, nil
}

// One bounded joined metadata read replaces a per-Attempt lookup or blind
// COUNT(state='captured'). SQL projects only fixed metadata and byte lengths,
// never nonce/ciphertext. Counts prove shape/scope/retention, not decryption.
func responseRetentionDisplayCounts(db *gorm.DB, orgID, runID, attempts int64, policy ResponseRetentionPolicy) (int64, int64, error) {
	type row struct {
		DisplayEvidenceRecord
		NonceBytes, CipherBytes                    int64
		AttemptRunID, AttemptSampleID              int64
		AttemptRequestHash, AttemptStatus, Receipt string
		StartedAt, FinishedAt                      *time.Time
	}
	columns := "e.organization_id,e.run_id,e.logical_sample_id,e.attempt_id,e.version,e.plaintext_bytes,e.captured_at_micros,e.expires_at_micros,e.created_at,COALESCE(length(e.nonce),0) AS nonce_bytes,COALESCE(length(e.ciphertext),0) AS cipher_bytes,a.run_id AS attempt_run_id,a.logical_sample_id AS attempt_sample_id,a.started_at,a.finished_at"
	for _, f := range []struct {
		column, alias string
		size          int
	}{{"e.request_hash", "request_hash", 64}, {"e.policy", "policy", 64}, {"e.state", "state", 64}, {"e.source_hash", "source_hash", 64}, {"e.payload_hash", "payload_hash", 64}, {"e.key_version", "key_version", 64}, {"a.request_hash", "attempt_request_hash", 64}, {"a.status", "attempt_status", 16}, {"a.response_body_receipt", "receipt", 32}} {
		columns += "," + readBoundedText(db, f.column, f.alias, f.size)
	}
	var rows []row
	if err := db.Table("integrity_display_evidence e").Select(columns).Joins("LEFT JOIN integrity_sample_attempts a ON a.organization_id=e.organization_id AND a.id=e.attempt_id").Where("e.organization_id=? AND e.run_id=?", orgID, runID).Order("e.attempt_id,e.policy").Limit(1537).Find(&rows).Error; err != nil {
		return 0, 0, err
	}
	if len(rows) > 1536 || int64(len(rows)) > attempts {
		return 0, 0, ErrRetentionSource
	}
	var captured, expired int64
	for _, r := range rows {
		if r.AttemptRunID != runID || r.AttemptSampleID <= 0 || r.StartedAt == nil || r.FinishedAt == nil || r.FinishedAt.Before(*r.StartedAt) || r.AttemptStatus != "COMPLETED" || (r.Receipt != DerivedLegacy && r.Receipt != BodyRecorded) || !executionHash.MatchString(r.AttemptRequestHash) {
			return 0, 0, ErrRetentionSource
		}
		facts := displayReadFacts{OrganizationID: orgID, Selection: DisplaySelection{RunID: runID, SampleID: r.AttemptSampleID, AttemptID: r.AttemptID}, RequestHash: r.AttemptRequestHash, StartedAt: *r.StartedAt, FinishedAt: *r.FinishedAt}
		if !validDisplayReadRow(r.DisplayEvidenceRecord, r.NonceBytes, r.CipherBytes, facts) {
			return 0, 0, ErrRetentionSource
		}
		if r.State == DisplayCaptured {
			reason, err := responseDeletionReason(policy, r.CapturedAtMicros, r.ExpiresAtMicros)
			if err != nil {
				return 0, 0, err
			}
			captured++
			if reason != "" {
				expired++
			}
		}
	}
	return captured, expired, nil
}
