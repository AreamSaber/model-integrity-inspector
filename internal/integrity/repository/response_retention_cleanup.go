package repository

import (
	"errors"
	"strconv"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// DeleteResponseEvidenceBatch accepts no caller-selected object, clock, policy,
// actor or limit. The current completion lease is its only execution authority.
func (tx *TenantTransaction) DeleteResponseEvidenceBatch() error {
	if tx == nil || tx.store == nil || tx.closed.Load() {
		return ErrTransactionClosed
	}
	if !tx.completing || tx.leaseJobID <= 0 || tx.leaseGeneration <= 0 {
		return ErrJobInvalid
	}
	var job Job
	if err := tx.db.Where("organization_id=? AND id=? AND status='running' AND attempt_count=?", tx.orgID, tx.leaseJobID, tx.leaseGeneration).Take(&job).Error; err != nil {
		return executionLeaseLookupError(err)
	}
	if JobType(job.Type) != JobRetentionDelete || job.ObjectID == tx.orgID {
		return ErrJobInvalid
	}
	batch, err := retentionJobBatch(tx.db, job)
	if err != nil {
		return err
	}
	policy, err := tx.LockResponseRetentionPolicy()
	if err != nil {
		return err
	}
	var schedule responseRetentionSchedule
	query := tx.db.Where("organization_id=? AND active_batch_id=?", tx.orgID, batch.ID)
	if tx.store.driver == "postgres" {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	if err := query.Take(&schedule).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrRetentionSource
		}
		return err
	}
	query = tx.db.Select("id,organization_id,created_by").Where("organization_id=? AND id=?", tx.orgID, batch.RunID)
	if tx.store.driver == "postgres" {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var run RunRecord
	if err := query.Take(&run).Error; err != nil {
		return err
	}
	if run.CreatedBy != batch.CreatedBy {
		return ErrRetentionSource
	}
	rows, err := loadExpiredResponseMetadata(tx.db, tx.orgID, batch.RunID, policy, true)
	if err != nil {
		return err
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return err
	}
	policy.observedAtMicros = now.UnixMicro()
	items := make([]evidenceDeletion, 0, len(rows))
	var total int64
	for _, row := range rows {
		if err := validateRetentionObject(tx.db, row, tx.orgID, batch.RunID); err != nil {
			return err
		}
		if total+row.CipherBytes > retentionBatchBytes {
			break
		}
		reason, err := responseDeletionReason(policy, row.CapturedMicros(), row.ExpiryMicros())
		if err != nil {
			return err
		}
		if reason == "" {
			return ErrRetentionSource
		}
		var existing int64
		if err := tx.db.Model(&evidenceDeletion{}).Where("organization_id=? AND attempt_id=? AND source_kind=?", tx.orgID, row.AttemptID, row.SourceKind).Count(&existing).Error; err != nil {
			return err
		}
		if existing != 0 {
			return ErrRetentionSource
		}
		item := evidenceDeletion{OrganizationID: tx.orgID, RunID: batch.RunID, LogicalSampleID: row.LogicalSampleID, AttemptID: row.AttemptID, SourceKind: row.SourceKind, Policy: row.Policy, BatchID: batch.ID, RequestHash: row.RequestHash, ContentHash: row.ContentHash, SourceHash: row.SourceHash, CapturedAtMicros: row.CapturedMicros(), ExpiresAtMicros: row.ExpiryMicros(), DeletedAtMicros: now.UnixMicro(), Reason: reason, CiphertextBytes: row.CipherBytes}
		if err := tx.db.Create(&item).Error; err != nil {
			return err
		}
		deleted := deleteRetentionObject(tx.db, row, tx.orgID, batch.RunID)
		if deleted.Error != nil {
			return deleted.Error
		}
		if deleted.RowsAffected != 1 {
			return ErrRetentionSource
		}
		items = append(items, item)
		total += row.CipherBytes
	}
	batch.State = "completed"
	batch.CompletedAt = &now
	batch.PolicyDays = policy.days
	batch.PolicyVersion = policy.version
	batch.PolicyCutoffMicros = policy.notBeforeMicros
	batch.ObservedAtMicros = now.UnixMicro()
	batch.DeletedRows = len(items)
	batch.DeletedBytes = total
	batch.ReceiptHash, err = responseRetentionReceiptHash(batch, items)
	if err != nil {
		return err
	}
	updated := tx.db.Model(&responseRetentionBatch{}).Where("organization_id=? AND id=? AND job_id=? AND state='planned'", tx.orgID, batch.ID, job.ID).Updates(map[string]any{"state": batch.State, "completed_at": now, "policy_days": batch.PolicyDays, "policy_version": batch.PolicyVersion, "policy_cutoff_micros": batch.PolicyCutoffMicros, "observed_at_micros": batch.ObservedAtMicros, "deleted_rows": batch.DeletedRows, "deleted_bytes": batch.DeletedBytes, "receipt_hash": batch.ReceiptHash})
	if updated.Error != nil {
		return updated.Error
	}
	if updated.RowsAffected != 1 {
		return ErrRetentionSource
	}
	// Revisit this Run after a non-empty bounded batch; a zero batch advances it.
	// The same daily sweep resumes after a restart from this committed cursor.
	cursor := batch.RunID
	if len(items) > 0 {
		cursor--
	}
	updated = tx.db.Model(&responseRetentionSchedule{}).Where("organization_id=? AND active_batch_id=?", tx.orgID, batch.ID).Updates(map[string]any{"active_batch_id": nil, "cursor_run_id": cursor, "last_checked_at": now})
	if updated.Error != nil {
		return updated.Error
	}
	if updated.RowsAffected != 1 {
		return ErrRetentionSource
	}
	if err := tx.store.appendAuditWithClock(tx.ctx, tx.db, tx.orgID, AuditCommand{Action: retentionAuditAction, ObjectType: retentionAuditObject, ObjectID: strconv.FormatInt(batch.ID, 10) + ":" + batch.ReceiptHash, Result: "success"}, nil, true); err != nil {
		return err
	}
	if tx.store.driver == "sqlite" {
		// CompleteWith fences the Job after this callback, but that does not
		// replace the separate SQLite process-consumer authority. Recheck its
		// persisted owner and fresh expiry after every deletion/audit lock wait;
		// never renew or resurrect an expired consumer from this transaction.
		now, err = queueTime(tx.db, tx.store.driver)
		if err != nil {
			return err
		}
		if job.LeaseOwner == nil || *job.LeaseOwner == "" {
			return ErrJobLeaseLost
		}
		var count int64
		if err := tx.db.Table("integrity_queue_consumer_leases").Where("lock_name=? AND owner=? AND lease_until>?", queueConsumerName, *job.LeaseOwner, now).Count(&count).Error; err != nil {
			return err
		}
		if count != 1 {
			return ErrConsumerLost
		}
	}
	return nil
}

func retentionJobBatch(db *gorm.DB, job Job) (responseRetentionBatch, error) {
	var batch responseRetentionBatch
	if JobType(job.Type) != JobRetentionDelete || job.OrganizationID <= 0 || job.ObjectID <= 0 || job.ObjectID == job.OrganizationID || job.IdempotencyKey != "response-retention:"+strconv.FormatInt(job.ObjectID, 10) {
		return batch, ErrJobInvalid
	}
	if err := db.Where("organization_id=? AND id=? AND job_id=? AND state='planned'", job.OrganizationID, job.ObjectID, job.ID).Take(&batch).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return batch, ErrJobInvalid
		}
		return batch, err
	}
	if batch.CreatedBy <= 0 || batch.RunID <= 0 || batch.CreatedAt.IsZero() {
		return batch, ErrJobInvalid
	}
	var creator int64
	read := db.Model(&RunRecord{}).Select("created_by").Where("organization_id=? AND id=?", batch.OrganizationID, batch.RunID).Scan(&creator)
	if read.Error != nil {
		return batch, read.Error
	}
	if read.RowsAffected != 1 || creator != batch.CreatedBy {
		return batch, ErrJobInvalid
	}
	return batch, nil
}

// These fields are SQL-bounded metadata; ciphertext and nonce are never read.
type retentionObject struct {
	OrganizationID, RunID, LogicalSampleID, AttemptID                    int64
	SourceKind, Policy, RequestHash, ContentHash, SourceHash, KeyVersion string
	PlaintextBytes, Version                                              int
	CapturedAtMicros, ExpiresAtMicros                                    int64
	CreatedAt, ExpiresAt                                                 time.Time
	NonceBytes, CipherBytes                                              int64
}

func (r retentionObject) CapturedMicros() int64 {
	if r.SourceKind == retentionRawSource {
		return r.CreatedAt.UnixMicro()
	}
	return r.CapturedAtMicros
}
func (r retentionObject) ExpiryMicros() int64 {
	if r.SourceKind == retentionRawSource {
		return r.ExpiresAt.UnixMicro()
	}
	return r.ExpiresAtMicros
}

func loadExpiredResponseMetadata(db *gorm.DB, orgID, runID int64, policy ResponseRetentionPolicy, lock bool) ([]retentionObject, error) {
	var objects []retentionObject
	for _, source := range []string{retentionRawSource, retentionDisplaySource} {
		remaining := retentionBatchRows - len(objects)
		if remaining == 0 {
			break
		}
		columns := "organization_id,run_id,logical_sample_id,attempt_id,plaintext_bytes,created_at,COALESCE(length(nonce),0) AS nonce_bytes,COALESCE(length(ciphertext),0) AS cipher_bytes"
		columns += "," + readBoundedText(db, "request_hash", "request_hash", 64) + "," + readBoundedText(db, "key_version", "key_version", 64)
		if source == retentionRawSource {
			columns += ",expires_at," + readBoundedText(db, "content_hash", "content_hash", 64)
		} else {
			columns += ",captured_at_micros,expires_at_micros,version," + readBoundedText(db, "source_hash", "source_hash", 64) + "," + readBoundedText(db, "payload_hash", "content_hash", 64) + "," + readBoundedText(db, "policy", "policy", 64)
		}
		query := expiredResponseQuery(db, orgID, runID, source, policy).Select(columns).Order("attempt_id").Limit(remaining)
		if lock && db.Name() == "postgres" {
			query = query.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		var rows []retentionObject
		if err := query.Find(&rows).Error; err != nil {
			return nil, err
		}
		for i := range rows {
			rows[i].SourceKind = source
			if source == retentionRawSource {
				rows[i].Policy = retentionRawPolicy
			}
		}
		objects = append(objects, rows...)
	}
	return objects, nil
}

func validateRetentionObject(db *gorm.DB, r retentionObject, orgID, runID int64) error {
	if r.OrganizationID != orgID || r.RunID != runID || r.LogicalSampleID <= 0 || r.AttemptID <= 0 || !executionHash.MatchString(r.RequestHash) || !executionHash.MatchString(r.ContentHash) || !responseEvidenceVersion.MatchString(r.KeyVersion) || r.NonceBytes != 12 || r.PlaintextBytes < 1 || r.CipherBytes != int64(r.PlaintextBytes)+16 || r.CreatedAt.IsZero() {
		return ErrRetentionSource
	}
	var attempt AttemptRecord
	columns := "id,organization_id,run_id,logical_sample_id,started_at,finished_at," + readBoundedText(db, "request_hash", "request_hash", 64) + "," + readBoundedText(db, "status", "status", 16)
	if err := db.Select(columns).Where("organization_id=? AND run_id=? AND logical_sample_id=? AND id=?", orgID, runID, r.LogicalSampleID, r.AttemptID).Take(&attempt).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrRetentionSource
		}
		return err
	}
	if attempt.RequestHash != r.RequestHash || attempt.Status != "COMPLETED" || attempt.StartedAt == nil || attempt.FinishedAt == nil || attempt.FinishedAt.Before(*attempt.StartedAt) || r.CapturedMicros() < attempt.StartedAt.UnixMicro() || r.CapturedMicros() > attempt.FinishedAt.UnixMicro() {
		return ErrRetentionSource
	}
	if r.SourceKind == retentionRawSource {
		if r.Policy != retentionRawPolicy || r.PlaintextBytes > 1<<20 || r.SourceHash != "" || r.ExpiresAt.IsZero() {
			return ErrRetentionSource
		}
	} else if r.SourceKind != retentionDisplaySource || r.Policy != DisplayEvidencePolicy || r.Version != 1 || r.PlaintextBytes > 4<<20 || !executionHash.MatchString(r.SourceHash) || r.CreatedAt.Before(*attempt.FinishedAt) || r.ExpiresAtMicros-r.CapturedAtMicros < responseRetentionDayMicros || r.ExpiresAtMicros-r.CapturedAtMicros > 180*responseRetentionDayMicros || (r.ExpiresAtMicros-r.CapturedAtMicros)%responseRetentionDayMicros != 0 {
		return ErrRetentionSource
	}
	return nil
}

func deleteRetentionObject(db *gorm.DB, r retentionObject, orgID, runID int64) *gorm.DB {
	q := db.Where("organization_id=? AND run_id=? AND logical_sample_id=? AND attempt_id=? AND request_hash=? AND key_version=? AND plaintext_bytes=? AND length(nonce)=? AND length(ciphertext)=?", orgID, runID, r.LogicalSampleID, r.AttemptID, r.RequestHash, r.KeyVersion, r.PlaintextBytes, r.NonceBytes, r.CipherBytes)
	if r.SourceKind == retentionRawSource {
		return q.Where("content_hash=? AND created_at=? AND expires_at=?", r.ContentHash, r.CreatedAt, r.ExpiresAt).Delete(&ResponseEvidenceRecord{})
	}
	return q.Where("policy=? AND state='captured' AND source_hash=? AND payload_hash=? AND version=? AND captured_at_micros=? AND expires_at_micros=? AND created_at=?", r.Policy, r.SourceHash, r.ContentHash, r.Version, r.CapturedAtMicros, r.ExpiresAtMicros, r.CreatedAt).Delete(&DisplayEvidenceRecord{})
}
