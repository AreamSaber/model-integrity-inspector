package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

var ErrRetentionSource = errors.New("MI_RETENTION_SOURCE_INVALID")

const (
	retentionBatchRows     = 32
	retentionBatchBytes    = 8 << 20
	retentionRawSource     = "analysis-response"
	retentionDisplaySource = "response-display"
	retentionRawPolicy     = "analysis-response-v1"
	retentionAuditAction   = "response.evidence.delete"
	retentionAuditObject   = "response_retention_batch"
)

// Fixed aliases are shared by Claim and reconcile. This grants only the
// disabled-organization exception, never an exception to cancellation, retry
// limits, or lease fencing. Legacy organization-only retention Jobs do not bind.
const retentionDisabledJobSQL = `o.status='disabled' AND j.type='integrity.retention.delete'
 AND j.object_id<>j.organization_id AND j.idempotency_key='response-retention:' || CAST(j.object_id AS TEXT)
 AND EXISTS (SELECT 1 FROM integrity_response_retention_batches b
 JOIN integrity_runs r ON r.organization_id=b.organization_id AND r.id=b.run_id AND r.created_by=b.created_by
 WHERE b.organization_id=j.organization_id AND b.id=j.object_id AND b.job_id=j.id
 AND b.run_id>0 AND b.created_by>0 AND b.state='planned')`

type responseRetentionSchedule struct {
	OrganizationID           int64 `gorm:"primaryKey"`
	NextDueAt, LastCheckedAt time.Time
	SweepDay, CursorRunID    int64
	ActiveBatchID            *int64
}

func (responseRetentionSchedule) TableName() string { return "integrity_response_retention_schedule" }

type responseRetentionBatch struct {
	ID                                   int64 `gorm:"primaryKey"`
	OrganizationID, RunID                int64
	JobID                                *int64
	CreatedBy                            int64
	State                                string
	CreatedAt                            time.Time
	CompletedAt                          *time.Time
	PolicyDays, PolicyVersion            int
	PolicyCutoffMicros, ObservedAtMicros int64
	DeletedRows                          int
	DeletedBytes                         int64
	ReceiptHash                          string
}

func (responseRetentionBatch) TableName() string { return "integrity_response_retention_batches" }

// evidenceDeletion certifies removal of one stored S2 object, not authenticity
// of its plaintext. Its canonical batch is bound to an existing signed audit
// event. No credential, nonce, body or arbitrary user text may enter this type.
type evidenceDeletion struct {
	OrganizationID, RunID, LogicalSampleID, AttemptID  int64
	SourceKind, Policy                                 string
	BatchID                                            int64
	RequestHash, ContentHash, SourceHash               string
	CapturedAtMicros, ExpiresAtMicros, DeletedAtMicros int64
	Reason                                             string
	CiphertextBytes                                    int64
}

func (evidenceDeletion) TableName() string { return "integrity_evidence_deletions" }

// ResponseRetentionSummary is authorized S1 metadata for one published Run.
// Counts refer only to response objects, not request snapshots or all M6 data.
type ResponseRetentionSummary struct {
	ObservedAt                                         time.Time
	PolicyDays, PolicyVersion                          int
	AttemptCount, RawDeletedCount, DisplayDeletedCount int
	DisplayExpiredCount, DisplayRetainedCount          int
	LastDeletedAt                                      *time.Time
}

// Expiry is distinct from read eligibility: a disabled organization, malformed
// timestamp, or unavailable actor is never authority to delete a live body.
func responseDeletionReason(policy ResponseRetentionPolicy, captured, expiry int64) (string, error) {
	if policy.organizationID <= 0 || policy.version <= 0 || policy.days < 0 || policy.days > 180 || policy.notBeforeMicros < 0 || policy.observedAtMicros <= 0 || captured <= 0 || captured > policy.observedAtMicros || expiry <= captured {
		return "", ErrRetentionSource
	}
	switch {
	case policy.days == 0:
		return "policy_zero", nil
	case expiry <= policy.observedAtMicros:
		return "sealed_expiry", nil
	case captured <= policy.notBeforeMicros:
		return "policy_cutoff", nil
	case captured <= policy.observedAtMicros-int64(policy.days)*responseRetentionDayMicros:
		return "day_window", nil
	default:
		return "", nil
	}
}

func validEvidenceDeletion(d evidenceDeletion, batch responseRetentionBatch) bool {
	if d.OrganizationID != batch.OrganizationID || d.RunID != batch.RunID || d.BatchID != batch.ID || d.LogicalSampleID <= 0 || d.AttemptID <= 0 || !executionHash.MatchString(d.RequestHash) || !executionHash.MatchString(d.ContentHash) || d.DeletedAtMicros != batch.ObservedAtMicros || d.CiphertextBytes < 17 || d.CiphertextBytes > (4<<20)+16 {
		return false
	}
	if d.SourceKind == retentionRawSource {
		if d.Policy != retentionRawPolicy || d.SourceHash != "" || d.CiphertextBytes > (1<<20)+16 {
			return false
		}
	} else if d.SourceKind != retentionDisplaySource || d.Policy != DisplayEvidencePolicy || !executionHash.MatchString(d.SourceHash) {
		return false
	}
	p := ResponseRetentionPolicy{organizationID: batch.OrganizationID, version: batch.PolicyVersion, days: batch.PolicyDays, notBeforeMicros: batch.PolicyCutoffMicros, observedAtMicros: batch.ObservedAtMicros}
	reason, err := responseDeletionReason(p, d.CapturedAtMicros, d.ExpiresAtMicros)
	return err == nil && reason != "" && reason == d.Reason
}

func responseRetentionReceiptHash(batch responseRetentionBatch, items []evidenceDeletion) (string, error) {
	if batch.ID <= 0 || batch.OrganizationID <= 0 || batch.RunID <= 0 || batch.JobID == nil || *batch.JobID <= 0 || batch.CreatedBy <= 0 || batch.CreatedAt.IsZero() || batch.State != "completed" || batch.CompletedAt == nil || batch.CompletedAt.UnixMicro() != batch.ObservedAtMicros || batch.CompletedAt.Before(batch.CreatedAt) || batch.PolicyVersion <= 0 || batch.PolicyDays < 0 || batch.PolicyDays > 180 || batch.PolicyCutoffMicros < 0 || batch.ObservedAtMicros <= 0 || len(items) != batch.DeletedRows || len(items) > retentionBatchRows || batch.DeletedBytes < 0 || batch.DeletedBytes > retentionBatchBytes {
		return "", ErrRetentionSource
	}
	ordered := slices.Clone(items)
	slices.SortFunc(ordered, func(a, b evidenceDeletion) int {
		if a.AttemptID < b.AttemptID {
			return -1
		}
		if a.AttemptID > b.AttemptID {
			return 1
		}
		if a.SourceKind < b.SourceKind {
			return -1
		}
		if a.SourceKind > b.SourceKind {
			return 1
		}
		return 0
	})
	var total int64
	for i, item := range ordered {
		if !validEvidenceDeletion(item, batch) || i > 0 && ordered[i-1].AttemptID == item.AttemptID && ordered[i-1].SourceKind == item.SourceKind {
			return "", ErrRetentionSource
		}
		total += item.CiphertextBytes
	}
	if total != batch.DeletedBytes {
		return "", ErrRetentionSource
	}
	batch.ReceiptHash = ""
	encoded, err := json.Marshal(struct {
		Version string
		Batch   responseRetentionBatch
		Items   []evidenceDeletion
	}{"mii.response-deletion.v1", batch, ordered})
	if err != nil {
		return "", ErrRetentionSource
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
