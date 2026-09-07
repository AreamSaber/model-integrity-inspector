package repository

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"time"

	"gorm.io/gorm/clause"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

var (
	ErrPrecheckStale   = errors.New("MI_PRECHECK_STALE")
	ErrPrecheckExpired = errors.New("MI_PRECHECK_EXPIRED")
	ErrPrecheckBudget  = errors.New("MI_PRECHECK_BUDGET_EXCEEDED")
	ErrJobCancelled    = errors.New("JOB_CANCELLED")
)

const PrecheckMaxRequests = 3
const PrecheckLifetime = 15 * time.Minute
const PrecheckExecutionLimit = 60 * time.Second

type PrecheckRecord struct {
	ID                 int64
	OrganizationID     int64
	TargetID           int64
	TargetVersion      int64
	SecretID           int64
	SecretVersion      int64
	RequestKey         string `json:"-"`
	SnapshotJSON       string `json:"-"`
	Status             string
	JobID              *int64
	RequestCount       int
	MaxOutputParameter string
	ResultJSON         string
	ErrorCode          string
	CreatedBy          int64
	CreatedAt          time.Time
	StartedAt          *time.Time
	FinishedAt         *time.Time
	Version            int64
}

func (PrecheckRecord) TableName() string { return "integrity_target_prechecks" }

// PrecheckCheck is a closed classification vocabulary, never an upstream body,
// header value, provider request ID, claimed model name or parser diagnostic.
type PrecheckCheck struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
}

type PrecheckOutcome struct {
	Status             string
	Checks             []PrecheckCheck
	MaxOutputParameter string
	ErrorCode          string
}

var precheckRequestKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var precheckCodes = map[string]bool{
	"": true, "MI_AUTH_FAILED": true, "MI_MODEL_NOT_FOUND": true, "MI_PROTOCOL_UNSUPPORTED": true,
	"MI_RATE_LIMITED": true, "MI_TARGET_BLOCKED_ADDRESS": true, "MI_SECRET_UNAVAILABLE": true,
	"MI_SERVICE_UNAVAILABLE": true, "MI_NETWORK_FAILED": true, "MI_TIMEOUT": true,
	"MI_PRECHECK_STALE": true, "MI_PRECHECK_EXPIRED": true, "MI_PRECHECK_CANCELLED": true,
	"MI_UNCERTAIN_ATTEMPT": true, "MI_PRECHECK_BUDGET_EXCEEDED": true,
	"MI_PRECHECK_ATTEMPTS_EXHAUSTED": true,
}

func validPrecheckOutcome(outcome PrecheckOutcome) bool {
	if (outcome.Status != "passed" && outcome.Status != "failed") || len(outcome.Checks) > 6 || !precheckCodes[outcome.ErrorCode] ||
		(outcome.MaxOutputParameter != "" && outcome.MaxOutputParameter != "max_tokens" && outcome.MaxOutputParameter != "max_completion_tokens") {
		return false
	}
	if (outcome.Status == "passed" && (outcome.ErrorCode != "" || len(outcome.Checks) != 6 || outcome.MaxOutputParameter == "")) || (outcome.Status == "failed" && outcome.ErrorCode == "") {
		return false
	}
	seen := map[string]bool{}
	for _, check := range outcome.Checks {
		if seen[check.Name] {
			return false
		}
		seen[check.Name] = true
		switch check.Name {
		case "network", "authentication", "model", "nonstream", "stream", "parameters":
		default:
			return false
		}
		if (check.Status != "passed" && check.Status != "failed" && check.Status != "unsupported") || !precheckCodes[check.ErrorCode] ||
			(check.Status == "passed" && check.ErrorCode != "") || (check.Status != "passed" && check.ErrorCode == "") || (outcome.Status == "passed" && check.Status != "passed") {
			return false
		}
	}
	return true
}

// EnqueuePrecheck commits a frozen reference and its typed job atomically. The
// target version lock makes the earlier pure snapshot serialization safe.
func (t *Tenant) EnqueuePrecheck(candidate PrecheckRecord) (PrecheckRecord, error) {
	actor, err := t.targetActor()
	if err != nil {
		return PrecheckRecord{}, err
	}
	if candidate.OrganizationID != t.orgID || candidate.TargetID <= 0 || candidate.TargetVersion <= 0 || candidate.SecretID <= 0 || candidate.SecretVersion <= 0 ||
		!precheckRequestKeyPattern.MatchString(candidate.RequestKey) || len(candidate.SnapshotJSON) > 32<<10 || !json.Valid([]byte(candidate.SnapshotJSON)) {
		return PrecheckRecord{}, ErrConfiguration
	}
	var result PrecheckRecord
	err = t.InTransaction(func(tx *TenantTransaction) error {
		locked, err := tx.LockTargetForRun(candidate.TargetID, candidate.TargetVersion)
		if err != nil {
			return err
		}
		if locked.Secret.ID != candidate.SecretID || locked.Secret.Version != candidate.SecretVersion {
			return ErrConflict
		}
		var existing PrecheckRecord
		found := tx.db.Where("organization_id = ? AND request_key = ?", t.orgID, candidate.RequestKey).Find(&existing)
		if found.Error != nil {
			return found.Error
		}
		if found.RowsAffected != 0 {
			if existing.TargetID != candidate.TargetID || existing.TargetVersion != candidate.TargetVersion || existing.SecretVersion != candidate.SecretVersion || existing.SnapshotJSON != candidate.SnapshotJSON {
				return ErrConflict
			}
			result = existing
			return nil
		}
		now, err := queueTime(tx.db, t.store.driver)
		if err != nil {
			return err
		}
		id, err := NewID()
		if err != nil {
			return err
		}
		candidate.ID, candidate.CreatedBy, candidate.CreatedAt, candidate.Version = id, actor, now, 1
		candidate.Status, candidate.RequestCount, candidate.ResultJSON = "queued", 0, "[]"
		candidate.MaxOutputParameter, candidate.ErrorCode, candidate.JobID, candidate.StartedAt, candidate.FinishedAt = "", "", nil, nil, nil
		if err := tx.db.Create(&candidate).Error; err != nil {
			return err
		}
		job, err := tx.Enqueue(JobSpec{Type: JobTargetPrecheck, ObjectID: id, IdempotencyKey: "precheck:" + strconv.FormatInt(id, 10), MaxAttempts: 2})
		if err != nil {
			return err
		}
		if err := tx.db.Model(&PrecheckRecord{}).Where("organization_id = ? AND id = ?", t.orgID, id).Update("job_id", job.ID).Error; err != nil {
			return err
		}
		candidate.JobID = &job.ID
		if err := t.store.appendAudit(t.ctx, tx.db, t.orgID, auditObject("target.precheck.enqueue", "target_precheck", id), nil); err != nil {
			return err
		}
		result = candidate
		return nil
	})
	if err != nil {
		return PrecheckRecord{}, precheckError(err)
	}
	return result, nil
}

func (t *Tenant) GetPrecheck(targetID, id int64) (PrecheckRecord, error) {
	var record PrecheckRecord
	err := t.scoped().Where("target_id = ? AND id = ?", targetID, id).First(&record).Error
	return record, persistenceError(err)
}

func (t *Tenant) GetPrecheckForWorker(id int64) (PrecheckRecord, error) {
	var record PrecheckRecord
	err := t.scoped().Where("id = ?", id).First(&record).Error
	return record, persistenceError(err)
}

func (t *Tenant) GetLatestPrecheck(targetID int64) (PrecheckRecord, error) {
	var record PrecheckRecord
	err := t.scoped().Where("target_id = ?", targetID).Order("created_at DESC, id DESC").First(&record).Error
	return record, persistenceError(err)
}

func (tx *TenantTransaction) lockedPrecheck(id, jobID int64) (PrecheckRecord, error) {
	if tx.closed.Load() {
		return PrecheckRecord{}, ErrTransactionClosed
	}
	if tx.leaseJobID <= 0 || tx.leaseJobID != jobID || tx.leaseGeneration <= 0 {
		return PrecheckRecord{}, ErrJobLeaseLost
	}
	var record PrecheckRecord
	err := tx.db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("organization_id = ? AND id = ? AND job_id = ?", tx.orgID, id, jobID).First(&record).Error
	return record, persistenceError(err)
}

func (tx *TenantTransaction) BeginPrecheck(id, jobID int64) (PrecheckRecord, error) {
	if tx.completing {
		return PrecheckRecord{}, ErrJobLeaseLost
	}
	record, err := tx.lockedPrecheck(id, jobID)
	if err != nil {
		return PrecheckRecord{}, err
	}
	if record.Status == "passed" || record.Status == "failed" {
		return record, nil
	}
	if record.Status != "queued" && record.Status != "running" {
		return PrecheckRecord{}, ErrConflict
	}
	if record.Status == "running" {
		return record, nil
	} // Handler classifies interrupted attempts; never implicitly replays.
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return PrecheckRecord{}, err
	}
	changed := tx.db.Model(&PrecheckRecord{}).Where("organization_id = ? AND id = ? AND version = ?", tx.orgID, id, record.Version).
		Updates(map[string]any{"status": "running", "started_at": now, "version": record.Version + 1})
	if changed.Error != nil {
		return PrecheckRecord{}, persistenceError(changed.Error)
	}
	if changed.RowsAffected != 1 {
		return PrecheckRecord{}, ErrConflict
	}
	record.Status, record.StartedAt, record.Version = "running", &now, record.Version+1
	return record, nil
}

// ReservePrecheckRequest must be inside JobQueue.WithLease immediately before
// each real Do call, including adapter parameter fallback. Even uncertain calls
// remain charged to this counter and are not automatically issued again.
func (tx *TenantTransaction) ReservePrecheckRequest(id, jobID int64) error {
	if tx.completing {
		return ErrJobLeaseLost
	}
	record, err := tx.lockedPrecheck(id, jobID)
	if err != nil {
		return err
	}
	if record.Status != "running" || record.StartedAt == nil {
		return ErrConflict
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return err
	}
	if now.After(record.CreatedAt.Add(PrecheckLifetime)) {
		return ErrPrecheckExpired
	}
	if !now.Before(record.StartedAt.Add(PrecheckExecutionLimit)) {
		return ErrPrecheckBudget
	}
	if record.RequestCount >= PrecheckMaxRequests {
		return ErrPrecheckBudget
	}
	if err := tx.precheckTargetCurrent(record); err != nil {
		return err
	}
	changed := tx.db.Model(&PrecheckRecord{}).Where("organization_id = ? AND id = ? AND version = ? AND request_count < ?", tx.orgID, id, record.Version, PrecheckMaxRequests).
		Updates(map[string]any{"request_count": record.RequestCount + 1, "version": record.Version + 1})
	if changed.Error != nil {
		return persistenceError(changed.Error)
	}
	if changed.RowsAffected != 1 {
		return ErrPrecheckBudget
	}
	return nil
}

// FinishPrecheck is only a typed CompleteWith callback. Failed compatibility is
// a processed job, not a successful check, and never becomes a model risk score.
func (tx *TenantTransaction) FinishPrecheck(id, jobID int64, outcome PrecheckOutcome) error {
	if !tx.completing {
		return ErrJobLeaseLost
	}
	if !validPrecheckOutcome(outcome) {
		return ErrConfiguration
	}
	record, err := tx.lockedPrecheck(id, jobID)
	if err != nil {
		return err
	}
	var job Job
	if err := tx.db.Where("organization_id = ? AND id = ?", tx.orgID, jobID).First(&job).Error; err != nil {
		return persistenceError(err)
	}
	if job.CancelRequestedAt != nil {
		outcome = PrecheckOutcome{Status: "failed", ErrorCode: "MI_PRECHECK_CANCELLED", Checks: []PrecheckCheck{}}
	}
	if outcome.Status == "passed" {
		if err := tx.precheckTargetCurrent(record); err != nil {
			if !errors.Is(err, ErrPrecheckStale) {
				return err
			}
			outcome = PrecheckOutcome{Status: "failed", ErrorCode: "MI_PRECHECK_STALE", Checks: []PrecheckCheck{}}
		}
	}
	if outcome.Status == "passed" && (record.StartedAt == nil || record.RequestCount < 2 || record.RequestCount > PrecheckMaxRequests) {
		return ErrConfiguration
	}
	encoded, err := json.Marshal(outcome.Checks)
	if err != nil {
		return ErrConfiguration
	}
	if record.Status == "passed" || record.Status == "failed" {
		if record.Status != outcome.Status || record.ResultJSON != string(encoded) || record.ErrorCode != outcome.ErrorCode {
			return ErrConflict
		}
		return nil
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return err
	}
	changed := tx.db.Model(&PrecheckRecord{}).Where("organization_id = ? AND id = ? AND version = ?", tx.orgID, id, record.Version).
		Updates(map[string]any{"status": outcome.Status, "result_json": string(encoded), "error_code": outcome.ErrorCode, "max_output_parameter": outcome.MaxOutputParameter, "finished_at": now, "version": record.Version + 1})
	if changed.Error != nil {
		return persistenceError(changed.Error)
	}
	if changed.RowsAffected != 1 {
		return ErrConflict
	}
	actorCtx := audit.WithActor(tx.ctx, audit.Actor{ActorID: record.CreatedBy, ReasonCode: "target.precheck.finish"})
	return tx.store.appendAudit(actorCtx, tx.db, tx.orgID, auditObject("target.precheck.finish", "target_precheck", id), nil)
}

func (tx *TenantTransaction) precheckTargetCurrent(record PrecheckRecord) error {
	// Serialize the short reservation/final-result transaction against target
	// mutation. Never retain this row lock across an HTTP call.
	var current TargetRecord
	locked := tx.db.Clauses(clause.Locking{Strength: "SHARE"}).Select("id", "version", "secret_id", "status", "deleted_at").
		Where("organization_id = ? AND id = ?", tx.orgID, record.TargetID).Find(&current)
	if locked.Error != nil {
		return persistenceError(locked.Error)
	}
	if locked.RowsAffected != 1 || current.Version != record.TargetVersion || current.SecretID != record.SecretID || current.Status != "active" || current.DeletedAt != nil {
		return ErrPrecheckStale
	}
	var count int64
	err := tx.db.Table("integrity_secrets AS secret").Joins("JOIN organizations AS org ON org.id = secret.organization_id AND org.status = 'active'").
		Where("secret.organization_id = ?", tx.orgID).
		Where("secret.id = ? AND secret.secret_version = ? AND secret.deleted_at IS NULL", record.SecretID, record.SecretVersion).Count(&count).Error
	if err != nil {
		return persistenceError(err)
	}
	if count != 1 {
		return ErrPrecheckStale
	}
	return nil
}

func precheckError(err error) error {
	for _, known := range []error{ErrPrecheckStale, ErrPrecheckExpired, ErrPrecheckBudget, ErrJobCancelled} {
		if errors.Is(err, known) {
			return known
		}
	}
	return queueError(err)
}
