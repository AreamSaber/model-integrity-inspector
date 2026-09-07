package repository

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
)

var ErrEstimateExpired = errors.New("MI_RUN_ESTIMATE_EXPIRED")
var ErrEstimateLimit = errors.New("MI_RUN_ESTIMATE_LIMIT")
var ErrEstimateStale = errors.New("MI_RUN_ESTIMATE_STALE")

const RunEstimateLifetime = 10 * time.Minute
const maxActiveEstimates = 20

// RunEstimateRecord is an owner-scoped, expiring S2 preparation artifact. It
// creates no Job or Attempt. Only a confirmed Run retains it as durable evidence.
type RunEstimateRecord struct {
	ID             int64
	OrganizationID int64
	TargetID       int64
	TargetVersion  int64
	CreatedBy      int64
	ManifestHash   string
	SnapshotJSON   string `json:"-"`
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

func (RunEstimateRecord) TableName() string            { return "integrity_run_estimates" }
func (RunEstimateRecord) String() string               { return "[S2 run estimate]" }
func (v RunEstimateRecord) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }

func runEstimateError(err error) error {
	for _, known := range []error{ErrEstimateExpired, ErrEstimateLimit, ErrEstimateStale} {
		if errors.Is(err, known) {
			return known
		}
	}
	return executionError(err)
}

func estimateSnapshot(plan domain.ExecutionPlan, policy scheduler.Policy) (domain.ExecutionPlan, domain.ExecutionLimits, []byte, error) {
	beforeBudget, err := json.Marshal(plan.Budget)
	if err != nil {
		return plan, domain.ExecutionLimits{}, nil, ErrConfiguration
	}
	beforeConcurrency := plan.Concurrency
	plan, limits, err := policy.Apply(plan)
	if err != nil {
		return plan, limits, nil, err
	}
	afterBudget, err := json.Marshal(plan.Budget)
	if err != nil || beforeConcurrency != plan.Concurrency || !bytes.Equal(beforeBudget, afterBudget) {
		return plan, limits, nil, ErrEstimateStale
	}
	if plan.Target.AuthType == "" {
		plan.Target.AuthType = "bearer"
	}
	if plan.Target.TimeoutSeconds == 0 {
		plan.Target.TimeoutSeconds = 180
	}
	if !validateExecutionPlan(plan) || len(plan.Manifest) == 0 {
		return plan, limits, nil, ErrConfiguration
	}
	data, err := json.Marshal(executionSnapshot{Plan: plan, Limits: limits})
	if err != nil || len(data) > 8<<20 {
		return plan, limits, nil, ErrConfiguration
	}
	return plan, limits, data, nil
}

// SaveRunEstimate runs in the same authorization/target serialization boundary
// as writes, but never enqueues execution or calls the upstream. At most twenty
// unexpired drafts per creator limit preparation storage abuse.
func (t *Tenant) SaveRunEstimate(plan domain.ExecutionPlan, policy scheduler.Policy) (RunEstimateRecord, error) {
	plan, _, encoded, err := estimateSnapshot(plan, policy)
	if err != nil {
		return RunEstimateRecord{}, err
	}
	actor, err := t.targetActor()
	if err != nil {
		return RunEstimateRecord{}, err
	}
	// Separate transaction keeps cleanup's draft/audit locks out of the target
	// write lock order, and bounds storage even while no Worker is running.
	if err := t.controlTenantTransaction("run.create", func(tx *TenantTransaction) error {
		return tx.store.pruneRunEstimates(tx.ctx, tx.db, t.orgID, actor)
	}); err != nil {
		return RunEstimateRecord{}, runEstimateError(err)
	}
	var result RunEstimateRecord
	var classified error
	err = t.controlTenantTransaction("run.create", func(tx *TenantTransaction) error {
		if err := tx.validateEstimateBindings(plan, actor); err != nil {
			classified = err
			return err
		}
		state, err := tx.LockTargetForRun(plan.Target.ID, plan.Target.Version)
		if err != nil {
			return err
		}
		if state.Secret.ID != plan.Target.SecretID || state.Secret.Version != plan.Target.SecretVersion {
			return ErrConflict
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		var count int64
		if err := tx.db.Model(&RunEstimateRecord{}).Where("organization_id = ? AND created_by = ? AND expires_at > ?", t.orgID, actor, now).Count(&count).Error; err != nil {
			return err
		}
		if count >= maxActiveEstimates {
			classified = ErrEstimateLimit
			return classified
		}
		id, err := NewID()
		if err != nil {
			return err
		}
		result = RunEstimateRecord{ID: id, OrganizationID: t.orgID, TargetID: plan.Target.ID, TargetVersion: plan.Target.Version, CreatedBy: actor, ManifestHash: plan.ManifestHash, SnapshotJSON: string(encoded), CreatedAt: now, ExpiresAt: now.Add(RunEstimateLifetime)}
		if err := tx.db.Create(&result).Error; err != nil {
			return err
		}
		return tx.store.appendAudit(t.ctx, tx.db, t.orgID, auditObject("run.estimate.create", "run_estimate", id), nil)
	})
	if classified != nil {
		return RunEstimateRecord{}, classified
	}
	return result, runEstimateError(err)
}

func (t *Tenant) GetRunEstimate(id int64) (RunEstimateRecord, error) {
	actor, err := t.targetActor()
	if err != nil {
		return RunEstimateRecord{}, err
	}
	var record RunEstimateRecord
	err = t.controlTransaction("run.create", func(db *gorm.DB) error {
		return db.Where("organization_id = ? AND id = ? AND created_by = ?", t.orgID, id, actor).First(&record).Error
	})
	return record, runEstimateError(err)
}

// FindConfirmedEstimate only recovers an existing receipt. It cannot create a
// Run, and remains owner/session scoped even if the target is now disabled.
func (t *Tenant) FindConfirmedEstimate(id int64, hash string) (RunRecord, error) {
	actor, err := t.targetActor()
	if err != nil {
		return RunRecord{}, err
	}
	var run RunRecord
	err = t.controlTransaction("run.create", func(db *gorm.DB) error {
		return db.Where("organization_id = ? AND request_key = ? AND created_by = ? AND manifest_hash = ?", t.orgID, "estimate:"+strconv.FormatInt(id, 10), actor, hash).First(&run).Error
	})
	return run, runEstimateError(err)
}

// DecodeRunEstimate returns detached internal configuration, never an HTTP DTO.
// The service must verify Manifest HMAC and reconstruct the requests before
// passing that verified plan to ConfirmRunEstimate.
func DecodeRunEstimate(record RunEstimateRecord) (domain.ExecutionPlan, error) {
	if len(record.SnapshotJSON) > 8<<20 {
		return domain.ExecutionPlan{}, ErrConfiguration
	}
	var snapshot executionSnapshot
	if json.Unmarshal([]byte(record.SnapshotJSON), &snapshot) != nil || !validateExecutionPlan(snapshot.Plan) || len(snapshot.Plan.Manifest) == 0 || snapshot.Plan.ManifestHash != record.ManifestHash || snapshot.Plan.Target.ID != record.TargetID || snapshot.Plan.Target.Version != record.TargetVersion {
		return domain.ExecutionPlan{}, ErrConfiguration
	}
	return snapshot.Plan, nil
}

// ConfirmRunEstimate serializes ownership, TTL, configuration equivalence and
// Run/Job creation together. A draft has one permanent, server-derived request
// identity; changing HTTP idempotency headers cannot duplicate its paid work.
func (t *Tenant) ConfirmRunEstimate(id int64, verifiedPlan domain.ExecutionPlan, policy scheduler.Policy) (RunRecord, error) {
	plan, limits, encoded, err := estimateSnapshot(verifiedPlan, policy)
	if err != nil {
		return RunRecord{}, err
	}
	actor, err := t.targetActor()
	if err != nil {
		return RunRecord{}, err
	}
	var run RunRecord
	var classified error
	err = t.controlTenantTransaction("run.create", func(tx *TenantTransaction) error {
		var draft RunEstimateRecord
		query := tx.db.Where("organization_id = ? AND id = ? AND created_by = ?", t.orgID, id, actor)
		if tx.store.driver == "postgres" {
			query = query.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := query.First(&draft).Error; err != nil {
			return err
		}
		if draft.ManifestHash != plan.ManifestHash || draft.SnapshotJSON != string(encoded) {
			classified = ErrEstimateStale
			return classified
		}
		requestKey := "estimate:" + strconv.FormatInt(id, 10)
		// Return the already-created identity even after TTL or target rotation.
		// This is receipt recovery, not authorization to issue another request.
		err := tx.db.Where("organization_id = ? AND request_key = ? AND created_by = ?", t.orgID, requestKey, actor).First(&run).Error
		if err == nil {
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if !time.Now().Before(draft.ExpiresAt) {
			classified = ErrEstimateExpired
			return classified
		}
		if err := tx.validateEstimateBindings(plan, actor); err != nil {
			classified = err
			return err
		}
		run, err = t.createRunInTransaction(tx, plan, limits, encoded, requestKey)
		return err
	})
	if classified != nil {
		return RunRecord{}, classified
	}
	return run, runEstimateError(err)
}

// Lock order is identical to target edits: target then catalog. Terminal
// prechecks are immutable and bind the exact target and Secret versions.
func (tx *TenantTransaction) validateEstimateBindings(plan domain.ExecutionPlan, actor int64) error {
	permissions, err := managementPermissions(tx.db, tx.orgID, actor)
	if err != nil {
		return persistenceError(err)
	}
	if plan.Package == "custom" && !slices.Contains(permissions, "run.custom") {
		return ErrManagementPermission
	}
	if (plan.Package == "deep" || plan.Budget.MaxRequests > 60 || plan.Budget.MaxTokens > 50000 || (plan.Budget.MaxCostMicros != nil && *plan.Budget.MaxCostMicros > 2000000)) && !slices.Contains(permissions, "run.high-cost") {
		return ErrManagementPermission
	}
	state, err := tx.LockTargetForRun(plan.Target.ID, plan.Target.Version)
	if err != nil {
		return err
	}
	if plan.PrecheckID > 0 {
		var precheck PrecheckRecord
		if err := tx.db.Where("organization_id = ? AND id = ?", tx.orgID, plan.PrecheckID).First(&precheck).Error; err != nil {
			return persistenceError(err)
		}
		if precheck.Status != "passed" || precheck.TargetID != plan.Target.ID || precheck.TargetVersion != plan.Target.Version || precheck.SecretID != plan.Target.SecretID || precheck.SecretVersion != plan.Target.SecretVersion || precheck.MaxOutputParameter != plan.Target.MaxOutputParameter {
			return ErrEstimateStale
		}
	}
	if plan.ModelProfile != nil {
		if state.Target.ModelProfileID == nil || *state.Target.ModelProfileID != plan.ModelProfile.ID {
			return ErrEstimateStale
		}
		var profile ModelProfile
		query := tx.db.Where("organization_id = ? AND id = ? AND deleted_at IS NULL", tx.orgID, plan.ModelProfile.ID)
		if tx.store.driver == "postgres" {
			query = query.Clauses(clause.Locking{Strength: "SHARE"})
		}
		if err := query.First(&profile).Error; err != nil {
			return persistenceError(err)
		}
		if profile.Status != "active" || int64(profile.Version) != plan.ModelProfile.Version {
			return ErrEstimateStale
		}
	}
	return nil
}
