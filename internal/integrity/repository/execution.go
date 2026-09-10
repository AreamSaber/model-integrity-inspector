package repository

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"

	"gorm.io/gorm/clause"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
)

var (
	ErrExecutionBudget      = errors.New("MI_EXECUTION_BUDGET_EXCEEDED")
	ErrExecutionLimit       = errors.New("MI_EXECUTION_CONCURRENCY_LIMIT")
	ErrExecutionRPM         = errors.New("MI_EXECUTION_RATE_LIMIT")
	ErrExecutionClosed      = errors.New("MI_EXECUTION_CLOSED")
	ErrExecutionCancelled   = errors.New("MI_EXECUTION_CANCELLED")
	ErrExecutionStale       = errors.New("MI_EXECUTION_TARGET_STALE")
	ErrAttemptUncertain     = errors.New("MI_UNCERTAIN_ATTEMPT")
	ErrExecutionCircuitOpen = errors.New("MI_EXECUTION_CIRCUIT_OPEN")
)

func executionKnownError(err error) error {
	for _, known := range []error{ErrAnalysisSource, ErrAnalysisLimit, ErrBundleIntegrity, ErrBundleUnavailable} {
		if errors.Is(err, known) {
			return known
		}
	}
	for _, known := range []error{ErrExecutionBudget, ErrExecutionLimit, ErrExecutionRPM, ErrExecutionClosed, ErrExecutionCancelled, ErrExecutionStale, ErrAttemptUncertain, ErrExecutionCircuitOpen, scheduler.ErrOverflow, scheduler.ErrPolicy, scheduler.ErrUnknownPrice} {
		if errors.Is(err, known) {
			return known
		}
	}
	return nil
}
func executionError(err error) error {
	if known := executionKnownError(err); known != nil {
		return known
	}
	for _, known := range []error{ErrManagementSession, ErrManagementPermission, ErrPasswordChangeRequired} {
		if errors.Is(err, known) {
			return known
		}
	}
	return queueError(err)
}

var executionLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
var executionHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

func validateExecutionPlan(plan domain.ExecutionPlan) bool {
	if _, err := planAnalysisSource(plan); err != nil {
		return false
	}
	if plan.Target.ID <= 0 || plan.Target.Version <= 0 || plan.Target.SecretID <= 0 || plan.Target.SecretVersion <= 0 || !executionHash.MatchString(plan.ManifestHash) || len(plan.Probes) == 0 || len(plan.Probes) > 200 || (plan.Target.MaxOutputParameter != "max_tokens" && plan.Target.MaxOutputParameter != "max_completion_tokens") || (plan.BaselineRunID != nil && *plan.BaselineRunID <= 0) {
		return false
	}
	if len(plan.Manifest) > 0 {
		if len(plan.Manifest) > 8<<20 {
			return false
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(plan.Manifest, &object) != nil || object == nil {
			return false
		}
		// Preserve compiler bytes/hash when embedded in the frozen snapshot.
		encoded, err := json.Marshal(plan.Manifest)
		if err != nil || !bytes.Equal(encoded, plan.Manifest) {
			return false
		}
		hash := sha256.Sum256(plan.Manifest)
		if hex.EncodeToString(hash[:]) != plan.ManifestHash {
			return false
		}
	}
	switch plan.Package {
	case "quick", "standard", "deep", "custom":
	default:
		return false
	}
	for _, v := range []string{plan.Versions.Rule, plan.Versions.Template, plan.Versions.Scoring, plan.Versions.Tokenizer} {
		if !executionLabel.MatchString(v) {
			return false
		}
	}
	count := 0
	for _, probe := range plan.Probes {
		for _, v := range []string{probe.Type, probe.TemplateID, probe.TemplateVersion, probe.Category, probe.Variant} {
			if !executionLabel.MatchString(v) {
				return false
			}
		}
		if len(probe.Samples) == 0 {
			return false
		}
		seen := map[int]bool{}
		for _, sample := range probe.Samples {
			if sample.Ordinal < 0 || seen[sample.Ordinal] || !executionLabel.MatchString(sample.Nonce) || (sample.PairID != "" && !executionLabel.MatchString(sample.PairID)) || sample.EstimatedInputTokens < 1 || sample.EstimatedInputTokens > 1_000_000_000 || sample.Request.Model != plan.Target.Model || sample.Request.MaxOutputTokens < 1 || sample.Request.MaxOutputTokens > 131072 || len(sample.Request.Messages) == 0 || len(sample.Request.Messages) > 256 {
				return false
			}
			for _, msg := range sample.Request.Messages {
				if msg.Role != "system" && msg.Role != "user" && msg.Role != "assistant" {
					return false
				}
				if len(msg.Content) > 1<<20 || !utf8.ValidString(msg.Content) {
					return false
				}
			}
			if !validExecutionParameters(sample.Request) {
				return false
			}
			for name := range sample.Request.ExtraAllowedParams {
				if name != "frequency_penalty" && name != "presence_penalty" {
					return false
				}
			}
			seen[sample.Ordinal] = true
			count++
		}
	}
	return count <= 1000
}

func validExecutionParameters(request domain.NormalizedRequest) bool {
	if request.Temperature != nil && (math.IsNaN(*request.Temperature) || *request.Temperature < 0 || *request.Temperature > 2) {
		return false
	}
	if request.TopP != nil && (math.IsNaN(*request.TopP) || *request.TopP < 0 || *request.TopP > 1) {
		return false
	}
	if request.ResponseFormat != nil && request.ResponseFormat.Type != "text" && request.ResponseFormat.Type != "json_object" {
		return false
	}
	if len(request.Stop) > 4 {
		return false
	}
	for _, stop := range request.Stop {
		if len(stop) == 0 || len(stop) > 256 || !utf8.ValidString(stop) {
			return false
		}
	}
	for _, value := range request.ExtraAllowedParams {
		encoded, err := json.Marshal(value)
		if err != nil {
			return false
		}
		var number float64
		if json.Unmarshal(encoded, &number) != nil || number < -2 || number > 2 {
			return false
		}
	}
	return true
}

// CreateRun freezes the typed plan, target/Secret versions and clamped admin
// policy in the same authorized transaction as the initial typed plan Job.
func (t *Tenant) CreateRun(plan domain.ExecutionPlan, policy scheduler.Policy, requestKey string) (RunRecord, error) {
	if plan.Target.AuthType == "" {
		plan.Target.AuthType = "bearer"
	}
	if plan.Target.TimeoutSeconds == 0 {
		plan.Target.TimeoutSeconds = 180
	}
	plan, limits, err := policy.Apply(plan)
	if err != nil {
		return RunRecord{}, err
	}
	if !validateExecutionPlan(plan) || !precheckRequestKeyPattern.MatchString(requestKey) {
		return RunRecord{}, ErrConfiguration
	}
	encoded, err := json.Marshal(executionSnapshot{Plan: plan, Limits: limits})
	if err != nil || len(encoded) > 8<<20 {
		return RunRecord{}, ErrConfiguration
	}
	var result RunRecord
	err = t.controlTenantTransaction("run.create", func(tx *TenantTransaction) error {
		var operationError error
		result, operationError = t.createRunInTransaction(tx, plan, limits, encoded, requestKey)
		return operationError
	})
	return result, executionError(err)
}

// createRunInTransaction also serves estimate confirmation. The caller must
// already hold the authorized controlTenantTransaction (including draft locks).
// It never opens a nested transaction or relaxes frozen-plan/target validation.
func (t *Tenant) createRunInTransaction(tx *TenantTransaction, plan domain.ExecutionPlan, limits domain.ExecutionLimits, encoded []byte, requestKey string) (RunRecord, error) {
	if tx == nil || tx.closed.Load() {
		return RunRecord{}, ErrTransactionClosed
	}
	if tx.store != t.store || tx.orgID != t.orgID || !validateExecutionPlan(plan) || !precheckRequestKeyPattern.MatchString(requestKey) {
		return RunRecord{}, ErrConfiguration
	}
	canonical, err := json.Marshal(executionSnapshot{Plan: plan, Limits: limits})
	if err != nil || len(canonical) > 8<<20 || !bytes.Equal(canonical, encoded) {
		return RunRecord{}, ErrConfiguration
	}
	actor, err := t.targetActor()
	if err != nil {
		return RunRecord{}, err
	}
	var result RunRecord
	err = func() error {
		if err := tx.validateBootstrapPlan(plan); err != nil {
			return err
		}
		permissions, err := managementPermissions(tx.db, t.orgID, actor)
		if err != nil {
			return err
		}
		if !slices.Contains(permissions, "run.create") {
			return ErrManagementPermission
		}
		if plan.Package == "custom" && !slices.Contains(permissions, "run.custom") {
			return ErrManagementPermission
		}
		highCost := plan.Package == "deep" || plan.Budget.MaxRequests > 60 || plan.Budget.MaxTokens > 50000 || (plan.Budget.MaxCostMicros != nil && *plan.Budget.MaxCostMicros > 2000000)
		if highCost && !slices.Contains(permissions, "run.high-cost") {
			return ErrManagementPermission
		}
		locked, err := tx.LockTargetForRun(plan.Target.ID, plan.Target.Version)
		if err != nil {
			return err
		}
		if locked.Secret.ID != plan.Target.SecretID || locked.Secret.Version != plan.Target.SecretVersion || locked.Target.Endpoint != plan.Target.Endpoint || locked.Target.Model != plan.Target.Model || locked.Target.Protocol != plan.Target.Protocol {
			return ErrExecutionStale
		}
		var options struct {
			TimeoutSeconds int `json:"timeout_seconds"`
		}
		if json.Unmarshal([]byte(locked.Target.OptionsJSON), &options) != nil {
			return ErrConfiguration
		}
		if options.TimeoutSeconds == 0 {
			options.TimeoutSeconds = 180
		}
		if locked.Target.AuthType != plan.Target.AuthType || locked.Target.AuthHeaderName != plan.Target.AuthHeaderName || options.TimeoutSeconds != plan.Target.TimeoutSeconds {
			return ErrExecutionStale
		}
		var existing RunRecord
		found := tx.db.Where("organization_id = ? AND request_key = ?", t.orgID, requestKey).Find(&existing)
		if found.Error != nil {
			return found.Error
		}
		if found.RowsAffected > 0 {
			if existing.ConfigSnapshot != string(encoded) {
				return ErrConflict
			}
			result = existing
			return nil
		}
		if plan.BaselineRunID != nil {
			var count int64
			if err := tx.db.Model(&RunRecord{}).Where("organization_id = ? AND id = ? AND status = 'COMPLETED'", t.orgID, *plan.BaselineRunID).Count(&count).Error; err != nil {
				return err
			}
			if count != 1 {
				return ErrNotFound
			}
		}
		now, err := queueTime(tx.db, tx.store.driver)
		if err != nil {
			return err
		}
		id, err := NewID()
		if err != nil {
			return err
		}
		result = RunRecord{ID: id, OrganizationID: t.orgID, TargetID: plan.Target.ID, BaselineRunID: plan.BaselineRunID, Package: plan.Package, ObservationMode: "blackbox", Status: "QUEUED", ConfigSnapshot: string(encoded), ManifestHash: plan.ManifestHash, RuleBundleVersion: plan.Versions.Rule, TemplateBundleVersion: plan.Versions.Template, ScoringVersion: plan.Versions.Scoring, TokenizerBundleVersion: plan.Versions.Tokenizer, RequestBudget: plan.Budget.MaxRequests, TokenBudget: plan.Budget.MaxTokens, MoneyBudgetMicros: plan.Budget.MaxCostMicros, CostKnown: plan.Pricing.InputMicrosPerMillion != nil && plan.Pricing.OutputMicrosPerMillion != nil, CreatedBy: actor, CreatedAt: now, Version: 1, RequestKey: requestKey}
		result.AnalysisSourceVersion, err = planAnalysisSource(plan)
		if err != nil {
			return err
		}
		if err := tx.db.Create(&result).Error; err != nil {
			return err
		}
		executionOrdinal := 0
		for _, probe := range plan.Probes {
			probeID, err := NewID()
			if err != nil {
				return err
			}
			record := ProbeRecord{ID: probeID, OrganizationID: t.orgID, RunID: id, ProbeType: probe.Type, TemplateID: probe.TemplateID, TemplateVersion: probe.TemplateVersion, Category: probe.Category, Variant: probe.Variant, PlannedSamples: len(probe.Samples), Status: "PLANNED", ParametersJSON: "{}", CreatedAt: now}
			if err := tx.db.Create(&record).Error; err != nil {
				return err
			}
			for _, sample := range probe.Samples {
				sampleID, err := NewID()
				if err != nil {
					return err
				}
				frozen, err := json.Marshal(sample)
				if err != nil {
					return ErrConfiguration
				}
				var pair *string
				if sample.PairID != "" {
					v := sample.PairID
					pair = &v
				}
				record := LogicalSampleRecord{ID: sampleID, OrganizationID: t.orgID, RunID: id, ProbeInstanceID: probeID, Ordinal: sample.Ordinal, ExecutionOrdinal: executionOrdinal, PairID: pair, IdempotencyKey: "sample:" + strconv.FormatInt(sampleID, 10), RequestPlan: string(frozen), Validity: "PENDING", CreatedAt: now}
				executionOrdinal++
				if err := tx.db.Create(&record).Error; err != nil {
					return err
				}
			}
		}
		job, err := tx.Enqueue(JobSpec{Type: JobRunPlan, ObjectID: id, IdempotencyKey: "run-plan:" + strconv.FormatInt(id, 10), MaxAttempts: 3})
		if err != nil {
			return err
		}
		result.PlanJobID = &job.ID
		if err := tx.db.Model(&RunRecord{}).Where("organization_id = ? AND id = ?", t.orgID, id).Update("plan_job_id", job.ID).Error; err != nil {
			return err
		}
		return tx.store.appendAudit(t.ctx, tx.db, t.orgID, auditObject("run.create", "run", id), nil)
	}()
	return result, executionError(err)
}

func (t *Tenant) GetRun(id int64) (RunRecord, error) {
	var r RunRecord
	err := t.scoped().Where("id = ?", id).First(&r).Error
	return r, executionError(err)
}
func (t *Tenant) GetExecutionPlan(id int64) (domain.ExecutionPlan, error) {
	r, err := t.GetRun(id)
	if err != nil {
		return domain.ExecutionPlan{}, err
	}
	var s executionSnapshot
	if json.Unmarshal([]byte(r.ConfigSnapshot), &s) != nil || !validRunAnalysisSource(r, s.Plan) {
		return domain.ExecutionPlan{}, ErrConfiguration
	}
	return s.Plan, nil
}
func (t *Tenant) ListExecutionSamples(runID int64) ([]LogicalSampleRecord, error) {
	var r []LogicalSampleRecord
	err := t.scoped().Where("run_id = ?", runID).Order("execution_ordinal, id").Find(&r).Error
	return r, executionError(err)
}
func (t *Tenant) ListAttempts(sampleID int64) ([]AttemptRecord, error) {
	var r []AttemptRecord
	err := t.scoped().Where("logical_sample_id = ?", sampleID).Order("attempt_no").Find(&r).Error
	return r, executionError(err)
}

func (t *Tenant) CancelRun(id, expectedVersion int64) (RunRecord, error) {
	actor, err := t.targetActor()
	if err != nil {
		return RunRecord{}, err
	}
	grants, err := t.PermissionsForUser(actor)
	if err != nil {
		return RunRecord{}, err
	}
	permission := "run.cancel-own"
	if slices.Contains(grants, "run.cancel-any") {
		permission = "run.cancel-any"
	}
	var result RunRecord
	err = t.controlTenantTransactionPurpose(permission, maintenanceCancel, func(tx *TenantTransaction) error {
		if err := tx.db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("organization_id = ? AND id = ?", t.orgID, id).First(&result).Error; err != nil {
			return err
		}
		if permission == "run.cancel-own" && result.CreatedBy != actor {
			return ErrManagementPermission
		}
		if result.Version != expectedVersion {
			return ErrConflict
		}
		if result.Status == "CANCELLED" || result.Status == "CANCELLING" {
			return nil
		}
		if result.ExecutionClosedAt != nil {
			return ErrExecutionClosed
		}
		now, err := queueTime(tx.db, tx.store.driver)
		if err != nil {
			return err
		}
		result.Status = "CANCELLING"
		result.CancelRequestedAt = &now
		result.Version++
		if err := tx.db.Model(&RunRecord{}).Where("organization_id = ? AND id = ?", t.orgID, id).Updates(map[string]any{"status": result.Status, "cancel_requested_at": now, "version": result.Version}).Error; err != nil {
			return err
		}
		// Do not mark an in-flight job completed or destroy its credential. The
		// Worker observes this flag, cancels I/O, and persists fenced outcomes.
		return tx.store.appendAudit(t.ctx, tx.db, t.orgID, auditObject("run.cancel", "run", id), nil)
	})
	return result, executionError(err)
}

func (tx *TenantTransaction) executionJob(jobType JobType, objectID int64, completing bool) (Job, error) {
	if tx.closed.Load() {
		return Job{}, ErrTransactionClosed
	}
	if tx.leaseJobID <= 0 || tx.leaseGeneration <= 0 || tx.completing != completing {
		return Job{}, ErrJobLeaseLost
	}
	var job Job
	err := tx.db.Where("organization_id = ? AND id = ? AND type = ? AND object_id = ? AND status = 'running' AND attempt_count = ?", tx.orgID, tx.leaseJobID, string(jobType), objectID, tx.leaseGeneration).First(&job).Error
	if err != nil {
		return Job{}, executionLeaseLookupError(err)
	}
	if job.CancelRequestedAt != nil {
		return Job{}, ErrExecutionCancelled
	}
	return job, nil
}

func (tx *TenantTransaction) lockRun(id int64) (RunRecord, executionSnapshot, error) {
	var run RunRecord
	var snapshot executionSnapshot
	err := tx.db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("organization_id = ? AND id = ?", tx.orgID, id).First(&run).Error
	if err != nil {
		return run, snapshot, err
	}
	if json.Unmarshal([]byte(run.ConfigSnapshot), &snapshot) != nil || !validRunAnalysisSource(run, snapshot.Plan) {
		return run, snapshot, ErrConfiguration
	}
	return run, snapshot, nil
}

// StartRun is only valid inside completion of the frozen plan Job. Claiming the
// Job alone does not create any successful sample or issue an outbound request.
func (tx *TenantTransaction) StartRun(id int64) error {
	return tx.startRun(id, AnalysisSourceLegacyV1)
}

// StartRunWithDerivedSource never upgrades an old frozen plan or guesses mode.
func (tx *TenantTransaction) StartRunWithDerivedSource(id int64) error {
	return tx.startRun(id, domain.AnalysisSourceDerivedV1)
}

func (tx *TenantTransaction) startRun(id int64, requiredSource string) error {
	if _, err := tx.executionJob(JobRunPlan, id, true); err != nil {
		return err
	}
	if _, err := tx.LockResponseRetentionPolicy(); err != nil {
		return err
	}
	run, snapshot, err := tx.lockRun(id)
	if err != nil {
		return err
	}
	if run.PlanJobID == nil || *run.PlanJobID != tx.leaseJobID {
		return ErrJobLeaseLost
	}
	if run.AnalysisSourceVersion != requiredSource {
		return ErrAnalysisSource
	}
	if run.Status != "QUEUED" && run.Status != "CANCELLING" {
		return ErrExecutionClosed
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return err
	}
	if run.CancelRequestedAt != nil {
		return tx.closeUnstartedRun(run, now)
	}
	if err := tx.executionTargetCurrent(snapshot.Plan.Target); err != nil {
		return err
	}
	deadline := now.Add(time.Duration(snapshot.Plan.Budget.TimeoutSeconds) * time.Second)
	if err := tx.db.Model(&RunRecord{}).Where("organization_id = ? AND id = ?", tx.orgID, id).Updates(map[string]any{"status": "RUNNING", "started_at": now, "deadline_at": deadline, "version": run.Version + 1}).Error; err != nil {
		return err
	}
	var samples []LogicalSampleRecord
	if err := tx.db.Where("organization_id = ? AND run_id = ?", tx.orgID, id).Order("execution_ordinal, id").Find(&samples).Error; err != nil {
		return err
	}
	for _, sample := range samples {
		if _, err := tx.enqueueSample(sample, 1, now.Add(time.Duration(sample.ExecutionOrdinal)*time.Microsecond)); err != nil {
			return err
		}
	}
	return tx.store.appendAudit(tx.ctx, tx.db, tx.orgID, auditObject("run.start", "run", id), nil)
}

func (tx *TenantTransaction) enqueueSample(sample LogicalSampleRecord, attempt int, at time.Time) (Job, error) {
	job, err := tx.Enqueue(JobSpec{Type: JobSampleExecute, ObjectID: sample.ID, IdempotencyKey: "execute:" + strconv.FormatInt(sample.ID, 10) + ":" + strconv.Itoa(attempt), AvailableAt: at, MaxAttempts: 3})
	if err != nil {
		return Job{}, err
	}
	err = tx.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND id = ?", tx.orgID, sample.ID).Update("job_id", job.ID).Error
	return job, err
}

func (tx *TenantTransaction) closeUnstartedRun(run RunRecord, now time.Time) error {
	if err := tx.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND run_id = ? AND completed_at IS NULL", tx.orgID, run.ID).Updates(map[string]any{"validity": "NOT_APPLICABLE", "completed_at": now}).Error; err != nil {
		return err
	}
	return tx.closeExecutionIfFinished(run.ID, now)
}

func (tx *TenantTransaction) executionTargetCurrent(target domain.ExecutionTarget) error {
	var record TargetRecord
	if err := tx.db.Clauses(clause.Locking{Strength: "SHARE"}).Where("organization_id = ? AND id = ? AND version = ? AND status = 'active' AND deleted_at IS NULL", tx.orgID, target.ID, target.Version).First(&record).Error; err != nil {
		if errors.Is(persistenceError(err), ErrNotFound) {
			return ErrExecutionStale
		}
		return err
	}
	if record.SecretID != target.SecretID {
		return ErrExecutionStale
	}
	var count int64
	if err := tx.db.Table("integrity_secrets").Where("organization_id = ? AND id = ? AND secret_version = ? AND deleted_at IS NULL", tx.orgID, target.SecretID, target.SecretVersion).Count(&count).Error; err != nil {
		return err
	}
	if count != 1 {
		return ErrExecutionStale
	}
	return nil
}
