package api

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"

	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
)

var runManifestHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (c *control) registerRunRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/runs/estimate", c.estimateRun)
	mux.HandleFunc("POST /api/v1/runs", c.confirmRun)
	mux.HandleFunc("GET /api/v1/runs/{id}", c.getRun)
	mux.HandleFunc("POST /api/v1/runs/{id}/cancel", c.cancelRun)
}

func (c *control) runError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, runservice.ErrInvalid), errors.Is(err, scheduler.ErrPolicy):
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
	case errors.Is(err, scheduler.ErrUnknownPrice):
		c.failure(w, r, 400, "MI_PRICE_UNKNOWN")
	case errors.Is(err, generator.ErrBudget):
		c.failure(w, r, 400, "MI_PROBE_BUDGET_INSUFFICIENT")
	case errors.Is(err, generator.ErrConfiguration):
		c.failure(w, r, 400, "MI_PROBE_CONFIGURATION_INVALID")
	case errors.Is(err, repository.ErrEstimateExpired):
		c.failure(w, r, 409, "MI_RUN_ESTIMATE_EXPIRED")
	case errors.Is(err, repository.ErrEstimateStale):
		c.failure(w, r, 409, "MI_RUN_ESTIMATE_STALE")
	case errors.Is(err, repository.ErrEstimateLimit):
		c.failure(w, r, 429, "MI_RUN_ESTIMATE_LIMIT")
	case errors.Is(err, runservice.ErrPrecheckRequired):
		c.failure(w, r, 409, "MI_PRECHECK_REQUIRED")
	case errors.Is(err, repository.ErrPrecheckStale):
		c.failure(w, r, 409, "MI_PRECHECK_STALE")
	case errors.Is(err, runservice.ErrExecutionNotReady):
		c.failure(w, r, 503, "MI_EXECUTION_NOT_READY")
	case errors.Is(err, repository.ErrExecutionClosed):
		c.failure(w, r, 409, "MI_EXECUTION_CLOSED")
	case errors.Is(err, repository.ErrExecutionStale):
		c.failure(w, r, 409, "MI_EXECUTION_TARGET_STALE")
	default:
		c.targetError(w, r, err)
	}
}

func quoteFields(q runservice.Quote) (map[string]string, map[string]any) {
	versions := map[string]string{"rule_bundle": q.Versions.Rule, "template_bundle": q.Versions.Template, "scoring": q.Versions.Scoring, "tokenizer_bundle": q.Versions.Tokenizer}
	estimate := map[string]any{"requests": q.Projection.Requests, "input_tokens": q.Projection.InputTokens, "max_output_tokens": q.Projection.OutputTokens, "cost_micros": q.Projection.EstimatedCostMicros, "duration_seconds": q.Projection.TimeUpperBoundSeconds, "usage_safety_factor": 1.25, "warnings": q.Warnings, "completeness": q.Completeness}
	return versions, estimate
}
func quoteDTO(q runservice.Quote) any {
	versions, estimate := quoteFields(q)
	return map[string]any{"id": strconv.FormatInt(q.ID, 10), "target_id": strconv.FormatInt(q.TargetID, 10), "target_version": q.TargetVersion, "package": q.Package, "manifest_hash": q.ManifestHash, "versions": versions, "estimate": estimate, "expires_at": q.ExpiresAt, "budgets": map[string]any{"max_requests": q.Budget.MaxRequests, "max_tokens": q.Budget.MaxTokens, "max_cost_micros": q.Budget.MaxCostMicros, "timeout_seconds": q.Budget.TimeoutSeconds}}
}

func (c *control) estimateRun(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, org, ok := c.authorizeOrganization(w, r, "run.create")
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	var body struct {
		TargetID      string             `json:"target_id"`
		TargetVersion int64              `json:"target_version"`
		Package       string             `json:"package"`
		Options       runservice.Options `json:"options"`
	}
	if !c.decode(w, r, &body) {
		return
	}
	id, ok := managementID(body.TargetID)
	if !ok || body.TargetVersion <= 0 || body.TargetVersion > 2147483647 {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	q, err := c.cfg.Runs.Estimate(ctx, org, runservice.Input{TargetID: id, TargetVersion: body.TargetVersion, Package: body.Package, Options: body.Options})
	if err != nil {
		c.runError(w, r, err)
		return
	}
	c.success(w, r, 200, quoteDTO(q))
}

func (c *control) confirmRun(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, org, ok := c.authorizeOrganization(w, r, "run.create")
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	var body struct {
		EstimateID   string `json:"estimate_id"`
		ManifestHash string `json:"manifest_hash"`
		ConfirmCost  bool   `json:"confirm_cost"`
	}
	if !c.decode(w, r, &body) {
		return
	}
	id, ok := managementID(body.EstimateID)
	if !ok || !body.ConfirmCost || !runManifestHash.MatchString(body.ManifestHash) {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	created, err := c.cfg.Runs.Confirm(ctx, org, id, body.ManifestHash)
	if err != nil {
		c.runError(w, r, err)
		return
	}
	c.respondRun(w, r.WithContext(ctx), org, created.ID, 202)
}

func (c *control) getRun(w http.ResponseWriter, r *http.Request) {
	ctx, org, ok := c.authorizeOrganization(w, r, "run.read")
	if !ok {
		return
	}
	id, ok := managementID(r.PathValue("id"))
	if !ok || r.URL.RawQuery != "" {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	c.respondRun(w, r.WithContext(ctx), org, id, 200)
}

func (c *control) cancelRun(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	// The repository selects cancel-own / cancel-any from persisted effective
	// grants and rechecks ownership atomically. run.read is not cancellation.
	ctx, org, ok := c.authorizeOrganization(w, r, "run.read")
	if !ok {
		return
	}
	id, ok := managementID(r.PathValue("id"))
	if !ok || r.URL.RawQuery != "" {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	var body struct {
		Version int64 `json:"version"`
	}
	if !c.decode(w, r, &body) {
		return
	}
	if body.Version <= 0 || body.Version > 2147483647 {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	if _, err := c.cfg.Runs.Cancel(ctx, org, id, body.Version); err != nil {
		c.runError(w, r, err)
		return
	}
	c.respondRun(w, r.WithContext(ctx), org, id, 200)
}

func (c *control) respondRun(w http.ResponseWriter, r *http.Request, org, id int64, status int) {
	record, q, planned, completed, err := c.cfg.Runs.Get(r.Context(), org, id)
	if err != nil {
		c.runError(w, r, err)
		return
	}
	versions, estimate := quoteFields(q)
	var cost *int64
	if record.CostKnown {
		cost = &record.EstimatedCostMicros
	}
	// No provider diagnostics are allowed into the summary. More detailed
	// per-class sample counts are supplied by the later analysis projection.
	summary := []map[string]any{}
	if record.ErrorSummary != nil {
		code := "MI_SERVICE_UNAVAILABLE"
		switch *record.ErrorSummary {
		case "MI_EXECUTION_BUDGET_EXCEEDED", "MI_EXECUTION_CANCELLED", "MI_EXECUTION_TARGET_STALE", "MI_UNCERTAIN_ATTEMPT", "MI_TIMEOUT", "MI_EXECUTION_CIRCUIT_OPEN", "MI_AUTH_FAILED", "MI_MODEL_NOT_FOUND", "MI_PROTOCOL_UNSUPPORTED", "MI_CIRCUIT_AUTH_FAILURES", "MI_CIRCUIT_MODEL_FAILURES", "MI_CIRCUIT_PROTOCOL_FAILURES":
			code = *record.ErrorSummary
		}
		summary = append(summary, map[string]any{"code": code, "count": 1})
	}
	c.success(w, r, status, map[string]any{"id": strconv.FormatInt(record.ID, 10), "target_id": strconv.FormatInt(record.TargetID, 10), "created_by": strconv.FormatInt(record.CreatedBy, 10), "package": record.Package, "status": record.Status, "version": record.Version, "versions": versions, "estimate": estimate, "manifest_hash": record.ManifestHash, "request_count": record.RequestCount, "token_count": record.TokenCount, "estimated_cost_micros": cost, "valid_sample_count": record.ValidSampleCount, "planned_samples": planned, "completed_samples": completed, "created_at": record.CreatedAt, "started_at": record.StartedAt, "finished_at": record.FinishedAt, "execution_closed_at": record.ExecutionClosedAt, "error_summary": summary})
}
