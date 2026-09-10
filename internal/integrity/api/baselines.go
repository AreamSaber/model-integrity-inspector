package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/baseline"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func (c *control) registerBaselineRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/baselines", c.listBaselines)
	mux.HandleFunc("POST /api/v1/baselines", c.createBaseline)
	mux.HandleFunc("GET /api/v1/baselines/{id}", c.getBaseline)
	mux.HandleFunc("PATCH /api/v1/baselines/{id}", c.patchBaseline)
	mux.HandleFunc("POST /api/v1/baselines/{id}/approve", c.approveBaseline)
	mux.HandleFunc("POST /api/v1/baselines/{id}/retire", c.retireBaseline)
}
func (c *control) baselineError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, repository.ErrBaselineInvalid):
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
	case errors.Is(err, repository.ErrBaselineIntegrity):
		c.failure(w, r, 503, "MI_BASELINE_INTEGRITY")
	case errors.Is(err, repository.ErrBaselineSource):
		c.failure(w, r, 409, "MI_BASELINE_SOURCE_INVALID")
	case errors.Is(err, repository.ErrBaselineState):
		c.failure(w, r, 409, "MI_BASELINE_STATE_CONFLICT")
	case errors.Is(err, repository.ErrBaselineExpired):
		c.failure(w, r, 409, "MI_BASELINE_EXPIRED")
	default:
		c.runError(w, r, err)
	}
}
func (c *control) listBaselines(w http.ResponseWriter, r *http.Request) {
	ctx, org, ok := c.authorizeOrganization(w, r, "baseline.read")
	if !ok {
		return
	}
	r = r.WithContext(ctx)
	scope, err := resultScope(r, org, "baselines")
	if err != nil {
		c.baselineError(w, r, err)
		return
	}
	// List remains q/cursor/limit only, as in the frozen contract. Status and
	// expiry are explicit DTO fields; no unsigned ad-hoc filter is accepted.
	p, err := c.parsePage(r, scope)
	if err != nil {
		c.baselineError(w, r, err)
		return
	}
	rows, err := c.cfg.Baselines.List(ctx, org, baseline.ListInput{AfterID: p.AfterID, Limit: p.Limit, Query: p.Query})
	if err != nil {
		c.baselineError(w, r, err)
		return
	}
	last := int64(0)
	if len(rows) > 0 {
		last, _ = strconv.ParseInt(rows[len(rows)-1].ID, 10, 64)
	}
	more := false
	if len(rows) == p.Limit {
		next, e := c.cfg.Baselines.List(ctx, org, baseline.ListInput{AfterID: last, Limit: 1, Query: p.Query})
		if e != nil {
			c.baselineError(w, r, e)
			return
		}
		more = len(next) > 0
	}
	result, err := c.pageResult(rows, last, more, scope, p.Query)
	if err != nil {
		c.baselineError(w, r, err)
		return
	}
	c.success(w, r, 200, result)
}
func (c *control) getBaseline(w http.ResponseWriter, r *http.Request) {
	ctx, org, ok := c.authorizeOrganization(w, r, "baseline.read")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	view, err := c.cfg.Baselines.Get(ctx, org, id)
	if err != nil {
		c.baselineError(w, r, err)
		return
	}
	c.success(w, r, 200, view)
}
func (c *control) createBaseline(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, org, ok := c.authorizeOrganization(w, r, "baseline.write")
	if !ok {
		return
	}
	var input struct {
		Name             string    `json:"name"`
		RunID            string    `json:"run_id"`
		AnalysisRevision *int      `json:"analysis_revision"`
		Source           string    `json:"source"`
		Region           string    `json:"region"`
		ExpiresAt        time.Time `json:"expires_at"`
	}
	if !c.decodeManagement(w, r, &input) {
		return
	}
	runID, ok := managementID(input.RunID)
	if !ok {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	revision := 1
	if input.AnalysisRevision != nil {
		revision = *input.AnalysisRevision
		if revision != 1 {
			c.failure(w, r, 400, "MI_INVALID_REQUEST")
			return
		}
	}
	view, err := c.cfg.Baselines.Create(ctx, org, baseline.CreateInput{RunID: runID, AnalysisRevision: revision, Name: input.Name, Source: input.Source, Region: input.Region, ExpiresAt: input.ExpiresAt})
	if err != nil {
		c.baselineError(w, r, err)
		return
	}
	c.success(w, r, 201, view)
}
func (c *control) patchBaseline(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, org, ok := c.authorizeOrganization(w, r, "baseline.write")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	var input struct {
		Version   int        `json:"version"`
		Name      *string    `json:"name"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if !c.decodeManagement(w, r, &input) {
		return
	}
	view, err := c.cfg.Baselines.Patch(ctx, org, id, baseline.PatchInput{Version: input.Version, Name: input.Name, ExpiresAt: input.ExpiresAt})
	if err != nil {
		c.baselineError(w, r, err)
		return
	}
	c.success(w, r, 200, view)
}
func (c *control) approveBaseline(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, org, ok := c.authorizeOrganization(w, r, "baseline.approve")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	var input struct {
		Version        int    `json:"version"`
		Reason         string `json:"reason"`
		BusinessReview string `json:"business_review"`
		Acknowledged   bool   `json:"acknowledge_development_limits"`
	}
	if !c.decodeManagement(w, r, &input) {
		return
	}
	view, err := c.cfg.Baselines.Approve(ctx, org, id, baseline.ApprovalInput{Version: input.Version, Reason: input.Reason, BusinessReview: input.BusinessReview, AcknowledgeDevelopmentLimits: input.Acknowledged})
	if err != nil {
		c.baselineError(w, r, err)
		return
	}
	c.success(w, r, 200, view)
}
func (c *control) retireBaseline(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, org, ok := c.authorizeOrganization(w, r, "baseline.approve")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	var input struct {
		Version int    `json:"version"`
		Reason  string `json:"reason"`
	}
	if !c.decodeManagement(w, r, &input) {
		return
	}
	view, err := c.cfg.Baselines.Retire(ctx, org, id, input.Version, input.Reason)
	if err != nil {
		c.baselineError(w, r, err)
		return
	}
	c.success(w, r, 200, view)
}
