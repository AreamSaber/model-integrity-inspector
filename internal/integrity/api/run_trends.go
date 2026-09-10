package api

import (
	"net/http"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func (c *control) listRunTrends(w http.ResponseWriter, r *http.Request) {
	ctx, org, ok := c.authorizeOrganization(w, r, "run.read")
	if !ok {
		return
	}
	r = r.WithContext(ctx)
	scope, err := resultScope(r, org, "run-trends/revision:1")
	if err != nil {
		c.resultError(w, r, err)
		return
	}
	filters, pageRequest, scope, err := runHistoryRequest(r, scope)
	if err != nil || filters.TargetID <= 0 {
		c.resultError(w, r, ErrPagination)
		return
	}
	page, err := c.parsePage(pageRequest, scope)
	if err != nil {
		c.resultError(w, r, err)
		return
	}
	filters.Query = page.Query
	items, more, err := c.cfg.Runs.Trends(ctx, org, repository.ListOptions{AfterID: page.AfterID, Limit: page.Limit}, filters)
	if err != nil {
		c.resultError(w, r, err)
		return
	}
	last := int64(0)
	if len(items) > 0 {
		last, _ = managementID(items[len(items)-1].Run.ID)
	}
	data, err := c.pageResult(items, last, more, scope, page.Query)
	if err != nil {
		c.resultError(w, r, err)
		return
	}
	// Closed scope/method labels make a paged trend impossible to mistake for
	// a complete-target aggregate or a calibrated future success probability.
	data["scope"] = "run_page"
	data["analysis_revision"] = 1
	data["success_rate_basis"] = "confirmed_successes_over_all_dispatches_percent"
	data["latency_basis"] = "completed_attempts_with_observed_duration"
	data["development"] = true
	data["calibrated"] = false
	c.success(w, r, http.StatusOK, data)
}
