package api

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func (c *control) registerRunResultRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/runs", c.listRunHistory)
	mux.HandleFunc("GET /api/v1/runs/trends", c.listRunTrends)
	mux.HandleFunc("GET /api/v1/runs/{id}/result", c.getRunResult)
	mux.HandleFunc("GET /api/v1/runs/{id}/response-retention", c.getResponseRetention)
	mux.HandleFunc("GET /api/v1/runs/{id}/findings", c.listRunFindings)
	mux.HandleFunc("GET /api/v1/runs/{id}/samples", c.listRunSamples)
	mux.HandleFunc("GET /api/v1/runs/{id}/samples/{sampleId}", c.getRunSample)
}

func (c *control) resultError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, repository.ErrResultDocument) {
		c.failure(w, r, 503, "MI_ANALYSIS_RESULT_INVALID")
		return
	}
	c.runError(w, r, err)
}

func resultScope(r *http.Request, orgID int64, resource string) (string, error) {
	actor, err := audit.ActorFromContext(r.Context())
	if err != nil || actor.ActorID <= 0 {
		return "", repository.ErrManagementSession
	}
	return "user:" + strconv.FormatInt(actor.ActorID, 10) + "/org:" + strconv.FormatInt(orgID, 10) + "/" + resource, nil
}

func runHistoryRequest(r *http.Request, scope string) (repository.RunFilters, *http.Request, string, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return repository.RunFilters{}, nil, "", ErrPagination
	}
	filters := repository.RunFilters{}
	bound := url.Values{}
	for _, name := range []string{"target_id", "status", "package", "model", "channel_id", "risk_level", "date_from", "date_to"} {
		values, exists := q[name]
		if !exists {
			continue
		}
		if len(values) != 1 || values[0] == "" {
			return filters, nil, "", ErrPagination
		}
		value := strings.TrimSpace(values[0])
		if value == "" {
			return filters, nil, "", ErrPagination
		}
		bound.Set(name, value)
		q.Del(name)
		switch name {
		case "target_id":
			id, ok := managementID(value)
			if !ok {
				return filters, nil, "", ErrPagination
			}
			filters.TargetID = id
		case "status":
			filters.Status = value
		case "package":
			filters.Package = value
		case "model":
			filters.Model = value
		case "channel_id":
			filters.ChannelID = value
		case "risk_level":
			mapped, ok := map[string]string{"low": "low", "watch": "attention", "medium": "medium", "high": "high", "critical": "severe_black_box_statistical_judgment", "insufficient": "insufficient"}[value]
			if !ok {
				return filters, nil, "", ErrPagination
			}
			filters.RiskLevel = mapped
		case "date_from", "date_to":
			parsed, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return filters, nil, "", ErrPagination
			}
			parsed = parsed.UTC()
			if name == "date_from" {
				filters.From = &parsed
			} else {
				filters.To = &parsed
			}
			bound.Set(name, parsed.Format(time.RFC3339Nano))
		}
	}
	if !filters.Valid() {
		return filters, nil, "", ErrPagination
	}
	clone := r.Clone(r.Context())
	clone.URL.RawQuery = q.Encode()
	return filters, clone, scope + "/filters:" + bound.Encode(), nil
}

func (c *control) listRunHistory(w http.ResponseWriter, r *http.Request) {
	ctx, org, ok := c.authorizeOrganization(w, r, "run.read")
	if !ok {
		return
	}
	r = r.WithContext(ctx)
	scope, err := resultScope(r, org, "runs")
	if err != nil {
		c.resultError(w, r, err)
		return
	}
	filters, pageRequest, scope, err := runHistoryRequest(r, scope)
	if err != nil {
		c.resultError(w, r, err)
		return
	}
	page, err := c.parsePage(pageRequest, scope)
	if err != nil {
		c.resultError(w, r, err)
		return
	}
	filters.Query = page.Query
	rows, err := c.cfg.Runs.History(ctx, org, repository.ListOptions{AfterID: page.AfterID, Limit: page.Limit}, filters)
	if err != nil {
		c.resultError(w, r, err)
		return
	}
	last := int64(0)
	if len(rows) > 0 {
		last, _ = managementID(rows[len(rows)-1].ID)
	}
	more := false
	if len(rows) == page.Limit {
		next, err := c.cfg.Runs.History(ctx, org, repository.ListOptions{AfterID: last, Limit: 1}, filters)
		if err != nil {
			c.resultError(w, r, err)
			return
		}
		more = len(next) > 0
	}
	result, err := c.pageResult(rows, last, more, scope, page.Query)
	if err != nil {
		c.resultError(w, r, err)
		return
	}
	c.success(w, r, 200, result)
}

func resultRequest(r *http.Request, allowPage, allowStatistics bool) (int, bool, *http.Request, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return 0, false, nil, ErrPagination
	}
	revision := 1
	statistics := false
	if values, exists := q["analysis_revision"]; exists {
		if len(values) != 1 {
			return 0, false, nil, ErrPagination
		}
		parsed, err := strconv.Atoi(values[0])
		if err != nil || parsed < 1 || parsed > 2147483647 || strconv.Itoa(parsed) != values[0] {
			return 0, false, nil, ErrPagination
		}
		revision = parsed
		q.Del("analysis_revision")
	}
	if values, exists := q["include"]; exists {
		if !allowStatistics || len(values) != 1 || values[0] != "statistics" {
			return 0, false, nil, ErrPagination
		}
		statistics = true
		q.Del("include")
	}
	if !allowPage && len(q) > 0 || q.Has("q") {
		return 0, false, nil, ErrPagination
	}
	clone := r.Clone(r.Context())
	clone.URL.RawQuery = q.Encode()
	return revision, statistics, clone, nil
}

func (c *control) getRunResult(w http.ResponseWriter, r *http.Request) {
	ctx, org, ok := c.authorizeOrganization(w, r, "run.read")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	revision, statistics, _, err := resultRequest(r, false, true)
	if err != nil {
		c.resultError(w, r, err)
		return
	}
	view, err := c.cfg.Runs.Result(ctx, org, id, revision, statistics)
	if err != nil {
		c.resultError(w, r, err)
		return
	}
	c.success(w, r, 200, view)
}

func (c *control) listRunFindings(w http.ResponseWriter, r *http.Request) {
	c.runEvidenceList(w, r, true)
}
func (c *control) listRunSamples(w http.ResponseWriter, r *http.Request) {
	c.runEvidenceList(w, r, false)
}

func (c *control) runEvidenceList(w http.ResponseWriter, r *http.Request, findings bool) {
	ctx, org, ok := c.authorizeOrganization(w, r, "evidence.read")
	if !ok {
		return
	}
	r = r.WithContext(ctx)
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	revision, _, pageRequest, err := resultRequest(r, true, false)
	if err != nil {
		c.resultError(w, r, err)
		return
	}
	resource := "samples"
	if findings {
		resource = "findings"
	}
	scope, err := resultScope(r, org, "runs/"+strconv.FormatInt(id, 10)+"/"+resource+"/revision:"+strconv.Itoa(revision))
	if err != nil {
		c.resultError(w, r, err)
		return
	}
	page, err := c.parsePage(pageRequest, scope)
	if err != nil {
		c.resultError(w, r, err)
		return
	}
	options := repository.ListOptions{AfterID: page.AfterID, Limit: page.Limit}
	var items any
	var last int64
	more := false
	if findings {
		rows, err := c.cfg.Runs.Findings(ctx, org, id, revision, options)
		if err != nil {
			c.resultError(w, r, err)
			return
		}
		items = rows
		if len(rows) > 0 {
			last, _ = managementID(rows[len(rows)-1].ID)
		}
		if len(rows) == page.Limit {
			next, err := c.cfg.Runs.Findings(ctx, org, id, revision, repository.ListOptions{AfterID: last, Limit: 1})
			if err != nil {
				c.resultError(w, r, err)
				return
			}
			more = len(next) > 0
		}
	} else {
		rows, err := c.cfg.Runs.Samples(ctx, org, id, revision, options)
		if err != nil {
			c.resultError(w, r, err)
			return
		}
		items = rows
		if len(rows) > 0 {
			last, _ = managementID(rows[len(rows)-1].ID)
		}
		if len(rows) == page.Limit {
			next, err := c.cfg.Runs.Samples(ctx, org, id, revision, repository.ListOptions{AfterID: last, Limit: 1})
			if err != nil {
				c.resultError(w, r, err)
				return
			}
			more = len(next) > 0
		}
	}
	result, err := c.pageResult(items, last, more, scope, "")
	if err != nil {
		c.resultError(w, r, err)
		return
	}
	c.success(w, r, 200, result)
}

func (c *control) getRunSample(w http.ResponseWriter, r *http.Request) {
	ctx, org, ok := c.authorizeOrganization(w, r, "evidence.read")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	sampleID, ok := c.managementPathID(w, r, "sampleId")
	if !ok {
		return
	}
	revision, _, _, err := resultRequest(r, false, false)
	if err != nil {
		c.resultError(w, r, err)
		return
	}
	view, err := c.cfg.Runs.Sample(ctx, org, id, sampleID, revision)
	if err != nil {
		c.resultError(w, r, err)
		return
	}
	c.success(w, r, 200, view)
}
