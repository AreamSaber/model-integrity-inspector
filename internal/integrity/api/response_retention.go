package api

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func isResponseRetentionRequest(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/api/v1/runs/") && strings.HasSuffix(r.URL.Path, "/response-retention")
}

func validResponseRetentionRequest(r *http.Request) bool {
	if r.Method != http.MethodGet || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		return false
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	return err == nil && len(query) == 1 && len(query["analysis_revision"]) == 1 && query.Get("analysis_revision") == "1"
}

func (c *control) getResponseRetention(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		c.failure(w, r, 405, "MI_INVALID_REQUEST")
		return
	}
	if !validResponseRetentionRequest(r) {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	ctx, org, ok := c.authorizeOrganization(w, r, "run.read")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	view, err := c.cfg.Runs.ResponseRetention(ctx, org, id)
	if err != nil {
		if errors.Is(err, repository.ErrRetentionSource) {
			c.failure(w, r, 503, "MI_RETENTION_SOURCE_INVALID")
		} else {
			c.resultError(w, r, err)
		}
		return
	}
	c.success(w, r, 200, view)
}
