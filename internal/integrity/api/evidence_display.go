package api

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

// Match conservatively before authentication to bound expensive setup/session
// reads as well as the disclosure itself. The router still validates exact IDs.
func isEvidenceDisplayRequest(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/api/v1/runs/") && strings.HasSuffix(r.URL.Path, "/evidence")
}

func (c *control) registerEvidenceDisplayRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/runs/{id}/samples/{sampleId}/attempts/{attemptId}/evidence", c.readEvidenceDisplay)
}

func (c *control) evidenceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, runservice.ErrEvidenceLimit):
		w.Header().Set("Retry-After", "2")
		c.failure(w, r, 429, "MI_EVIDENCE_LIMIT")
	case errors.Is(err, runservice.ErrEvidenceUnavailable), errors.Is(err, repository.ErrDisplaySource), errors.Is(err, repository.ErrConflict):
		c.failure(w, r, 503, "MI_EVIDENCE_UNAVAILABLE")
	default:
		c.resultError(w, r, err)
	}
}

func (c *control) readEvidenceDisplay(w http.ResponseWriter, r *http.Request) {
	// net/http's GET route also matches HEAD. A HEAD/Range/conditional request
	// must not become a second path around the one-time audited body release.
	if r.Method != http.MethodGet {
		c.failure(w, r, 405, "MI_INVALID_REQUEST")
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	for _, name := range []string{"Range", "If-Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since"} {
		if len(r.Header.Values(name)) != 0 {
			c.failure(w, r, 400, "MI_INVALID_REQUEST")
			return
		}
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["analysis_revision"]) != 1 || query.Get("analysis_revision") != "1" {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	ctx, org, ok := c.authorizeOrganization(w, r, "evidence.body")
	if !ok {
		return
	}
	r = r.WithContext(ctx)
	selection := repository.DisplaySelection{AnalysisRevision: 1}
	for _, field := range []struct {
		name string
		id   *int64
	}{{"id", &selection.RunID}, {"sampleId", &selection.SampleID}, {"attemptId", &selection.AttemptID}} {
		id, ok := c.managementPathID(w, r, field.name)
		if !ok {
			return
		}
		*field.id = id
	}
	requestID, _ := ctx.Value(requestIDKey{}).(string)
	disclosure, err := c.cfg.Evidence.PrepareDisplay(ctx, org, selection, requestID)
	if err != nil {
		c.evidenceError(w, r, err)
		return
	}
	defer disclosure.Close()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// No Content-Length/ETag: grant failures can still return the normal safe
	// error envelope, and conditional responses must never bypass authorization.
	sink := &evidenceHTTPWriter{writer: w, controller: http.NewResponseController(w), request: r}
	_, err = disclosure.WriteTo(ctx, sink)
	if err != nil && !sink.started {
		c.evidenceError(w, r, err)
	}
	// Once any Write was attempted, never append an error JSON to partial S2.
}

type evidenceHTTPWriter struct {
	writer     http.ResponseWriter
	controller *http.ResponseController
	request    *http.Request
	started    bool
}

func (w *evidenceHTTPWriter) Write(data []byte) (int, error) {
	if w.request.Context().Err() != nil {
		return 0, runservice.ErrEvidenceUnavailable
	}
	deadline := time.Now().Add(2 * time.Second)
	if original, ok := w.request.Context().Deadline(); ok && original.Before(deadline) {
		deadline = original
	}
	if err := w.controller.SetWriteDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return 0, runservice.ErrEvidenceUnavailable
	}
	w.started = true
	// #nosec G705 -- bounded authenticated JSON encoded by the private display service; application/json, nosniff and no-store. Never interpreted as HTML.
	return w.writer.Write(data)
}
