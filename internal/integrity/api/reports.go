package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/reportstorage"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func (c *control) registerReportRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/runs/{id}/reports", c.createReport)
	mux.HandleFunc("GET /api/v1/runs/{id}/reports", c.listReports)
	mux.HandleFunc("GET /api/v1/reports/{reportId}", c.getReport)
	mux.HandleFunc("GET /api/v1/reports/{reportId}/download", c.downloadReport)
}
func (c *control) reportError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, repository.ErrReportInvalid):
		c.failure(w, r, 400, "MI_REPORT_INVALID")
	case errors.Is(err, repository.ErrReportNotReady):
		c.failure(w, r, 409, "MI_REPORT_NOT_READY")
	case errors.Is(err, repository.ErrReportLimit):
		c.failure(w, r, 429, "MI_REPORT_LIMIT")
	case errors.Is(err, repository.ErrConflict):
		c.failure(w, r, 409, "MI_REPORT_CONFLICT")
	case errors.Is(err, reportstorage.ErrUnsafe), errors.Is(err, reportstorage.ErrUnavailable), errors.Is(err, reportstorage.ErrIntegrity):
		c.failure(w, r, 503, "MI_REPORT_FILE_UNAVAILABLE")
	default:
		c.resultError(w, r, err)
	}
}
func (c *control) createReport(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, org, ok := c.authorizeOrganization(w, r, "report.export")
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
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	var body struct {
		Format            string `json:"format"`
		AnalysisRevision  int    `json:"analysis_revision"`
		IncludeRestricted bool   `json:"include_restricted_content"`
	}
	if !c.decode(w, r, &body) {
		return
	}
	if body.IncludeRestricted {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	view, err := c.cfg.Reports.Create(ctx, org, repository.ReportInput{RunID: id, AnalysisRevision: body.AnalysisRevision, Format: body.Format, IdempotencyKey: keys[0]})
	if err != nil {
		c.reportError(w, r, err)
		return
	}
	c.success(w, r, 202, view)
}
func (c *control) getReport(w http.ResponseWriter, r *http.Request) {
	ctx, org, ok := c.authorizeOrganization(w, r, "report.export")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "reportId")
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	view, err := c.cfg.Reports.Get(ctx, org, id)
	if err != nil {
		c.reportError(w, r, err)
		return
	}
	c.success(w, r, 200, view)
}
func (c *control) listReports(w http.ResponseWriter, r *http.Request) {
	ctx, org, ok := c.authorizeOrganization(w, r, "report.export")
	if !ok {
		return
	}
	r = r.WithContext(ctx)
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	revision, _, request, err := resultRequest(r, true, false)
	if err != nil {
		c.reportError(w, r, err)
		return
	}
	scope, err := resultScope(r, org, "runs/"+strconv.FormatInt(id, 10)+"/reports/revision:"+strconv.Itoa(revision))
	if err != nil {
		c.reportError(w, r, err)
		return
	}
	page, err := c.parsePage(request, scope)
	if err != nil {
		c.reportError(w, r, err)
		return
	}
	rows, err := c.cfg.Reports.List(ctx, org, id, revision, repository.ListOptions{AfterID: page.AfterID, Limit: page.Limit})
	if err != nil {
		c.reportError(w, r, err)
		return
	}
	last := int64(0)
	if len(rows) > 0 {
		last, _ = managementID(rows[len(rows)-1].ID)
	}
	more := false
	if len(rows) == page.Limit {
		next, err := c.cfg.Reports.List(ctx, org, id, revision, repository.ListOptions{AfterID: last, Limit: 1})
		if err != nil {
			c.reportError(w, r, err)
			return
		}
		more = len(next) > 0
	}
	data, err := c.pageResult(rows, last, more, scope, "")
	if err != nil {
		c.reportError(w, r, err)
		return
	}
	c.success(w, r, 200, data)
}
func (c *control) downloadReport(w http.ResponseWriter, r *http.Request) {
	ctx, org, ok := c.authorizeOrganization(w, r, "report.export")
	if !ok {
		return
	}
	r = r.WithContext(ctx)
	id, ok := c.managementPathID(w, r, "reportId")
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	download, err := c.cfg.Reports.PrepareDownload(ctx, org, id)
	if err != nil {
		c.reportError(w, r, err)
		return
	}
	defer download.Close()
	view := download.View()
	contentType, extension, ok := reportDownloadFormat(view.Format)
	if !ok {
		c.failure(w, r, 503, "MI_REPORT_FILE_UNAVAILABLE")
		return
	}
	data := download.Bytes()
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		c.failure(w, r, 503, "MI_REPORT_FILE_UNAVAILABLE")
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="report-`+view.ID+"-r"+strconv.Itoa(view.Revision)+"."+extension+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("X-Report-Content-Hash", *view.ContentHash)
	w.Header().Set("X-Report-File-Hash", *view.FileHash)
	started, lastCheck := time.Now(), time.Now()
	for offset := 0; offset < len(data); {
		if r.Context().Err() != nil || time.Since(started) > time.Minute {
			return
		}
		if time.Since(lastCheck) >= time.Second {
			check, stop := context.WithTimeout(r.Context(), time.Second)
			err := download.Revalidate(check)
			stop()
			if err != nil {
				return
			}
			lastCheck = time.Now()
		}
		if err := controller.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return
		}
		end := min(offset+64*1024, len(data))
		// #nosec G705 -- bytes are a bounded verified report artifact, never caller HTML; attachment/nosniff and sandbox default-src none apply to all three fixed MIME types.
		n, err := w.Write(data[offset:end])
		if err != nil || n == 0 {
			return
		}
		offset += n
	}
}

func reportDownloadFormat(format string) (contentType, extension string, ok bool) {
	switch format {
	case "json":
		return "application/json; charset=utf-8", "json", true
	case "html":
		return "text/html; charset=utf-8", "html", true
	case "csv":
		return "text/csv; charset=utf-8", "csv", true
	default:
		return "", "", false
	}
}
