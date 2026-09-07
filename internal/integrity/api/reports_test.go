package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/reportstorage"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
	"model-integrity-inspector.local/mii/internal/integrity/worker"
)

type reportHTTPFixture struct {
	resultHTTPFixture
	storage   *reportstorage.Store
	directory string
}

func newReportHTTPFixture(t *testing.T) reportHTTPFixture {
	t.Helper()
	f := newResultHTTPFixture(t)
	directory := filepath.Join(t.TempDir(), "reports")
	storage, err := reportstorage.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	f.cfg.Reports, err = runservice.NewReportService(runservice.ReportConfig{Store: f.cfg.Store, Storage: storage, Ready: func(context.Context) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	f.handler, err = NewControlHandler(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return reportHTTPFixture{f, storage, directory}
}

func (f reportHTTPFixture) create(t *testing.T, format, key string, cookie *http.Cookie, headers map[string]string) runservice.ReportView {
	t.Helper()
	h := runAuthorizationHeaders(headers["X-Organization-ID"], headers["X-CSRF-Token"])
	h["Idempotency-Key"] = key
	w := f.request(t, "POST", "/api/v1/runs/"+strconv.FormatInt(f.runID, 10)+"/reports", `{"format":"`+format+`","analysis_revision":1}`, h, cookie)
	expectControl(t, w, 202, "")
	resultNoS2(t, w.Body.String())
	var view runservice.ReportView
	managementHTTPData(t, w, &view)
	return view
}

func (f reportHTTPFixture) generate(t *testing.T, view runservice.ReportView) runservice.ReportView {
	t.Helper()
	lease, err := f.queue.Claim(t.Context())
	if err != nil || lease == nil || lease.Job.Type != string(repository.JobReportGenerate) {
		t.Fatal("report claim", err)
	}
	handler, err := worker.NewReportHandler(worker.ReportConfig{Storage: f.storage})
	if err != nil {
		t.Fatal(err)
	}
	completion, err := handler(t.Context(), worker.Execution{Queue: f.queue, Lease: *lease})
	if err != nil {
		t.Fatal("real report generation", err)
	}
	if err := f.queue.CompleteWith(t.Context(), *lease, completion); err != nil {
		t.Fatal(err)
	}
	w := f.request(t, "GET", "/api/v1/reports/"+view.ID, "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	managementHTTPData(t, w, &view)
	if view.Status != "ready" || view.FileHash == nil || view.ContentHash == nil || view.FileSize == nil || view.ReviewState != "not_included" {
		t.Fatal("ready metadata")
	}
	return view
}

// Actual adapter/evidence/analysis -> queued report -> real artifact -> HTTP.
// All model output is synthetic and no public/paid upstream is contacted.
func TestReportHTTPGenerationDownloadPaginationAndIntegrity(t *testing.T) {
	f := newReportHTTPFixture(t)
	path := "/api/v1/runs/" + strconv.FormatInt(f.runID, 10) + "/reports"
	h := runAuthorizationHeaders(f.headers["X-Organization-ID"], f.headers["X-CSRF-Token"])
	h["Idempotency-Key"] = "report-before-published"
	expectControl(t, f.request(t, "POST", path, `{"format":"json","analysis_revision":1}`, h, f.cookie), 404, "MI_NOT_FOUND")
	f.publish(t)
	var ready []runservice.ReportView
	for _, format := range []string{"json", "html"} {
		view := f.create(t, format, "report-logical-create-"+format, f.cookie, f.headers)
		if view.Status != "queued" || view.ContentHash != nil || view.FileSize != nil {
			t.Fatal("synchronous report publication")
		}
		expectControl(t, f.request(t, "GET", "/api/v1/reports/"+view.ID+"/download", "", f.headers, f.cookie), 409, "MI_REPORT_NOT_READY")
		view = f.generate(t, view)
		retry := f.create(t, format, "report-logical-create-"+format, f.cookie, f.headers)
		if retry.ID != view.ID || !retry.CreatedAt.Equal(view.CreatedAt) || retry.Revision != view.Revision {
			t.Fatal("idempotent report changed")
		}
		ready = append(ready, view)
		server := httptest.NewServer(f.handler)
		request, err := http.NewRequestWithContext(t.Context(), "GET", server.URL+"/api/v1/reports/"+view.ID+"/download", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.AddCookie(f.cookie)
		request.Header.Set("X-Organization-ID", f.headers["X-Organization-ID"])
		response, err := server.Client().Do(request)
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, reportstorage.MaxBytes+1))
		_ = response.Body.Close()
		server.Close()
		if err != nil || response.StatusCode != 200 {
			t.Fatal("download", response.StatusCode, err)
		}
		resultNoS2(t, string(body))
		sum := sha256.Sum256(body)
		if int64(len(body)) != *view.FileSize || "sha256:"+hex.EncodeToString(sum[:]) != *view.FileHash || response.Header.Get("X-Report-Content-Hash") != *view.ContentHash || response.Header.Get("X-Report-File-Hash") != *view.FileHash {
			t.Fatal("artifact hashes")
		}
		if !strings.HasPrefix(response.Header.Get("Content-Disposition"), "attachment;") || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("Content-Security-Policy") != "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'" || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("download security headers")
		}
		if !strings.Contains(string(body), "not_included") || strings.Contains(string(body), "<script") {
			t.Fatal("review/HTML boundary")
		}
	}
	w := f.request(t, "GET", path+"?limit=1", "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	var page struct {
		Items []runservice.ReportView `json:"items"`
		Next  *string                 `json:"next_cursor"`
	}
	managementHTTPData(t, w, &page)
	if len(page.Items) != 1 || page.Next == nil {
		t.Fatal("report cursor")
	}
	first := page.Items[0].ID
	w = f.request(t, "GET", path+"?cursor="+*page.Next, "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	managementHTTPData(t, w, &page)
	if len(page.Items) != 1 || page.Items[0].ID == first || page.Next != nil {
		t.Fatal("report pagination")
	}
	// A corrupted local file never produces an attachment or partial body.
	view := ready[0]
	name := reportstorage.Reference{OrganizationID: f.org, Hash: strings.TrimPrefix(*view.FileHash, "sha256:"), Format: view.Format, Size: *view.FileSize}.Name()
	if err := os.WriteFile(filepath.Join(f.directory, name), []byte("CORRUPTED_REPORT_CANARY"), 0600); err != nil {
		t.Fatal(err)
	}
	w = f.request(t, "GET", "/api/v1/reports/"+view.ID+"/download", "", f.headers, f.cookie)
	expectControl(t, w, 503, "MI_REPORT_FILE_UNAVAILABLE")
	if w.Header().Get("Content-Disposition") != "" || strings.Contains(w.Body.String(), "CORRUPTED_REPORT_CANARY") {
		t.Fatal("corrupt file disclosed")
	}
	if err := f.cfg.Store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}

func TestReportHTTPStrictInputsTenantAndRevocation(t *testing.T) {
	f := newReportHTTPFixture(t)
	f.publish(t)
	org, csrf := f.headers["X-Organization-ID"], f.headers["X-CSRF-Token"]
	path := "/api/v1/runs/" + strconv.FormatInt(f.runID, 10) + "/reports"
	body := `{"format":"json","analysis_revision":1}`
	h := runAuthorizationHeaders(org, csrf)
	h["Idempotency-Key"] = "report-strict-inputs"
	for _, input := range []string{`{"format":"json","analysis_revision":1,"unknown":1}`, `{"format":"json","format":"html","analysis_revision":1}`, `{"format":"json","analysis_revision":null}`, `{"format":"json","analysis_revision":1,"include_restricted_content":true}`} {
		expectControl(t, f.request(t, "POST", path, input, h, f.cookie), 400, "MI_INVALID_REQUEST")
	}
	for _, input := range []string{`{"format":"pdf","analysis_revision":1}`, `{"format":"json","analysis_revision":2}`} {
		expectControl(t, f.request(t, "POST", path, input, h, f.cookie), 400, "MI_REPORT_INVALID")
	}
	expectControl(t, f.request(t, "POST", path, body, f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "POST", path, body, map[string]string{"X-Organization-ID": org, "Idempotency-Key": "report-no-csrf-token"}, f.cookie), 403, "MI_CSRF_INVALID")
	expectControl(t, f.request(t, "POST", path, body, h, nil), 401, "MI_SESSION_REQUIRED")
	expectControl(t, f.request(t, "POST", path+"?path=secret", body, h, f.cookie), 400, "MI_INVALID_REQUEST")
	view := f.generate(t, f.create(t, "json", "report-auth-ready-key", f.cookie, f.headers))
	reader := runAuthorizationMember(t, f.controlFixture, f.cookie, csrf, org, "report-reader", "viewer", nil)
	rh := runAuthorizationHeaders(org, reader.csrf)
	expectControl(t, f.request(t, "GET", "/api/v1/reports/"+view.ID, "", rh, reader.cookie), 403, "MI_PERMISSION_DENIED")
	runAuthorizationChange(t, f.controlFixture, f.cookie, csrf, org, &reader, "viewer", []string{"report.export"})
	for _, suffix := range []string{"", "/download"} {
		expectControl(t, f.request(t, "GET", "/api/v1/reports/"+view.ID+suffix, "", rh, reader.cookie), 200, "")
	}
	w := f.request(t, "POST", "/api/v1/organizations", `{"name":"Report isolation","timezone":"UTC"}`, f.headers, f.cookie)
	expectControl(t, w, 201, "")
	var other managementHTTPObject
	managementHTTPData(t, w, &other)
	for _, endpoint := range []string{path, "/api/v1/reports/" + view.ID, "/api/v1/reports/" + view.ID + "/download"} {
		expectControl(t, f.request(t, "GET", endpoint, "", runAuthorizationHeaders(other.ID, csrf), f.cookie), 404, "MI_NOT_FOUND")
		expectControl(t, f.request(t, "GET", endpoint+"?unexpected=1", "", f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
	}
	runAuthorizationChange(t, f.controlFixture, f.cookie, csrf, org, &reader, "viewer", nil)
	for _, suffix := range []string{"", "/download"} {
		expectControl(t, f.request(t, "GET", "/api/v1/reports/"+view.ID+suffix, "", rh, reader.cookie), 403, "MI_PERMISSION_DENIED")
	}
	// Queued work belongs to the persistent creator, not the login token.
	queued := f.create(t, "html", "report-logout-queued-key", f.cookie, f.headers)
	expectControl(t, f.request(t, "POST", "/api/v1/auth/logout", `{}`, f.headers, f.cookie), 200, "")
	expectControl(t, f.request(t, "GET", "/api/v1/reports/"+queued.ID, "", f.headers, f.cookie), 401, "MI_SESSION_REQUIRED")
	lease, err := f.queue.Claim(t.Context())
	if err != nil || lease == nil {
		t.Fatal(err)
	}
	if _, err := f.queue.LoadReportSource(t.Context(), *lease); err != nil {
		t.Fatal("logout cancelled creator authority", err)
	}
}

type reportRevokingWriter struct {
	*httptest.ResponseRecorder
	revoke func()
	writes int
}

func (w *reportRevokingWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		n, err := w.ResponseRecorder.Write(p[:1])
		w.revoke()
		time.Sleep(1100 * time.Millisecond)
		return n, err
	}
	return w.ResponseRecorder.Write(p)
}

func TestReportHTTPDownloadRevalidatesDuringTransferAndBoundsConcurrency(t *testing.T) {
	f := newReportHTTPFixture(t)
	f.publish(t)
	view := f.generate(t, f.create(t, "html", "report-slow-download-key", f.cookie, f.headers))
	id, _ := strconv.ParseInt(view.ID, 10, 64)
	var downloads []*runservice.ReportDownload
	for range 4 {
		d, err := f.cfg.Reports.PrepareDownload(f.ctx, f.org, id)
		if err != nil {
			t.Fatal(err)
		}
		downloads = append(downloads, d)
	}
	if d, err := f.cfg.Reports.PrepareDownload(f.ctx, f.org, id); !errors.Is(err, repository.ErrReportLimit) {
		if d != nil {
			d.Close()
		}
		t.Fatal("download limit", err)
	}
	for _, d := range downloads {
		d.Close()
		d.Close()
	}
	r := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/reports/"+view.ID+"/download", nil)
	r.Header.Set("X-Organization-ID", f.headers["X-Organization-ID"])
	r.AddCookie(f.cookie)
	w := &reportRevokingWriter{ResponseRecorder: httptest.NewRecorder(), revoke: func() {
		expectControl(t, f.request(t, "POST", "/api/v1/auth/logout", `{}`, f.headers, f.cookie), 200, "")
	}}
	f.handler.ServeHTTP(w, r)
	if w.writes != 1 || w.Body.Len() != 1 {
		t.Fatal("continued writing after persisted session revocation")
	}
	expectControl(t, f.request(t, "GET", "/api/v1/reports/"+view.ID+"/download", "", f.headers, f.cookie), 401, "MI_SESSION_REQUIRED")
}
