package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/report"
	"model-integrity-inspector.local/mii/internal/integrity/reportstorage"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

func TestReportDownloadFormatClosedMIMEAndExtension(t *testing.T) {
	for _, format := range []string{"json", "html", "csv"} {
		contentType, extension, ok := reportDownloadFormat(format)
		want := map[string]string{"json": "application/json; charset=utf-8", "html": "text/html; charset=utf-8", "csv": "text/csv; charset=utf-8"}[format]
		if !ok || contentType != want || extension != format {
			t.Fatal("report download format changed MIME/extension contract")
		}
	}
	for _, format := range []string{"", "CSV", "pdf", "text/csv", "../csv", "csv\r\nX-Evil: true"} {
		contentType, extension, ok := reportDownloadFormat(format)
		if ok || contentType != "" || extension != "" {
			t.Fatal("unknown stored format fell back to an attachment")
		}
	}
}

// Exercise the real HTTP transport (including Content-Length), not only a
// recorder. The fixture already uses real queue, evidence, analysis and storage.
func reportCSVHTTPDownload(t *testing.T, f reportHTTPFixture, server *httptest.Server, view runservice.ReportView) []byte {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), "GET", server.URL+"/api/v1/reports/"+view.ID+"/download", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(f.cookie)
	request.Header.Set("X-Organization-ID", f.headers["X-Organization-ID"])
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, reportstorage.MaxBytes+1))
	if err != nil || response.StatusCode != 200 {
		t.Fatal("real report HTTP download failed", response.StatusCode, err)
	}
	contentType, extension, ok := reportDownloadFormat(view.Format)
	if !ok || response.Header.Get("Content-Type") != contentType || response.Header.Get("Content-Disposition") != `attachment; filename="report-`+view.ID+"-r"+strconv.Itoa(view.Revision)+"."+extension+`"` {
		t.Fatal("report MIME/filename contract")
	}
	sum := sha256.Sum256(body)
	if view.ContentHash == nil || view.FileHash == nil || view.FileSize == nil || response.ContentLength != int64(len(body)) || response.Header.Get("Content-Length") != strconv.Itoa(len(body)) || *view.FileSize != int64(len(body)) || *view.FileHash != "sha256:"+hex.EncodeToString(sum[:]) || response.Header.Get("X-Report-Content-Hash") != *view.ContentHash || response.Header.Get("X-Report-File-Hash") != *view.FileHash {
		t.Fatal("report HTTP hash/length contract")
	}
	for header, want := range map[string]string{"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store", "Content-Security-Policy": "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'", "Referrer-Policy": "no-referrer"} {
		if response.Header.Get(header) != want {
			t.Fatal("report download lost a security header", header)
		}
	}
	resultNoS2(t, string(body))
	return body
}

func TestReportHTTPCSVFullDeliveryKeepsLegacyReportsAndDetectsCorruption(t *testing.T) {
	f := newReportHTTPFixture(t)
	f.publish(t)
	server := httptest.NewServer(f.handler)
	defer server.Close()
	var oldViews []runservice.ReportView
	var oldBytes [][]byte
	for _, format := range []string{"json", "html"} {
		view := f.generate(t, f.create(t, format, "csv-http-legacy-"+format, f.cookie, f.headers))
		oldViews = append(oldViews, view)
		oldBytes = append(oldBytes, reportCSVHTTPDownload(t, f, server, view))
	}
	queued := f.create(t, "csv", "csv-http-real-delivery", f.cookie, f.headers)
	if queued.Format != "csv" || queued.SchemaVersion != report.SchemaVersion || queued.Status != "queued" || queued.ContentHash != nil || queued.FileHash != nil || queued.FileSize != nil {
		t.Fatal("CSV create changed schema or fabricated publication")
	}
	endpoint := "/api/v1/reports/" + queued.ID + "/download"
	expectControl(t, f.request(t, "GET", endpoint, "", f.headers, f.cookie), 409, "MI_REPORT_NOT_READY")
	view := f.generate(t, queued)
	replay := f.create(t, "csv", "csv-http-real-delivery", f.cookie, f.headers)
	if !reflect.DeepEqual(replay, view) || view.SchemaVersion != report.SchemaVersion || view.ReviewState != "not_included" {
		t.Fatal("CSV idempotency or document schema changed")
	}
	body := reportCSVHTTPDownload(t, f, server, view)
	if bytes.HasPrefix(body, []byte{0xef, 0xbb, 0xbf}) || !bytes.HasSuffix(body, []byte("\r\n")) {
		t.Fatal("CSV encoding profile changed during delivery")
	}
	rows, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil || len(rows) < 2 || !reflect.DeepEqual(rows[0], []string{"csv_schema", "path", "value_type", "json_value"}) {
		t.Fatal("HTTP body is not the actual CSV profile", err)
	}
	nodes := make(map[string][]string)
	for _, row := range rows[1:] {
		if len(row) != 4 || row[0] != report.CSVSchemaVersion || nodes[row[1]] != nil || !json.Valid([]byte(row[3])) {
			t.Fatal("HTTP CSV node profile damaged")
		}
		nodes[row[1]] = row
		resultNoS2(t, row[3])
	}
	for path, want := range map[string]any{
		"/schema_version": report.SchemaVersion, "/report_id": view.ID,
		"/content_hash": *view.ContentHash, "/review_state": "not_included", "/review": nil,
		"/development": true, "/calibrated": false, "/disclaimer": report.Disclaimer,
	} {
		encoded, err := json.Marshal(want)
		if err != nil || nodes[path] == nil || nodes[path][3] != string(encoded) {
			t.Fatal("HTTP CSV lost frozen report content", path)
		}
	}
	for _, path := range []string{"/result/versions", "/run", "/result", "/findings", "/samples", "/recommendations"} {
		if nodes[path] == nil {
			t.Fatal("HTTP CSV missing report section", path)
		}
	}
	for i, old := range oldViews {
		w := f.request(t, "GET", "/api/v1/reports/"+old.ID, "", f.headers, f.cookie)
		expectControl(t, w, 200, "")
		var current runservice.ReportView
		managementHTTPData(t, w, &current)
		if !reflect.DeepEqual(old, current) || old.ID == view.ID || *old.ContentHash == *view.ContentHash || !bytes.Equal(oldBytes[i], reportCSVHTTPDownload(t, f, server, current)) {
			t.Fatal("CSV conversion overwrote a prior report identity/artifact")
		}
	}
	w := f.request(t, "GET", "/api/v1/runs/"+strconv.FormatInt(f.runID, 10)+"/reports", "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	var page struct {
		Items []runservice.ReportView `json:"items"`
	}
	managementHTTPData(t, w, &page)
	if len(page.Items) != 3 {
		t.Fatal("CSV did not remain an independent listed report row")
	}
	object := repository.ReportObjectName(f.org, strings.TrimPrefix(*view.FileHash, "sha256:"), "csv")
	if err := os.WriteFile(filepath.Join(f.directory, object), []byte("CSV_FILE_CORRUPTION_CANARY"), 0600); err != nil {
		t.Fatal(err)
	}
	w = f.request(t, "GET", endpoint, "", f.headers, f.cookie)
	expectControl(t, w, 503, "MI_REPORT_FILE_UNAVAILABLE")
	if w.Header().Get("Content-Disposition") != "" || w.Header().Get("X-Report-File-Hash") != "" || strings.Contains(w.Body.String(), "CSV_FILE_CORRUPTION_CANARY") {
		t.Fatal("corrupt CSV was exposed as an attachment")
	}
	if !bytes.Equal(oldBytes[0], reportCSVHTTPDownload(t, f, server, oldViews[0])) {
		t.Fatal("CSV corruption affected a legacy report")
	}
	if err := f.cfg.Store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal("CSV delivery audit chain", err)
	}
}

func TestReportHTTPCSVStrictInputsDownloadAuthorityAndTenantIsolation(t *testing.T) {
	f := newReportHTTPFixture(t)
	f.publish(t)
	org, csrf := f.headers["X-Organization-ID"], f.headers["X-CSRF-Token"]
	path := "/api/v1/runs/" + strconv.FormatInt(f.runID, 10) + "/reports"
	h := runAuthorizationHeaders(org, csrf)
	h["Idempotency-Key"] = "csv-http-strict-inputs"
	for _, body := range []string{`{"format":"csv","analysis_revision":1,"include_restricted_content":true}`, `{"format":"csv","analysis_revision":1,"csv_schema":"mii.report.csv.v1"}`, `{"format":"csv","format":"json","analysis_revision":1}`} {
		expectControl(t, f.request(t, "POST", path, body, h, f.cookie), 400, "MI_INVALID_REQUEST")
	}
	for _, format := range []string{"CSV", "text/csv", "pdf", "csv "} {
		expectControl(t, f.request(t, "POST", path, `{"format":"`+format+`","analysis_revision":1}`, h, f.cookie), 400, "MI_REPORT_INVALID")
	}
	body := `{"format":"csv","analysis_revision":1}`
	expectControl(t, f.request(t, "POST", path, body, f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "POST", path, body, map[string]string{"X-Organization-ID": org, "Idempotency-Key": "csv-no-csrf-token"}, f.cookie), 403, "MI_CSRF_INVALID")
	expectControl(t, f.request(t, "POST", path, body, h, nil), 401, "MI_SESSION_REQUIRED")
	view := f.generate(t, f.create(t, "csv", "csv-http-authority", f.cookie, f.headers))
	endpoint := "/api/v1/reports/" + view.ID + "/download"
	reader := runAuthorizationMember(t, f.controlFixture, f.cookie, csrf, org, "csv-reader", "viewer", nil)
	rh := runAuthorizationHeaders(org, reader.csrf)
	expectControl(t, f.request(t, "GET", endpoint, "", rh, reader.cookie), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "GET", endpoint, "", rh, nil), 401, "MI_SESSION_REQUIRED")
	runAuthorizationChange(t, f.controlFixture, f.cookie, csrf, org, &reader, "viewer", []string{"report.export"})
	expectControl(t, f.request(t, "GET", endpoint, "", rh, reader.cookie), 200, "")
	w := f.request(t, "POST", "/api/v1/organizations", `{"name":"CSV isolation","timezone":"UTC"}`, f.headers, f.cookie)
	expectControl(t, w, 201, "")
	var other managementHTTPObject
	managementHTTPData(t, w, &other)
	expectControl(t, f.request(t, "GET", endpoint, "", runAuthorizationHeaders(other.ID, csrf), f.cookie), 404, "MI_NOT_FOUND")
	expectControl(t, f.request(t, "GET", endpoint+"?format=json", "", f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
	runAuthorizationChange(t, f.controlFixture, f.cookie, csrf, org, &reader, "viewer", nil)
	expectControl(t, f.request(t, "GET", endpoint, "", rh, reader.cookie), 403, "MI_PERMISSION_DENIED")
}

func TestReportHTTPCSVConcurrencyAndMidTransferPermissionRevocation(t *testing.T) {
	f := newReportHTTPFixture(t)
	f.publish(t)
	view := f.generate(t, f.create(t, "csv", "csv-http-revalidation", f.cookie, f.headers))
	id, err := strconv.ParseInt(view.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "/api/v1/reports/" + view.ID + "/download"
	var held []*runservice.ReportDownload
	defer func() {
		for _, d := range held {
			d.Close()
		}
	}()
	for range 4 {
		d, err := f.cfg.Reports.PrepareDownload(f.ctx, f.org, id)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, d)
	}
	w := f.request(t, "GET", endpoint, "", f.headers, f.cookie)
	expectControl(t, w, 429, "MI_REPORT_LIMIT")
	if w.Header().Get("Content-Disposition") != "" {
		t.Fatal("download limit returned an attachment")
	}
	for _, d := range held {
		d.Close()
		d.Close()
	}
	held = nil
	expectControl(t, f.request(t, "GET", endpoint, "", f.headers, f.cookie), 200, "")
	org, csrf := f.headers["X-Organization-ID"], f.headers["X-CSRF-Token"]
	reader := runAuthorizationMember(t, f.controlFixture, f.cookie, csrf, org, "csv-slow-reader", "viewer", []string{"report.export"})
	r := httptest.NewRequestWithContext(t.Context(), "GET", endpoint, nil)
	r.Header.Set("X-Organization-ID", org)
	r.AddCookie(reader.cookie)
	writer := &reportRevokingWriter{ResponseRecorder: httptest.NewRecorder(), revoke: func() {
		runAuthorizationChange(t, f.controlFixture, f.cookie, csrf, org, &reader, "viewer", nil)
	}}
	f.handler.ServeHTTP(writer, r)
	if writer.writes != 1 || writer.Body.Len() != 1 || writer.Header().Get("Content-Type") != "text/csv; charset=utf-8" {
		t.Fatal("CSV continued writing after persisted permission revocation")
	}
	expectControl(t, f.request(t, "GET", endpoint, "", runAuthorizationHeaders(org, reader.csrf), reader.cookie), 403, "MI_PERMISSION_DENIED")
	// The aborted transfer must release its slot, not gradually exhaust the
	// four-download budget. These all pass through the real service authority.
	for range 4 {
		d, err := f.cfg.Reports.PrepareDownload(f.ctx, f.org, id)
		if err != nil {
			t.Fatal("revoked CSV transfer leaked its download slot", err)
		}
		held = append(held, d)
	}
}
