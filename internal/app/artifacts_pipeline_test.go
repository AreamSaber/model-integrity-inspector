package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/baseline"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

// Uses the actual app's authenticated HTTP, Worker, immutable TLS execution
// evidence and private filesystem. Synthetic business approvals are not release
// approvals, calibration evidence or provider-authenticated official sources.
func exercisePublishedArtifacts(t *testing.T, p *pipelineHTTP, runID string, expectedSamples int, poll func(func() bool)) {
	t.Helper()
	var reference baseline.View
	p.request(t, "POST", "/api/v1/baselines", map[string]any{"name": "Synthetic historical reference", "run_id": runID, "source": "historical", "region": "synthetic-declared-region", "expires_at": time.Now().UTC().Add(24 * time.Hour)}, 201, &reference)
	if reference.ID == "" || reference.Status != "draft" || !reference.Development || reference.Calibrated || reference.EligibleForScoring {
		t.Fatal("baseline creation lost frozen source limitations")
	}
	path := "/api/v1/baselines/" + reference.ID
	p.request(t, "GET", path, nil, 200, &reference)
	p.request(t, "PATCH", path, map[string]any{"version": reference.Version, "name": "Synthetic edited draft"}, 200, &reference)
	p.request(t, "POST", path+"/approve", map[string]any{"version": reference.Version, "reason": "Synthetic integration organization decision only", "business_review": "Synthetic high-risk review reference; no external certification", "acknowledge_development_limits": true}, 200, &reference)
	if reference.Status != "approved" || reference.ApprovedBy == nil || reference.ApprovedAt == nil || !reference.Development || reference.Calibrated || reference.EligibleForScoring {
		t.Fatal("organization approval incorrectly upgraded calibrated scoring trust")
	}
	p.request(t, "PATCH", path, map[string]any{"version": reference.Version, "name": "Forbidden approved mutation"}, 409, nil)
	p.request(t, "POST", path+"/retire", map[string]any{"version": reference.Version, "reason": "Synthetic integration retirement"}, 200, &reference)
	if reference.Status != "retired" || reference.ApprovedBy == nil || reference.RetiredAt == nil {
		t.Fatal("retirement erased historical organization approval")
	}
	p.request(t, "GET", "/api/v1/baselines?limit=1", nil, 200, nil)
	for _, format := range []string{"json", "html", "csv"} {
		p.retryKey = "synthetic-application-report-" + format
		body := map[string]any{"format": format, "analysis_revision": 1}
		var artifact runservice.ReportView
		p.request(t, "POST", "/api/v1/runs/"+runID+"/reports", body, 202, &artifact)
		id := artifact.ID
		if id == "" || artifact.RunID != runID || artifact.Format != format || artifact.ReviewState != "not_included" {
			t.Fatal("queued report receipt invalid")
		}
		// Fixed loop literals only: identify the failing renderer without IDs,
		// URLs, hashes, source snapshots or report contents in CI diagnostics.
		t.Logf("actual report Worker status polling format=%s", format)
		poll(func() bool {
			p.request(t, "GET", "/api/v1/reports/"+id, nil, 200, &artifact)
			if artifact.Status == "failed" {
				t.Fatal("actual application report Worker failed")
			}
			return artifact.Status == "ready"
		})
		if artifact.ContentHash == nil || artifact.FileHash == nil || artifact.FileSize == nil || *artifact.FileSize <= 0 || artifact.Revision < 1 {
			t.Fatal("ready report lacks independent file identity")
		}
		data := downloadPipelineReport(t, p, artifact)
		switch format {
		case "json":
			var doc struct {
				ReportID                string            `json:"report_id"`
				RunID                   string            `json:"run_id"`
				OrganizationID          string            `json:"organization_id"`
				Samples                 []json.RawMessage `json:"samples"`
				ReviewState             string            `json:"review_state"`
				Review                  json.RawMessage   `json:"review"`
				Development, Calibrated bool
			}
			if json.Unmarshal(data, &doc) != nil || doc.ReportID != id || doc.RunID != runID || doc.OrganizationID != p.orgID || len(doc.Samples) != expectedSamples || doc.ReviewState != "not_included" || string(doc.Review) != "null" || !doc.Development || doc.Calibrated {
				t.Fatal("report misrepresented development or human review state")
			}
		case "html":
			if !bytes.Contains(data, []byte("<!doctype html>")) || !bytes.Contains(data, []byte("未纳入人工复核快照")) {
				t.Fatal("HTML report missing truthful review boundary")
			}
		case "csv":
			checkPipelineCSV(t, data, artifact, p.orgID, expectedSamples)
		default:
			t.Fatal("unsupported actual pipeline report format")
		}
		p.request(t, "POST", "/api/v1/runs/"+runID+"/reports", body, 202, &artifact)
		if artifact.ID != id || !bytes.Equal(data, downloadPipelineReport(t, p, artifact)) {
			t.Fatal("report retry rewrote frozen artifact")
		}
	}
	p.retryKey = ""
	p.request(t, "GET", "/api/v1/runs/"+runID+"/reports?analysis_revision=1&limit=1", nil, 200, nil)
}

func downloadPipelineReport(t *testing.T, p *pipelineHTTP, artifact runservice.ReportView) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), "GET", p.endpoint+"/api/v1/reports/"+artifact.ID+"/download", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Organization-ID", p.orgID)
	response, err := p.client.Do(req)
	if err != nil {
		t.Fatal("actual report download failed")
	}
	defer func() { _ = response.Body.Close() }()
	mime, known := map[string]string{"json": "application/json", "html": "text/html", "csv": "text/csv"}[artifact.Format]
	if !known || response.Header.Get("Content-Type") != mime+"; charset=utf-8" || response.Header.Get("Content-Disposition") != `attachment; filename="report-`+artifact.ID+"-r"+strconv.Itoa(artifact.Revision)+"."+artifact.Format+`"` {
		t.Fatal("actual pipeline report MIME or immutable filename mismatch")
	}
	if response.StatusCode != 200 || response.Header.Get("X-Content-Type-Options") != "nosniff" || !strings.HasPrefix(response.Header.Get("Content-Disposition"), "attachment;") || !strings.Contains(response.Header.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("report download boundary failed: status %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
	if err != nil || len(data) > 16<<20 || artifact.FileSize == nil || int64(len(data)) != *artifact.FileSize || artifact.FileHash == nil || artifact.ContentHash == nil {
		t.Fatal("download size/identity invalid")
	}
	digest := sha256.Sum256(data)
	if "sha256:"+hex.EncodeToString(digest[:]) != *artifact.FileHash || response.Header.Get("X-Report-Content-Hash") != *artifact.ContentHash || response.Header.Get("X-Report-File-Hash") != *artifact.FileHash {
		t.Fatal("download independent hash mismatch")
	}
	for _, forbidden := range []string{pipelineKey, `"api_key"`, `"ciphertext"`, `"snapshot_json"`, `"messages"`} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatal("restricted content leaked into report")
		}
	}
	return data
}
