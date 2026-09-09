package app

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

// This helper runs only after actual TLS execution and publication. Unlike the
// normal S1 request helper, it deliberately admits authenticated S2 in this one
// explicit route while continuing to reject credentials and storage envelopes.
func exercisePipelineDisplay(t *testing.T, cfg Config, store *repository.Store, db *sql.DB, p *pipelineHTTP, runID string, days int) {
	t.Helper()
	var sampleID, attemptID string
	selection := `SELECT s.id,s.final_attempt_id FROM integrity_logical_samples s WHERE s.organization_id=$1 AND s.run_id=$2`
	if days > 0 {
		// Positive disclosure tests select a real captured copy. A safe sealing
		// failure is S1 metadata, not an available display body; the retention
		// helper below independently proves those rows survive body cleanup.
		selection += ` AND EXISTS (SELECT 1 FROM integrity_display_evidence d WHERE d.organization_id=s.organization_id AND d.run_id=s.run_id AND d.attempt_id=s.final_attempt_id AND d.state='captured')`
	}
	if err := db.QueryRowContext(t.Context(), selection+` ORDER BY s.id LIMIT 1`, p.orgID, runID).Scan(&sampleID, &attemptID); err != nil {
		t.Fatal("select actual published display attempt")
	}
	path := "/api/v1/runs/" + runID + "/samples/" + sampleID + "/attempts/" + attemptID + "/evidence?analysis_revision=1"
	read := func(method, suffix, header, value string, expected int) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, p.endpoint+path+suffix, nil)
		if err != nil {
			t.Fatal("construct bounded display request")
		}
		req.Header.Set("X-Organization-ID", p.orgID)
		if header != "" {
			req.Header.Set(header, value)
		}
		res, err := p.client.Do(req)
		if err != nil {
			t.Fatal("actual display HTTP failed")
		}
		defer func() { _ = res.Body.Close() }()
		data, err := io.ReadAll(io.LimitReader(res.Body, (8<<20)+1))
		if err != nil || len(data) > 8<<20 || res.StatusCode != expected {
			t.Fatalf("display HTTP status %d wanted %d; bounded read valid=%t", res.StatusCode, expected, err == nil)
		}
		if res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("X-Content-Type-Options") != "nosniff" || res.Header.Get("Referrer-Policy") != "no-referrer" || res.Header.Get("ETag") != "" {
			t.Fatal("display response omitted no-store boundaries")
		}
		for _, forbidden := range []string{pipelineKey, `"api_key"`, `"ciphertext"`, `"nonce"`, `"key_version"`, `"snapshot_json"`, "https://upstream.example.com"} {
			if bytes.Contains(data, []byte(forbidden)) {
				t.Fatal("display route leaked credentials or private storage/endpoint metadata")
			}
		}
		if expected != 200 && bytes.Contains(data, []byte(`"request_json"`)) {
			t.Fatal("failed disclosure released protected evidence")
		}
		return data
	}
	var envelope struct {
		Data struct {
			RunID            string          `json:"run_id"`
			SampleID         string          `json:"sample_id"`
			AttemptID        string          `json:"attempt_id"`
			AnalysisRevision int             `json:"analysis_revision"`
			IsFinal          bool            `json:"is_final"`
			Status           string          `json:"status"`
			Content          json.RawMessage `json:"content"`
		} `json:"data"`
	}
	data := read("GET", "", "", "", 200)
	if json.Unmarshal(data, &envelope) != nil || envelope.Data.RunID != runID || envelope.Data.SampleID != sampleID || envelope.Data.AttemptID != attemptID || envelope.Data.AnalysisRevision != 1 || !envelope.Data.IsFinal {
		t.Fatal("display route lost fixed historical scope")
	}
	if days == 0 {
		if envelope.Data.Status != "unavailable_policy_zero" || string(envelope.Data.Content) != "null" {
			t.Fatal("zero-day response invented available body")
		}
	} else {
		var content struct {
			Policy      string `json:"policy"`
			RequestJSON string `json:"request_json"`
			Response    struct {
				Content string `json:"content"`
			} `json:"response"`
		}
		if envelope.Data.Status != "available" || json.Unmarshal(envelope.Data.Content, &content) != nil || content.Policy != "display-redaction-v1" || !json.Valid([]byte(content.RequestJSON)) || content.Response.Content == "" {
			t.Fatal("actual TLS display envelope was not opened by the production HTTP service")
		}
	}
	for _, suffix := range []string{"&analysis_revision=1", "&analysis_revision=2", "&expiry=99999999"} {
		read("GET", suffix, "", "", 400)
	}
	read("HEAD", "", "", "", 405)
	read("GET", "", "Range", "bytes=0-5", 400)
	read("GET", "", "If-None-Match", `"invented"`, 400)
	// A real audit INSERT error must produce only an error response, even after
	// successful AEAD opening. The fault is removed with its exact test-only name.
	fault := "CREATE TRIGGER pipeline_display_audit_fault BEFORE INSERT ON integrity_audit_logs WHEN NEW.action = 'evidence.body.read' BEGIN SELECT RAISE(ABORT, 'display audit test failure'); END"
	remove := "DROP TRIGGER pipeline_display_audit_fault"
	if cfg.DatabaseDriver == "postgres" {
		fault = "ALTER TABLE integrity_audit_logs ADD CONSTRAINT pipeline_display_audit_fault CHECK (action <> 'evidence.body.read') NOT VALID"
		remove = "ALTER TABLE integrity_audit_logs DROP CONSTRAINT pipeline_display_audit_fault"
	}
	var before int
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM integrity_evidence_disclosures WHERE organization_id=$1", p.orgID).Scan(&before); err != nil || before != 1 {
		t.Fatal("read/disallowed variants did not create exactly one grant receipt")
	}
	if _, err := db.ExecContext(t.Context(), fault); err != nil {
		t.Fatal("install actual disclosure audit failure")
	}
	read("GET", "", "", "", 503)
	if _, err := db.ExecContext(t.Context(), remove); err != nil {
		t.Fatal("remove exact disclosure test fault")
	}
	var after int
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM integrity_evidence_disclosures WHERE organization_id=$1", p.orgID).Scan(&after); err != nil || after != before {
		t.Fatal("failed disclosure audit left a grant receipt")
	}
	var first, recovered struct{ Data json.RawMessage }
	if json.Unmarshal(data, &first) != nil || json.Unmarshal(read("GET", "", "", "", 200), &recovered) != nil || !bytes.Equal(first.Data, recovered.Data) {
		t.Fatal("display did not recover unchanged after rolled-back audit fault")
	}
	runNumber, runErr := strconv.ParseInt(runID, 10, 64)
	sampleNumber, sampleErr := strconv.ParseInt(sampleID, 10, 64)
	attemptNumber, attemptErr := strconv.ParseInt(attemptID, 10, 64)
	if runErr != nil || sampleErr != nil || attemptErr != nil {
		t.Fatal("invalid actual display service selection")
	}
	exercisePipelineDisplayService(t, cfg, store, db, p, repository.DisplaySelection{RunID: runNumber, SampleID: sampleNumber, AttemptID: attemptNumber, AnalysisRevision: 1})
	holdPipelineBrowser(t, cfg, p, days)
	retentionSnapshot := capturePipelineRetention(t, db, p, runID, days, os.Getenv("MII_TEST_BROWSER_HOLD") == cfg.DatabaseDriver)
	if days > 0 {
		// Disable through the actual management API. Old ciphertext may still be
		// physically present; it must not be returned or revived on extension.
		p.request(t, "PATCH", "/api/v1/organizations/"+p.orgID, map[string]any{"version": 2, "full_response_retention_days": 0}, 200, nil)
		if data := read("GET", "", "", "", 200); json.Unmarshal(data, &envelope) != nil || envelope.Data.Status != "unavailable_policy_zero" || string(envelope.Data.Content) != "null" {
			t.Fatal("new policy did not suppress already captured evidence")
		}
		p.request(t, "PATCH", "/api/v1/organizations/"+p.orgID, map[string]any{"version": 3, "full_response_retention_days": 30}, 200, nil)
		if data := read("GET", "", "", "", 200); json.Unmarshal(data, &envelope) != nil || !strings.HasPrefix(envelope.Data.Status, "unavailable_") || string(envelope.Data.Content) != "null" {
			t.Fatal("policy extension revived historical response")
		}
		finishPipelineRetention(t, store, db, p, runID, retentionSnapshot)
		if data := read("GET", "", "", "", 200); json.Unmarshal(data, &envelope) != nil || envelope.Data.Status != repository.DisplayReadDeleted || string(envelope.Data.Content) != "null" {
			t.Fatal("actual physical cleanup was not explained by a verified deletion receipt")
		}
	}
}
