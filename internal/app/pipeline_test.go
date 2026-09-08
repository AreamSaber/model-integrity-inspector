package app

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	mockupstream "model-integrity-inspector.local/mii/tests/mock-upstream"
)

const pipelineKey = "synthetic-app-pipeline-never-return-this-key"

type pipelineResolver struct{}

func (pipelineResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

// Every PostgreSQL test gets a newly allocated schema; cleanup can target only
// that numeric, test-owned name, never public or another caller's database.
func pipelineDatabase(t *testing.T, cfg Config, driver string) Config {
	t.Helper()
	if driver == "sqlite" {
		return cfg
	}
	dsn := os.Getenv("MII_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL test DSN not configured")
	}
	id, err := repository.NewID()
	if err != nil {
		t.Fatal(err)
	}
	schema := "mii_app_pipeline_" + strconv.FormatInt(id, 10)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("isolated database connection failed")
	}
	if _, err := db.ExecContext(t.Context(), "CREATE SCHEMA "+schema); err != nil {
		_ = db.Close()
		t.Fatal("isolated schema allocation failed")
	}
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := db.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error("isolated test schema cleanup failed")
		}
		_ = db.Close()
	})
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal("invalid isolated database DSN")
		}
		query := u.Query()
		query.Set("search_path", schema)
		u.RawQuery = query.Encode()
		dsn = u.String()
	} else {
		dsn += " search_path=" + schema
	}
	cfg.DatabaseDriver = "postgres"
	cfg.DatabaseDSN = dsn
	return cfg
}

type pipelineHTTP struct {
	client                  *http.Client
	endpoint, origin, orgID string
	csrf                    string
	retryKey                string
}

func (p *pipelineHTTP) request(t *testing.T, method, path string, body any, status int, out any) []byte {
	t.Helper()
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequestWithContext(t.Context(), method, p.endpoint+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal("create app request")
	}
	req.Header.Set("Origin", p.origin)
	req.Header.Set("Content-Type", "application/json")
	if p.orgID != "" {
		req.Header.Set("X-Organization-ID", p.orgID)
	}
	if p.csrf != "" {
		req.Header.Set("X-CSRF-Token", p.csrf)
	}
	if p.retryKey != "" {
		req.Header.Set("Idempotency-Key", p.retryKey)
	}
	res, err := p.client.Do(req)
	if err != nil {
		t.Fatal("app HTTP request failed")
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(res.Body, 5<<20))
	if err != nil || len(data) >= 5<<20 {
		t.Fatal("invalid app response size")
	}
	var envelope struct {
		Data  json.RawMessage       `json:"data"`
		Error struct{ Code string } `json:"error"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		t.Fatal("invalid app response envelope")
	}
	if res.StatusCode != status {
		t.Fatalf("app %s %s: status %d, code %s (wanted %d)", method, path, res.StatusCode, envelope.Error.Code, status)
	}
	for _, forbidden := range []string{pipelineKey, `"api_key"`, `"ciphertext"`, `"request_plan"`, `"snapshot_json"`, `"nonce"`, `"messages"`} {
		if bytes.Contains(data, []byte(forbidden)) {
			t.Fatal("S2/S3 leaked into application response")
		}
	}
	if out != nil && json.Unmarshal(envelope.Data, out) != nil {
		t.Fatal("invalid app response data")
	}
	return append([]byte(nil), envelope.Data...)
}

func TestApplicationActualTLSFromInitializationThroughPublishedEvidence(t *testing.T) {
	testApplicationActualPipeline(t, 30)
}

func TestApplicationActualTLSZeroDayRetentionThroughPublishedArtifacts(t *testing.T) {
	testApplicationActualPipeline(t, 0)
}

func testApplicationActualPipeline(t *testing.T, retentionDays int) {
	t.Helper()
	for _, driver := range []string{"sqlite", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			cfg := pipelineDatabase(t, testConfig(t), driver)
			upstream, err := mockupstream.NewHandler(mockupstream.Config{RequiredAPIKey: pipelineKey})
			if err != nil {
				t.Fatal(err)
			}
			tls := httptest.NewTLSServer(upstream)
			t.Cleanup(tls.Close)
			roots := x509.NewCertPool()
			roots.AddCert(tls.Certificate())
			network := outboundNetwork{resolver: pipelineResolver{}, rootCAs: roots, dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != "8.8.8.8:443" {
					return nil, errors.New("unexpected outbound destination in controlled test")
				}
				return (&net.Dialer{}).DialContext(ctx, network, tls.Listener.Addr().String())
			}}
			listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			cfg.PublicOrigin = "http://" + listener.Addr().String()
			app, err := prepareWithNetwork(t.Context(), cfg, network)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = app.close() })
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- app.serve(ctx, cfg, listener, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
			t.Cleanup(func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Error("application did not stop gracefully", err)
					}
				case <-time.After(12 * time.Second):
					t.Error("application shutdown deadline exceeded")
				}
			})
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			http := pipelineHTTP{client: &http.Client{Timeout: 5 * time.Second, Jar: jar}, endpoint: "http://" + listener.Addr().String(), origin: cfg.PublicOrigin}
			http.request(t, "POST", "/api/v1/setup/initialize", map[string]any{"organization_name": "Actual Pipeline", "username": "admin", "password": "synthetic-app-pipeline-password-2026"}, 201, nil)
			var session struct {
				CSRFToken     string `json:"csrf_token"`
				Organizations []struct {
					ID string `json:"id"`
				} `json:"organizations"`
			}
			http.request(t, "POST", "/api/v1/auth/login", map[string]any{"username": "admin", "password": "synthetic-app-pipeline-password-2026"}, 200, &session)
			if len(session.Organizations) != 1 || session.CSRFToken == "" {
				t.Fatal("actual application session missing")
			}
			http.csrf, http.orgID = session.CSRFToken, session.Organizations[0].ID
			bodyDB := configurePipelineRetention(t, cfg, &http, retentionDays)
			var target struct {
				ID string `json:"id"`
			}
			http.request(t, "POST", "/api/v1/targets", map[string]any{"name": "Actual TLS Mock", "endpoint": "https://upstream.example.com/v1", "protocol": "openai_chat", "model": "mock-model", "auth": map[string]string{"type": "bearer", "api_key": pipelineKey}}, 201, &target)
			var precheck struct{ ID, Status string }
			http.request(t, "POST", "/api/v1/targets/"+target.ID+"/precheck", map[string]int{"version": 1}, 202, &precheck)
			poll := func(read func() bool) {
				t.Helper()
				deadline := time.NewTimer(40 * time.Second)
				defer deadline.Stop()
				ticker := time.NewTicker(100 * time.Millisecond)
				defer ticker.Stop()
				for !read() {
					select {
					case <-ticker.C:
					case <-deadline.C:
						t.Fatal("application pipeline did not converge")
					}
				}
			}
			poll(func() bool {
				http.request(t, "GET", "/api/v1/targets/"+target.ID+"/prechecks/"+precheck.ID, nil, 200, &precheck)
				if precheck.Status == "failed" {
					t.Fatal("controlled actual TLS precheck failed")
				}
				return precheck.Status == "passed"
			})
			var quote struct {
				ID           string `json:"id"`
				ManifestHash string `json:"manifest_hash"`
			}
			http.request(t, "POST", "/api/v1/runs/estimate", map[string]any{"target_id": target.ID, "target_version": 1, "package": "quick"}, 200, &quote)
			before := len(upstream.Records())
			var record struct {
				ID, Status   string
				Version      int64
				RequestCount int `json:"request_count"`
				Planned      int `json:"planned_samples"`
				Valid        int `json:"valid_sample_count"`
			}
			confirm := map[string]any{"estimate_id": quote.ID, "manifest_hash": quote.ManifestHash, "confirm_cost": true}
			http.request(t, "POST", "/api/v1/runs", confirm, 202, &record)
			if record.ID == "" || record.Planned < 1 {
				t.Fatal("confirmation did not create an executable Run")
			}
			runPath := "/api/v1/runs/" + record.ID
			poll(func() bool {
				http.request(t, "GET", runPath, nil, 200, &record)
				if record.Status == "FAILED" || record.Status == "CANCELLED" {
					t.Fatal("controlled application Run failed")
				}
				return record.Status == "COMPLETED" || record.Status == "PARTIAL" || record.Status == "REVIEW_REQUIRED"
			})
			if record.Valid < 1 || record.RequestCount != len(upstream.Records())-before || record.RequestCount > 20 {
				t.Fatal("actual request counts/evidence not preserved")
			}
			var result struct {
				RunID                   string `json:"run_id"`
				Revision                int    `json:"analysis_revision"`
				Development, Calibrated bool
				Grade                   string `json:"evidence_grade"`
				Confidence              int
			}
			frozen := http.request(t, "GET", runPath+"/result?analysis_revision=1", nil, 200, &result)
			if result.RunID != record.ID || result.Revision != 1 || !result.Development || result.Calibrated || result.Grade != "C" && result.Grade != "D" || result.Confidence > 74 {
				t.Fatal("result omitted actual development evidence limitations")
			}
			http.request(t, "GET", runPath+"/result?analysis_revision=1&include=statistics", nil, 200, nil)
			var samples struct {
				Items []struct {
					ID string `json:"id"`
				} `json:"items"`
			}
			http.request(t, "GET", runPath+"/samples?analysis_revision=1", nil, 200, &samples)
			if len(samples.Items) == 0 {
				t.Fatal("published sample evidence missing")
			}
			var detail struct {
				Attempts []struct {
					Validity  string  `json:"validity"`
					ErrorCode *string `json:"error_code"`
				} `json:"attempts"`
			}
			http.request(t, "GET", runPath+"/samples/"+samples.Items[0].ID+"?analysis_revision=1", nil, 200, &detail)
			if len(detail.Attempts) != 1 || (detail.Attempts[0].Validity != "VALID" && detail.Attempts[0].Validity != "VALID_WITH_WARNING") || detail.Attempts[0].ErrorCode != nil {
				t.Fatal("successful controlled attempt was displayed as an execution error")
			}
			http.request(t, "GET", runPath+"/findings?analysis_revision=1", nil, 200, nil)
			http.request(t, "GET", "/api/v1/runs?target_id="+target.ID, nil, 200, nil)
			http.retryKey = "synthetic-application-review-1"
			var review struct{ ID string }
			http.request(t, "POST", runPath+"/reviews", map[string]any{"analysis_revision": 1, "conclusion": "watch", "explanation": "Synthetic integration review; no release approval or provider intent asserted."}, 201, &review)
			if review.ID == "" {
				t.Fatal("actual application review receipt missing")
			}
			http.retryKey = ""
			http.request(t, "GET", runPath+"/reviews", nil, 200, nil)
			exercisePublishedArtifacts(t, &http, record.ID, record.Planned, poll)
			originalID := record.ID
			http.request(t, "POST", "/api/v1/runs", confirm, 202, &record)
			if record.ID != originalID || !bytes.Equal(frozen, http.request(t, "GET", runPath+"/result?analysis_revision=1", nil, 200, nil)) {
				t.Fatal("idempotent receipt changed the immutable result")
			}
			repeatedBefore := len(upstream.Records())
			exerciseRepeatedDetection(t, &http, target.ID, originalID, frozen, poll)
			if len(upstream.Records())-repeatedBefore != 9 {
				t.Fatal("repeated detection did not execute exactly the new bounded TLS plan")
			}
			verifyPipelineDerivedStorage(t, bodyDB, http.orgID, retentionDays, record.Planned+9)
			if err := app.store.VerifyAllAudit(t.Context(), true); err != nil {
				t.Fatal(fmt.Errorf("actual pipeline audit invalid: %w", err))
			}
			if os.Getenv("MII_TEST_BROWSER_HOLD") == driver && retentionDays == 30 {
				// Opt-in test-only inspection of the real embedded frontend. The
				// private fixture and TLS mock remain alive for at most five minutes;
				// a marker in this test-owned temp directory ends the hold early.
				stopPath := filepath.Join(t.TempDir(), "browser.stop")
				t.Log("BROWSER_SMOKE_URL", http.endpoint)
				t.Log("BROWSER_SMOKE_STOP", stopPath)
				deadline := time.NewTimer(5 * time.Minute)
				defer deadline.Stop()
				tick := time.NewTicker(250 * time.Millisecond)
				defer tick.Stop()
				for {
					select {
					case <-t.Context().Done():
						return
					case <-deadline.C:
						return
					case <-tick.C:
						if _, err := os.Stat(stopPath); err == nil {
							return
						}
					}
				}
			}
		})
	}
}
