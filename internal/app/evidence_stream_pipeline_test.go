package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/identity"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	mockupstream "model-integrity-inspector.local/mii/tests/mock-upstream"
)

const streamDisplayRequestID = "38fd192e90bb45cda6e4ca3d62fd966f"
const streamDisplayChunk = 64 << 10

// A real legal 16KiB response becomes about 96KiB under the production JSON
// encoder's HTML escaping. No upstream, tokenizer, display or output cap moves.
func streamDisplayContent() string { return strings.Repeat("<", 16<<10) + " synthetic-stream-end" }

type streamDisplayFixture struct {
	store     *repository.Store
	db        *sql.DB
	api       *pipelineHTTP
	identity  *identity.Service
	service   *runservice.EvidenceService
	orgID     int64
	selection repository.DisplaySelection
	sessionID int64
	expiresAt time.Time
}

func (f *streamDisplayFixture) authority(t *testing.T, base context.Context) context.Context {
	t.Helper()
	token := streamDisplayCookie(t, f.api)
	principal, err := f.identity.Principal(base, token, f.orgID)
	if err != nil || principal.Authorize("evidence.body") != nil {
		t.Fatal("verify actual stream session principal")
	}
	hash := sha256.Sum256([]byte(token))
	ctx, err := f.store.BindControlAuthority(audit.WithActor(base, audit.Actor{ActorID: principal.UserID, ReasonCode: "display.stream.test"}), hex.EncodeToString(hash[:]), f.orgID)
	if err != nil {
		t.Fatal("bind actual stream session")
	}
	return ctx
}

func streamDisplayCookie(t *testing.T, p *pipelineHTTP) string {
	t.Helper()
	u, err := url.Parse(p.endpoint)
	if err != nil {
		t.Fatal("parse controlled app URL")
	}
	var token string
	for _, cookie := range p.client.Jar.Cookies(u) {
		if cookie.Name == "mii_session" {
			token = cookie.Value
		}
	}
	if token == "" {
		t.Fatal("original actual stream cookie absent")
	}
	return token
}

func (f *streamDisplayFixture) prepare(t *testing.T, ctx context.Context) *runservice.Disclosure {
	t.Helper()
	disclosure, err := f.service.PrepareDisplay(ctx, f.orgID, f.selection, streamDisplayRequestID)
	if err != nil || disclosure == nil || disclosure.View().Status != repository.DisplayReadAvailable {
		t.Fatal("open actual large Worker-sealed display")
	}
	t.Cleanup(disclosure.Close)
	return disclosure
}

type streamDisplayReceipt struct {
	id, bytes, sequence int64
	hash                string
}

func (f *streamDisplayFixture) latestGrant(t *testing.T, previous int64) streamDisplayReceipt {
	t.Helper()
	var receipt streamDisplayReceipt
	var receiptHash string
	// IDs are random, not clocks. The committed per-organization audit sequence
	// is the authoritative order and joins the exact immutable receipt hash.
	if err := f.db.QueryRowContext(t.Context(), `SELECT d.id,d.output_bytes,d.output_hash,d.receipt_hash,a.sequence FROM integrity_evidence_disclosures d JOIN integrity_audit_logs a ON a.organization_id=d.organization_id AND a.action='evidence.body.read' AND a.object_type='evidence_disclosure' AND a.object_id=CAST(d.id AS TEXT)||':'||d.receipt_hash WHERE d.organization_id=$1 AND d.run_id=$2 AND d.logical_sample_id=$3 AND d.attempt_id=$4 ORDER BY a.sequence DESC LIMIT 1`, f.orgID, f.selection.RunID, f.selection.SampleID, f.selection.AttemptID).Scan(&receipt.id, &receipt.bytes, &receipt.hash, &receiptHash, &receipt.sequence); err != nil || receipt.sequence <= previous || receipt.bytes <= streamDisplayChunk || receipt.bytes > 8<<20 {
		t.Fatal("first writer did not observe a committed multi-block receipt")
	}
	var matched int
	if err := f.db.QueryRowContext(t.Context(), "SELECT count(*) FROM integrity_audit_logs WHERE organization_id=$1 AND action='evidence.body.read' AND object_type='evidence_disclosure' AND object_id=$2", f.orgID, strconv.FormatInt(receipt.id, 10)+":"+receiptHash).Scan(&matched); err != nil || matched != 1 {
		t.Fatal("first writer did not observe the exact committed grant audit")
	}
	return receipt
}

func (f *streamDisplayFixture) grantCount(t *testing.T) int {
	t.Helper()
	var count int
	if err := f.db.QueryRowContext(t.Context(), "SELECT count(*) FROM integrity_evidence_disclosures WHERE organization_id=$1", f.orgID).Scan(&count); err != nil {
		t.Fatal("count scoped actual stream grants")
	}
	return count
}

func newStreamDisplayFixture(t *testing.T, driver string) *streamDisplayFixture {
	t.Helper()
	cfg := pipelineDatabase(t, testConfig(t), driver)
	var armed atomic.Bool
	var largeResponses atomic.Int32
	upstream, err := mockupstream.NewHandler(mockupstream.Config{RequiredAPIKey: pipelineKey, Responder: func(request mockupstream.Request, budget int) (mockupstream.Generation, error) {
		if armed.CompareAndSwap(true, false) {
			largeResponses.Add(1)
			return mockupstream.Generation{Tokens: []string{streamDisplayContent()}, PromptTokens: 32, FinishReason: "stop"}, nil
		}
		result := mockupstream.Generation{FinishReason: "length"}
		for _, message := range request.Messages {
			result.PromptTokens += len(strings.Fields(message.Content))
		}
		for i := range budget {
			result.Tokens = append(result.Tokens, fmt.Sprintf("item%06d ", i+1))
		}
		return result, nil
	}})
	if err != nil {
		t.Fatal("create bounded synthetic stream upstream")
	}
	upstreamTLS := httptest.NewTLSServer(upstream)
	t.Cleanup(upstreamTLS.Close)
	roots := x509.NewCertPool()
	roots.AddCert(upstreamTLS.Certificate())
	network := outboundNetwork{resolver: pipelineResolver{}, rootCAs: roots, dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "8.8.8.8:443" {
			return nil, errors.New("unexpected bounded stream destination")
		}
		return (&net.Dialer{}).DialContext(ctx, network, upstreamTLS.Listener.Addr().String())
	}}
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen on isolated stream app")
	}
	t.Cleanup(func() { _ = listener.Close() })
	cfg.PublicOrigin = "http://" + listener.Addr().String()
	diagnostics := &pipelineDiagnosticBuffer{}
	logger := slog.New(slog.NewJSONHandler(diagnostics, nil))
	t.Cleanup(func() {
		if t.Failed() {
			text, truncated := diagnostics.snapshot()
			t.Logf("bounded stream application diagnostics (truncated=%t):\n%s", truncated, text)
		}
	})
	application, err := prepareWithNetworkAndLogger(t.Context(), cfg, network, logger)
	if err != nil {
		t.Fatal("prepare real stream application")
	}
	t.Cleanup(func() { _ = application.close() })
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- application.serve(ctx, cfg, listener, logger) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error("actual stream application shutdown failed")
			}
		case <-time.After(12 * time.Second):
			t.Error("actual stream application shutdown deadline")
		}
	})
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal("create actual stream cookie jar")
	}
	p := &pipelineHTTP{client: &http.Client{Timeout: 5 * time.Second, Jar: jar}, endpoint: cfg.PublicOrigin, origin: cfg.PublicOrigin}
	p.request(t, "POST", "/api/v1/setup/initialize", map[string]any{"organization_name": "Actual Stream", "username": "admin", "password": "synthetic-app-pipeline-password-2026"}, 201, nil)
	var session struct {
		CSRFToken     string `json:"csrf_token"`
		Organizations []struct {
			ID string `json:"id"`
		} `json:"organizations"`
	}
	p.request(t, "POST", "/api/v1/auth/login", map[string]any{"username": "admin", "password": "synthetic-app-pipeline-password-2026"}, 200, &session)
	if len(session.Organizations) != 1 || session.CSRFToken == "" {
		t.Fatal("stream application session unavailable")
	}
	p.orgID, p.csrf = session.Organizations[0].ID, session.CSRFToken
	db := configurePipelineRetention(t, cfg, p, 30)
	var target struct{ ID string }
	p.request(t, "POST", "/api/v1/targets", map[string]any{"name": "Actual Stream TLS", "endpoint": "https://upstream.example.com/v1", "protocol": "openai_chat", "model": "mock-model", "auth": map[string]string{"type": "bearer", "api_key": pipelineKey}}, 201, &target)
	var precheck struct{ ID, Status string }
	p.request(t, "POST", "/api/v1/targets/"+target.ID+"/precheck", map[string]int{"version": 1}, 202, &precheck)
	poll := func(read func() bool) {
		t.Helper()
		deadline, tick := time.NewTimer(40*time.Second), time.NewTicker(100*time.Millisecond)
		defer deadline.Stop()
		defer tick.Stop()
		for !read() {
			select {
			case <-tick.C:
			case <-deadline.C:
				t.Fatal("actual stream publication did not converge")
			case <-t.Context().Done():
				t.Fatal("actual stream pipeline canceled")
			}
		}
	}
	poll(func() bool {
		p.request(t, "GET", "/api/v1/targets/"+target.ID+"/prechecks/"+precheck.ID, nil, 200, &precheck)
		if precheck.Status == "failed" {
			t.Fatal("actual stream TLS precheck failed")
		}
		return precheck.Status == "passed"
	})
	var quote struct {
		ID           string
		ManifestHash string `json:"manifest_hash"`
	}
	p.request(t, "POST", "/api/v1/runs/estimate", map[string]any{"target_id": target.ID, "target_version": 1, "package": "quick"}, 200, &quote)
	armed.Store(true)
	var run struct{ ID, Status string }
	p.request(t, "POST", "/api/v1/runs", map[string]any{"estimate_id": quote.ID, "manifest_hash": quote.ManifestHash, "confirm_cost": true}, 202, &run)
	poll(func() bool {
		p.request(t, "GET", "/api/v1/runs/"+run.ID, nil, 200, &run)
		if run.Status == "FAILED" || run.Status == "CANCELLED" {
			t.Fatal("actual large-response Run failed")
		}
		return run.Status == "COMPLETED" || run.Status == "PARTIAL" || run.Status == "REVIEW_REQUIRED"
	})
	p.request(t, "GET", "/api/v1/runs/"+run.ID+"/result?analysis_revision=1", nil, 200, nil)
	orgID, err := strconv.ParseInt(p.orgID, 10, 64)
	if err != nil {
		t.Fatal("parse stream organization")
	}
	runID, err := strconv.ParseInt(run.ID, 10, 64)
	if err != nil {
		t.Fatal("parse stream Run")
	}
	selection := repository.DisplaySelection{RunID: runID, AnalysisRevision: 1}
	if err := db.QueryRowContext(t.Context(), `SELECT s.id,s.final_attempt_id FROM integrity_logical_samples s JOIN integrity_display_evidence d ON d.organization_id=s.organization_id AND d.run_id=s.run_id AND d.logical_sample_id=s.id AND d.attempt_id=s.final_attempt_id WHERE s.organization_id=$1 AND s.run_id=$2 AND d.state='captured' AND d.plaintext_bytes>$3 ORDER BY s.id LIMIT 1`, orgID, runID, streamDisplayChunk).Scan(&selection.SampleID, &selection.AttemptID); err != nil || largeResponses.Load() != 1 {
		t.Fatal("large real TLS response did not reach authenticated persisted display")
	}
	identities, err := identity.NewService(t.Context(), application.store)
	if err != nil {
		t.Fatal("construct stream principal verifier")
	}
	key, err := secret.LoadKeyFile(cfg.MasterKeyFile, cfg.MasterKeyVersion)
	if err != nil {
		t.Fatal("load actual stream display key")
	}
	_, opener, err := key.NewDisplayCapabilities(time.Now)
	if err != nil {
		t.Fatal("derive actual stream display-only opener")
	}
	service, err := runservice.NewEvidenceService(application.store, opener)
	if err != nil {
		t.Fatal("construct actual stream service")
	}
	f := &streamDisplayFixture{store: application.store, db: db, api: p, identity: identities, service: service, orgID: orgID, selection: selection}
	sessionHash := sha256.Sum256([]byte(streamDisplayCookie(t, p)))
	actualSession, err := application.store.GetSession(t.Context(), hex.EncodeToString(sessionHash[:]), time.Now())
	if err != nil {
		t.Fatal("read original persisted stream session interval")
	}
	f.sessionID, f.expiresAt = actualSession.ID, actualSession.ExpiresAt
	return f
}

func TestApplicationEvidenceDisplayActualTLSMultiBlockAuthorization(t *testing.T) {
	for _, driver := range []string{"sqlite", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			f := newStreamDisplayFixture(t, driver)
			var full []byte
			var lastSequence int64
			if !t.Run("multiple_actual_blocks", func(t *testing.T) {
				ctx := f.authority(t, t.Context())
				disclosure := f.prepare(t, ctx)
				before, calls := f.grantCount(t), 0
				var output bytes.Buffer
				var receipt streamDisplayReceipt
				n, err := disclosure.WriteTo(ctx, pipelineDisplayWriterFunc(func(data []byte) (int, error) {
					calls++
					if calls == 1 {
						receipt = f.latestGrant(t, lastSequence)
					}
					if len(data) < 1 || len(data) > streamDisplayChunk {
						t.Fatal("writer chunk exceeds production cap")
					}
					return output.Write(data)
				}))
				full = bytes.Clone(output.Bytes())
				if err != nil || calls < 2 || n != int64(len(full)) || n != receipt.bytes || f.grantCount(t) != before+1 {
					t.Fatal("real large display did not produce multiple bounded writes under one grant")
				}
				sum := sha256.Sum256(full)
				if hex.EncodeToString(sum[:]) != receipt.hash {
					t.Fatal("output bytes differ from committed full-output hash")
				}
				var envelope struct {
					RequestID string `json:"request_id"`
					Data      struct {
						runservice.EvidenceDisplayView
						Content json.RawMessage `json:"content"`
					} `json:"data"`
				}
				if json.Unmarshal(full, &envelope) != nil || envelope.RequestID != streamDisplayRequestID || envelope.Data.Status != repository.DisplayReadAvailable || !envelope.Data.IsFinal || envelope.Data.RunID != strconv.FormatInt(f.selection.RunID, 10) || envelope.Data.AttemptID != strconv.FormatInt(f.selection.AttemptID, 10) {
					t.Fatal("actual large display scope or available state drifted")
				}
				var payload struct {
					Policy      string `json:"policy"`
					RequestJSON string `json:"request_json"`
					Response    struct {
						Content string `json:"content"`
					} `json:"response"`
				}
				if json.Unmarshal(envelope.Data.Content, &payload) != nil || payload.Policy != repository.DisplayEvidencePolicy || !json.Valid([]byte(payload.RequestJSON)) || payload.Response.Content != streamDisplayContent() {
					t.Fatal("large JSON was a length illusion rather than original authenticated TLS content")
				}
				payloadHash := sha256.Sum256(envelope.Data.Content)
				canonical, err := json.Marshal(json.RawMessage(full))
				if err != nil || !bytes.Equal(canonical, full) || hex.EncodeToString(payloadHash[:]) != envelope.Data.PayloadHash {
					t.Fatal("actual display canonical bytes or payload hash drifted")
				}
				lastSequence = receipt.sequence
			}) {
				t.Fatal("actual multi-block positive control failed")
			}
			if len(full) <= streamDisplayChunk {
				t.Fatal("multi-block positive control did not complete")
			}
			defer clear(full)
			for _, mode := range []string{"run.read", "evidence.read", "evidence.body", "cancel-original", "cancel-write", "permit-natural-expiry", "session-natural-expiry", "policy-zero"} {
				t.Run(mode, func(t *testing.T) {
					base := f.authority(t, t.Context())
					var sessionExpiry time.Time
					if mode == "session-natural-expiry" {
						sessionExpiry = time.Now().UTC().Add(1500 * time.Millisecond)
						if _, err := f.db.ExecContext(t.Context(), "UPDATE user_sessions SET expires_at=$1 WHERE id=$2", sessionExpiry, f.sessionID); err != nil {
							t.Fatal("set bounded actual session expiry")
						}
						defer func() {
							ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
							defer cancel()
							if _, err := f.db.ExecContext(ctx, "UPDATE user_sessions SET expires_at=$1 WHERE id=$2", f.expiresAt, f.sessionID); err != nil {
								t.Error("restore exact original session expiry")
							}
						}()
					}
					original, cancelOriginal := context.WithCancel(base)
					defer cancelOriginal()
					writeCtx, cancelWrite := context.WithCancel(base)
					defer cancelWrite()
					disclosure := f.prepare(t, original)
					before, calls := f.grantCount(t), 0
					var partial bytes.Buffer
					var receipt streamDisplayReceipt
					n, err := disclosure.WriteTo(writeCtx, pipelineDisplayWriterFunc(func(data []byte) (int, error) {
						calls++
						if calls > 1 {
							return partial.Write(data)
						}
						receipt = f.latestGrant(t, lastSequence)
						if receipt.bytes != int64(len(full)) || len(data) != streamDisplayChunk {
							t.Fatal("negative stream did not start with the genuine full-output grant")
						}
						n, err := partial.Write(data)
						if err != nil {
							return n, err
						}
						switch mode {
						case "run.read", "evidence.read", "evidence.body":
							pipelineRemoveDisplayPermission(t, f.db, f.orgID, mode)
						case "cancel-original":
							cancelOriginal()
						case "cancel-write":
							cancelWrite()
						case "permit-natural-expiry":
							// The permit is capped at two seconds before this Write.
							// Wait only here, after observing its committed first block.
							timer := time.NewTimer(2100 * time.Millisecond)
							defer timer.Stop()
							select {
							case <-timer.C:
							case <-t.Context().Done():
								t.Fatal("stream expiry test canceled")
							}
						case "session-natural-expiry":
							if !sessionExpiry.After(time.Now()) {
								t.Fatal("session expired before actual first-block release")
							}
							timer := time.NewTimer(time.Until(sessionExpiry) + 10*time.Millisecond)
							defer timer.Stop()
							select {
							case <-timer.C:
							case <-t.Context().Done():
								t.Fatal("session expiry test canceled")
							}
						case "policy-zero":
							var version int
							if err := f.db.QueryRowContext(t.Context(), "SELECT version FROM organizations WHERE id=$1", f.orgID).Scan(&version); err != nil {
								t.Fatal("read real policy CAS version")
							}
							f.api.request(t, "PATCH", "/api/v1/organizations/"+f.api.orgID, map[string]any{"version": version, "full_response_retention_days": 0}, 200, nil)
						}
						return n, nil
					}))
					if (mode == "run.read" || mode == "evidence.read" || mode == "evidence.body") && !errors.Is(err, repository.ErrManagementPermission) {
						// Revalidate checks the original permit's context/deadline
						// before reading grants. Permission denial therefore proves
						// revocation completed while that permit was still live;
						// natural expiry would return a source/context error instead.
						t.Fatal("permission revocation was not the actual next-block denial cause")
					}
					if err == nil || calls != 1 || n != streamDisplayChunk || partial.Len() != streamDisplayChunk || !bytes.Equal(partial.Bytes(), full[:streamDisplayChunk]) || f.grantCount(t) != before+1 {
						t.Fatal("authorization change or natural expiry allowed another block or fabricated error output")
					}
					lastSequence = receipt.sequence
					if n, err := disclosure.WriteTo(base, io.Discard); n != 0 || err == nil {
						t.Fatal("partially disclosed handle became replayable")
					}
					if err := f.store.VerifyAllAudit(t.Context(), true); err != nil {
						t.Fatal("partial grant damaged immutable audit chain")
					}
				})
			}
		})
	}
}
