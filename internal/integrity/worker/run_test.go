package worker

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
	mockupstream "model-integrity-inspector.local/mii/tests/mock-upstream"
)

type runFixture struct {
	workerFixture
	ring   *secret.KeyRing
	tokens *tokenizer.Engine
}

type executionLogBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *executionLogBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(value)
}

func (b *executionLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func eachRunDatabase(t *testing.T, test func(*testing.T, runFixture)) {
	t.Helper()
	eachWorkerDatabase(t, func(t *testing.T, f workerFixture) {
		for _, permission := range []string{"run.create", "run.custom", "run.high-cost", "run.cancel-own", "run.cancel-any"} {
			if _, err := f.db.ExecContext(f.ctx, "INSERT INTO permissions (code,description) VALUES ($1,'') ON CONFLICT (code) DO NOTHING", permission); err != nil {
				t.Fatal("grant execution fixture permission")
			}
			if _, err := f.db.ExecContext(f.ctx, "INSERT INTO role_permissions (organization_id,role_id,permission_code) SELECT organization_id,id,$1 FROM roles WHERE organization_id=$2 AND name='administrator' ON CONFLICT DO NOTHING", permission, f.orgID); err != nil {
				t.Fatal("grant execution fixture role")
			}
		}
		ring, err := secret.NewKeyRing("worker-test", map[string][]byte{"worker-test": bytes.Repeat([]byte{0x82}, 32)})
		if err != nil {
			t.Fatal(err)
		}
		tokens, err := tokenizer.NewBuiltin()
		if err != nil {
			t.Fatal(err)
		}
		test(t, runFixture{f, ring, tokens})
	})
}

func (f runFixture) createRun(t *testing.T, streamModes []bool) (*repository.Tenant, repository.RunRecord, []repository.LogicalSampleRecord) {
	t.Helper()
	value := f.createTarget(t, "max_tokens")
	snapshot, err := f.service.Snapshot(f.ctx, f.orgID, value.ID)
	if err != nil {
		t.Fatal(err)
	}
	manifest := json.RawMessage(`{"fixture":"run-worker","order":[0,1]}`)
	hash := sha256.Sum256(manifest)
	plan := domain.ExecutionPlan{Target: domain.ExecutionTarget{ID: snapshot.TargetID, Version: snapshot.TargetVersion, SecretID: snapshot.SecretID, SecretVersion: snapshot.SecretVersion, Endpoint: snapshot.Endpoint, Model: snapshot.Model, Protocol: snapshot.Protocol, MaxOutputParameter: "max_tokens", AuthType: snapshot.AuthType, AuthHeaderName: snapshot.AuthHeaderName, TimeoutSeconds: snapshot.Options.TimeoutSeconds}, Package: "custom", Manifest: manifest, ManifestHash: hex.EncodeToString(hash[:]), Versions: domain.BundleVersions{Rule: "1", Template: "1", Scoring: "1", Tokenizer: f.tokens.Version()}, Budget: domain.ExecutionBudget{MaxRequests: 12, MaxTokens: 2000, TimeoutSeconds: 60}, Concurrency: 3, MaxRetries: 2}
	probe := domain.ProbePlan{Type: "contract", TemplateID: "fixture", TemplateVersion: "1", Category: "format", Variant: "en"}
	for i, stream := range streamModes {
		probe.Samples = append(probe.Samples, domain.SamplePlan{Ordinal: i, Nonce: fmt.Sprintf("fixture-nonce-%d", i), EstimatedInputTokens: 10, Request: domain.NormalizedRequest{Model: snapshot.Model, Messages: []domain.NormalizedMessage{{Role: "user", Content: "Produce fixture OK"}}, MaxOutputTokens: 20, Stream: stream}})
	}
	plan.Probes = []domain.ProbePlan{probe}
	policy, err := scheduler.NewPolicy(scheduler.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := f.store.WithOrganization(f.ctx, f.orgID)
	if err != nil {
		t.Fatal(err)
	}
	run, err := tenant.CreateRun(plan, policy, "worker-run")
	if err != nil {
		t.Fatal(err)
	}
	samples, err := tenant.ListExecutionSamples(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	return tenant, run, samples
}

func runTLSConfig(t *testing.T, f runFixture, handler http.Handler) RunConfig {
	t.Helper()
	config := tlsPrecheckConfig(t, f.workerFixture, handler)
	return RunConfig{Store: f.store, Secrets: f.secrets, EvidenceKeys: f.ring, Tokenizer: f.tokens, URLPolicy: config.URLPolicy, Resolver: config.Resolver, DialContext: config.DialContext, RootCAs: config.RootCAs, LivenessInterval: 20 * time.Millisecond, RequestTimeout: 2 * time.Second}
}

func startRunWorker(t *testing.T, f runFixture, config RunConfig, log io.Writer) (*Runner, context.CancelFunc) {
	t.Helper()
	handlers, err := NewRunHandlers(config)
	if err != nil {
		t.Fatal(err)
	}
	if log == nil {
		log = io.Discard
	}
	runner, err := New(Config{Store: f.store, Handlers: handlers, Logger: slog.New(slog.NewTextHandler(log, nil)), PollInterval: 10 * time.Millisecond, HeartbeatInterval: 40 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("run worker shutdown: %v", err)
			}
		case <-time.After(7 * time.Second):
			t.Error("run worker failed to stop")
		}
	})
	return runner, cancel
}

func awaitRunClosed(t *testing.T, tenant *repository.Tenant, id int64) repository.RunRecord {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		run, err := tenant.GetRun(id)
		if err == nil && run.ExecutionClosedAt != nil {
			return run
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("run execution did not close")
	return repository.RunRecord{}
}

func evidenceFor(t *testing.T, f runFixture, tenant *repository.Tenant, sample repository.LogicalSampleRecord) (repository.AttemptRecord, domain.NormalizedResponse) {
	t.Helper()
	attempts, err := tenant.ListAttempts(sample.ID)
	if err != nil || len(attempts) == 0 {
		t.Fatal("missing attempt", err)
	}
	attempt := attempts[len(attempts)-1]
	record, err := tenant.GetResponseEvidenceForAnalysis(sample.RunID, sample.ID, attempt.ID)
	if err != nil {
		t.Fatal("missing encrypted evidence", err)
	}
	if bytes.Contains(record.Ciphertext, []byte(workerCanary)) {
		t.Fatal("plaintext credential in evidence persistence")
	}
	var response domain.NormalizedResponse
	err = f.ring.WithResponseEvidence(secret.EvidenceScope{OrganizationID: f.orgID, RunID: sample.RunID, LogicalSampleID: sample.ID, AttemptID: attempt.ID, RequestHash: attempt.RequestHash}, secret.EvidenceRecord{KeyVersion: record.KeyVersion, Nonce: record.Nonce, Ciphertext: record.Ciphertext, PlaintextBytes: record.PlaintextBytes, ContentHash: record.ContentHash}, func(value domain.NormalizedResponse) error { response = value; return nil })
	if err != nil {
		t.Fatal(err)
	}
	return attempt, response
}

func TestRunWorkerRealTLSNonstreamStreamAndEncryptedEvidence(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		mock, err := mockupstream.NewHandler(mockupstream.Config{RequiredAPIKey: workerCanary})
		if err != nil {
			t.Fatal(err)
		}
		tenant, run, samples := f.createRun(t, []bool{false, true})
		if len(mock.Records()) != 0 {
			t.Fatal("run creation performed outbound call")
		}
		var logs executionLogBuffer
		_, cancel := startRunWorker(t, f, runTLSConfig(t, f, mock), &logs)
		finished := awaitRunClosed(t, tenant, run.ID)
		if finished.Status != "ANALYZING" || finished.RequestCount != 2 || finished.ValidSampleCount != 2 || finished.ReservedTokens != 0 {
			t.Fatal("wrong completed execution counters")
		}
		if len(mock.Records()) != 2 || mock.Records()[0].Request.Stream || !mock.Records()[1].Request.Stream {
			t.Fatal("protocol/sample plan changed")
		}
		for _, sample := range samples {
			attempt, response := evidenceFor(t, f, tenant, sample)
			if response.Content == "" || attempt.TokenizerQuality != "heuristic" || attempt.LocalCompletionTokens == nil {
				t.Fatal("missing response/quality evidence")
			}
			var plaintext, meta string
			if err := f.db.QueryRowContext(f.ctx, "SELECT COALESCE(response_content_redacted,''),response_meta FROM integrity_sample_attempts WHERE organization_id=$1 AND id=$2", f.orgID, attempt.ID).Scan(&plaintext, &meta); err != nil {
				t.Fatal(err)
			}
			if plaintext != "" || strings.Contains(meta, response.Content) {
				t.Fatal("S2 plaintext copied to attempt metadata")
			}
		}
		// Analysis is not registered here; it must never be falsely completed.
		time.Sleep(30 * time.Millisecond)
		var count int
		if err := f.db.QueryRowContext(f.ctx, "SELECT count(*) FROM integrity_jobs WHERE organization_id=$1 AND type='integrity.run.analyze' AND status='completed'", f.orgID).Scan(&count); err != nil || count != 0 {
			t.Fatal("unimplemented analysis fabricated completion")
		}
		if strings.Contains(logs.String(), workerCanary) || strings.Contains(logs.String(), "fixture-nonce") || strings.Contains(logs.String(), "Produce fixture OK") {
			t.Fatal("execution log leaked credentials or S2 input")
		}
		cancel()
	})
}

func TestRunWorkerLimitsTimeoutAndFixedParameterNoFallback(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		code     string
		attempts int64
	}{{"oversize", "MI_CLIENT_SAFETY_LIMIT", 1}, {"gzip-oversize", "MI_CLIENT_SAFETY_LIMIT", 1}, {"evidence-overhead", "MI_EVIDENCE_LIMIT", 1}, {"slow-body", "MI_TIMEOUT", 3}, {"parameter-rejected", "MI_PROTOCOL_UNSUPPORTED", 1}, {"long-retry-after", "MI_RATE_LIMITED", 1}} {
		t.Run(scenario.name, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				var calls atomic.Int64
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requestBody, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
					calls.Add(1)
					w.Header().Set("Content-Type", "application/json")
					switch scenario.name {
					case "parameter-rejected":
						if !bytes.Contains(requestBody, []byte(`"max_tokens"`)) || bytes.Contains(requestBody, []byte("max_completion_tokens")) {
							t.Error("worker changed frozen parameter")
						}
						w.WriteHeader(http.StatusBadRequest)
						_, _ = io.WriteString(w, `{"error":{"param":"max_tokens","code":"unsupported_parameter","message":"use max_completion_tokens"}}`)
					case "long-retry-after":
						w.Header().Set("Retry-After", "7200")
						w.WriteHeader(http.StatusTooManyRequests)
						_, _ = io.WriteString(w, `{"error":{"message":"synthetic"}}`)
					case "slow-body":
						_, _ = io.WriteString(w, `{"choices":[`)
						w.(http.Flusher).Flush()
						<-r.Context().Done()
					default:
						length := (1 << 20) + 1
						if scenario.name == "evidence-overhead" {
							length = (1 << 20) - 300
						}
						body := `{"id":"fixture","model":"fixture","choices":[{"index":0,"message":{"role":"assistant","content":"` + strings.Repeat("a", length) + `"},"finish_reason":"stop"}]}`
						if scenario.name == "gzip-oversize" {
							w.Header().Set("Content-Encoding", "gzip")
							compressed := gzip.NewWriter(w)
							_, _ = io.WriteString(compressed, body)
							_ = compressed.Close()
						} else {
							_, _ = io.WriteString(w, body)
						}
					}
				})
				tenant, run, samples := f.createRun(t, []bool{false})
				config := runTLSConfig(t, f, handler)
				if scenario.name == "slow-body" {
					config.RequestTimeout = 100 * time.Millisecond
				}
				startRunWorker(t, f, config, nil)
				finished := awaitRunClosed(t, tenant, run.ID)
				if finished.RequestCount != scenario.attempts || calls.Load() != scenario.attempts || finished.ValidSampleCount != 0 || finished.ReservedTokens != 0 {
					t.Fatal("wrong bounded execution counts")
				}
				attempt, response := evidenceFor(t, f, tenant, samples[0])
				if attempt.ErrorCode == nil || *attempt.ErrorCode != scenario.code {
					t.Fatalf("wrong limit classification: got %v, want %s", attempt.ErrorCode, scenario.code)
				}
				if scenario.name == "evidence-overhead" && (response.Content != "" || response.ParseStatus != "invalid" || response.EndCause != "client_safety_limit") {
					t.Fatal("missing evidence disguised as complete")
				}
			})
		})
	}
}

func TestRunWorkerHTTPFailuresAndPartialStreamAreTruthful(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		config   mockupstream.Config
		stream   bool
		attempts int
		valid    bool
		code     string
	}{{"auth", mockupstream.Config{HTTPErrorRate: 1, HTTPErrorStatus: 401}, false, 1, false, "MI_AUTH_FAILED"}, {"not-found", mockupstream.Config{HTTPErrorRate: 1, HTTPErrorStatus: 404}, false, 1, false, "MI_MODEL_NOT_FOUND"}, {"limited", mockupstream.Config{HTTPErrorRate: 1, HTTPErrorStatus: 429}, false, 3, false, "MI_RATE_LIMITED"}, {"unavailable", mockupstream.Config{HTTPErrorRate: 1, HTTPErrorStatus: 503}, false, 3, false, "MI_SERVICE_UNAVAILABLE"}, {"partial", mockupstream.Config{StreamMode: "omit_done"}, true, 1, true, ""}, {"malformed", mockupstream.Config{StreamMode: "malformed_event"}, true, 1, false, "MI_PROTOCOL_UNSUPPORTED"}} {
		t.Run(scenario.name, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				config := scenario.config
				config.RequiredAPIKey = workerCanary
				mock, err := mockupstream.NewHandler(config)
				if err != nil {
					t.Fatal(err)
				}
				tenant, run, samples := f.createRun(t, []bool{scenario.stream})
				startRunWorker(t, f, runTLSConfig(t, f, mock), nil)
				finished := awaitRunClosed(t, tenant, run.ID)
				if finished.RequestCount != int64(scenario.attempts) || len(mock.Records()) != scenario.attempts {
					t.Fatal("wrong physical request count")
				}
				wantValid := 0
				if scenario.valid {
					wantValid = 1
				}
				if finished.ValidSampleCount != wantValid {
					t.Fatal("invalid error/partial validity")
				}
				attempt, response := evidenceFor(t, f, tenant, samples[0])
				if attempt.ErrorCode == nil || *attempt.ErrorCode != scenario.code {
					t.Fatal("wrong failure classification")
				}
				if scenario.name == "partial" && (attempt.Validity != "VALID_WITH_WARNING" || response.ParseStatus != "partial") {
					t.Fatal("partial stream disguised as complete")
				}
			})
		})
	}
}

func TestRunWorkerCancellationAndRotationAbortInflightWithinFiveSeconds(t *testing.T) {
	for _, action := range []string{"cancel", "rotate"} {
		t.Run(action, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				started, stopped := make(chan struct{}, 1), make(chan struct{}, 1)
				var calls atomic.Int64
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					calls.Add(1)
					started <- struct{}{}
					select {
					case <-r.Context().Done():
						stopped <- struct{}{}
					case <-time.After(5 * time.Second):
					}
				})
				tenant, run, samples := f.createRun(t, []bool{false, false})
				config := runTLSConfig(t, f, handler)
				config.RequestTimeout = 10 * time.Second
				startRunWorker(t, f, config, nil)
				select {
				case <-started:
				case <-time.After(5 * time.Second):
					t.Fatal("upstream call not started")
				}
				began := time.Now()
				if action == "cancel" {
					for {
						current, err := tenant.GetRun(run.ID)
						if err != nil {
							t.Fatal(err)
						}
						_, err = tenant.CancelRun(run.ID, current.Version)
						if errors.Is(err, repository.ErrConflict) {
							continue
						}
						if err != nil {
							t.Fatal(err)
						}
						break
					}
				} else {
					if _, err := f.service.RotateSecret(f.ctx, f.orgID, run.TargetID, 1, 1, secret.Input{Type: "bearer", APIKey: []byte("replacement-worker-key-28")}); err != nil {
						t.Fatal(err)
					}
				}
				select {
				case <-stopped:
					if time.Since(began) > 5*time.Second {
						t.Fatal("outbound cancellation exceeded bound")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("inflight request not cancelled")
				}
				finished := awaitRunClosed(t, tenant, run.ID)
				if finished.RequestCount != 1 || finished.ValidSampleCount != 0 || calls.Load() != 1 {
					t.Fatal("new request after cancel/rotation")
				}
				if action == "cancel" && finished.Status != "CANCELLED" {
					t.Fatal("cancelled run not retained")
				}
				_, _ = evidenceFor(t, f, tenant, samples[0])
			})
		})
	}
}

func TestRunWorkerLostLeaseStopsAndRecoversUncertainWithoutRedispatch(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		started, stopped := make(chan struct{}, 1), make(chan struct{}, 1)
		var calls atomic.Int64
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			if calls.Add(1) == 1 {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"id":"fixture","model":"fixture","choices":[{"index":0,"message":{"role":"assistant","content":"retained evidence"},"finish_reason":"stop"}]}`)
				return
			}
			started <- struct{}{}
			select {
			case <-r.Context().Done():
				stopped <- struct{}{}
			case <-time.After(5 * time.Second):
			}
		})
		tenant, run, samples := f.createRun(t, []bool{false, false})
		config := runTLSConfig(t, f, handler)
		config.RequestTimeout = 10 * time.Second
		handlers, err := NewRunHandlers(config)
		if err != nil {
			t.Fatal(err)
		}
		runner, err := New(Config{Store: f.store, Handlers: handlers, PollInterval: 10 * time.Millisecond, HeartbeatInterval: 40 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- runner.Run(ctx) }()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("second sample never dispatched")
		}
		second, err := tenant.GetExecutionSampleForWorker(samples[1].ID)
		if err != nil || second.JobID == nil {
			t.Fatal("missing current sample job")
		}
		if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_jobs SET lease_owner=$1,attempt_count=attempt_count+1,lease_until=$2 WHERE organization_id=$3 AND id=$4", "replacement-owner", time.Now().UTC().Add(time.Minute), f.orgID, *second.JobID); err != nil {
			t.Fatal("replace lease fixture")
		}
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Fatal("lost lease did not stop outbound request")
		}
		select {
		case err := <-done:
			if !errors.Is(err, repository.ErrJobLeaseLost) {
				t.Fatal("lost generation not reported", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("lost lease worker stayed active")
		}
		if runner.Ready() {
			t.Fatal("lost lease worker still ready")
		}
		attempts, err := tenant.ListAttempts(samples[1].ID)
		if err != nil || len(attempts) != 1 || attempts[0].Status != "DISPATCHED" {
			t.Fatal("lost generation committed a result")
		}
		if _, err := tenant.GetResponseEvidenceForAnalysis(run.ID, samples[1].ID, attempts[0].ID); !errors.Is(err, repository.ErrNotFound) {
			t.Fatal("lost generation persisted evidence")
		}
		if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_jobs SET lease_until=$1 WHERE organization_id=$2 AND id=$3", time.Now().UTC().Add(-time.Second), f.orgID, *second.JobID); err != nil {
			t.Fatal("expire replacement lease fixture")
		}
		startRunWorker(t, f, config, nil)
		finished := awaitRunClosed(t, tenant, run.ID)
		attempts, err = tenant.ListAttempts(samples[1].ID)
		if err != nil || len(attempts) != 1 || attempts[0].Status != "UNCERTAIN" || finished.RequestCount != 2 || finished.ValidSampleCount != 1 || finished.ReservedTokens != 0 || calls.Load() != 2 {
			t.Fatal("uncertain recovery repeated request or lost completed sample")
		}
		_, response := evidenceFor(t, f, tenant, samples[0])
		if response.Content != "retained evidence" {
			t.Fatal("recovery discarded existing complete evidence")
		}
	})
}
