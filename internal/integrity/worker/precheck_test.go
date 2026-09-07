package worker

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/target"
	mockupstream "model-integrity-inspector.local/mii/tests/mock-upstream"
)

const workerCanary = "synthetic-worker-credential-canary-67ac"

func ioReadRequest(r *http.Request) ([]byte, error) { return io.ReadAll(io.LimitReader(r.Body, 8192)) }
func ioNopBody(data []byte) io.ReadCloser           { return io.NopCloser(bytes.NewReader(data)) }

func TestRunnerAndPrecheckRejectMissingConfiguration(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("runner accepted missing store")
	}
	if _, err := NewPrecheckHandler(PrecheckConfig{}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("precheck accepted missing infrastructure")
	}
}

type workerFixture struct {
	store   *repository.Store
	db      *sql.DB
	service *target.Service
	secrets *secret.Service
	ctx     context.Context
	orgID   int64
}

func eachWorkerDatabase(t *testing.T, test func(*testing.T, workerFixture)) {
	t.Helper()
	for _, driver := range []string{"sqlite", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			cfg := repository.Config{Driver: driver, DSN: filepath.Join(t.TempDir(), "worker.db")}
			if driver == "postgres" {
				dsn := os.Getenv("MII_TEST_POSTGRES_DSN")
				if dsn == "" {
					t.Skip("real PostgreSQL not configured")
				}
				id, err := repository.NewID()
				if err != nil {
					t.Fatal(err)
				}
				schema := fmt.Sprintf("mii_worker_test_%d", id)
				admin, err := sql.Open("pgx", dsn)
				if err != nil {
					t.Fatal("test database connection failed")
				}
				if _, err := admin.ExecContext(t.Context(), "CREATE SCHEMA "+schema); err != nil {
					_ = admin.Close()
					t.Fatal("test schema creation failed")
				}
				t.Cleanup(func() {
					if _, err := admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
						t.Error("test schema cleanup failed")
					}
					_ = admin.Close()
				})
				if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
					parsed, err := url.Parse(dsn)
					if err != nil {
						t.Fatal("test DSN invalid")
					}
					query := parsed.Query()
					query.Set("search_path", schema)
					parsed.RawQuery = query.Encode()
					cfg.DSN = parsed.String()
				} else {
					cfg.DSN = dsn + " search_path=" + schema
				}
			}
			ring, err := secret.NewKeyRing("worker-test", map[string][]byte{"worker-test": bytes.Repeat([]byte{0x82}, 32)})
			if err != nil {
				t.Fatal(err)
			}
			cfg.AuditSigner = ring
			store, err := repository.Open(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			if err := store.Migrate(t.Context()); err != nil {
				t.Fatal(err)
			}
			ctx := audit.WithActor(t.Context(), audit.Actor{ActorID: 0, ReasonCode: "worker.test"})
			// #nosec G101 -- synthetic fixture only, not a deployment credential/hash.
			initial, err := store.Initialize(ctx, repository.Initialization{OrganizationName: "Worker test", Username: "admin", PasswordHash: "synthetic-fixture-not-a-password-hash", AdminRole: "administrator", Roles: []repository.InitialRole{{Name: "administrator", Permissions: []string{"target.read", "target.write"}}}})
			if err != nil {
				t.Fatal(err)
			}
			ctx = audit.WithActor(t.Context(), audit.Actor{ActorID: initial.User.ID, ReasonCode: "worker.test"})
			secrets, err := secret.NewService(store, ring)
			if err != nil {
				t.Fatal(err)
			}
			service, err := target.NewService(target.Config{Store: store, Secrets: secrets})
			if err != nil {
				t.Fatal(err)
			}
			sqlDriver := "sqlite"
			inspectionDSN := cfg.DSN
			if driver == "postgres" {
				sqlDriver = "pgx"
			} else {
				// Match the application's bounded writer wait on this independent
				// inspection connection while heartbeat transactions are active.
				inspectionDSN += "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
			}
			db, err := sql.Open(sqlDriver, inspectionDSN)
			if err != nil {
				t.Fatal("test database inspection failed")
			}
			t.Cleanup(func() { _ = db.Close() })
			test(t, workerFixture{store, db, service, secrets, ctx, initial.Organization.ID})
		})
	}
}

func (f workerFixture) createTarget(t *testing.T, parameter string) target.View {
	t.Helper()
	value, err := f.service.Create(f.ctx, f.orgID, target.Input{Name: "Worker target", Endpoint: "https://upstream.example.com/v1", Protocol: "openai_chat", Model: "mock-model", Options: target.Options{MaxOutputParameter: parameter}}, secret.Input{Type: "bearer", APIKey: []byte(workerCanary), Headers: map[string]string{"X-Private-Test": "synthetic-header-canary"}})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

type workerResolver struct{}

func (workerResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

func tlsPrecheckConfig(t *testing.T, f workerFixture, handler http.Handler) PrecheckConfig {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return PrecheckConfig{Store: f.store, Secrets: f.secrets, RootCAs: roots, Resolver: workerResolver{}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "8.8.8.8:443" {
			t.Error("unvalidated dial target")
		}
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}}
}

func startRunner(t *testing.T, f workerFixture, handler Handler) (*Runner, context.CancelFunc, <-chan error) {
	t.Helper()
	runner, err := New(Config{Store: f.store, Handlers: map[repository.JobType]Handler{repository.JobTargetPrecheck: handler}, PollInterval: 10 * time.Millisecond, HeartbeatInterval: 30 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if runner.Ready() {
		t.Fatal("new runner incorrectly ready")
	}
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("runner cleanup: %v", err)
			}
		case <-time.After(7 * time.Second):
			t.Error("runner shutdown timed out")
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for !runner.Ready() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !runner.Ready() {
		t.Fatal("runner did not become ready")
	}
	return runner, cancel, done
}

func awaitPrecheck(t *testing.T, f workerFixture, targetID, id int64) target.PrecheckView {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		value, err := f.service.GetPrecheck(f.ctx, f.orgID, targetID, id)
		if err != nil {
			t.Fatal(err)
		}
		if value.Status == "passed" || value.Status == "failed" {
			return value
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("precheck did not finish")
	return target.PrecheckView{}
}

func TestPrecheckActualTLSMockThroughAsyncWorker(t *testing.T) {
	eachWorkerDatabase(t, func(t *testing.T, f workerFixture) {
		mock, err := mockupstream.NewHandler(mockupstream.Config{RequiredAPIKey: workerCanary})
		if err != nil {
			t.Fatal(err)
		}
		handler, err := NewPrecheckHandler(tlsPrecheckConfig(t, f, mock))
		if err != nil {
			t.Fatal(err)
		}
		value := f.createTarget(t, "auto")
		queued, err := f.service.EnqueuePrecheck(f.ctx, f.orgID, value.ID, 1, "same-request")
		if err != nil || queued.Status != "queued" || queued.RequestCount != 0 {
			t.Fatalf("enqueue: %v", err)
		}
		if len(mock.Records()) != 0 {
			t.Fatal("enqueue performed synchronous network")
		}
		same, err := f.service.EnqueuePrecheck(f.ctx, f.orgID, value.ID, 1, "same-request")
		if err != nil || same.ID != queued.ID {
			t.Fatal("enqueue retry duplicated work")
		}
		runner, _, _ := startRunner(t, f, handler)
		result := awaitPrecheck(t, f, value.ID, queued.ID)
		if result.Status != "passed" || result.RequestCount != 2 || len(result.Checks) != 6 || result.MaxOutputParameter != "max_tokens" || result.CheckedAt == nil {
			t.Fatalf("real precheck failed: status=%s code=%s requests=%d", result.Status, result.ErrorCode, result.RequestCount)
		}
		if !runner.Ready() {
			t.Fatal("runner lost readiness after completion")
		}
		records := mock.Records()
		if len(records) != 2 || records[0].Request.Stream || !records[1].Request.Stream || records[0].RequestedTokens != 16 || records[1].RequestedTokens != 16 {
			t.Fatal("wrong precheck call budget/protocol")
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		var snapshot, resultJSON string
		if err := f.db.QueryRowContext(f.ctx, "SELECT snapshot_json, result_json FROM integrity_target_prechecks WHERE organization_id = $1 AND id = $2", f.orgID, result.ID).Scan(&snapshot, &resultJSON); err != nil {
			t.Fatal("inspect precheck persistence failed")
		}
		for _, text := range []string{string(encoded), snapshot, resultJSON} {
			for _, forbidden := range []string{workerCanary, "synthetic-header-canary", "X-Private-Test", "provider_request_id", "content", "model_reported"} {
				if strings.Contains(text, forbidden) {
					t.Fatal("precheck leaked upstream/credential material")
				}
			}
		}
		tenant, _ := f.store.WithOrganization(f.ctx, f.orgID)
		job, err := tenant.GetJob(result.JobID)
		if err != nil || job.Status != "completed" {
			t.Fatal("job completion not atomic")
		}
		if _, err := tenant.VerifyAuditFull(); err != nil {
			t.Fatal("worker completion audit invalid")
		}
	})
}

func TestPrecheckParameterFallbackBudgetAndExplicitSetting(t *testing.T) {
	eachWorkerDatabase(t, func(t *testing.T, f workerFixture) {
		mock, err := mockupstream.NewHandler(mockupstream.Config{RequiredAPIKey: workerCanary})
		if err != nil {
			t.Fatal(err)
		}
		var requests atomic.Int64
		upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			var payload map[string]json.RawMessage
			data, err := ioReadRequest(r)
			if err != nil {
				t.Error("read fixture request")
				return
			}
			if json.Unmarshal(data, &payload) != nil {
				t.Error("invalid fixture request")
				return
			}
			if _, found := payload["max_tokens"]; found {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":{"code":"unsupported_parameter","param":"max_tokens"}}`))
				return
			}
			r.Body = ioNopBody(data)
			mock.ServeHTTP(w, r)
		})
		handler, err := NewPrecheckHandler(tlsPrecheckConfig(t, f, upstream))
		if err != nil {
			t.Fatal(err)
		}
		startRunner(t, f, handler)
		value := f.createTarget(t, "auto")
		queued, err := f.service.EnqueuePrecheck(f.ctx, f.orgID, value.ID, 1, "")
		if err != nil {
			t.Fatal(err)
		}
		result := awaitPrecheck(t, f, value.ID, queued.ID)
		if result.Status != "passed" || result.RequestCount != 3 || requests.Load() != 3 || result.MaxOutputParameter != "max_completion_tokens" {
			t.Fatalf("fallback: %s %s %d", result.Status, result.ErrorCode, result.RequestCount)
		}
		explicit := f.createTarget(t, "max_tokens")
		queued, err = f.service.EnqueuePrecheck(f.ctx, f.orgID, explicit.ID, 1, "")
		if err != nil {
			t.Fatal(err)
		}
		result = awaitPrecheck(t, f, explicit.ID, queued.ID)
		if result.Status != "failed" || result.RequestCount != 1 || result.ErrorCode != "MI_PROTOCOL_UNSUPPORTED" || requests.Load() != 4 {
			t.Fatal("explicit parameter silently changed/retried")
		}
	})
}

func TestPrecheckFailureClassificationAndPartialStream(t *testing.T) {
	eachWorkerDatabase(t, func(t *testing.T, f workerFixture) {
		for _, test := range []struct {
			name   string
			config mockupstream.Config
			code   string
			calls  int
		}{
			{"auth", mockupstream.Config{HTTPErrorRate: 1, HTTPErrorStatus: 401}, "MI_AUTH_FAILED", 1},
			{"missing-model", mockupstream.Config{HTTPErrorRate: 1, HTTPErrorStatus: 404}, "MI_MODEL_NOT_FOUND", 1},
			{"rate-limit", mockupstream.Config{HTTPErrorRate: 1, HTTPErrorStatus: 429}, "MI_RATE_LIMITED", 1},
			{"unavailable", mockupstream.Config{HTTPErrorRate: 1, HTTPErrorStatus: 503}, "MI_SERVICE_UNAVAILABLE", 1},
			{"partial-stream", mockupstream.Config{StreamMode: "omit_done"}, "MI_PROTOCOL_UNSUPPORTED", 2},
			{"malformed-stream", mockupstream.Config{StreamMode: "malformed_event"}, "MI_PROTOCOL_UNSUPPORTED", 2},
		} {
			t.Run(test.name, func(t *testing.T) {
				mock, err := mockupstream.NewHandler(test.config)
				if err != nil {
					t.Fatal(err)
				}
				handler, err := NewPrecheckHandler(tlsPrecheckConfig(t, f, mock))
				if err != nil {
					t.Fatal(err)
				}
				value := f.createTarget(t, "auto")
				queued, err := f.service.EnqueuePrecheck(f.ctx, f.orgID, value.ID, 1, "")
				if err != nil {
					t.Fatal(err)
				}
				startRunner(t, f, handler)
				result := awaitPrecheck(t, f, value.ID, queued.ID)
				if result.Status != "failed" || result.ErrorCode != test.code || result.RequestCount != test.calls {
					t.Fatalf("classification status=%s code=%s calls=%d", result.Status, result.ErrorCode, result.RequestCount)
				}
			})
		}
	})
}

func TestPrecheckCancellationRotationAndDisableStopOutbound(t *testing.T) {
	eachWorkerDatabase(t, func(t *testing.T, f workerFixture) {
		for _, mode := range []string{"cancel", "rotate", "disable"} {
			t.Run(mode, func(t *testing.T) {
				started, stopped := make(chan struct{}, 1), make(chan struct{}, 1)
				var calls atomic.Int64
				upstream := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					calls.Add(1)
					started <- struct{}{}
					select {
					case <-r.Context().Done():
					case <-time.After(4 * time.Second):
					}
					stopped <- struct{}{}
				})
				handler, err := NewPrecheckHandler(tlsPrecheckConfig(t, f, upstream))
				if err != nil {
					t.Fatal(err)
				}
				value := f.createTarget(t, "auto")
				queued, err := f.service.EnqueuePrecheck(f.ctx, f.orgID, value.ID, 1, "")
				if err != nil {
					t.Fatal(err)
				}
				startRunner(t, f, handler)
				select {
				case <-started:
				case <-time.After(3 * time.Second):
					t.Fatal("request did not start")
				}
				if err := f.service.Delete(f.ctx, f.orgID, value.ID, 1); !errors.Is(err, repository.ErrConflict) {
					t.Fatal("delete bypassed active precheck")
				}
				code := "MI_PRECHECK_STALE"
				switch mode {
				case "cancel":
					code = "MI_PRECHECK_CANCELLED"
					if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_jobs SET cancel_requested_at = $1 WHERE organization_id = $2 AND id = $3", time.Now().UTC(), f.orgID, queued.JobID); err != nil {
						t.Fatal("cancel fixture job failed")
					}
				case "rotate":
					if _, err := f.service.RotateSecret(f.ctx, f.orgID, value.ID, 1, 1, secret.Input{Type: "bearer", APIKey: []byte("replacement-test-key-9342")}); err != nil {
						t.Fatal(err)
					}
				case "disable":
					if _, err := f.service.Update(f.ctx, f.orgID, value.ID, 1, value.Input, "disabled"); err != nil {
						t.Fatal(err)
					}
				}
				select {
				case <-stopped:
				case <-time.After(2 * time.Second):
					t.Fatal("cancel/stale target did not interrupt HTTP")
				}
				result := awaitPrecheck(t, f, value.ID, queued.ID)
				if result.Status != "failed" || result.ErrorCode != code || result.RequestCount != 1 || calls.Load() != 1 {
					t.Fatalf("cancel/stale outcome=%s code=%s calls=%d", result.Status, result.ErrorCode, result.RequestCount)
				}
			})
		}
	})
}

func TestPrecheckRecoveryNeverRepeatsUnknownOutbound(t *testing.T) {
	eachWorkerDatabase(t, func(t *testing.T, f workerFixture) {
		value := f.createTarget(t, "auto")
		queued, err := f.service.EnqueuePrecheck(f.ctx, f.orgID, value.ID, 1, "")
		if err != nil {
			t.Fatal(err)
		}
		first, err := f.store.OpenJobQueue(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		lease, err := first.Claim(f.ctx)
		if err != nil || lease == nil {
			t.Fatal("claim initial generation")
		}
		if err := first.WithLease(f.ctx, *lease, func(tx *repository.TenantTransaction) error {
			if _, err := tx.BeginPrecheck(queued.ID, queued.JobID); err != nil {
				return err
			}
			return tx.ReservePrecheckRequest(queued.ID, queued.JobID)
		}); err != nil {
			t.Fatal(err)
		}
		if err := first.Close(f.ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_jobs SET lease_until = $1 WHERE organization_id = $2 AND id = $3", time.Now().UTC().Add(-time.Second), f.orgID, queued.JobID); err != nil {
			t.Fatal("expire test lease failed")
		}
		var calls atomic.Int64
		handler, err := NewPrecheckHandler(tlsPrecheckConfig(t, f, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(500) })))
		if err != nil {
			t.Fatal(err)
		}
		startRunner(t, f, handler)
		result := awaitPrecheck(t, f, value.ID, queued.ID)
		if result.Status != "failed" || result.ErrorCode != "MI_UNCERTAIN_ATTEMPT" || result.RequestCount != 1 || calls.Load() != 0 {
			t.Fatal("recovery replayed uncertain call")
		}
		tenant, _ := f.store.WithOrganization(f.ctx, f.orgID)
		job, err := tenant.GetJob(queued.JobID)
		if err != nil || job.Status != "completed" || job.AttemptCount != 2 {
			t.Fatal("recovery result not atomically completed")
		}
	})
}

func TestPrecheckTimeoutIsBoundedAndDoesNotRetry(t *testing.T) {
	eachWorkerDatabase(t, func(t *testing.T, f workerFixture) {
		var calls atomic.Int64
		config := tlsPrecheckConfig(t, f, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			calls.Add(1)
			select {
			case <-r.Context().Done():
			case <-time.After(4 * time.Second):
			}
		}))
		config.ExecutionTimeout = 200 * time.Millisecond
		handler, err := NewPrecheckHandler(config)
		if err != nil {
			t.Fatal(err)
		}
		value := f.createTarget(t, "auto")
		queued, err := f.service.EnqueuePrecheck(f.ctx, f.orgID, value.ID, 1, "")
		if err != nil {
			t.Fatal(err)
		}
		startRunner(t, f, handler)
		result := awaitPrecheck(t, f, value.ID, queued.ID)
		if result.Status != "failed" || result.ErrorCode != "MI_TIMEOUT" || result.RequestCount > 1 || calls.Load() > 1 {
			t.Fatalf("timeout escaped bounds: %s %s", result.Status, result.ErrorCode)
		}
	})
}

func TestRunnerLeaseLossStopsHTTPAndCannotCommitSuccess(t *testing.T) {
	eachWorkerDatabase(t, func(t *testing.T, f workerFixture) {
		started, stopped := make(chan struct{}, 1), make(chan struct{}, 1)
		config := tlsPrecheckConfig(t, f, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			started <- struct{}{}
			select {
			case <-r.Context().Done():
			case <-time.After(4 * time.Second):
			}
			stopped <- struct{}{}
		}))
		handler, err := NewPrecheckHandler(config)
		if err != nil {
			t.Fatal(err)
		}
		value := f.createTarget(t, "auto")
		queued, err := f.service.EnqueuePrecheck(f.ctx, f.orgID, value.ID, 1, "")
		if err != nil {
			t.Fatal(err)
		}
		runner, err := New(Config{Store: f.store, Handlers: map[repository.JobType]Handler{repository.JobTargetPrecheck: handler}, PollInterval: 10 * time.Millisecond, HeartbeatInterval: 30 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()
		done := make(chan error, 1)
		stoppedRunner := make(chan struct{})
		go func() { defer close(stoppedRunner); done <- runner.Run(ctx) }()
		t.Cleanup(func() {
			cancel()
			select {
			case <-stoppedRunner:
			case <-time.After(7 * time.Second):
				t.Error("lost-lease runner did not stop")
			}
		})
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("HTTP never started")
		}
		if !runner.Ready() {
			t.Fatal("running consumer not ready")
		}
		if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_jobs SET lease_owner = $1, attempt_count = attempt_count + 1, lease_until = $2 WHERE organization_id = $3 AND id = $4", "replacement-owner", time.Now().UTC().Add(time.Minute), f.orgID, queued.JobID); err != nil {
			t.Fatal("lease replacement fixture failed")
		}
		select {
		case <-stopped:
		case <-time.After(2 * time.Second):
			t.Fatal("lost lease did not close outbound request")
		}
		select {
		case err := <-done:
			if !errors.Is(err, repository.ErrJobLeaseLost) {
				t.Fatalf("runner ignored lost generation: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("lost-lease runner remained active")
		}
		if runner.Ready() {
			t.Fatal("lost-lease runner stayed ready")
		}
		tenant, _ := f.store.WithOrganization(f.ctx, f.orgID)
		record, err := tenant.GetPrecheck(value.ID, queued.ID)
		if err != nil || record.Status != "running" || record.FinishedAt != nil || record.RequestCount != 1 {
			t.Fatal("lost owner committed final result")
		}
		job, err := tenant.GetJob(queued.JobID)
		if err != nil || job.Status != "running" || job.LeaseOwner == nil || *job.LeaseOwner != "replacement-owner" {
			t.Fatal("lost owner modified replacement lease")
		}
	})
}

func TestRunnerReadinessDropsOnDatabaseFailure(t *testing.T) {
	eachWorkerDatabase(t, func(t *testing.T, f workerFixture) {
		runner, err := New(Config{Store: f.store, Handlers: map[repository.JobType]Handler{repository.JobTargetPrecheck: func(context.Context, Execution) (Completion, error) { return nil, nil }}, PollInterval: 10 * time.Millisecond, HeartbeatInterval: 30 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		if runner.Ready() {
			t.Fatal("new runner reported ready")
		}
		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- runner.Run(ctx) }()
		deadline := time.Now().Add(3 * time.Second)
		for !runner.Ready() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if !runner.Ready() {
			t.Fatal("runner did not start")
		}
		if err := f.store.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if !errors.Is(err, repository.ErrUnavailable) {
				t.Fatalf("database outage masked: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("database outage did not stop consumer")
		}
		if runner.Ready() {
			t.Fatal("database outage left false readiness")
		}
	})
}
