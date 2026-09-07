package worker

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	mockupstream "model-integrity-inspector.local/mii/tests/mock-upstream"
)

func TestRuntimeRunUsesPersistedInitiatorWithoutHTTPContext(t *testing.T) {
	for _, spoof := range []bool{false, true} {
		name := "background"
		if spoof {
			name = "spoofed-caller"
		}
		t.Run(name, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				tenant, run, samples := f.createRun(t, []bool{false, true})
				creator, err := audit.ActorFromContext(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				mock, err := mockupstream.NewHandler(mockupstream.Config{RequiredAPIKey: workerCanary})
				if err != nil {
					t.Fatal(err)
				}
				var calls atomic.Int32
				config := runTLSConfig(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					mock.ServeHTTP(w, r)
				}))
				// Create commands above use real control authority. Runtime below
				// starts exactly like app.Run: no session, actor, request IP or UA.
				runtime := f
				runtime.ctx = context.Background()
				if spoof {
					runtime.ctx = audit.WithActor(runtime.ctx, audit.Actor{ActorID: creator.ActorID + 1, ReasonCode: "spoof.runtime", IPSummary: "spoof-ip", UserAgentSummary: "spoof-agent"})
				}
				startRunWorker(t, runtime, config, nil)
				closed := awaitRunClosed(t, tenant, run.ID)
				if closed.Status != "ANALYZING" || closed.RequestCount != 2 || calls.Load() != 2 {
					t.Fatal("background runtime did not execute both real mock calls")
				}
				for _, sample := range samples {
					attempts, err := tenant.ListAttempts(sample.ID)
					if err != nil || len(attempts) != 1 || attempts[0].Status != "COMPLETED" {
						t.Fatal("background attempt not durably completed")
					}
					if _, err := tenant.GetResponseEvidenceForAnalysis(run.ID, sample.ID, attempts[0].ID); err != nil {
						t.Fatal(err)
					}
				}
				assertRuntimeAudit(t, f, creator.ActorID, 4)
				if _, err := tenant.VerifyAuditFull(); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func assertRuntimeAudit(t *testing.T, f runFixture, creator int64, minimum int) {
	t.Helper()
	rows, err := f.db.QueryContext(context.Background(), "SELECT actor_id, diff_summary, ip_summary, user_agent_summary FROM integrity_audit_logs WHERE organization_id=$1 AND action IN ('run.start','run.attempt.finish','run.execution.close','run.sample.reconcile')", f.orgID)
	if err != nil {
		t.Fatal("read runtime audit")
	}
	defer func() { _ = rows.Close() }()
	count := 0
	for rows.Next() {
		var actor int64
		var diff, ip, ua string
		if rows.Scan(&actor, &diff, &ip, &ua) != nil {
			t.Fatal("read runtime audit fields")
		}
		var reason struct {
			Code string `json:"reason_code"`
		}
		if json.Unmarshal([]byte(diff), &reason) != nil || actor != creator || !strings.HasPrefix(reason.Code, "worker.") || ip != "" || ua != "" {
			t.Fatal("runtime audit used caller data instead of persisted initiator")
		}
		count++
	}
	if rows.Err() != nil || count < minimum {
		t.Fatal("runtime audit events missing")
	}
}

func TestRuntimeTerminalRecoveryUsesBackgroundContext(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		tenant, run, _ := f.createRun(t, []bool{false})
		creator, err := audit.ActorFromContext(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		queue, err := f.store.OpenJobQueue(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = queue.Close(context.Background()) })
		lease, err := queue.Claim(context.Background())
		if err != nil || lease == nil {
			t.Fatal("claim unstarted run")
		}
		if err := queue.Fail(context.Background(), *lease, "WORKER_HANDLER_UNAVAILABLE"); err != nil {
			t.Fatal(err)
		}
		if err := ReconcileRunJobs(context.Background(), queue); err != nil {
			t.Fatal(err)
		}
		closed, err := tenant.GetRun(run.ID)
		if err != nil || closed.Status != "FAILED" || closed.ExecutionClosedAt == nil || closed.RequestCount != 0 {
			t.Fatal("background terminal recovery did not close unstarted run")
		}
		assertRuntimeAudit(t, f, creator.ActorID, 1)
		if _, err := tenant.VerifyAuditFull(); err != nil {
			t.Fatal(err)
		}
	})
}
