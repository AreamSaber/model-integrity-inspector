package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func newRunHTTPFixture(t *testing.T, ready bool) controlFixture {
	t.Helper()
	return newControlFixture(t, func(cfg *ControlConfig) {
		engine, err := tokenizer.NewBuiltin()
		if err != nil {
			t.Fatal(err)
		}
		data, hash, err := templates.Builtin().Canonical()
		if err != nil {
			t.Fatal(err)
		}
		key, ok := cfg.CursorSigner.(*secret.KeyRing)
		if !ok {
			t.Fatal("test key missing")
		}
		compiler, err := generator.New(data, hash, engine, key)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Runs, err = runservice.NewService(runservice.Config{Store: cfg.Store, Targets: cfg.Targets, Generator: compiler, Limits: scheduler.DefaultLimits(), RuleVersion: "test-dev.1", ScoringVersion: "test-dev.1", ExecutionReady: func(context.Context) bool { return ready }})
		if err != nil {
			t.Fatal(err)
		}
	})
}

// This is a control-plane fixture, not a claim of a real upstream precheck.
// The Worker TLS tests separately cover producing this persisted outcome.
func runHTTPPassedPrecheck(t *testing.T, f controlFixture, cookie *http.Cookie, headers map[string]string, targetID string) {
	t.Helper()
	w := f.request(t, "POST", "/api/v1/targets/"+targetID+"/precheck", `{"version":1}`, headers, cookie)
	expectControl(t, w, 202, "")
	var p struct {
		ID string `json:"id"`
	}
	managementHTTPData(t, w, &p)
	id, _ := managementID(p.ID)
	queue, err := f.cfg.Store.OpenJobQueue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = queue.Close(context.Background()) }()
	lease, err := queue.Claim(t.Context())
	if err != nil || lease == nil || lease.Job.ObjectID != id {
		t.Fatal("claim fixture precheck failed")
	}
	if err := queue.WithLease(t.Context(), *lease, func(tx *repository.TenantTransaction) error { _, err := tx.BeginPrecheck(id, lease.Job.ID); return err }); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := queue.WithLease(t.Context(), *lease, func(tx *repository.TenantTransaction) error { return tx.ReservePrecheckRequest(id, lease.Job.ID) }); err != nil {
			t.Fatal(err)
		}
	}
	outcome := repository.PrecheckOutcome{Status: "passed", MaxOutputParameter: "max_tokens"}
	for _, name := range []string{"network", "authentication", "model", "parameters", "nonstream", "stream"} {
		outcome.Checks = append(outcome.Checks, repository.PrecheckCheck{Name: name, Status: "passed"})
	}
	if err := queue.CompleteWith(t.Context(), *lease, func(tx *repository.TenantTransaction) error { return tx.FinishPrecheck(id, lease.Job.ID, outcome) }); err != nil {
		t.Fatal(err)
	}
}

type runHTTPQuote struct {
	ID       string `json:"id"`
	Hash     string `json:"manifest_hash"`
	Estimate struct {
		Requests int    `json:"requests"`
		Cost     *int64 `json:"cost_micros"`
	} `json:"estimate"`
}
type runHTTPView struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	Version      int64  `json:"version"`
	RequestCount int    `json:"request_count"`
	Planned      int    `json:"planned_samples"`
	Completed    int    `json:"completed_samples"`
}

func runHTTPConfirm(q runHTTPQuote) string {
	return `{"estimate_id":"` + q.ID + `","manifest_hash":"` + q.Hash + `","confirm_cost":true}`
}
func runHTTPAssertNoS2(t *testing.T, data string) {
	t.Helper()
	for _, forbidden := range []string{targetHTTPKey, "nonce", "messages", "request_plan", "snapshot_json", "api_key", "secret_id", "manifest\"", "1000000", "ciphertext"} {
		if strings.Contains(data, forbidden) {
			t.Fatalf("S2 field disclosed: %s", forbidden)
		}
	}
}

func TestRunHTTPRuntimeVersionChangeRejectsDraftButPreservesReceipt(t *testing.T) {
	f := newRunHTTPFixture(t, true)
	f.initialize(t)
	cookie, csrf, org := f.login(t)
	headers := map[string]string{"X-CSRF-Token": csrf, "X-Organization-ID": org}
	w := f.request(t, "POST", "/api/v1/targets", targetHTTPBody, headers, cookie)
	expectControl(t, w, 201, "")
	var target targetHTTPView
	managementHTTPData(t, w, &target)
	runHTTPPassedPrecheck(t, f, cookie, headers, target.ID)
	quotes := make([]runHTTPQuote, 2)
	for i := range quotes {
		w = f.request(t, "POST", "/api/v1/runs/estimate", `{"target_id":"`+target.ID+`","target_version":1,"package":"quick"}`, headers, cookie)
		expectControl(t, w, 200, "")
		managementHTTPData(t, w, &quotes[i])
	}
	w = f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(quotes[0]), headers, cookie)
	expectControl(t, w, 202, "")
	var original runHTTPView
	managementHTTPData(t, w, &original)
	engine, err := tokenizer.NewBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	data, hash, err := templates.Builtin().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	key, ok := f.cfg.CursorSigner.(*secret.KeyRing)
	if !ok {
		t.Fatal("fixture key missing")
	}
	compiler, err := generator.New(data, hash, engine, key)
	if err != nil {
		t.Fatal(err)
	}
	f.cfg.Runs, err = runservice.NewService(runservice.Config{Store: f.cfg.Store, Targets: f.cfg.Targets, Generator: compiler, Limits: scheduler.DefaultLimits(), RuleVersion: "test-dev.2", ScoringVersion: "test-dev.2", ExecutionReady: func(context.Context) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	f.handler, err = NewControlHandler(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	expectControl(t, f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(quotes[1]), headers, cookie), 409, "MI_RUN_ESTIMATE_STALE")
	w = f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(quotes[0]), headers, cookie)
	expectControl(t, w, 202, "")
	var receipt runHTTPView
	managementHTTPData(t, w, &receipt)
	if receipt.ID != original.ID {
		t.Fatal("runtime change lost existing receipt")
	}
	queue, err := f.cfg.Store.OpenJobQueue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = queue.Close(context.Background()) }()
	first, err := queue.Claim(t.Context())
	if err != nil || first == nil || first.Job.ObjectID <= 0 {
		t.Fatal("missing original run job", err)
	}
	if extra, err := queue.Claim(t.Context()); err != nil || extra != nil {
		t.Fatal("stale draft created another job", err)
	}
}

func TestRunHTTPQuoteConfirmReceiptReadAndCancel(t *testing.T) {
	f := newRunHTTPFixture(t, true)
	f.initialize(t)
	cookie, csrf, org := f.login(t)
	headers := map[string]string{"X-CSRF-Token": csrf, "X-Organization-ID": org}
	w := f.request(t, "POST", "/api/v1/targets", targetHTTPBody, headers, cookie)
	expectControl(t, w, 201, "")
	var target targetHTTPView
	managementHTTPData(t, w, &target)
	body := `{"target_id":"` + target.ID + `","target_version":1,"package":"quick","options":{"max_cost_micros":null}}`
	expectControl(t, f.request(t, "POST", "/api/v1/runs/estimate", body, headers, cookie), 409, "MI_PRECHECK_REQUIRED")
	runHTTPPassedPrecheck(t, f, cookie, headers, target.ID)
	w = f.request(t, "POST", "/api/v1/runs/estimate", body, headers, cookie)
	expectControl(t, w, 200, "")
	runHTTPAssertNoS2(t, w.Body.String())
	var q runHTTPQuote
	managementHTTPData(t, w, &q)
	if q.Estimate.Requests != 18 || q.Estimate.Cost != nil || len(q.Hash) != 64 {
		t.Fatal("wrong actual quote")
	}
	// Estimation did not enqueue a Run or any outbound work.
	queue, err := f.cfg.Store.OpenJobQueue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := queue.Claim(t.Context())
	if err != nil || lease != nil {
		t.Fatal("estimate dispatched work")
	}
	_ = queue.Close(context.Background())
	expectControl(t, f.request(t, "POST", "/api/v1/runs", strings.Replace(runHTTPConfirm(q), "true", "false", 1), headers, cookie), 400, "MI_INVALID_REQUEST")
	w = f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(q), headers, cookie)
	expectControl(t, w, 202, "")
	runHTTPAssertNoS2(t, w.Body.String())
	var run runHTTPView
	managementHTTPData(t, w, &run)
	if run.Status != "QUEUED" || run.RequestCount != 0 || run.Planned != 18 || run.Completed != 0 {
		t.Fatal("run creation did not preserve planned state")
	}
	id := run.ID
	w = f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(q), headers, cookie)
	expectControl(t, w, 202, "")
	managementHTTPData(t, w, &run)
	if run.ID != id {
		t.Fatal("duplicate confirmation created another run")
	}
	expectControl(t, f.request(t, "GET", "/api/v1/runs/"+id, "", headers, cookie), 200, "")
	expectControl(t, f.request(t, "POST", "/api/v1/runs/"+id+"/cancel", `{"version":2}`, headers, cookie), 409, "MI_VERSION_CONFLICT")
	w = f.request(t, "POST", "/api/v1/runs/"+id+"/cancel", `{"version":1}`, headers, cookie)
	expectControl(t, w, 200, "")
	managementHTTPData(t, w, &run)
	if run.Status != "CANCELLING" || run.Version != 2 {
		t.Fatal("cancel did not persist requested state")
	}
	// Rotation after confirmation cannot erase receipt recovery or repeat paid work.
	expectControl(t, f.request(t, "PATCH", "/api/v1/targets/"+target.ID, `{"version":1,"name":"Changed target"}`, headers, cookie), 200, "")
	w = f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(q), headers, cookie)
	expectControl(t, w, 202, "")
	managementHTTPData(t, w, &run)
	if run.ID != id {
		t.Fatal("changed target duplicated receipt")
	}
	if err := f.cfg.Store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}

func TestRunHTTPStrictInputsCustomAndRuntimeGate(t *testing.T) {
	f := newRunHTTPFixture(t, false)
	f.initialize(t)
	cookie, csrf, org := f.login(t)
	headers := map[string]string{"X-CSRF-Token": csrf, "X-Organization-ID": org}
	w := f.request(t, "POST", "/api/v1/targets", targetHTTPBody, headers, cookie)
	var target targetHTTPView
	managementHTTPData(t, w, &target)
	runHTTPPassedPrecheck(t, f, cookie, headers, target.ID)
	base := `{"target_id":"` + target.ID + `","target_version":1,"package":"quick","options":{}}`
	for _, body := range []string{
		strings.Replace(base, `"options":{}`, `"options":{"max_tokens":null}`, 1),
		strings.Replace(base, `"options":{}`, `"options":{"max_requests":1,"max_requests":20}`, 1),
		strings.Replace(base, `"options":{}`, `"options":{"pricing":0}`, 1),
		strings.Replace(base, `"options":{}`, `"options":{"stream_modes":[true]}`, 1),
		strings.Replace(base, `"target_id":"`+target.ID+`"`, `"target_id":12`, 1),
		strings.Replace(base, `"target_version":1`, `"Target_version":1`, 1),
	} {
		expectControl(t, f.request(t, "POST", "/api/v1/runs/estimate", body, headers, cookie), 400, "MI_INVALID_REQUEST")
	}
	expectControl(t, f.request(t, "POST", "/api/v1/runs/estimate", base, map[string]string{"X-Organization-ID": org}, cookie), 403, "MI_CSRF_INVALID")
	expectControl(t, f.request(t, "POST", "/api/v1/runs/estimate", strings.Replace(base, `"options":{}`, `"options":{"max_cost_micros":100}`, 1), headers, cookie), 400, "MI_PRICE_UNKNOWN")
	custom := `{"target_id":"` + target.ID + `","target_version":1,"package":"custom","options":{"probe_types":["format"],"languages":["en-US"],"repetitions":3,"stream_modes":[true]}}`
	w = f.request(t, "POST", "/api/v1/runs/estimate", custom, headers, cookie)
	expectControl(t, w, 200, "")
	var q runHTTPQuote
	managementHTTPData(t, w, &q)
	if q.Estimate.Requests != 9 {
		t.Fatal("custom request ignored")
	}
	expectControl(t, f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(q), headers, cookie), 503, "MI_EXECUTION_NOT_READY")
	orgID, _ := managementID(org)
	id, _ := managementID(q.ID)
	// Only authenticated service/HTTP has authority to read private drafts.
	tenant, err := f.cfg.Store.WithOrganization(t.Context(), orgID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tenant.GetRunEstimate(id); err == nil {
		t.Fatal("unbound estimate read")
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(w.Body.Bytes(), &envelope) != nil {
		t.Fatal("bad response")
	}
}
