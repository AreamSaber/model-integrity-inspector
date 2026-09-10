package api

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func runHTTPSourceMode(t *testing.T, f *controlFixture, mode string) *generator.Generator {
	t.Helper()
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
		t.Fatal("fixture signer unavailable")
	}
	compiler, err := generator.New(data, hash, engine, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := runservice.Config{Store: f.cfg.Store, Targets: f.cfg.Targets, Generator: compiler, Limits: scheduler.DefaultLimits(), RuleVersion: "test-dev.1", ScoringVersion: "test-dev.1", AnalysisSourceVersion: mode, ExecutionReady: func(context.Context) bool { return true }}
	invalid := cfg
	invalid.AnalysisSourceVersion = "caller-selected-unknown"
	if _, err := runservice.NewService(invalid); !errors.Is(err, runservice.ErrInvalid) {
		t.Fatal("unknown deployment source mode accepted")
	}
	f.cfg.Runs, err = runservice.NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.handler, err = NewControlHandler(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return compiler
}

// Real HTTP/service/database control-plane flow. The precheck is the existing
// explicitly synthetic fixture; this does not exercise the new Worker pipeline.
func TestRunHTTPAnalysisSourceModeIsSignedAndDraftTransitionPreservesReceipts(t *testing.T) {
	f := newRunHTTPFixture(t, true)
	f.initialize(t)
	cookie, csrf, org := f.login(t)
	headers := runAuthorizationHeaders(org, csrf)
	target := runAuthorizationTarget(t, f, cookie, csrf, org)
	body := runAuthorizationQuick(target)
	oldConfirmed := runAuthorizationEstimate(t, f, cookie, csrf, org, body)
	oldPending := runAuthorizationEstimate(t, f, cookie, csrf, org, body)
	oldRun := runAuthorizationConfirm(t, f, cookie, csrf, org, oldConfirmed)
	compiler := runHTTPSourceMode(t, &f, domain.AnalysisSourceDerivedV1)
	expectControl(t, f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(oldPending), headers, cookie), 409, "MI_RUN_ESTIMATE_STALE")
	if got := runAuthorizationConfirm(t, f, cookie, csrf, org, oldConfirmed); got.ID != oldRun.ID {
		t.Fatal("source-mode upgrade lost the original legacy receipt")
	}
	for _, request := range []string{
		strings.TrimSuffix(body, "}") + `,"analysis_source_version":""}`,
		strings.Replace(body, `"options":{}`, `"options":{"analysis_source_version":"mii.derived-s1.v1"}`, 1),
	} {
		expectControl(t, f.request(t, "POST", "/api/v1/runs/estimate", request, headers, cookie), 400, "")
	}
	newQuote := runAuthorizationEstimate(t, f, cookie, csrf, org, body)
	newPending := runAuthorizationEstimate(t, f, cookie, csrf, org, body)
	newRun := runAuthorizationConfirm(t, f, cookie, csrf, org, newQuote)
	orgID, _ := managementID(org)
	tenant, err := f.cfg.Store.WithOrganization(t.Context(), orgID)
	if err != nil {
		t.Fatal(err)
	}
	var frozenNew []byte
	for _, tc := range []struct {
		id, mode string
	}{{oldRun.ID, ""}, {newRun.ID, domain.AnalysisSourceDerivedV1}} {
		id, _ := managementID(tc.id)
		plan, err := tenant.GetExecutionPlan(id)
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := compiler.Verify(plan.Manifest, plan.ManifestHash, orgID)
		if err != nil || manifest.Options.AnalysisSourceVersion != tc.mode || plan.AnalysisSourceVersion != tc.mode {
			t.Fatal("persisted source mode is not the original authenticated selection")
		}
		if tc.mode != "" {
			frozenNew = bytes.Clone(plan.Manifest)
		}
	}
	runHTTPSourceMode(t, &f, "")
	expectControl(t, f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(newPending), headers, cookie), 409, "MI_RUN_ESTIMATE_STALE")
	if got := runAuthorizationConfirm(t, f, cookie, csrf, org, newQuote); got.ID != newRun.ID {
		t.Fatal("source-mode rollback lost the existing derived receipt")
	}
	id, _ := managementID(newRun.ID)
	unchanged, err := tenant.GetExecutionPlan(id)
	if err != nil || !bytes.Equal(frozenNew, unchanged.Manifest) || unchanged.AnalysisSourceVersion != domain.AnalysisSourceDerivedV1 {
		t.Fatal("deployment transition rewrote an already confirmed manifest")
	}
}
