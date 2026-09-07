package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func budgetRunFixture(t *testing.T, ceiling int64) controlFixture {
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
			t.Fatal("missing fixture key")
		}
		compiler, err := generator.New(data, hash, engine, key)
		if err != nil {
			t.Fatal(err)
		}
		limits := scheduler.DefaultLimits()
		limits.MaxCostMicros = ceiling
		cfg.Runs, err = runservice.NewService(runservice.Config{Store: cfg.Store, Targets: cfg.Targets, Generator: compiler, Limits: limits, RuleVersion: "test-dev.1", ScoringVersion: "test-dev.1", ExecutionReady: func(context.Context) bool { return true }})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func budgetRunTarget(t *testing.T, f controlFixture, cookie *http.Cookie, headers map[string]string, inputPrice, outputPrice *int64) (targetHTTPView, managementHTTPObject) {
	t.Helper()
	provider := catalogHTTPProvider(t, f, cookie, headers, "Budget provider")
	body, err := json.Marshal(map[string]any{"provider_id": provider.ID, "name": "gpt-4o", "protocol": "openai_chat", "supports_stream": true, "supports_seed": true, "context_window": 128000, "max_output_tokens": 4096, "input_price_micros_per_million": inputPrice, "output_price_micros_per_million": outputPrice})
	if err != nil {
		t.Fatal(err)
	}
	w := f.request(t, "POST", "/api/v1/model-profiles", string(body), headers, cookie)
	expectControl(t, w, 201, "")
	var profile managementHTTPObject
	managementHTTPData(t, w, &profile)
	var targetBody map[string]any
	if json.Unmarshal([]byte(targetHTTPBody), &targetBody) != nil {
		t.Fatal("invalid target fixture")
	}
	targetBody["provider_id"], targetBody["model_profile_id"], targetBody["model"] = provider.ID, profile.ID, "gpt-4o"
	body, err = json.Marshal(targetBody)
	if err != nil {
		t.Fatal(err)
	}
	w = f.request(t, "POST", "/api/v1/targets", string(body), headers, cookie)
	expectControl(t, w, 201, "")
	var target targetHTTPView
	managementHTTPData(t, w, &target)
	runHTTPPassedPrecheck(t, f, cookie, headers, target.ID)
	return target, profile
}

type budgetRunQuote struct {
	ID       string `json:"id"`
	Hash     string `json:"manifest_hash"`
	Estimate struct {
		Requests     int      `json:"requests"`
		Cost         *int64   `json:"cost_micros"`
		Warnings     []string `json:"warnings"`
		Completeness string   `json:"completeness"`
	} `json:"estimate"`
	Budgets struct {
		Money *int64 `json:"max_cost_micros"`
	} `json:"budgets"`
}

func budgetRunInput(t *testing.T, targetID, packageName string, options map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{"target_id": targetID, "target_version": 1, "package": packageName, "options": options})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
func budgetRunNoJob(t *testing.T, f controlFixture) {
	t.Helper()
	queue, err := f.cfg.Store.OpenJobQueue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := queue.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	lease, err := queue.Claim(t.Context())
	if err != nil || lease != nil {
		t.Fatal("rejected/estimated request dispatched paid job")
	}
}
func budgetRunConfirmed(t *testing.T, f controlFixture, cookie *http.Cookie, headers map[string]string, q budgetRunQuote) repository.RunRecord {
	t.Helper()
	w := f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(runHTTPQuote{ID: q.ID, Hash: q.Hash}), headers, cookie)
	expectControl(t, w, 202, "")
	var result runHTTPView
	managementHTTPData(t, w, &result)
	orgID, _ := managementID(headers["X-Organization-ID"])
	runID, _ := managementID(result.ID)
	tenant, err := f.cfg.Store.WithOrganization(t.Context(), orgID)
	if err != nil {
		t.Fatal(err)
	}
	run, err := tenant.GetRun(runID)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := tenant.GetExecutionPlan(runID)
	if err != nil {
		t.Fatal(err)
	}
	if (q.Budgets.Money == nil) != (run.MoneyBudgetMicros == nil) || (q.Budgets.Money == nil) != (plan.Budget.MaxCostMicros == nil) {
		t.Fatal("quote/run/signed-plan money presence drift")
	}
	if q.Budgets.Money != nil && (*q.Budgets.Money != *run.MoneyBudgetMicros || *q.Budgets.Money != *plan.Budget.MaxCostMicros) {
		t.Fatal("money budget changed after confirmation")
	}
	var frozen struct {
		Options struct {
			Budget domain.ExecutionBudget `json:"budget"`
		} `json:"options"`
	}
	if json.Unmarshal(plan.Manifest, &frozen) != nil {
		t.Fatal("invalid signed fixture manifest")
	}
	if q.Budgets.Money != nil && (frozen.Options.Budget.MaxCostMicros == nil || *frozen.Options.Budget.MaxCostMicros != *q.Budgets.Money) {
		t.Fatal("money ceiling was added after signing/quote")
	}
	return run
}

func TestRunBudgetHTTPKnownNilAndOmittedFreezeOrdinaryDefault(t *testing.T) {
	for _, tc := range []struct {
		name          string
		ceiling, want int64
		options       map[string]any
	}{
		{"omitted", 1000000000, 2000000, map[string]any{}},
		{"explicit_null", 1000000000, 2000000, map[string]any{"max_cost_micros": nil}},
		{"admin_lower", 900000, 900000, map[string]any{}},
		{"explicit_lower", 1000000000, 500000, map[string]any{"max_cost_micros": 500000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := budgetRunFixture(t, tc.ceiling)
			f.initialize(t)
			admin, csrf, org := f.login(t)
			headers := map[string]string{"X-Organization-ID": org, "X-CSRF-Token": csrf}
			price := int64(1000000)
			target, _ := budgetRunTarget(t, f, admin, headers, &price, &price)
			// Operators have run.create but intentionally not run.high-cost.
			user, operator, operatorCSRF := managementHTTPUser(t, f, admin, csrf, "budget-operator")
			expectControl(t, f.request(t, "POST", "/api/v1/organizations/"+org+"/members", `{"user_id":"`+user.ID+`","roles":["operator"]}`, headers, admin), 201, "")
			operatorHeaders := map[string]string{"X-Organization-ID": org, "X-CSRF-Token": operatorCSRF}
			w := f.request(t, "POST", "/api/v1/runs/estimate", budgetRunInput(t, target.ID, "quick", tc.options), operatorHeaders, operator)
			expectControl(t, w, 200, "")
			var q budgetRunQuote
			managementHTTPData(t, w, &q)
			if q.Budgets.Money == nil || *q.Budgets.Money != tc.want || q.Estimate.Cost == nil || *q.Estimate.Cost > tc.want || q.Estimate.Requests != 18 || slices.Contains(q.Estimate.Warnings, "MI_PRICE_UNKNOWN_REQUEST_TOKEN_ONLY") {
				t.Fatal("ordinary known-price budget missing/wrong")
			}
			budgetRunNoJob(t, f)
			budgetRunConfirmed(t, f, operator, operatorHeaders, q)
			// Authorization follows the actual frozen allowance, not an input
			// value that the administrator already clamped to a safe amount.
			w = f.request(t, "POST", "/api/v1/runs/estimate", budgetRunInput(t, target.ID, "quick", map[string]any{"max_cost_micros": 2000001}), operatorHeaders, operator)
			if tc.ceiling > 2000000 {
				expectControl(t, w, 403, "MI_PERMISSION_DENIED")
			} else {
				expectControl(t, w, 200, "")
				var clamped budgetRunQuote
				managementHTTPData(t, w, &clamped)
				if clamped.Budgets.Money == nil || *clamped.Budgets.Money != tc.ceiling {
					t.Fatal("actual authorized amount not frozen")
				}
			}
		})
	}
}

func TestRunBudgetHTTPZeroCeilingAndUnknownPrices(t *testing.T) {
	for _, tc := range []struct {
		name          string
		input, output *int64
		wantStatus    int
	}{
		{"known_free", new(int64), new(int64), 200},
		{"known_positive", func() *int64 { v := int64(1000000); return &v }(), func() *int64 { v := int64(1000000); return &v }(), 400},
		{"unknown", nil, nil, 200},
		{"only_input", new(int64), nil, 200},
		{"only_output", nil, new(int64), 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := budgetRunFixture(t, 0)
			f.initialize(t)
			cookie, csrf, org := f.login(t)
			headers := map[string]string{"X-Organization-ID": org, "X-CSRF-Token": csrf}
			target, _ := budgetRunTarget(t, f, cookie, headers, tc.input, tc.output)
			w := f.request(t, "POST", "/api/v1/runs/estimate", budgetRunInput(t, target.ID, "quick", map[string]any{"max_cost_micros": nil}), headers, cookie)
			if tc.wantStatus != 200 {
				expectControl(t, w, 400, "MI_PROBE_BUDGET_INSUFFICIENT")
				budgetRunNoJob(t, f)
				return
			}
			expectControl(t, w, 200, "")
			var q budgetRunQuote
			managementHTTPData(t, w, &q)
			known := tc.input != nil && tc.output != nil
			if known {
				if q.Budgets.Money == nil || *q.Budgets.Money != 0 || q.Estimate.Cost == nil || *q.Estimate.Cost != 0 {
					t.Fatal("zero admin money ceiling discarded")
				}
			} else {
				if q.Budgets.Money != nil || q.Estimate.Cost != nil || !slices.Contains(q.Estimate.Warnings, "MI_PRICE_UNKNOWN_REQUEST_TOKEN_ONLY") {
					t.Fatal("unknown price fabricated monetary bound")
				}
				expectControl(t, f.request(t, "POST", "/api/v1/runs/estimate", budgetRunInput(t, target.ID, "quick", map[string]any{"max_cost_micros": 0}), headers, cookie), 400, "MI_PRICE_UNKNOWN")
			}
			budgetRunNoJob(t, f)
			budgetRunConfirmed(t, f, cookie, headers, q)
		})
	}
}

func TestRunBudgetHTTPExpensivePricingOmitsBeforeQuoteAndProfileChangeRejects(t *testing.T) {
	f := newRunHTTPFixture(t, true)
	f.initialize(t)
	cookie, csrf, org := f.login(t)
	headers := map[string]string{"X-Organization-ID": org, "X-CSRF-Token": csrf}
	price := int64(500000000)
	target, profile := budgetRunTarget(t, f, cookie, headers, &price, &price)
	w := f.request(t, "POST", "/api/v1/runs/estimate", budgetRunInput(t, target.ID, "standard", map[string]any{}), headers, cookie)
	expectControl(t, w, 200, "")
	var q budgetRunQuote
	managementHTTPData(t, w, &q)
	if q.Budgets.Money == nil || *q.Budgets.Money != 2000000 || q.Estimate.Cost == nil || *q.Estimate.Cost > 2000000 || q.Estimate.Requests >= 60 || q.Estimate.Completeness != "partial" || !slices.Contains(q.Estimate.Warnings, "MI_COST_BUDGET_LIMIT") {
		t.Fatal("expensive groups not omitted before quote")
	}
	budgetRunNoJob(t, f)
	w = f.request(t, "PATCH", "/api/v1/model-profiles/"+profile.ID, `{"version":1,"output_price_micros_per_million":600000000}`, headers, cookie)
	expectControl(t, w, 200, "")
	w = f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(runHTTPQuote{ID: q.ID, Hash: q.Hash}), headers, cookie)
	expectControl(t, w, 409, "MI_RUN_ESTIMATE_STALE")
	budgetRunNoJob(t, f)
	orgID, _ := managementID(org)
	session, err := f.cfg.Store.GetSession(t.Context(), digest(cookie.Value), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := f.cfg.Store.BindControlAuthority(audit.WithActor(t.Context(), audit.Actor{ActorID: session.UserID, ReasonCode: "test.run-budget"}), digest(cookie.Value), orgID)
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := f.cfg.Store.WithOrganization(ctx, orgID)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := managementID(q.ID)
	if _, err := tenant.FindConfirmedEstimate(id, q.Hash); !errors.Is(err, repository.ErrNotFound) {
		t.Fatal("stale confirmation retained a Run receipt")
	}
	if err := f.cfg.Store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}

func TestRunBudgetHTTPRevokedHighCostGrantRejectsConfirmation(t *testing.T) {
	f := newRunHTTPFixture(t, true)
	f.initialize(t)
	admin, csrf, org := f.login(t)
	headers := map[string]string{"X-Organization-ID": org, "X-CSRF-Token": csrf}
	price := int64(1000000)
	target, _ := budgetRunTarget(t, f, admin, headers, &price, &price)
	user, operator, operatorCSRF := managementHTTPUser(t, f, admin, csrf, "high-budget-operator")
	w := f.request(t, "POST", "/api/v1/organizations/"+org+"/members", `{"user_id":"`+user.ID+`","roles":["operator"],"permissions":["run.high-cost"]}`, headers, admin)
	expectControl(t, w, 201, "")
	var member managementHTTPObject
	managementHTTPData(t, w, &member)
	operatorHeaders := map[string]string{"X-Organization-ID": org, "X-CSRF-Token": operatorCSRF}
	w = f.request(t, "POST", "/api/v1/runs/estimate", budgetRunInput(t, target.ID, "quick", map[string]any{"max_cost_micros": 2000001}), operatorHeaders, operator)
	expectControl(t, w, 200, "")
	var q budgetRunQuote
	managementHTTPData(t, w, &q)
	if q.Budgets.Money == nil || *q.Budgets.Money != 2000001 {
		t.Fatal("granted high budget was not frozen")
	}
	budgetRunNoJob(t, f)
	w = f.request(t, "PATCH", "/api/v1/organizations/"+org+"/members/"+member.ID, `{"version":1,"roles":["operator"],"permissions":[]}`, headers, admin)
	expectControl(t, w, 200, "")
	w = f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(runHTTPQuote{ID: q.ID, Hash: q.Hash}), operatorHeaders, operator)
	expectControl(t, w, 403, "MI_PERMISSION_DENIED")
	budgetRunNoJob(t, f)
	if err := f.cfg.Store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}
