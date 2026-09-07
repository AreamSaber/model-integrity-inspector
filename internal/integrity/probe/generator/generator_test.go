package generator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func testGenerator(t testing.TB) *Generator {
	t.Helper()
	data, hash, err := templates.Builtin().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := tokenizer.NewBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := secret.NewKeyRing("test-one", map[string][]byte{"test-one": bytes.Repeat([]byte{17}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(data, hash, engine, ring)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func testOptions() Options {
	return Options{OrganizationID: 42, Target: domain.ExecutionTarget{ID: 11, Version: 2, SecretID: 12, SecretVersion: 3, Model: "gpt-4o-2024-08-06", Endpoint: "https://example.com/v1", Protocol: "openai_chat", MaxOutputParameter: "max_tokens"}, Package: "standard", Budget: domain.ExecutionBudget{MaxRequests: 150, MaxTokens: 1000000, TimeoutSeconds: 600}, RuleVersion: "1.0.0-dev.1", ScoringVersion: "1.0.0-dev.1", ContextWindow: 128000, MaxOutputTokens: 4096, SupportsSeed: true, SupportsStream: true, Concurrency: 3, MaxRetries: 2}
}

func TestPackagesCountsConditionsAndFrozenReplay(t *testing.T) {
	g := testGenerator(t)
	for kind, expected := range map[string]int{"quick": 18, "standard": 60, "deep": 120} {
		t.Run(kind, func(t *testing.T) {
			o := testOptions()
			o.Package = kind
			m, err := g.Generate(o)
			if err != nil {
				t.Fatal(err)
			}
			if len(m.Samples) != expected || m.Projection.Requests != expected || len(m.Omissions) != 0 || m.Completeness != "COMPLETE" {
				t.Fatalf("wrong package coverage: %d, %+v", len(m.Samples), m.Omissions)
			}
			if m.Projection.EstimatedCostMicros != nil || m.Projection.RetryRequestsIncluded {
				t.Fatal("unknown price/retries fabricated")
			}
			if kind == "quick" && !slices.Contains(m.Warnings, "MI_QUICK_NO_HIGH_CONFIDENCE_NEGATIVE") {
				t.Fatal("quick confidence warning missing")
			}
			raw, hash, err := m.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			verified, err := g.Verify(raw, hash, o.OrganizationID)
			if err != nil || !reflect.DeepEqual(verified, m) {
				t.Fatalf("replay drift: %v", err)
			}
			plan, err := g.ExecutionPlan(raw, hash, o.OrganizationID)
			if err != nil {
				t.Fatal(err)
			}
			again, err := g.ExecutionPlan(raw, hash, o.OrganizationID)
			if err != nil || !reflect.DeepEqual(plan, again) {
				t.Fatal("replay generated new parameters")
			}
			if !bytes.Equal(plan.Manifest, raw) || plan.ManifestHash != hash || len(plan.Probes) != expected {
				t.Fatal("plan lost reproduction artifact")
			}
			*again.Probes[0].Samples[0].Request.Temperature = 1.5
			if *again.Probes[1].Samples[0].Request.Temperature != 0 || *plan.Probes[0].Samples[0].Request.Temperature != 0 {
				t.Fatal("replay requests share mutable parameter pointers")
			}
			ladder := map[int]map[bool]int{}
			for i, s := range m.Samples {
				p := plan.Probes[i].Samples[0]
				if s.Ordinal != i || p.Ordinal != i || len(s.Variables.Nonce) != 24 || len(s.NonceMAC) != 64 || p.Request.Temperature == nil || *p.Request.Temperature != 0 || p.Request.Seed == nil || len(p.Request.Stop) != 0 || len(p.Request.ExtraAllowedParams) != 0 {
					t.Fatal("unstable/unsafe default parameters")
				}
				if p.EstimatedInputTokens != s.InputEstimate.BudgetTokens || s.InputEstimate.Quality == tokenizer.Exact {
					t.Fatal("input framing falsely exact")
				}
				if !strings.Contains(p.Request.Messages[0].Content, s.Variables.Nonce) || strings.Contains(p.Request.Messages[0].Content, "[[") {
					t.Fatal("missing or unexpanded nonce")
				}
				if s.Family == "sequence" || s.Family == "jsonl" {
					if ladder[s.MaxOutputTokens] == nil {
						ladder[s.MaxOutputTokens] = map[bool]int{}
					}
					ladder[s.MaxOutputTokens][s.Stream]++
					if s.Variables.Count != 1000000 {
						t.Fatal("premature natural completion point")
					}
				}
				if s.Family == "self_report" && (!s.AuxiliaryOnly || plan.Probes[i].Category != "auxiliary") {
					t.Fatal("self report mixed with scoring data")
				}
			}
			if kind != "quick" {
				for _, tier := range []int{64, 128, 256, 512} {
					if ladder[tier][true] == 0 || ladder[tier][false] == 0 {
						t.Fatal("missing stream mode/tier")
					}
				}
			}
			if strings.Contains(fmt.Sprintf("%+v %#v %s", m, m.Samples[0], m.Samples[0].Variables), m.Samples[0].Variables.Nonce) {
				t.Fatal("ordinary formatting leaked S2")
			}
		})
	}
}

func TestDifferentialChangesOneSurfaceVariable(t *testing.T) {
	g := testGenerator(t)
	o := testOptions()
	m, err := g.Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	pairs := map[string][]Sample{}
	for _, s := range m.Samples {
		if s.Family == "differential" {
			pairs[s.PairID] = append(pairs[s.PairID], s)
		}
	}
	if len(pairs) != 3 {
		t.Fatal("missing independent repetitions")
	}
	for _, pair := range pairs {
		if len(pair) != 2 || pair[0].Arm == pair[1].Arm || pair[0].Variables != pair[1].Variables || pair[0].GroupID != pair[1].GroupID || *pair[0].Seed != *pair[1].Seed || pair[0].Stream != pair[1].Stream {
			t.Fatal("pair variables confounded")
		}
		a, _ := g.request(m.Options, pair[0])
		b, _ := g.request(m.Options, pair[1])
		a.Messages[0].Content = strings.ReplaceAll(a.Messages[0].Content, "标签甲", "标签乙")
		b.Messages[0].Content = strings.ReplaceAll(b.Messages[0].Content, "标签甲", "标签乙")
		if !reflect.DeepEqual(a, b) {
			t.Fatal("pair changes more than label name")
		}
	}
}

func TestRandomVariablesUniqueBetweenRunsAndDetached(t *testing.T) {
	g := testGenerator(t)
	o := testOptions()
	temperature := 0.25
	o.Temperature = &temperature
	a, err := g.Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	b, err := g.Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	if a.RunNonce == b.RunNonce {
		t.Fatal("run nonce reused")
	}
	seen := map[string]bool{}
	for _, s := range a.Samples {
		seen[s.Variables.Nonce] = true
	}
	for _, s := range b.Samples {
		if seen[s.Variables.Nonce] {
			t.Fatal("sample group nonce reused across runs")
		}
	}
	temperature = 1.5
	if *a.Options.Temperature != 0.25 {
		t.Fatal("caller mutated retained options")
	}
	changed := false
	for i := range a.Samples {
		if a.Samples[i].ConditionID != b.Samples[i].ConditionID {
			changed = true
			break
		}
	}
	if !changed {
		t.Fatal("Fisher-Yates ordering not randomized")
	}
}

func TestWholeGroupReductionBudgetsContextAndApplicability(t *testing.T) {
	g := testGenerator(t)
	for _, fixture := range []struct {
		name, reason string
		change       func(*Options)
	}{
		{"output", "MI_MODEL_OUTPUT_LIMIT", func(o *Options) { o.MaxOutputTokens = 128 }},
		{"context", "MI_CONTEXT_WINDOW_LIMIT", func(o *Options) { o.ContextWindow = 400 }},
		{"request", "MI_REQUEST_BUDGET_LIMIT", func(o *Options) { o.Budget.MaxRequests = 40 }},
		{"tokens", "MI_TOKEN_BUDGET_LIMIT", func(o *Options) { o.Budget.MaxTokens = 10000 }},
		{"money", "MI_COST_BUDGET_LIMIT", func(o *Options) {
			price := int64(1000000)
			money := int64(10000)
			o.Pricing = domain.ExecutionPricing{InputMicrosPerMillion: &price, OutputMicrosPerMillion: &price}
			o.Budget.MaxCostMicros = &money
		}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			o := testOptions()
			fixture.change(&o)
			m, err := g.Generate(o)
			if err != nil {
				t.Fatal(err)
			}
			if m.Completeness != "PARTIAL" {
				t.Fatal("reduced package claimed complete")
			}
			found := false
			for _, om := range m.Omissions {
				if om.Reason == fixture.reason {
					found = true
				}
			}
			if !found {
				t.Fatalf("reason missing: %+v", m.Omissions)
			}
			counts := map[string]int{}
			for _, s := range m.Samples {
				counts[s.ConditionID]++
			}
			for _, count := range counts {
				if count != 3 {
					t.Fatal("partially dropped condition")
				}
			}
			if m.Projection.ReservedTokens > o.Budget.MaxTokens || int64(m.Projection.Requests) > o.Budget.MaxRequests {
				t.Fatal("projected budget exceeded")
			}
		})
	}
	o := testOptions()
	o.Budget.MaxRequests = 1
	if _, err := g.Generate(o); !errors.Is(err, ErrBudget) {
		t.Fatal("unusable package not rejected")
	}
	o = testOptions()
	o.SupportsStream = false
	o.SupportsSeed = false
	m, err := g.Generate(o)
	if err != nil || m.Completeness != "PARTIAL" {
		t.Fatal("unsupported stream not disclosed")
	}
	for _, s := range m.Samples {
		if s.Stream || s.Seed != nil {
			t.Fatal("unsupported parameters emitted")
		}
	}
}

func TestManifestTamperTenantVersionAndCanonicalEnforcement(t *testing.T) {
	g := testGenerator(t)
	o := testOptions()
	m, err := g.Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	raw, hash, _ := m.Canonical()
	if _, err := g.Verify(raw, hash, o.OrganizationID+1); err == nil {
		t.Fatal("cross tenant replay accepted")
	}
	for _, mutate := range []func(*Manifest){
		func(m *Manifest) { m.Samples[0].Variables.Nonce = "aaaaaaaaaaaaaaaaaaaaaaaa" },
		func(m *Manifest) { m.Samples[0].InputEstimate.BudgetTokens++ },
		func(m *Manifest) { m.Samples[0], m.Samples[1] = m.Samples[1], m.Samples[0] },
		func(m *Manifest) { m.TemplateHash = strings.Repeat("0", 64) },
		func(m *Manifest) { m.KeyVersion = "missing" },
		func(m *Manifest) { m.Options.Target.SecretVersion++ },
		func(m *Manifest) { m.Options.OrganizationID++ },
		func(m *Manifest) { m.Projection.ReservedTokens++ },
		func(m *Manifest) { m.Integrity = strings.Repeat("0", 64) },
	} {
		var changed Manifest
		if json.Unmarshal(raw, &changed) != nil {
			t.Fatal("fixture")
		}
		mutate(&changed)
		data, sum, _ := changed.Canonical()
		if _, err := g.Verify(data, sum, o.OrganizationID); err == nil {
			t.Fatal("forged manifest accepted with recomputed unkeyed hash")
		}
	}
	for _, ambiguous := range [][]byte{append(bytes.Clone(raw), ' '), bytes.Replace(raw, []byte(`"run_nonce":`), []byte(`"run_nonce":"x","run_nonce":`), 1), append(bytes.Clone(raw), []byte(` {}`)...)} {
		if _, err := g.Verify(ambiguous, digest(ambiguous), o.OrganizationID); err == nil {
			t.Fatal("noncanonical JSON accepted")
		}
	}
}

func TestCustomSelectionAndInputRejection(t *testing.T) {
	g := testGenerator(t)
	o := testOptions()
	o.Package = "custom"
	o.Custom = &Custom{Families: []string{"format", "differential", "self_report"}, Languages: []string{"en-US"}, Repetitions: 3}
	m, err := g.Generate(o)
	if err != nil || len(m.Samples) != 18 {
		t.Fatalf("custom package: %v", err)
	}
	for _, s := range m.Samples {
		if s.Language != "en-US" {
			t.Fatal("custom language ignored")
		}
	}
	for _, change := range []func(*Options){
		func(o *Options) { o.Custom.Repetitions = 0 }, func(o *Options) { o.Custom.Families = []string{"shell"} }, func(o *Options) { o.Custom.Families = []string{"format", "format"} }, func(o *Options) { o.Custom.Languages = []string{"../../"} }, func(o *Options) { o.Custom.Tiers = []int{128, 64} }, func(o *Options) { o.Target.Protocol = "unsupported" }, func(o *Options) { o.Target.MaxOutputParameter = "auto" }, func(o *Options) { o.OrganizationID = 0 }, func(o *Options) { o.Budget.MaxCostMicros = new(int64) },
	} {
		var copyOptions Options
		data, _ := json.Marshal(o)
		if json.Unmarshal(data, &copyOptions) != nil {
			t.Fatal("fixture")
		}
		change(&copyOptions)
		if _, err := g.Generate(copyOptions); err == nil {
			t.Fatal("invalid custom/trusted metadata accepted")
		}
	}
}

func TestCustomWithoutStreamProbeAndStructuredLogRedaction(t *testing.T) {
	g := testGenerator(t)
	o := testOptions()
	o.Package = "custom"
	o.SupportsStream = false
	o.Custom = &Custom{Families: []string{"format"}, Languages: []string{"en-US"}, Repetitions: 3}
	m, err := g.Generate(o)
	if err != nil || len(m.Samples) != 9 || m.Completeness != "COMPLETE" || slices.Contains(m.Warnings, "MI_STREAM_COMPARISON_NOT_APPLICABLE") {
		t.Fatal("unrequested stream comparison reduced completeness", err)
	}
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	logger.Info("synthetic-check", slog.Any("manifest", m), slog.Any("sample", m.Samples[0]), slog.Any("variables", m.Samples[0].Variables), slog.Any("bundle", g.bundle), slog.Any("template", g.bundle.Templates[0]))
	for _, s := range m.Samples {
		if strings.Contains(output.String(), s.Variables.Nonce) {
			t.Fatal("structured JSON logger leaked nonce")
		}
	}
	if strings.Contains(output.String(), "生成编号") || strings.Contains(output.String(), "TemplateVersion") || strings.Contains(output.String(), "sample_nonce") {
		t.Fatal("structured logger serialized S2 contents")
	}
	if !strings.Contains(output.String(), "[S2 probe manifest]") {
		t.Fatal("missing explicit redaction")
	}
	raw, _, err := m.Canonical()
	if err != nil || !bytes.Contains(raw, []byte(m.Samples[0].Variables.Nonce)) {
		t.Fatal("explicit reproduction persistence was disabled")
	}
}

func FuzzManifestVerify(f *testing.F) {
	g := testGenerator(f)
	o := testOptions()
	o.Package = "custom"
	o.Custom = &Custom{Families: []string{"neutral"}, Languages: []string{"en-US"}, Repetitions: 1}
	m, err := g.Generate(o)
	if err != nil {
		f.Fatal(err)
	}
	raw, _, _ := m.Canonical()
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxManifestBytes {
			t.Skip()
		}
		_, _ = g.Verify(data, digest(data), 42)
	})
}
