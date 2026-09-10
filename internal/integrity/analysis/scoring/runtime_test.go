package scoring

import (
	"errors"
	"fmt"
	"math"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/behavior"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func candidateRules(t *testing.T) (Rules, *tokenrisk.Engine) {
	t.Helper()
	r := tokenrisk.Parameters()
	r.Version = "1.0.0-dev.2"
	tokens, err := tokenrisk.NewDevelopment(r)
	if err != nil {
		t.Fatal(err)
	}
	s := Parameters()
	s.Version, s.TokenVersion, s.TokenRulesHash = r.Version, r.Version, tokens.Hash()
	return s, tokens
}

func mostlyDeviatingInput(t *testing.T) Input {
	t.Helper()
	data, hash, err := templates.Builtin().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := behavior.VerifyCatalog(data, hash)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := behavior.New(catalog)
	if err != nil {
		t.Fatal(err)
	}
	samples := []behavior.Sample{}
	input := Input{}
	for _, spec := range []struct{ family, id string }{{"format", "format.en-us.1"}, {"differential", "differential.en-us.1"}} {
		for n := 0; n < 5; n++ {
			id := int64(len(samples) + 1)
			marker := fmt.Sprintf("MARKER_%08d", id)
			content := marker
			if n < 4 {
				content = "!" + marker
			}
			samples = append(samples, behavior.Sample{ID: id, Template: behavior.TemplateRef{ID: spec.id, Version: templates.BuiltinVersion, SHA256: hash}, Contract: behavior.Contract{Kind: behavior.Exact, Expected: marker}, Variables: []string{marker}, FinalAttemptID: id, Attempts: []behavior.Attempt{{ID: id, Number: 1, Validity: behavior.Valid, Content: content}}})
			input.Samples = append(input.Samples, Observation{SampleID: fmt.Sprint(id), Family: spec.family, Language: "en-US", TemplateID: spec.id, ClusterID: fmt.Sprint(n), Included: true, Protocol: normalProtocol(), Tokenizer: tokenizer.Exact})
		}
	}
	batch, err := engine.AnalyzeBatch(samples)
	if err != nil {
		t.Fatal(err)
	}
	input.ExpectedSamples, input.Behavior = len(samples), &batch
	return input
}

func TestDevelopmentScoringKnobsAffectRealFeatures(t *testing.T) {
	rules, tokens := candidateRules(t)
	input := mostlyDeviatingInput(t)
	base, err := NewDevelopment(rules, tokens)
	if err != nil {
		t.Fatal(err)
	}
	original, err := base.Analyze(input)
	if err != nil {
		t.Fatal(err)
	}
	if original.StableHitFamilies != 2 || original.Prompt.Score == nil || *original.Prompt.Score <= 39 {
		t.Fatal("fixture lacks actual stable effect")
	}
	for _, tc := range []struct {
		name   string
		change func(*Rules)
		check  func(Result) bool
	}{
		{"stability", func(r *Rules) { r.StableFraction = .9 }, func(r Result) bool { return r.StableHitFamilies == 0 && *r.Prompt.Score == 39 }},
		{"baseline", func(r *Rules) { r.NoBaselineFactor = .4 }, func(r Result) bool {
			return r.Confidence.BaselineFactor == .4 && r.Confidence.Score < original.Confidence.Score
		}},
		{"partial", func(r *Rules) { r.MissingDimensionFactor = .25 }, func(r Result) bool {
			return r.Confidence.ApplicabilityFactor == .25 && r.Confidence.Score < original.Confidence.Score
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := rules
			tc.change(&next)
			engine, err := NewDevelopment(next, tokens)
			if err != nil {
				t.Fatal(err)
			}
			result, err := engine.Analyze(input)
			if err != nil || !tc.check(result) || result.RulesHash == original.RulesHash {
				t.Fatal("knob did not govern calculation", err)
			}
			if result.Version != rules.Version || !result.Development || result.Calibrated || result.EvidenceGrade == "A" || result.EvidenceGrade == "B" || result.Confidence.Score > 74 {
				t.Fatal("candidate gained trust")
			}
		})
	}
	copy := base.Rules()
	copy.PromptWeights[0] = 1
	if base.Rules().PromptWeights[0] != .3 {
		t.Fatal("mutable runtime")
	}
}

func TestDevelopmentScoringRejectsUnsupportedAndMixedRules(t *testing.T) {
	base, tokens := candidateRules(t)
	builtinTokens, err := tokenrisk.NewDevelopment(tokenrisk.Parameters())
	if err != nil {
		t.Fatal(err)
	}
	changedBuiltin := Parameters()
	changedBuiltin.NoBaselineFactor = .4
	if _, err := NewDevelopment(changedBuiltin, builtinTokens); !errors.Is(err, ErrRules) {
		t.Fatal("builtin scoring version rebound")
	}
	for _, change := range []func(*Rules){
		func(r *Rules) { r.Version = Version }, func(r *Rules) { r.TokenRulesHash = tokenrisk.RulesHash() }, func(r *Rules) { r.TokenVersion = tokenrisk.Version },
		func(r *Rules) { r.StableFraction = math.NaN() }, func(r *Rules) { r.StableFraction = .79 }, func(r *Rules) { r.StableFraction = 1.1 },
		func(r *Rules) { r.NoBaselineFactor = .09 }, func(r *Rules) { r.NoBaselineFactor = .81 }, func(r *Rules) { r.NoBaselineFactor = math.Inf(1) },
		func(r *Rules) { r.MissingDimensionFactor = .09 }, func(r *Rules) { r.MissingDimensionFactor = .76 },
		func(r *Rules) { r.MinimumValid = 1 }, func(r *Rules) { r.PromptWeights[0] = 1 }, func(r *Rules) { r.DevelopmentConfidenceCeiling = 99 }, func(r *Rules) { r.HighEvidenceConfidence = 1 },
	} {
		r := base
		change(&r)
		if _, err := NewDevelopment(r, tokens); !errors.Is(err, ErrRules) {
			t.Fatal("unsupported scoring admitted", err)
		}
	}
	if _, err := NewDevelopment(base, nil); !errors.Is(err, ErrRules) {
		t.Fatal("missing kernel")
	}
	if _, err := NewDevelopment(base, &tokenrisk.Engine{}); !errors.Is(err, ErrRules) {
		t.Fatal("zero kernel")
	}
	for _, e := range []*Engine{nil, {}} {
		if _, err := e.Analyze(Input{}); !errors.Is(err, ErrRules) || e.Hash() != "" || e.Rules() != (Rules{}) {
			t.Fatal("zero scoring usable")
		}
	}
	engine, err := NewDevelopment(base, tokens)
	if err != nil {
		t.Fatal(err)
	}
	// Matching version alone cannot mix a different token parameter artifact.
	other := tokens.Rules()
	other.RobustCV = .01
	otherEngine, err := tokenrisk.NewDevelopment(other)
	if err != nil {
		t.Fatal(err)
	}
	tokenResult, err := otherEngine.Analyze(tokenrisk.Input{OrganizationID: 1, RunID: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Analyze(Input{Tokens: &tokenResult}); !errors.Is(err, ErrInput) {
		t.Fatal("mixed token artifact accepted")
	}
}
