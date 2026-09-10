package scoring

import (
	"errors"
	"math"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/behavior"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func TestInputRejectsTamperAndIncompatibleFeatureBindings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Input)
	}{
		{"duplicate_id", func(in *Input) { in.Samples[1].SampleID = in.Samples[0].SampleID }},
		{"nondecimal_id", func(in *Input) { in.Samples[0].SampleID = "01" }},
		{"negative_id", func(in *Input) { in.Samples[0].SampleID = "-1" }},
		{"unknown_family", func(in *Input) { in.Samples[0].Family = "caller-family" }},
		{"empty_language", func(in *Input) { in.Samples[0].Language = "" }},
		{"absent_cluster", func(in *Input) { in.Samples[0].ClusterID = "" }},
		{"missing_expected", func(in *Input) { in.ExpectedSamples = 0 }},
		{"empty_protocol_enum", func(in *Input) { in.Samples[0].Protocol.Finish = "" }},
		{"invalid_protocol_enum", func(in *Input) { in.Samples[0].Protocol.Usage = "trusted" }},
		{"invalid_quality", func(in *Input) { in.Samples[0].Tokenizer = "excellent" }},
		{"batch_version", func(in *Input) { in.Behavior.Version = "9" }},
		{"batch_claim_calibrated", func(in *Input) { in.Behavior.RuleStatus = "calibrated" }},
		{"unknown_sample", func(in *Input) { in.Behavior.Samples[0].SampleID = "999" }},
		{"duplicate_feature", func(in *Input) { in.Behavior.Samples = append(in.Behavior.Samples, in.Behavior.Samples[0]) }},
		{"invalid_feature_version", func(in *Input) { in.Behavior.Samples[0].Version = "9" }},
		{"invalid_feature_state", func(in *Input) { in.Behavior.Samples[0].State = "trusted" }},
		{"invalid_validity", func(in *Input) { in.Samples[0].Included = false }},
		{"invalid_contract", func(in *Input) { in.Behavior.Samples[0].Contract = "score100" }},
		{"invalid_refusal", func(in *Input) { in.Behavior.Samples[0].Refusal = "maybe" }},
		{"invalid_identity", func(in *Input) { in.Behavior.Samples[0].Identity = "maybe" }},
		{"evidence_cross_sample", func(in *Input) { in.Behavior.Samples[0].Evidence[0].SampleID = "2" }},
		{"evidence_negative", func(in *Input) { in.Behavior.Samples[0].Evidence[0].StartByte = -1 }},
		{"evidence_unbounded", func(in *Input) { in.Behavior.Samples[0].Evidence[0].EndByte = behavior.MaxTextBytes + 1 }},
		{"pattern_claimed_count", func(in *Input) { in.Behavior.Patterns[0].FamilyCount = 100 }},
		{"pattern_no_language_coverage", func(in *Input) {
			for i := range in.Samples {
				in.Samples[i].Language = "en-US"
			}
		}},
		{"pattern_unlinked", func(in *Input) { in.Behavior.Patterns[0].Evidence[0].StartByte++ }},
		{"pattern_duplicate", func(in *Input) {
			in.Behavior.Patterns[0].Evidence = append(in.Behavior.Patterns[0].Evidence, in.Behavior.Patterns[0].Evidence[0])
		}},
		{"pattern_unknown_sample", func(in *Input) { in.Behavior.Patterns[0].Evidence[0].SampleID = "999" }},
		{"pattern_unknown_state", func(in *Input) { in.Behavior.Patterns[0].State = "verified" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := behaviorInput(t, formatDifferential, "strong")
			tc.change(&in)
			if _, err := Analyze(in); !errors.Is(err, ErrInput) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestTokenInputRejectsTamperAndNonfiniteScores(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*tokenrisk.Result)
	}{
		{"version", func(r *tokenrisk.Result) { r.Version = "2" }},
		{"hash", func(r *tokenrisk.Result) { r.RulesHash = strings.Repeat("0", 64) }},
		{"calibrated", func(r *tokenrisk.Result) { r.Calibrated = true }},
		{"count", func(r *tokenrisk.Result) { r.ValidSamples-- }},
		{"expected", func(r *tokenrisk.Result) { r.ExpectedSamples++ }},
		{"final_count", func(r *tokenrisk.Result) { r.FinalSamples = 0 }},
		{"nan_score", func(r *tokenrisk.Result) { r.Token.Strength = number(math.NaN()) }},
		{"inf_score", func(r *tokenrisk.Result) { r.Response.Strength = number(math.Inf(1)) }},
		{"negative_score", func(r *tokenrisk.Result) { r.Token.Strength = number(-1) }},
		{"arbitrary_score", func(r *tokenrisk.Result) { r.Token.Strength = number(100) }},
		{"weights", func(r *tokenrisk.Result) { r.Token.Components[0].Weight = .99 }},
		{"effective_weight", func(r *tokenrisk.Result) { r.Token.Components[0].EffectiveWeight = .99 }},
		{"component_name", func(r *tokenrisk.Result) { r.Token.Components[0].Name = "custom" }},
		{"component_missing", func(r *tokenrisk.Result) { r.Token.Components = r.Token.Components[:1] }},
		{"component_nan", func(r *tokenrisk.Result) { r.Token.Components[0].Strength = math.NaN() }},
		{"nil_available_score", func(r *tokenrisk.Result) { r.Token.Strength = nil }},
		{"tier_nan", func(r *tokenrisk.Result) { r.Series[0].Tiers[0].RobustCV = math.NaN() }},
		{"tier_inf", func(r *tokenrisk.Result) { r.Series[0].Tiers[0].RobustCV = math.Inf(1) }},
		{"tier_count", func(r *tokenrisk.Result) { r.Series[0].Tiers[0].Samples = -1 }},
		{"plateau_unknown_id", func(r *tokenrisk.Result) { r.Plateaus[0].SampleIDs[0] = 99999 }},
		{"plateau_wrong_family", func(r *tokenrisk.Result) { r.Plateaus[0].Family = "neutral" }},
		{"plateau_nan", func(r *tokenrisk.Result) { r.Plateaus[0].Strength = math.NaN() }},
		{"limitation_text", func(r *tokenrisk.Result) { r.Token.Limitations = []string{"private response body"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := tokenInput(t, "capped256", false)
			tc.change(in.Tokens)
			if _, err := Analyze(in); !errors.Is(err, ErrInput) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestLimitsUnverifiedBehaviorAndUnavailableDimensions(t *testing.T) {
	if _, err := Analyze(Input{ExpectedSamples: MaxSamples, Samples: make([]Observation, MaxSamples+1)}); !errors.Is(err, ErrLimit) {
		t.Fatal("sample bound")
	}
	in := behaviorInput(t, formatDifferential, "healthy")
	in.Behavior.Patterns = make([]behavior.Pattern, MaxSamples*4+1)
	if _, err := Analyze(in); !errors.Is(err, ErrLimit) {
		t.Fatal("pattern bound")
	}
	in = behaviorInput(t, formatDifferential, "strong")
	in.Behavior.Patterns = nil
	for i := range in.Behavior.Samples {
		in.Behavior.Samples[i].RegistryMatch = false
	}
	out, err := Analyze(in)
	if err != nil || out.Prompt.Score != nil {
		t.Fatal("unregistered behavior counted")
	}
	for i := range in.Samples {
		in.Samples[i].Tokenizer = tokenizer.Unavailable
	}
	out, err = Analyze(in)
	if err != nil || out.Token.Score != nil || out.Response.Score != nil {
		t.Fatal("missing token strengths fabricated")
	}
	// Less than six otherwise valid observations is explicitly insufficient.
	in = behaviorInput(t, []string{"format.en-us.1"}, "strong")
	out, err = Analyze(in)
	if err != nil || out.Completeness != "INSUFFICIENT" || out.EvidenceGrade != "D" {
		t.Fatal("small batch promoted")
	}
}

func TestRulesAreDetachedVersionedAndAllDisplayLevelsBounded(t *testing.T) {
	rules := Parameters()
	hash := RulesHash()
	rules.PromptWeights[0] = 100
	if Parameters().PromptWeights[0] != .30 || hash != RulesHash() || len(hash) != 64 {
		t.Fatal("rules mutable")
	}
	for _, tc := range []struct {
		n    float64
		want string
	}{{0, "low"}, {19, "low"}, {20, "attention"}, {39, "attention"}, {40, "medium"}, {69, "medium"}, {70, "high"}, {89, "high"}, {90, "severe_black_box_statistical_judgment"}, {100, "severe_black_box_statistical_judgment"}} {
		if level(tc.n) != tc.want {
			t.Fatal("risk band")
		}
	}
	t.Logf("scoring %s rules hash %s", Version, hash)
}
