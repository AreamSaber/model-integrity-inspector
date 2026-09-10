package behavior

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
)

func pairedSamples(n int, aPositive, bPositive bool) []Sample {
	samples := []Sample{}
	for i := 0; i < n; i++ {
		a, b := testMarker, testMarker
		if aPositive {
			a = "ordinary incorrect answer"
		}
		if bPositive {
			b = "ordinary incorrect answer"
		}
		control := sampleFor(int64(2*i+1), "differential.en-us.1", a)
		variant := sampleFor(int64(2*i+2), "differential.en-us.2", b)
		pairID := fmt.Sprintf("%024x", i+1)
		control.Pair = Pair{ID: pairID, Arm: Control, Contrast: SurfaceContrast, ComparableSHA256: strings.Repeat("1", 64)}
		variant.Pair = control.Pair
		variant.Pair.Arm = Variant
		samples = append(samples, control, variant)
	}
	return samples
}

func TestExactPairedEffectAndSmallSampleP(t *testing.T) {
	e := testEngine(t)
	for _, tc := range []struct {
		name      string
		n         int
		a, b      bool
		effect, p float64
		state     PairState
	}{
		{"six_B_only", 6, false, true, 1, 0.03125, PairAvailable},
		{"six_A_only", 6, true, false, -1, 0.03125, PairAvailable},
		{"one_pair", 1, false, true, 1, 1, PairInsufficient},
		{"all_matching", 6, false, false, 0, 1, PairUninformative},
		{"all_deviating", 6, true, true, 0, 1, PairUninformative},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := e.PairedDifference(pairedSamples(tc.n, tc.a, tc.b), ContractDeviation)
			if err != nil || out.CompletePairs != tc.n || out.RiskDifference == nil || out.ExactTwoSidedP == nil || *out.RiskDifference != tc.effect || *out.ExactTwoSidedP != tc.p || out.State != tc.state {
				t.Fatalf("unexpected paired result %+v err=%v", out, err)
			}
			if out.Multiplicity != "uncorrected_exploratory_no_fdr_claim" {
				t.Fatal("multiplicity not disclosed")
			}
		})
	}
	// Four extra tied pairs do not increase the exact-test binomial n.
	samples := pairedSamples(6, false, true)
	for i := 2; i < 6; i++ {
		samples[2*i+1].Attempts[0].Content = testMarker
	}
	out, err := e.PairedDifference(samples, ContractDeviation)
	if err != nil || out.VariantOnly != 2 || *out.ExactTwoSidedP != 0.5 || math.Abs(*out.RiskDifference-1.0/3) > 1e-12 {
		t.Fatal("ties inflated exact test")
	}
	for i := 0; i < 3; i++ {
		samples[2*i].Attempts[0].Content = "wrong"
		samples[2*i+1].Attempts[0].Content = testMarker
	}
	for i := 3; i < 6; i++ {
		samples[2*i].Attempts[0].Content = testMarker
		samples[2*i+1].Attempts[0].Content = "wrong"
	}
	out, err = e.PairedDifference(samples, ContractDeviation)
	if err != nil || *out.RiskDifference != 0 || *out.ExactTwoSidedP != 1 {
		t.Fatal("balanced discordance test incorrect")
	}
}

func TestPairSelectionNeverFillsMissingWithZeroOrDuplicatesAttempts(t *testing.T) {
	e := testEngine(t)
	for _, tc := range []struct {
		name   string
		mutate func([]Sample) []Sample
		reason string
	}{
		{"incomplete", func(s []Sample) []Sample { return s[:1] }, "incomplete_pair"},
		{"duplicate_arm", func(s []Sample) []Sample { s[1].Pair.Arm = Control; return s }, "duplicate_pair_arm"},
		{"third_record", func(s []Sample) []Sample {
			x := sampleFor(3, "differential.en-us.2", testMarker)
			x.Pair = s[1].Pair
			return append(s, x)
		}, "duplicate_pair_arm"},
		{"invalid_final", func(s []Sample) []Sample {
			s[1].Attempts = append(s[1].Attempts, Attempt{ID: 21, Number: 2, Validity: InvalidProtocol, Content: "bad"})
			s[1].FinalAttemptID = 21
			return s
		}, "excluded_or_not_applicable_arm"},
		{"different_settings", func(s []Sample) []Sample { s[1].Pair.ComparableSHA256 = strings.Repeat("2", 64); return s }, "incomparable_pair_conditions"},
		{"different_nonce", func(s []Sample) []Sample {
			s[1].Contract.Expected = "changed_123456"
			s[1].Variables = []string{"changed_123456"}
			return s
		}, "incomparable_pair_conditions"},
		{"language_as_surface", func(s []Sample) []Sample { s[1].Template.ID = "differential.zh-cn.2"; return s }, "incomparable_pair_conditions"},
		{"sensitive_excluded", func(s []Sample) []Sample { s[1].SensitiveTask = true; return s }, "excluded_or_not_applicable_arm"},
		{"auxiliary_excluded", func(s []Sample) []Sample { s[1].AuxiliaryOnly = true; return s }, "excluded_or_not_applicable_arm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := e.PairedDifference(tc.mutate(pairedSamples(1, false, true)), ContractDeviation)
			if err != nil || out.CompletePairs != 0 || out.ExcludedPairs != 1 || out.RiskDifference != nil || out.ExactTwoSidedP != nil || len(out.Exclusions) != 1 || out.Exclusions[0].Reason != tc.reason {
				t.Fatalf("missing/incomparable pair incorrectly counted %+v err=%v", out, err)
			}
		})
	}
	samples := pairedSamples(1, false, true)
	for i := 2; i <= MaxAttempts; i++ {
		samples[1].Attempts = append(samples[1].Attempts, Attempt{ID: int64(20 + i), Number: i, Validity: Valid, Content: "different"})
	}
	loose := sampleFor(99, "format.en-us.1", "wrong")
	samples = append(samples, loose)
	out, err := e.PairedDifference(samples, ContractDeviation)
	if err != nil || out.CompletePairs != 1 || out.VariantPositive != 1 || out.UnpairedSamples != 1 {
		t.Fatal("attempts/unpaired samples inflated paired n")
	}
}

func TestLanguageCapabilityContrastNotHiddenInstructionConclusion(t *testing.T) {
	e := testEngine(t)
	samples := pairedSamples(6, false, true)
	for i := range samples {
		samples[i].Pair.Contrast = LanguageContrast
		if i%2 == 1 {
			samples[i].Template.ID = "differential.zh-cn.2"
			samples[i].Attempts[0].Content = "I cannot understand the language of this task."
		}
	}
	out, err := e.PairedDifference(samples, ContractDeviation)
	if err != nil || out.CompletePairs != 6 || *out.RiskDifference != 1 {
		t.Fatal("planned language contrast did not report descriptive difference")
	}
	if !contains(out.Alternatives, "language_capability_difference_not_hidden_instruction_evidence") {
		t.Fatal("language capability alternative omitted")
	}
	batch, err := e.AnalyzeBatch(samples)
	if err != nil || len(batch.Patterns) != 0 {
		t.Fatal("language-only contract failures became a fixed prefix")
	}
	refusal, err := e.PairedDifference(samples, NeutralRefusal)
	if err != nil || refusal.CompletePairs != 0 || refusal.ExactTwoSidedP != nil {
		t.Fatal("non-neutral missing cues counted as no-refusal")
	}
}

func TestAuxiliaryNeverEntersAnyPairedMetric(t *testing.T) {
	e := testEngine(t)
	for _, metric := range []Metric{ContractDeviation, ExtraAffix, NeutralRefusal, UnsolicitedIdentity} {
		samples := pairedSamples(6, false, true)
		for i := range samples {
			samples[i].Template.ID = "self_report.en-us.1"
			samples[i].AuxiliaryOnly = false
		}
		out, err := e.PairedDifference(samples, metric)
		if err != nil || out.CompletePairs != 0 || out.RiskDifference != nil || len(out.Pairs) != 0 {
			t.Fatal("self report entered statistical denominator")
		}
	}
}

func TestPairOutputsAreContentFreeAndMetricIsClosed(t *testing.T) {
	e := testEngine(t)
	samples := pairedSamples(1, false, true)
	out, err := e.PairedDifference(samples, ContractDeviation)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{testMarker, samples[0].Pair.ID, "ordinary incorrect answer"} {
		if strings.Contains(string(data), private) {
			t.Fatal("pair output leaked response/nonce/pair marker")
		}
	}
	if _, err = e.PairedDifference(samples, "unknown"); !errors.Is(err, ErrInput) {
		t.Fatal("unknown metric accepted")
	}
	if _, err = e.PairedDifference([]Sample{samples[0], samples[0]}, ContractDeviation); !errors.Is(err, ErrInput) {
		t.Fatal("duplicate logical samples accepted")
	}
	for a := 0; a <= 128; a++ {
		for b := 0; b <= 128; b++ {
			p := exactDiscordance(a, b)
			if math.IsNaN(p) || p < 0 || p > 1 || p != exactDiscordance(b, a) {
				t.Fatal("invalid exact probability")
			}
		}
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
