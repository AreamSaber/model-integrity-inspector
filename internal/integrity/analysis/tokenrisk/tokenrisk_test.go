package tokenrisk

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/structure"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func testDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func sample(id, tier, output int64) Sample {
	return Sample{ID: id, AttemptID: id, FinalAttemptID: id, AttemptNumber: 1, Validity: Valid,
		Family: "sequence", Language: "en-US", TemplateID: "sequence.v1", TemplateVersion: "1.0.0", Variant: 1,
		ConditionID: fmt.Sprintf("sequence.tier-%d", tier), SeriesID: testDigest("sequence/en-US/v1"), GroupID: fmt.Sprintf("group-%d", id),
		RequestedMaxTokens: tier, Local: tokenizer.Estimate{Tokens: &output, Quality: tokenizer.Exact, TokenizerID: "cl100k_base", TokenizerVersion: "1.0.0", Scope: "visible_output"},
		Structure: structure.Features{Version: structure.Version, UTF8Valid: true, StructureComplete: true, FinishReason: "STOP"}}
}
func fixture(tiers []int64, repetitions int, output func(int64, int) int64) []Sample {
	result := []Sample{}
	for _, tier := range tiers {
		for repetition := 0; repetition < repetitions; repetition++ {
			s := sample(int64(len(result)+1), tier, output(tier, repetition))
			s.Repetition, s.Stream = repetition, repetition%2 == 1
			s.GroupID = fmt.Sprintf("pair-%d", repetition/2)
			s.Structure.StructureComplete, s.Structure.HardTruncation = false, true
			s.Structure.FinishReason = "LENGTH"
			if *s.Local.Tokens >= tier*9/10 && *s.Local.Tokens <= tier*11/10 {
				s.Structure.NormalRequestedLimit = true
			} else if *s.Local.Tokens < tier*7/10 {
				s.Structure.TerminationHints = []string{"MI_LENGTH_FAR_BELOW_REQUEST"}
			}
			result = append(result, s)
		}
	}
	return result
}
func analyzeTest(t testing.TB, samples []Sample) Result {
	t.Helper()
	r, err := Analyze(Input{OrganizationID: 1, RunID: 2, Samples: samples})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func component(t testing.TB, a Aggregate, name string) Component {
	t.Helper()
	for _, c := range a.Components {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("missing component %s", name)
	return Component{}
}

func TestStatisticsAndDeterministicClusterBootstrap(t *testing.T) {
	values := []float64{9, 1, 3, 2}
	if median(values) != 2.5 || mad(values) != 1 || math.Abs(robustCV(values)-0.59304) > 1e-10 || values[0] != 9 {
		t.Fatal("median/MAD/CV or input mutation")
	}
	if median(nil) != 0 || mad(nil) != 0 || ratio(2, 0) != 0 {
		t.Fatal("empty calculation")
	}
	left, right := [][]float64{{1}, {20}, {90}}, [][]float64{{11}, {30}, {100}}
	paired := bootstrap(left, right, true, "known")
	if !paired.Available || !paired.Paired || paired.Lower != 10 || paired.Upper != 10 || paired.Units != 3 {
		t.Fatalf("paired interval: %+v", paired)
	}
	unpaired := bootstrap(left, right, false, "known")
	if unpaired.Lower >= 10 || unpaired.Upper <= 10 {
		t.Fatalf("independent draws falsely paired: %+v", unpaired)
	}
	if !reflect.DeepEqual(unpaired, bootstrap(left, right, false, "known")) {
		t.Fatal("bootstrap not deterministic")
	}
	if bootstrap(left[:1], right[:1], true, "small").Available || bootstrap(left, right[:2], true, "mismatch").Available {
		t.Fatal("invented interval from missing blocks")
	}
	if percentile([]float64{0, 10}, 0.25) != 2.5 || percentile(nil, 0.5) != 0 {
		t.Fatal("percentile interpolation")
	}
}

func TestPooledTierCountsAndModeConfounding(t *testing.T) {
	constant := fixture([]int64{256, 512}, 3, func(int64, int) int64 { return 128 })
	r := analyzeTest(t, constant)
	if len(r.Series) != 1 || len(r.Plateaus) != 1 {
		t.Fatalf("must pool stream modes: series=%d plateaus=%d", len(r.Series), len(r.Plateaus))
	}
	p := r.Plateaus[0]
	if !p.Candidate || p.Strength <= 39 || p.Low.Samples != 3 || p.High.Samples != 3 || !p.LowModes.Comparable || p.LowModes.Stream.Samples != 1 || p.DifferenceCI.Units != 2 || !p.Limited {
		t.Fatalf("pooled fixture rejected or groups inflated: %+v", p)
	}
	if !slices.Contains(p.Limitations, "MI_INDEPENDENT_GROUPS_INSUFFICIENT") {
		t.Fatal("low cluster count must limit confidence")
	}
	shuffled := slices.Clone(constant)
	slices.Reverse(shuffled)
	if !reflect.DeepEqual(r, analyzeTest(t, shuffled)) {
		t.Fatal("input ordering changes results")
	}
	// Majority nonstream lengths can be constant even when stream has a
	// different plateau. That is not one comparable common-mode plateau.
	for i := range constant {
		if constant[i].Stream {
			v := int64(32)
			constant[i].Local.Tokens = &v
		}
	}
	r = analyzeTest(t, constant)
	if r.Plateaus[0].Candidate || !slices.Contains(r.Plateaus[0].Limitations, "MI_STREAM_MODES_NOT_COMPARABLE") {
		t.Fatal("incompatible arms pooled into a platform")
	}
}

func TestPlatformNegativeAndAlternativeExplanations(t *testing.T) {
	cases := []struct {
		name          string
		change        func([]Sample)
		wantCandidate bool
		limitation    string
	}{
		{"normal_length", func(ss []Sample) {
			for i := range ss {
				v := ss[i].RequestedMaxTokens
				ss[i].Local.Tokens = &v
				ss[i].Structure.NormalRequestedLimit = true
				ss[i].Structure.TerminationHints = nil
			}
		}, false, ""},
		{"natural_eos", func(ss []Sample) {
			for i := range ss {
				ss[i].Structure = structure.Features{Version: structure.Version, UTF8Valid: true, StructureComplete: true, CompleteEarlyStop: true, FinishReason: "STOP"}
			}
		}, false, "MI_NATURAL_EOS_ALTERNATIVE"},
		{"heuristic", func(ss []Sample) {
			for i := range ss {
				ss[i].Local.Quality = tokenizer.Heuristic
			}
		}, true, "MI_TOKENIZER_HEURISTIC_ONLY"},
		{"reasoning_unknown", func(ss []Sample) {
			for i := range ss {
				ss[i].ReasoningUnseparated = true
			}
		}, true, "MI_REASONING_UNSEPARATED"},
		{"missing_mode", func(ss []Sample) {
			for i := range ss {
				ss[i].Stream = false
			}
		}, true, "MI_MODE_TIER_COVERAGE_INSUFFICIENT"},
		{"complete_no_support", func(ss []Sample) {
			for i := range ss {
				ss[i].Structure.HardTruncation = false
				ss[i].Structure.StructureComplete = true
				ss[i].Structure.TerminationHints = nil
			}
		}, false, ""},
		{"high_variation", func(ss []Sample) {
			for i := range ss {
				v := int64((i%3 + 1) * 100)
				ss[i].Local.Tokens = &v
			}
		}, false, ""},
		{"minor_hard_majority_eos", func(ss []Sample) {
			for i := range ss {
				if ss[i].Repetition != 0 {
					ss[i].Structure = structure.Features{Version: structure.Version, UTF8Valid: true, StructureComplete: true, CompleteEarlyStop: true}
				}
			}
		}, true, "MI_NATURAL_EOS_ALTERNATIVE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ss := fixture([]int64{512, 1024}, 3, func(int64, int) int64 { return 256 })
			tc.change(ss)
			r := analyzeTest(t, ss)
			if len(r.Plateaus) != 1 || r.Plateaus[0].Candidate != tc.wantCandidate {
				t.Fatalf("candidate mismatch: %+v", r.Plateaus)
			}
			if tc.limitation != "" && (!slices.Contains(r.Plateaus[0].Limitations, tc.limitation) || r.Plateaus[0].Strength > 39) {
				t.Fatalf("alternative not bounded: %+v", r.Plateaus[0])
			}
			if !tc.wantCandidate && component(t, r.Token, "plateau").Strength != 0 {
				t.Fatal("negative platform strength")
			}
		})
	}
	ss := fixture([]int64{512, 1024}, 3, func(int64, int) int64 { return 256 })
	limit := int64(256)
	r, err := Analyze(Input{OrganizationID: 1, RunID: 2, Samples: ss, DeclaredModelOutputLimit: &limit})
	if err != nil || r.Token.Strength == nil || *r.Token.Strength > 39 || !slices.Contains(r.Token.Limitations, "MI_DECLARED_MODEL_OUTPUT_LIMIT") {
		t.Fatal("declared model limit not downgraded")
	}
	ss = fixture([]int64{64, 96, 128}, 3, func(int64, int) int64 { return 10 })
	r = analyzeTest(t, ss)
	if len(r.Plateaus) != 1 || r.Plateaus[0].Low.RequestedMaxTokens != 64 || r.Plateaus[0].High.RequestedMaxTokens != 96 {
		t.Fatal("nonadjacent tiers used to invent 1.5 ratio")
	}
}

func TestMissingPairedBlocksAndInsufficientHighSamples(t *testing.T) {
	ss := fixture([]int64{512, 1024}, 3, func(int64, int) int64 { return 256 })
	ss[5].GroupID = "unpaired-new"
	r := analyzeTest(t, ss)
	if !slices.Contains(r.Plateaus[0].Limitations, "MI_LADDER_PAIRS_INCOMPLETE") || r.Plateaus[0].Strength > 39 {
		t.Fatal("silently unpaired missing matched blocks")
	}
	ss = fixture([]int64{512, 1024}, 2, func(int64, int) int64 { return 256 })
	r = analyzeTest(t, ss)
	if r.Plateaus[0].Strength > 39 || !slices.Contains(r.Plateaus[0].Limitations, "MI_HIGH_TIER_SAMPLES_INSUFFICIENT") {
		t.Fatal("too few high tier samples")
	}
	// Different non-overlapping groups are genuinely unpaired, not missing
	// paired observations. Unequal block sizes remain bounded and deterministic.
	ss = fixture([]int64{512, 1024}, 6, func(int64, int) int64 { return 256 })
	for i := 6; i < len(ss); i++ {
		ss[i].GroupID = "high-" + ss[i].GroupID
	}
	r = analyzeTest(t, ss)
	if r.Plateaus[0].DifferenceCI.Paired || !r.Plateaus[0].DifferenceCI.Available {
		t.Fatal("unpaired tier design not analyzed")
	}
}

func TestUsageSameDirectionAndMissingRenormalization(t *testing.T) {
	makeUsage := func(n int, errorValue float64) []Sample {
		ss := []Sample{}
		for i := 0; i < n; i++ {
			s := sample(int64(i+1), int64(512+(i%2)*512), 256)
			s.Usage = tokenizer.UsageComparison{Available: true, EligibleForAggregate: true, RelativeError: errorValue, Direction: 1}
			ss = append(ss, s)
		}
		return ss
	}
	for _, tc := range []struct {
		n         int
		err       float64
		candidate bool
	}{{6, 0.16, true}, {5, 0.9, false}, {6, 0.15, false}, {6, 0.05, false}} {
		r := analyzeTest(t, makeUsage(tc.n, tc.err))
		if r.Usage.Candidate != tc.candidate {
			t.Fatalf("n=%d error=%f: %+v", tc.n, tc.err, r.Usage)
		}
	}
	ss := makeUsage(6, 0.5)
	for i := 0; i < 3; i++ {
		ss[i].Usage.Direction = -1
	}
	if analyzeTest(t, ss).Usage.Candidate {
		t.Fatal("opposite errors mistaken for same direction")
	}
	ss = makeUsage(30, 0)
	for i := 0; i < 6; i++ {
		ss[i].Usage.RelativeError = 0.9
	}
	if analyzeTest(t, ss).Usage.Candidate {
		t.Fatal("normal samples omitted from denominator")
	}
	ss = makeUsage(6, 0.4)
	for i := range ss {
		ss[i].Local.Quality = tokenizer.Heuristic
		ss[i].Usage.EligibleForAggregate = false
	}
	r := analyzeTest(t, ss)
	if !r.Usage.Candidate || r.Usage.Strength > 39 {
		t.Fatal("heuristic usage not capped")
	}
	for i := range ss {
		ss[i].Usage.RelativeError = 0.3
	}
	if analyzeTest(t, ss).Usage.Candidate {
		t.Fatal("heuristic enlarged threshold ignored")
	}
	ss = makeUsage(6, 0.9)
	for i := range ss {
		ss[i].ReasoningUnseparated = true
	}
	r = analyzeTest(t, ss)
	if r.Usage.Available || r.Usage.SkippedReasoning != 6 || component(t, r.Token, "usage").EffectiveWeight != 0 {
		t.Fatal("hidden reasoning compared as visible")
	}
	ss = fixture([]int64{512, 1024}, 6, func(int64, int) int64 { return 256 })
	r = analyzeTest(t, ss)
	if component(t, r.Token, "usage").Available || math.Abs(component(t, r.Token, "plateau").EffectiveWeight-0.5625) > 1e-10 {
		t.Fatalf("missing usage treated as zero: %+v", r.Token)
	}
	for i := range ss {
		ss[i].Usage = tokenizer.UsageComparison{Available: true, EligibleForAggregate: true}
	}
	normal := analyzeTest(t, ss)
	if *normal.Token.Strength >= *r.Token.Strength || component(t, normal.Token, "usage").EffectiveWeight != 0.2 {
		t.Fatal("available normal usage removed from denominator")
	}
}

func TestStreamPairsAndNoInflationFromSharedNonce(t *testing.T) {
	ss := fixture([]int64{512, 1024}, 6, func(tier int64, rep int) int64 {
		if rep%2 == 1 {
			return 128
		}
		return tier
	})
	r := analyzeTest(t, ss)
	if !r.Stream.Candidate || r.Stream.Strength <= 39 || r.Stream.Pairs != 6 || r.Stream.DifferenceCI.Units != 3 || r.Stream.Tiers != 2 {
		t.Fatalf("paired stream effect: %+v", r.Stream)
	}
	for _, p := range r.Plateaus {
		if p.Candidate {
			t.Fatal("stream-only clipping became common platform")
		}
	}
	ss = ss[:len(ss)-1]
	r = analyzeTest(t, ss)
	if r.Stream.Unmatched != 1 || !r.Stream.Limited || r.Stream.Strength > 39 {
		t.Fatal("incomplete stream pairs ignored")
	}
	ss = fixture([]int64{512, 1024}, 6, func(int64, int) int64 { return 128 })
	seed := int64(42)
	ss[1].Seed = &seed
	r = analyzeTest(t, ss)
	if r.Stream.SeedMismatch != 1 {
		t.Fatal("paired different seeds")
	}
	ss = fixture([]int64{512, 1024}, 6, func(int64, int) int64 { return 128 })
	ss[2].GroupID = ss[0].GroupID
	r = analyzeTest(t, ss)
	if r.Stream.Ambiguous == 0 {
		t.Fatal("ambiguous repeated group silently paired")
	}
	ss = fixture([]int64{128, 256, 512, 1024}, 2, func(tier int64, rep int) int64 {
		if rep%2 == 1 {
			return 10
		}
		return tier
	})
	r = analyzeTest(t, ss)
	if r.Stream.DifferenceCI.Units != 1 || r.Stream.Strength > 39 {
		t.Fatal("same nonce four tiers inflated independence")
	}
	ss = fixture([]int64{512, 1024}, 6, func(tier int64, rep int) int64 {
		if rep%2 == 1 {
			return 128
		}
		return tier
	})
	for i := range ss {
		ss[i].Structure = structure.Features{Version: structure.Version, UTF8Valid: true, StructureComplete: true}
	}
	r = analyzeTest(t, ss)
	if !r.Stream.Candidate || r.Stream.Strength > 39 || !slices.Contains(r.Stream.Limitations, "MI_STREAM_VARIATION_ALTERNATIVE") {
		t.Fatal("natural mode variation treated as truncation")
	}
}

func TestFinalAttemptSelectionAndPartialResults(t *testing.T) {
	ss := fixture([]int64{512, 1024}, 3, func(int64, int) int64 { return 256 })
	old := ss[0]
	old.AttemptID = 99
	old.Validity = InvalidRetryable
	old.NetworkFailure = true
	ss = append(ss, old, ss[0])
	r := analyzeTest(t, ss)
	if r.IgnoredAttempts != 1 || r.DuplicateFinals != 1 || r.FinalSamples != 6 || r.ValidSamples != 6 || r.IndependentFamilies != 1 || r.NetworkErrorRate != 0 {
		t.Fatal("retry inflated logical evidence")
	}
	conflict := ss[0]
	conflict.AttemptNumber = 2
	if _, err := Analyze(Input{OrganizationID: 1, RunID: 2, Samples: append(ss, conflict)}); !errors.Is(err, ErrInput) {
		t.Fatal("conflicting final rows accepted")
	}
	ss = ss[1:6]
	ss = append(ss, old)
	r = analyzeTest(t, ss)
	if r.MissingFinals != 1 || !r.Partial || r.FinalSamples != 5 || *r.Token.Strength > 39 {
		t.Fatal("missing final fabricated")
	}
	ss = fixture([]int64{512}, 6, func(int64, int) int64 { return 256 })
	r = analyzeTest(t, ss)
	if !r.Token.Limited || *r.Token.Strength > 39 || !slices.Contains(r.Token.Limitations, "MI_SINGLE_TIER_LIMIT") {
		t.Fatal("single tier lacks cap")
	}
	s := sample(100, 1024, 1)
	s.Family = "self_report"
	s.SeriesID = testDigest("self-report")
	s.Validity = InvalidProtocol
	s.NetworkFailure = true
	r = analyzeTest(t, append(ss, s))
	if r.IndependentFamilies != 1 || r.ValidSamples != 6 || r.NetworkErrorRate != 0 || r.Partial {
		t.Fatal("self report nonzero weight")
	}
}

func TestResponseMissingSignalsNormalLengthAndNetworkAttribution(t *testing.T) {
	ss := fixture([]int64{512, 1024}, 6, func(tier int64, _ int) int64 { return tier })
	r := analyzeTest(t, ss)
	if component(t, r.Token, "termination").Strength != 0 || component(t, r.Response, "metadata_consistency").Strength != 0 {
		t.Fatal("normal LENGTH hard boundary falsely contradictory")
	}
	if component(t, r.Response, "fixed_suffix").Available || component(t, r.Response, "protocol_anomaly").Available {
		t.Fatal("unchecked signal treated as normal")
	}
	for i := range ss {
		ss[i].ProtocolChecked = true
		ss[i].ProtocolAnomaly = true
	}
	r = analyzeTest(t, ss)
	if component(t, r.Response, "protocol_anomaly").Strength != 100 {
		t.Fatal("protocol aggregate absent")
	}
	for i := range ss {
		ss[i].Structure.NormalRequestedLimit = false
		ss[i].Structure.FinishReason = "UNKNOWN"
		ss[i].Structure.TerminationHints = nil
	}
	r = analyzeTest(t, ss)
	if component(t, r.Token, "termination").Strength != 0 {
		t.Fatal("hard truncation alone implies contradictory metadata")
	}
	for i := range ss {
		ss[i].Structure.HardTruncation = false
		ss[i].Structure.StructureComplete = true
		ss[i].SuffixChecked = true
		ss[i].SuffixFingerprint = testDigest("closed-suffix")
		if i%2 == 1 {
			ss[i].Family = "jsonl"
			ss[i].SeriesID = testDigest("jsonl/en-US/v1")
		}
	}
	r = analyzeTest(t, ss)
	if component(t, r.Response, "fixed_suffix").Strength != 100 {
		t.Fatal("stable suffix with independent families not detected")
	}
	for i := range ss {
		ss[i].Family = "sequence"
		ss[i].SeriesID = testDigest("sequence/en-US/v1")
	}
	r = analyzeTest(t, ss)
	if component(t, r.Response, "fixed_suffix").Strength > 39 {
		t.Fatal("suffix same-family evidence inflated")
	}
	ss = fixture([]int64{512, 1024}, 6, func(tier int64, _ int) int64 { return tier })
	for i := range ss {
		ss[i].Stream = true
		ss[i].GroupID = fmt.Sprintf("independent-%d", i)
		ss[i].Structure.TerminationHints = []string{"MI_STREAM_TERMINATOR_MISSING"}
	}
	r = analyzeTest(t, ss)
	if component(t, r.Response, "sse_termination").Strength != 100 {
		t.Fatal("normal LENGTH hid missing SSE terminator")
	}
	for i := 0; i < 3; i++ {
		s := sample(int64(100+i), 512, 0)
		s.NetworkFailure = true
		s.Validity = InvalidRetryable
		ss = append(ss, s)
	}
	r = analyzeTest(t, ss)
	if r.NetworkErrorRate != 0.2 || r.SSEAttributionFactor != 1 {
		t.Fatal("exact 20 percent boundary wrong")
	}
	s := sample(200, 512, 0)
	s.NetworkFailure = true
	s.Validity = InvalidRetryable
	ss = append(ss, s)
	r = analyzeTest(t, ss)
	if r.SSEAttributionFactor != 0.5 || component(t, r.Response, "sse_termination").Strength != 50 {
		t.Fatal("network attribution not halved")
	}
}

func TestValidationAndResourceLimits(t *testing.T) {
	base := sample(1, 512, 256)
	for _, change := range []func(*Sample){
		func(s *Sample) { s.SeriesID = "not-digest" }, func(s *Sample) { s.Usage.RelativeError = math.NaN() }, func(s *Sample) { s.Usage.RelativeError = math.Inf(1) }, func(s *Sample) { s.Local.Quality = "claimed-exact" }, func(s *Sample) { s.ProtocolAnomaly = true }, func(s *Sample) { s.SuffixFingerprint = testDigest("not-checked") }, func(s *Sample) { s.Structure.HardTruncation = true }, func(s *Sample) { s.Local.TokenizerID = strings.Repeat("x", 129) }, func(s *Sample) { s.Local.Tokens = nil }, func(s *Sample) { s.Validity = "invented" }, func(s *Sample) { s.AttemptNumber = 9 }, func(s *Sample) { s.Family = "made-up-probe" },
	} {
		s := base
		change(&s)
		if _, err := Analyze(Input{OrganizationID: 1, RunID: 2, Samples: []Sample{s}}); !errors.Is(err, ErrInput) {
			t.Fatalf("bad input accepted: %v", err)
		}
	}
	ss := []Sample{base, sample(2, 512, 256)}
	ss[1].Language = "zh-CN"
	if _, err := Analyze(Input{OrganizationID: 1, RunID: 2, Samples: ss}); !errors.Is(err, ErrInput) {
		t.Fatal("SeriesID conflates language")
	}
	ss = make([]Sample, MaxObservations+1)
	if _, err := Analyze(Input{OrganizationID: 1, RunID: 2, Samples: ss}); !errors.Is(err, ErrLimit) {
		t.Fatal("observations not bounded")
	}
	ss = nil
	for i := 0; i <= MaxSamples; i++ {
		ss = append(ss, sample(int64(i+1), 512, 256))
	}
	if _, err := Analyze(Input{OrganizationID: 1, RunID: 2, Samples: ss}); !errors.Is(err, ErrLimit) {
		t.Fatal("logical samples not bounded")
	}
	ss = nil
	for i := 0; i <= MaxSeries; i++ {
		s := sample(int64(i+1), 512, 256)
		s.SeriesID = testDigest(fmt.Sprintf("series-%d", i))
		ss = append(ss, s)
	}
	if _, err := Analyze(Input{OrganizationID: 1, RunID: 2, Samples: ss}); !errors.Is(err, ErrLimit) {
		t.Fatal("series not bounded")
	}
	r, err := Analyze(Input{OrganizationID: 1, RunID: 2})
	if err != nil || r.Token.Strength != nil || r.Response.Strength != nil || !r.Token.Limited {
		t.Fatal("empty data fabricated normal risk")
	}
	ss = fixture([]int64{512, 1024}, 3, func(int64, int) int64 { return 256 })
	for i := range ss {
		ss[i].Structure.Warnings = []string{"MI_TERMINATION_NOT_APPLICABLE"}
	}
	r = analyzeTest(t, ss)
	if len(r.Plateaus) != 0 || r.Usage.Available || component(t, r.Token, "termination").Strength != 0 {
		t.Fatal("refusal/filter counted as token platform")
	}
	if Version != "1.0.0-dev.1" || RulesHash() != "d3db37d195acc4f77b63888d86731debfba2178117d665960d3ff40f48e11f94" {
		t.Fatal("development version not frozen")
	}
	t.Logf("frozen development rules hash: %s", RulesHash())
}
