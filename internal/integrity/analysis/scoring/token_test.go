package scoring

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"reflect"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/structure"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func testHash(s string) string { hash := sha256.Sum256([]byte(s)); return hex.EncodeToString(hash[:]) }

// Synthetic derived features follow the standard 24 ladder + 36 behavior
// layout. tokenrisk's separate actual-standard test also tokenizes real clipped
// text; this test checks the scoring boundary cannot reinterpret its 41 result.
func tokenInput(t testing.TB, mode string, oneTier bool) Input {
	t.Helper()
	in := Input{}
	rows := []tokenrisk.Sample{}
	add := func(family string, tier int64, repeat int) {
		id := int64(len(rows) + 1)
		output := tier
		if mode != "healthy" {
			output = min(tier, 256)
		}
		quality := tokenizer.Exact
		if mode == "heuristic" {
			quality = tokenizer.Heuristic
		}
		s := tokenrisk.Sample{ID: id, AttemptID: id, FinalAttemptID: id, AttemptNumber: 1, Validity: tokenrisk.Valid, Family: family, Language: "en-US", TemplateID: family + ".en-us.1", TemplateVersion: "1.0.0", Variant: 1, ConditionID: fmt.Sprintf("%s-%d", family, tier), SeriesID: testHash(family), GroupID: fmt.Sprintf("%s-cluster-%d", family, repeat/2), RequestedMaxTokens: tier, Repetition: repeat, Stream: repeat == 1,
			Local:     tokenizer.Estimate{Tokens: &output, Quality: quality, TokenizerID: "cl100k_base", TokenizerVersion: "1.0.0", Scope: "visible_output"},
			Structure: structure.Features{Version: structure.Version, UTF8Valid: true, HardTruncation: true, FinishReason: "LENGTH"}, ProtocolChecked: true,
			Usage: tokenizer.UsageComparison{EligibleForAggregate: true, Available: true, RelativeError: 0, Direction: 0, Band: "consistent"}}
		if output == tier {
			s.Structure.NormalRequestedLimit = true
		} else {
			s.Structure.TerminationHints = []string{"MI_LENGTH_FAR_BELOW_REQUEST"}
		}
		if family == "format" {
			s.Structure.HardTruncation = false
			s.Structure.StructureComplete = true
			s.Structure.FinishReason = "STOP"
			s.Structure.NormalRequestedLimit = false
			s.Structure.TerminationHints = nil
		}
		rows = append(rows, s)
		in.Samples = append(in.Samples, Observation{SampleID: fmt.Sprint(id), Family: family, Language: s.Language, TemplateID: s.TemplateID, ClusterID: s.GroupID, Included: true, Protocol: normalProtocol(), Tokenizer: quality})
	}
	tiers := []int64{64, 128, 256, 512}
	if oneTier {
		tiers = []int64{512}
	}
	for _, family := range []string{"sequence", "jsonl"} {
		for _, tier := range tiers {
			for repeat := 0; repeat < 3; repeat++ {
				add(family, tier, repeat)
			}
		}
	}
	if !oneTier {
		for repeat := 0; repeat < 36; repeat++ {
			add("format", 64, repeat)
		}
	}
	in.ExpectedSamples = len(rows)
	out, err := tokenrisk.Analyze(tokenrisk.Input{OrganizationID: 1, RunID: 2, ExpectedSamples: len(rows), Samples: rows})
	if err != nil {
		t.Fatal(err)
	}
	in.Tokens = &out
	return in
}

func TestToken41IsPreservedAndDoesNotGrantStatisticalEvidence(t *testing.T) {
	in := tokenInput(t, "capped256", false)
	if len(in.Samples) != 60 || in.Tokens.Token.Strength == nil || math.Abs(*in.Tokens.Token.Strength-41) > 1e-9 {
		t.Fatalf("fixture token=%+v", in.Tokens.Token)
	}
	before := *in.Tokens.Token.Strength
	out, err := Analyze(in)
	if err != nil {
		t.Fatal(err)
	}
	if *out.Token.Score != before || *out.Response.Score != *in.Tokens.Response.Strength || out.EvidenceGrade == "A" || out.EvidenceGrade == "B" || out.Confidence.Score >= 75 {
		t.Fatal("upstream score or grade was promoted")
	}
	for i, c := range in.Tokens.Token.Components {
		if out.Token.Components[i].EffectiveWeight != c.EffectiveWeight || out.Token.Components[i].Weight != c.Weight || c.Available && *out.Token.Components[i].Score != c.Strength {
			t.Fatal("token weights changed")
		}
	}
	*out.Token.Score = 100
	if *in.Tokens.Token.Strength != before {
		t.Fatal("aliased token score")
	}
	t.Logf("standard-shaped 60 sample fixed-256 Token %.0f retained; no calibration claim", before)
}

func TestTokenHealthyHeuristicOneTierAndInvalidAggregate(t *testing.T) {
	for _, tc := range []struct {
		mode string
		one  bool
	}{{"healthy", false}, {"heuristic", false}, {"capped256", true}} {
		t.Run(fmt.Sprintf("%s-one-%t", tc.mode, tc.one), func(t *testing.T) {
			in := tokenInput(t, tc.mode, tc.one)
			out, err := Analyze(in)
			if err != nil {
				t.Fatal(err)
			}
			if *out.Token.Score != *in.Tokens.Token.Strength || !reflect.DeepEqual(out.Token.Limitations, in.Tokens.Token.Limitations) || out.Confidence.Score >= 75 {
				t.Fatal("upstream cap/limits altered")
			}
			if (tc.one || tc.mode == "heuristic") && *out.Token.Score > 39 {
				t.Fatal("upstream 39 cap lost")
			}
			if tc.mode == "healthy" && (*out.Token.Score != 0 || *out.Response.Score != 0) {
				t.Fatal("normal LENGTH became anomaly")
			}
		})
	}
}
