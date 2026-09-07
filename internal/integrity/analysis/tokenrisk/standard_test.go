package tokenrisk

import (
	"crypto/rand"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"

	codec "github.com/tiktoken-go/tokenizer"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/structure"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

// This uses the actual frozen compiler, offline tokenizer and structure engine.
// Only the upstream response is synthetic: it emits deterministic numbered
// units and clips the actual encoded response at a configured token budget.
// No network service, paid endpoint or acceptance dataset is involved.
func standardFixture(t testing.TB, mode string) []Sample {
	t.Helper()
	engine, err := tokenizer.NewBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal(err)
	}
	ring, err := secret.NewKeyRing("test", map[string][]byte{"test": key})
	if err != nil {
		t.Fatal(err)
	}
	data, hash, err := templates.Builtin().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	g, err := generator.New(data, hash, engine, ring)
	if err != nil {
		t.Fatal(err)
	}
	m, err := g.Generate(generator.Options{OrganizationID: 1,
		Target:  domain.ExecutionTarget{ID: 1, Version: 1, SecretID: 1, SecretVersion: 1, Model: "gpt-4o-2024-08-06", Endpoint: "https://example.com/v1", Protocol: "openai_chat", MaxOutputParameter: "max_tokens"},
		Package: "standard", Budget: domain.ExecutionBudget{MaxRequests: 150, MaxTokens: 1000000, TimeoutSeconds: 600},
		RuleVersion: Version, ScoringVersion: Version, ContextWindow: 128000, MaxOutputTokens: 4096, SupportsStream: true, SupportsSeed: true, Concurrency: 3, MaxRetries: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Samples) != 60 {
		t.Fatalf("standard schedule drift: %d", len(m.Samples))
	}
	encoding, err := codec.Get(codec.O200kBase)
	if err != nil {
		t.Fatal(err)
	}
	result := make([]Sample, 0, len(m.Samples))
	for _, manifest := range m.Samples {
		s := sample(int64(manifest.Ordinal+1), int64(manifest.MaxOutputTokens), 0)
		s.Family, s.Language, s.Variant = manifest.Family, manifest.Language, manifest.Variant
		s.TemplateID, s.TemplateVersion = manifest.TemplateID, manifest.TemplateVersion
		s.Repetition, s.GroupID, s.Seed, s.Stream = manifest.Repetition, manifest.GroupID, manifest.Seed, manifest.Stream
		s.ConditionID = manifest.ConditionID
		// Fixed task/settings identity deliberately excludes tier, stream mode
		// and nonce. Style/format/language semantics are retained.
		s.SeriesID = testDigest(fmt.Sprintf("%s/%s/%d/%s/%s/%s/model:gpt4o/temp:0", s.Family, s.Language, s.Variant, s.TemplateID, s.TemplateVersion, manifest.Variables.Style))
		s.ProtocolChecked = true
		output := "Complete."
		finish := "STOP"
		contract := structure.Contract{Kind: structure.Text}
		if ladder(s) {
			var body strings.Builder
			for n := 1; n <= 100; n++ {
				if s.Family == "jsonl" {
					fmt.Fprintf(&body, "{\"%s\":\"%s\",\"n\":%d}\n", manifest.Variables.Label, manifest.Variables.Nonce, n)
				} else {
					fmt.Fprintf(&body, "%s|%d\n", manifest.Variables.Nonce, n)
				}
			}
			ids, _, encodeErr := encoding.Encode(body.String())
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			budget := manifest.MaxOutputTokens
			if mode == "capped256" || (mode == "stream_only" && s.Stream) {
				budget = min(budget, 256)
			}
			if len(ids) <= budget {
				t.Fatal("synthetic task ended naturally before budget")
			}
			output, err = encoding.Decode(ids[:budget])
			if err != nil {
				t.Fatal(err)
			}
			finish = "LENGTH"
			contract = structure.Contract{Kind: structure.Sequence, SequencePrefix: manifest.Variables.Nonce, FirstNumber: 1, ExpectedUnits: int64(manifest.Variables.Count)}
			if s.Family == "jsonl" {
				contract.Kind = structure.JSONL
				contract.JSONNumberKey = "n"
			}
		}
		s.Local, err = engine.CountOutput(output, tokenizer.Selection{RequestedModel: m.Options.Target.Model})
		if err != nil || (s.Local.Quality != tokenizer.Exact && s.Local.Quality != tokenizer.Compatible) || s.Local.Tokens == nil {
			t.Fatalf("actual local tokenizer failed: %v", err)
		}
		if ladder(s) {
			expected := manifest.MaxOutputTokens
			if mode == "capped256" || (mode == "stream_only" && s.Stream) {
				expected = min(expected, 256)
			}
			if *s.Local.Tokens != int64(expected) {
				t.Fatalf("synthetic clipping drift: count=%d budget=%d", *s.Local.Tokens, expected)
			}
		}
		s.Structure, err = structure.Analyze(structure.Input{Content: output, Contract: contract, FinishReason: finish, RequestedMaxTokens: s.RequestedMaxTokens, LocalCompletionTokens: s.Local.Tokens, TokenizerQuality: s.Local.Quality, Stream: s.Stream, StreamTerminated: true})
		if err != nil {
			t.Fatal(err)
		}
		// Honest visible Usage remains a checked negative, not missing. A
		// capped proxy need not forge Usage to have a platform feature.
		s.Usage = tokenizer.CompareUsage(domain.NormalizedResponse{CompletionTokens: s.Local.Tokens}, s.Local, false)
		result = append(result, s)
	}
	return result
}

func TestActualStandard60SamplesFixed256Proxy(t *testing.T) {
	r := analyzeTest(t, standardFixture(t, "capped256"))
	hitFamilies := map[string]bool{}
	for _, p := range r.Plateaus {
		if p.Low.RequestedMaxTokens == 256 && p.High.RequestedMaxTokens == 512 {
			if !p.Candidate || p.Strength <= 39 || p.Low.Samples != 3 || p.High.Samples != 3 || p.Low.Median != 256 || p.High.Median != 256 || !p.LowModes.Comparable || !p.HighModes.Comparable {
				t.Fatalf("fixed-256 proxy lost: %+v", p)
			}
			if p.DifferenceCI.Units != 2 || !slices.Contains(p.Limitations, "MI_INDEPENDENT_GROUPS_INSUFFICIENT") {
				t.Fatal("shared nonce cluster count hidden")
			}
			hitFamilies[p.Family] = true
		}
	}
	if r.FinalSamples != 60 || r.ValidSamples != 60 || len(hitFamilies) != 2 || r.Calibrated || !r.Development {
		t.Fatal("standard plan coverage or development boundary wrong")
	}
	if r.Token.Strength == nil || math.Abs(*r.Token.Strength-41) > 1e-10 {
		t.Fatal("frozen weighting/ladder denominator drift")
	}
	t.Logf("synthetic fixed-256: candidate families=%d token strength=%.2f (development, uncalibrated)", len(hitFamilies), *r.Token.Strength)
}

func TestActualStandard60HealthyAndStreamOnlyControls(t *testing.T) {
	for _, mode := range []string{"healthy", "stream_only"} {
		t.Run(mode, func(t *testing.T) {
			r := analyzeTest(t, standardFixture(t, mode))
			for _, p := range r.Plateaus {
				if p.Candidate {
					t.Fatalf("%s fabricated common-mode platform: %+v", mode, p)
				}
			}
			if mode == "healthy" && (*r.Token.Strength != 0 || *r.Response.Strength != 0) {
				t.Fatalf("healthy response anomaly: token=%f response=%f", *r.Token.Strength, *r.Response.Strength)
			}
			if mode == "stream_only" {
				confounded := 0
				for _, p := range r.Plateaus {
					if p.High.RequestedMaxTokens == 512 && !p.HighModes.Comparable && slices.Contains(p.Limitations, "MI_STREAM_MODES_NOT_COMPARABLE") {
						confounded++
					}
				}
				if confounded != 2 {
					t.Fatal("stream-only response difference not exposed")
				}
			}
		})
	}
}
