package features

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func TestSeriesExcludesVaryingFactorsAndClustersSharedNonce(t *testing.T) {
	f := newFixture(t, nil)
	batch, err := f.builder.Build(f.input)
	if err != nil {
		t.Fatal(err)
	}
	features := batch.Features().Samples
	series := map[string]string{}
	clusters := map[string]string{}
	for i, s := range f.manifest.Samples {
		if s.Family == "sequence" || s.Family == "jsonl" {
			if hash, ok := series[s.TemplateID]; ok && hash != features[i].SeriesHash {
				t.Fatal("stream/cap/nonce/repetition fragmented fixed series")
			}
			series[s.TemplateID] = features[i].SeriesHash
		}
		if hash, ok := clusters[s.GroupID]; ok && hash != features[i].ClusterHash {
			t.Fatal("shared-nonce cluster lost")
		}
		clusters[s.GroupID] = features[i].ClusterHash
	}
	s := f.manifest.Samples[0]
	request := f.input.Samples[0].RequestPlan.Request
	local := *features[0].Local
	base := seriesHash(f.manifest, s, request, local)
	s.Variables.Nonce = "changed-nonce"
	s.GroupID = "changed-group"
	s.Stream = !s.Stream
	s.MaxOutputTokens *= 2
	s.Repetition++
	request.Stream = !request.Stream
	request.MaxOutputTokens *= 2
	seed := int64(777)
	request.Seed = &seed
	request.Messages = nil
	if seriesHash(f.manifest, s, request, local) != base {
		t.Fatal("varying factors entered series identity")
	}
	temperature := 0.75
	request.Temperature = &temperature
	if seriesHash(f.manifest, s, request, local) == base {
		t.Fatal("temperature omitted from fixed series identity")
	}
	request = f.input.Samples[0].RequestPlan.Request
	local.TokenizerID = "different-encoding"
	if seriesHash(f.manifest, s, request, local) == base {
		t.Fatal("tokenizer omitted from fixed series identity")
	}
	local = *features[0].Local
	s.Language = "other"
	if seriesHash(f.manifest, s, request, local) == base {
		t.Fatal("language omitted from fixed series identity")
	}
}

func TestReasoningModelAndUsageUnknownDoNotBecomeZeroMismatch(t *testing.T) {
	for _, separated := range []bool{false, true} {
		name := "unseparated"
		if separated {
			name = "separated"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, func(o *generator.Options) { o.ReasoningModel = true })
			if separated {
				for i := range f.input.Samples {
					r := &f.input.Samples[i].Attempts[0].Evidence.response
					reasoning := int64(5)
					completion := *r.CompletionTokens + reasoning
					r.CompletionTokens = &completion
					r.ReasoningTokens = &reasoning
				}
			}
			batch, err := f.builder.Build(f.input)
			if err != nil {
				t.Fatal(err)
			}
			for _, sample := range batch.Features().Samples {
				if separated {
					if !sample.Usage.Available || !sample.Usage.ReasoningSeparated || sample.Usage.RelativeError == nil || *sample.Usage.RelativeError != 0 {
						t.Fatal("reasoning not separated")
					}
				} else {
					if sample.Usage.Available || sample.Usage.RelativeError != nil || !slices.Contains(sample.Limitations, "MI_REASONING_UNSEPARATED") || sample.Structure.LengthComparisonAvailable {
						t.Fatal("hidden reasoning fabricated visible mismatch")
					}
				}
			}
		})
	}
	f := newFixture(t, nil)
	r := &f.input.Samples[0].Attempts[0].Evidence.response
	r.CompletionTokens = nil
	r.PromptTokens = nil
	r.TotalTokens = nil
	r.ModelReported = ""
	batch, err := f.builder.Build(f.input)
	if err != nil {
		t.Fatal(err)
	}
	s := batch.Features().Samples[0]
	if s.Usage.Available || s.Usage.ReportedCompletion != nil || s.Usage.RelativeError != nil || s.Protocol.ModelEcho != "unavailable" {
		t.Fatal("missing usage/model echo treated as normal zero")
	}
}

func TestProtocolAndParserWarningsAreDerivedClosedStates(t *testing.T) {
	for _, kind := range []string{"partial-stream", "wrong-type", "bad-choice", "negative-usage", "unknown-finish", "model-differs", "refusal", "safety-body", "stream-without-done"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, nil)
			index := 0
			if kind == "partial-stream" || kind == "stream-without-done" {
				for i, s := range f.manifest.Samples {
					if s.Stream {
						index = i
						break
					}
				}
			}
			r := &f.input.Samples[index].Attempts[0].Evidence.response
			switch kind {
			case "partial-stream":
				r.ParseStatus = "partial"
				r.EndCause = "eof"
				r.StreamTerminated = false
				r.ParseWarnings = []string{"STREAM_EOF_BEFORE_DONE"}
			case "wrong-type":
				r.ContentType = "text/html"
			case "bad-choice":
				r.ChoiceCount = 2
			case "negative-usage":
				value := int64(-1)
				r.CompletionTokens = &value
			case "unknown-finish":
				r.FinishReason = "raw-finish-canary"
			case "model-differs":
				r.ModelReported = "gpt-4"
			case "refusal":
				r.Refusal = true
			case "safety-body":
				r.EndCause = "client_safety_limit"
			case "stream-without-done":
				r.StreamTerminated = false
			}
			batch, err := f.builder.Build(f.input)
			if err != nil {
				t.Fatal(err)
			}
			s := batch.Features().Samples[index]
			switch kind {
			case "partial-stream":
				if !s.Included || s.Validity != "VALID_WITH_WARNING" || !s.Protocol.Partial || s.Protocol.StreamTerminated || s.Protocol.State != "valid_with_warning" {
					t.Fatal("valid partial stream discarded or marked complete")
				}
			case "unknown-finish":
				if s.Structure.FinishReason != "UNKNOWN" {
					t.Fatal("untrusted finish escaped normalization")
				}
			case "model-differs":
				if s.Protocol.ModelEcho != "differs" || s.SeriesHash == batch.Features().Samples[(index+1)%60].SeriesHash {
					t.Fatal("reported model identity lost")
				}
			default:
				if s.Included || s.Validity == "VALID" || s.Validity == "VALID_WITH_WARNING" {
					t.Fatal("invalid protocol/safety/refusal entered statistics")
				}
			}
		})
	}
}

func TestResponseResourceLimitsAreExplicit(t *testing.T) {
	base := domain.NormalizedResponse{Content: "OK", DurationMs: 10}
	for _, mutate := range []func(*domain.NormalizedResponse){
		func(r *domain.NormalizedResponse) { r.Content = strings.Repeat("x", MaxResponseBytes+1) },
		func(r *domain.NormalizedResponse) { r.Content = strings.Repeat("\x00", MaxResponseBytes/2) },
		func(r *domain.NormalizedResponse) { r.Content = string([]byte{0xff}) },
		func(r *domain.NormalizedResponse) { r.ParseWarnings = make([]string, 33) },
		func(r *domain.NormalizedResponse) { r.DurationMs = -1 },
		func(r *domain.NormalizedResponse) { r.FirstTokenMs = new(int64); *r.FirstTokenMs = 99 },
	} {
		r := base
		mutate(&r)
		if _, err := NewEvidence(EvidenceScope{}, r); !errors.Is(err, ErrLimit) {
			t.Fatal("unbounded/invalid evidence accepted")
		}
	}
	f := newFixture(t, nil)
	for i := 0; i < 20; i++ {
		r := &f.input.Samples[i].Attempts[0].Evidence.response
		r.Content = strings.Repeat("x\n", 250000)
	}
	if _, err := f.builder.Build(f.input); !errors.Is(err, ErrLimit) {
		t.Fatal("aggregate byte budget not enforced", err)
	}
	f = newFixture(t, nil)
	f.input.Samples[0].Attempts[0].Evidence.response.Content = strings.Repeat("x", 65<<10)
	batch, err := f.builder.Build(f.input)
	if err != nil {
		t.Fatal(err)
	}
	s := batch.Features().Samples[0]
	if s.Included || s.Validity != "INVALID_SAFETY_LIMIT" || !slices.Contains(s.Limitations, "MI_FEATURE_STRUCTURE_LIMIT") {
		t.Fatal("structural resource stop became a valid zero")
	}
}

func TestOfflineOnlyAndMissingConfiguration(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("missing infrastructure accepted")
	}
	var b *Builder
	if _, err := b.Build(Input{}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("nil builder accepted")
	}
	if _, err := (noNetwork{}).Do(nil); !errors.Is(err, ErrConfiguration) {
		t.Fatal("analysis permits network")
	}
	f := newFixture(t, nil)
	// Analysis only reconstructs the already-signed wire body. A current network
	// transport configuration is never needed or invoked by this pure package.
	if _, err := f.builder.verifier.ExecutionPlan(f.input.Run.Plan.Manifest, f.input.Run.Plan.ManifestHash, 42); err != nil {
		t.Fatal(err)
	}
	zero := &tokenizer.Engine{}
	if _, err := New(Config{Verifier: f.builder.verifier, Tokenizer: zero}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("unverified tokenizer accepted")
	}
}

func TestBehaviorLimitAndCustomContractCannotMasqueradeAsApproval(t *testing.T) {
	f := newFixture(t, nil)
	index := 0
	for i, s := range f.manifest.Samples {
		if s.Family == "format" && s.Variant == 1 {
			index = i
			break
		}
	}
	f.input.Samples[index].Attempts[0].Evidence.response.Content = strings.Repeat(strings.Repeat("x", 198)+".\n", 400)
	batch, err := f.builder.Build(f.input)
	if err != nil {
		t.Fatal(err)
	}
	s := batch.Features().Samples[index]
	if !s.Included || s.Local == nil || s.Structure == nil || s.Behavior != nil || !slices.Contains(s.Limitations, "MI_FEATURE_BEHAVIOR_LIMIT") {
		t.Fatal("behavior limit erased independent features or became valid behavior zero")
	}
	custom := templates.Builtin()
	custom.Version = "1.0.1-dev.1"
	for i := range custom.Templates {
		custom.Templates[i].Version = custom.Version
		custom.Templates[i].Prompt += " Fixed synthetic variation."
	}
	f = newFixture(t, nil, custom)
	batch, err = f.builder.Build(f.input)
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range batch.Features().Samples {
		if sample.Behavior != nil || !slices.Contains(sample.Limitations, "MI_FEATURE_CONTRACT_UNSUPPORTED") {
			t.Fatal("custom artifact inherited builtin semantic approval")
		}
	}
}
