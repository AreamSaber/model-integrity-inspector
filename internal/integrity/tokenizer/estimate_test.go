package tokenizer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"

	tiktoken "github.com/tiktoken-go/tokenizer"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestBuiltinOfflineVocabularyAndCanonicalIntegrity(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	e := testEngine(t)
	if e.Hash() != BuiltinHash || e.Version() != BuiltinVersion {
		t.Fatal("wrong frozen bundle")
	}
	for _, bad := range [][]byte{nil, append(append([]byte{}, builtinBytes...), '\n'), bytes.Replace(builtinBytes, []byte("gpt-4o"), []byte("unsafe"), 1)} {
		if _, err := Load(bad, BuiltinHash); !errors.Is(err, ErrBundle) {
			t.Fatal("modified artifact accepted")
		}
		sum := sha256.Sum256(bad)
		if _, err := Load(bad, hex.EncodeToString(sum[:])); !errors.Is(err, ErrBundle) {
			t.Fatal("self-declared digest accepted")
		}
	}
	codec, err := tiktoken.Get(tiktoken.Cl100kBase)
	if err != nil {
		t.Fatal(err)
	}
	badArtifact := e.bundle.Encodings[0]
	badArtifact.SHA256 = strings.Repeat("0", 64)
	if verifyVocabulary(codec, badArtifact) == nil {
		t.Fatal("wrong vocabulary digest accepted")
	}
}

func TestCountsMatchPublishedReferenceVectors(t *testing.T) {
	e := testEngine(t)
	// Synthetic strings/short vectors published by OpenAI's counting cookbook.
	cases := []struct {
		text  string
		cl, o int64
	}{
		{"", 0, 0}, {"hello world", 2, 2}, {"antidisestablishmentarianism", 6, 6},
		{"2 + 2 = 4", 7, 7}, {"お誕生日おめでとう", 9, 8},
		{"\x00\x01\x7f", 3, 3}, {"\r\n\t\r\n\t", 2, 2}, {"\n \n\n", 2, 1},
	}
	for i, test := range cases {
		for _, variant := range []struct {
			model string
			want  int64
		}{{"gpt-4", test.cl}, {"gpt-4o", test.o}} {
			got, err := e.CountOutput(test.text, Selection{RequestedModel: variant.model})
			if err != nil || got.Tokens == nil || *got.Tokens != variant.want || got.Quality != Exact || got.BudgetSafetyApplied {
				t.Fatalf("vector %d failed for %s: %+v %v", i, variant.model, got, err)
			}
		}
	}
}

func TestSelectionPriorityAndQualityAreRegistryOwned(t *testing.T) {
	e := testEngine(t)
	cases := []struct {
		s       Selection
		id, by  string
		quality Quality
	}{
		{Selection{ReportedModel: "gpt-4o", RequestedModel: "gpt-4"}, "o200k_base", "reported_model", Exact},
		{Selection{ReportedModel: "gpt-4o-unverified-suffix", RequestedModel: "gpt-4"}, "o200k_base", "reported_model", Compatible},
		{Selection{ReportedModel: "unknown", RequestedModel: "gpt-4"}, "cl100k_base", "requested_model", Exact},
		{Selection{ReportedModel: "unknown", RequestedModel: "deployment-alias", StandardModel: "gpt-4o"}, "o200k_base", "standard_model", Compatible},
		{Selection{ReportedModel: "gpt-oss-120b"}, "unicode-byte-heuristic", "heuristic", Heuristic},
		{Selection{RequestedModel: "unregistered-exact-tokenizer"}, "unicode-byte-heuristic", "heuristic", Heuristic},
	}
	for i, test := range cases {
		got, err := e.CountOutput("short synthetic output", test.s)
		if err != nil || got.TokenizerID != test.id || got.SelectedBy != test.by || got.Quality != test.quality {
			t.Fatalf("selection %d: %+v %v", i, got, err)
		}
		if got.Quality != Exact && (!got.BudgetSafetyApplied || got.BudgetTokens < ceilSafety(*got.Tokens)) {
			t.Fatal("uncertain count lacked reserve")
		}
	}
}

func TestInputFramingIsEstimatedAndBudgetIsRoundedUp(t *testing.T) {
	e := testEngine(t)
	r := domain.NormalizedRequest{Model: "gpt-4o", Messages: []domain.NormalizedMessage{{Role: "user", Content: "hello world"}}}
	got, err := e.EstimateInput(r)
	if err != nil || got.Tokens == nil || *got.Tokens != 10 || got.Quality != Compatible || got.BudgetTokens != 13 || !got.BudgetSafetyApplied || !contains(got.Warnings, "MI_INPUT_FRAMING_ESTIMATED") {
		t.Fatalf("framing: %+v %v", got, err)
	}
	r.Model = "unknown-deployment"
	got, err = e.EstimateInput(r)
	if err != nil || got.Quality != Heuristic || got.BudgetTokens < int64(len("userhello world")) {
		t.Fatal("heuristic input reserve not conservative")
	}
	r.Model = "gpt-4o"
	for _, bad := range []domain.NormalizedRequest{
		{Model: "gpt-4o"},
		{Model: "gpt-4o", Messages: []domain.NormalizedMessage{{Role: "tool", Content: "ignored prompt"}}},
		{Model: "gpt-4o", Messages: r.Messages, ExtraAllowedParams: map[string]any{"tools": []any{}}},
		{Model: "gpt-4o", Messages: r.Messages, ExtraAllowedParams: map[string]any{"presence_penalty": math.NaN()}},
		{Model: "gpt-4o", Messages: []domain.NormalizedMessage{{Role: "user", Content: string([]byte{0xff})}}},
	} {
		got, err = e.EstimateInput(bad)
		if err == nil || got.Tokens != nil || got.Quality != Unavailable {
			t.Fatal("invalid input produced usable budget")
		}
	}
}

func TestResourceLimitsDowngradeWithoutPartialExactCounts(t *testing.T) {
	e := testEngine(t)
	selection := Selection{RequestedModel: "gpt-4o"}
	for _, value := range []string{strings.Repeat("a", maxBPESpan+1), strings.Repeat(" ", maxBPESpan+1), strings.Repeat("abcd ", MaxBPEBytes/5+1)} {
		got, err := e.CountOutput(value, selection)
		if err != nil || got.Quality != Heuristic || !contains(got.Warnings, "MI_TOKENIZER_COMPLEXITY_FALLBACK") || got.BudgetTokens < ceilSafety(int64(len(value))) {
			t.Fatal("unsafe BPE work did not downgrade")
		}
	}
	for _, test := range []struct {
		text string
		want error
	}{{strings.Repeat("a", MaxTextBytes+1), ErrLimit}, {string([]byte{0xe4, 0xb8}), ErrInput}} {
		got, err := e.CountOutput(test.text, selection)
		if !errors.Is(err, test.want) || got.Quality != Unavailable || got.Tokens != nil {
			t.Fatal("unavailable count fabricated a number")
		}
	}
}

func TestConcurrentCountsDoNotMutatePublishedEngine(t *testing.T) {
	e := testEngine(t)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			for range 20 {
				got, err := e.CountOutput("hello world", Selection{RequestedModel: "gpt-4o"})
				if err != nil || got.Tokens == nil || *got.Tokens != 2 || got.Quality != Exact {
					t.Error("concurrent count failed")
				}
				got.Warnings = append(got.Warnings, "caller-mutation")
			}
		})
	}
	wg.Wait()
	got, err := e.CountOutput("hello world", Selection{RequestedModel: "gpt-4o"})
	if err != nil || *got.Tokens != 2 || contains(got.Warnings, "caller-mutation") {
		t.Fatal("caller mutated engine")
	}
	data, err := json.Marshal(got)
	if err != nil || bytes.Contains(data, []byte("hello world")) {
		t.Fatal("estimate leaked content")
	}
}

func TestUsageEvidenceAndReasoningSeparation(t *testing.T) {
	count := int64(100)
	local := Estimate{Tokens: &count, Quality: Exact, Scope: "visible_output"}
	for _, test := range []struct {
		reported  int64
		band      string
		direction int
	}{{100, "normal", 0}, {105, "normal", 1}, {106, "warning", 1}, {115, "warning", 1}, {116, "mismatch", 1}, {60, "mismatch", -1}} {
		got := CompareUsage(domain.NormalizedResponse{CompletionTokens: &test.reported}, local, false)
		if !got.Available || got.Band != test.band || got.Direction != test.direction || !got.EligibleForAggregate {
			t.Fatalf("usage comparison: %+v", got)
		}
	}
	completion, reasoning := int64(160), int64(60)
	got := CompareUsage(domain.NormalizedResponse{CompletionTokens: &completion, ReasoningTokens: &reasoning}, local, true)
	if !got.Available || got.Band != "normal" || !got.ReasoningSeparated {
		t.Fatal("reasoning was compared as visible output")
	}
	if got := CompareUsage(domain.NormalizedResponse{CompletionTokens: &completion}, local, true); got.Available || got.Warning != "MI_REASONING_UNSEPARATED" {
		t.Fatal("unknown reasoning did not skip")
	}
	reasoning = completion + 1
	if got := CompareUsage(domain.NormalizedResponse{CompletionTokens: &completion, ReasoningTokens: &reasoning}, local, true); got.Available {
		t.Fatal("invalid usage accepted")
	}
	local.Quality = Heuristic
	if got := CompareUsage(domain.NormalizedResponse{CompletionTokens: &completion}, local, false); got.EligibleForAggregate || got.EvidenceCeiling != "C" {
		t.Fatal("heuristic escalated evidence")
	}
	local.Scope = "input"
	if got := CompareUsage(domain.NormalizedResponse{CompletionTokens: &completion}, local, false); got.Available {
		t.Fatal("input estimate treated as completion")
	}
}

func FuzzVisibleTokenCountBounds(f *testing.F) {
	for _, text := range []string{"hello", "中文😀", "\x00\x01\x7f", "\r\n\t\r\n\t", "<|endoftext|>", string([]byte{0xff})} {
		f.Add(text, true)
	}
	f.Fuzz(func(t *testing.T, text string, modern bool) {
		model := "gpt-4"
		if modern {
			model = "gpt-4o"
		}
		result, err := testEngine(t).CountOutput(text, Selection{RequestedModel: model})
		if err == nil && (result.Tokens == nil || *result.Tokens < 0 || *result.Tokens > int64(len(text)) || (len(text) > 0 && *result.Tokens == 0)) {
			t.Fatal("invalid visible token count")
		}
		if err != nil && (result.Tokens != nil || result.Quality != Unavailable) {
			t.Fatal("failed tokenizer returned partial usable evidence")
		}
	})
}
