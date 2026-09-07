package structure

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func requireFeatures(t *testing.T, input Input) Features {
	t.Helper()
	f, err := Analyze(input)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestJSONClosureAndSyntaxAreIndependent(t *testing.T) {
	cases := []struct {
		name, text              string
		parse, brackets, quoted State
		hard                    bool
	}{
		{"nested", `{"a":[1,{"b":"escaped \\\" ] }"}]}`, Complete, Complete, Complete, false},
		{"array", "[1,2,3]", Complete, Complete, Complete, false},
		{"string", `"scalar"`, Complete, Complete, Complete, false},
		{"number", "123", Complete, Complete, Complete, false},
		{"unfinished_object", `{"a":1`, Incomplete, Incomplete, Complete, true},
		{"unfinished_array", `[1,2,`, Incomplete, Incomplete, Complete, true},
		{"unfinished_string", `{"a":"unfinished`, Incomplete, Incomplete, Incomplete, true},
		{"escaped_final_slash", `{"a":"unfinished\`, Incomplete, Incomplete, Incomplete, true},
		{"trailing_comma", `{"a":1,}`, Invalid, Complete, Complete, false},
		{"extra_root", `{} {}`, Invalid, Complete, Complete, false},
		{"bracket_mismatch", `{]`, Invalid, Invalid, Complete, false},
		{"trailing_text", `{} explanation`, Invalid, Complete, Complete, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := requireFeatures(t, Input{Content: test.text, Contract: Contract{Kind: JSON}, FinishReason: "stop"})
			if f.Parse != test.parse || f.Brackets != test.brackets || f.Strings != test.quoted || f.HardTruncation != test.hard || f.StructureComplete != (test.parse == Complete) {
				t.Fatalf("incorrect JSON feature %+v", f)
			}
			if slices.Contains(f.TerminationHints, "MI_STOP_WITH_INCOMPLETE_STRUCTURE") != test.hard {
				t.Fatal("hard termination hint incorrect")
			}
		})
	}
}

func TestJSONLUnitsContinuityAndFinalUnit(t *testing.T) {
	cases := []struct {
		name, text             string
		parse, numbering, last State
		units                  int64
		hard                   bool
	}{
		{"complete", "{\"label\":\"canary\",\"n\":1}\n{\"label\":\"canary\",\"n\":2}\n", Complete, Complete, Complete, 2, false},
		{"crlf", "{\"n\":1}\r\n{\"n\":2}\r\n\r\n", Complete, Complete, Complete, 2, false},
		{"no_final_newline", "{\"n\":1}\n{\"n\":2}", Complete, Complete, Complete, 2, false},
		{"partial_last", "{\"n\":1}\n{\"n\":", Incomplete, Complete, Incomplete, 1, true},
		{"string_last", "{\"n\":1}\n{\"n\":2,\"s\":\"partial", Incomplete, Complete, Incomplete, 1, true},
		{"gap", "{\"n\":1}\n{\"n\":3}", Complete, Invalid, Complete, 2, false},
		{"repeat", "{\"n\":1}\n{\"n\":1}", Complete, Invalid, Complete, 2, false},
		{"string_number", "{\"n\":\"1\"}", Complete, Invalid, Complete, 1, false},
		{"duplicate_key", "{\"n\":99,\"n\":1}", Complete, Invalid, Complete, 1, false},
		{"missing_key", "{\"other\":1}", Complete, Invalid, Complete, 1, false},
		{"fraction", "{\"n\":1.0}", Complete, Invalid, Complete, 1, false},
		{"large_number", "{\"n\":9223372036854775808}", Complete, Invalid, Complete, 1, false},
		{"interior_blank", "{\"n\":1}\n\n{\"n\":2}", Invalid, Complete, Complete, 2, false},
		{"array_record", "[1,2]", Invalid, Complete, Invalid, 0, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := requireFeatures(t, Input{Content: test.text, Contract: Contract{Kind: JSONL, JSONNumberKey: "n", FirstNumber: 1, ExpectedUnits: 1000}, FinishReason: "stop"})
			if f.Parse != test.parse || f.Numbering != test.numbering || f.LastUnit != test.last || f.CompleteUnits != test.units || f.HardTruncation != test.hard {
				t.Fatalf("incorrect JSONL feature %+v", f)
			}
			if f.TaskComplete == nil || *f.TaskComplete || f.ExpectedUnitsRemaining == nil || *f.ExpectedUnitsRemaining != 1000-test.units {
				t.Fatal("finite task progress incorrect")
			}
			if f.StructureComplete && (!f.CompleteEarlyStop || f.HardTruncation) {
				t.Fatal("whole-unit early stop mislabeled hard truncation")
			}
		})
	}
}

func TestNumberedSequencesAndExpectedCompletion(t *testing.T) {
	cases := []struct {
		name, text, prefix     string
		parse, numbering, last State
		units                  int64
		hard                   bool
	}{
		{"tagged_complete", "nonce|1\nnonce|2", "nonce", Complete, Complete, Complete, 2, false},
		{"tagged_newline", "nonce|1\nnonce|2\n", "nonce", Complete, Complete, Complete, 2, false},
		{"partial_marker", "nonce|1\nnon", "nonce", Incomplete, Complete, Incomplete, 1, true},
		{"partial_number", "nonce|1\nnonce|", "nonce", Incomplete, Complete, Incomplete, 1, true},
		{"sequence_gap", "nonce|1\nnonce|3", "nonce", Complete, Invalid, Complete, 2, false},
		{"sequence_repeat", "nonce|1\nnonce|1", "nonce", Complete, Invalid, Complete, 2, false},
		{"leading_zero", "nonce|01", "nonce", Invalid, Complete, Invalid, 0, false},
		{"heading", "heading\nnonce|1", "nonce", Invalid, Complete, Complete, 1, false},
		{"heading_full_count", "heading\nnonce|1\nnonce|2", "nonce", Invalid, Complete, Complete, 2, false},
		{"huge_number", "nonce|9999999999999999999999999", "nonce", Invalid, Complete, Invalid, 0, false},
		{"numbered_units", "1. First unit\n2) Second unit", "", Complete, Complete, Complete, 2, false},
		{"numbered_partial", "1. First unit\n2.", "", Incomplete, Complete, Incomplete, 1, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := requireFeatures(t, Input{Content: test.text, Contract: Contract{Kind: Sequence, SequencePrefix: test.prefix, ExpectedUnits: 2}, FinishReason: "stop"})
			if f.Parse != test.parse || f.Numbering != test.numbering || f.LastUnit != test.last || f.CompleteUnits != test.units || f.HardTruncation != test.hard {
				t.Fatalf("incorrect sequence feature %+v", f)
			}
			if f.TaskComplete != nil && *f.TaskComplete && !f.StructureComplete {
				t.Fatal("invalid sequence declared task complete")
			}
		})
	}
}

func TestMarkdownFenceRulesAndProseAmbiguity(t *testing.T) {
	cases := []struct {
		text string
		want State
	}{
		{"```go\ncode\n```", Complete}, {"~~~go\ncode\n~~~", Complete}, {"````\n```\n````", Complete},
		{"```go\ncode", Incomplete}, {"```\ncode\n~~~", Incomplete}, {"````\ncode\n```", Incomplete},
		{"A line with ``` inline markers.", Complete}, {"    ```indented code", Complete}, {" ```\ncode\n   ```", Complete},
		{"```\ncode\n``` trailing text", Incomplete}, {"```a`b", Complete},
	}
	for i, test := range cases {
		f := requireFeatures(t, Input{Content: test.text, Contract: Contract{Kind: Markdown}, FinishReason: "stop"})
		if f.CodeFences != test.want || f.HardTruncation != (test.want == Incomplete) {
			t.Fatalf("fence fixture %d: %+v", i, f)
		}
	}
	for _, test := range []struct {
		text string
		want State
	}{{"A complete sentence.", Complete}, {"完整句子。", Complete}, {"He said “done!”", Complete}, {"continuing,", Incomplete}, {"因此：", Incomplete}, {"short answer", Unknown}, {"OK", Unknown}} {
		f := requireFeatures(t, Input{Content: test.text, Contract: Contract{Kind: Text}, FinishReason: "stop"})
		if f.Sentence != test.want || f.HardTruncation || len(f.TerminationHints) > 0 {
			t.Fatal("sentence uncertainty became hard truncation")
		}
	}
}

func TestUTF8BoundaryAndExplicitResourceLimits(t *testing.T) {
	for _, test := range []struct {
		text            string
		valid, boundary bool
	}{{"中文😀", true, true}, {"x" + string([]byte{0xe4, 0xb8}), false, false}, {string([]byte{0xff}) + "x", false, true}, {"�", true, true}} {
		f := requireFeatures(t, Input{Content: test.text, Contract: Contract{Kind: Text}})
		if f.UTF8Valid != test.valid || f.EndsAtUTF8Boundary != test.boundary {
			t.Fatal("UTF-8 boundary misclassified")
		}
	}
	for _, test := range []Input{
		{Content: strings.Repeat("a", MaxTextBytes+1), Contract: Contract{Kind: Text}},
		{Content: strings.Repeat("a", MaxLineBytes+1), Contract: Contract{Kind: Text}},
		{Content: strings.Repeat("x\n", MaxLines+1), Contract: Contract{Kind: Text}},
		{Content: strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1), Contract: Contract{Kind: JSON}},
	} {
		f, err := Analyze(test)
		if !errors.Is(err, ErrLimit) || !f.LimitExceeded || f.StructureComplete || f.HardTruncation {
			t.Fatal("client limit mislabeled as upstream truncation")
		}
	}
	for _, bad := range []Input{{Contract: Contract{Kind: "unknown"}}, {Contract: Contract{Kind: Sequence, SequencePrefix: "bad\n"}}, {Contract: Contract{Kind: Text}, FinishReason: strings.Repeat("x", 129)}} {
		if _, err := Analyze(bad); !errors.Is(err, ErrInput) {
			t.Fatal("invalid contract accepted")
		}
	}
}

func TestNormalUserLimitIsNotTerminationContradiction(t *testing.T) {
	count := int64(128)
	base := Input{Content: `{"unfinished":"`, Contract: Contract{Kind: JSON}, FinishReason: "length", RequestedMaxTokens: 128, LocalCompletionTokens: &count, TokenizerQuality: tokenizer.Exact}
	f := requireFeatures(t, base)
	if !f.HardTruncation || !f.NormalRequestedLimit || !f.LengthComparisonAvailable || len(f.TerminationHints) != 0 {
		t.Fatal("normal requested output limit became contradiction")
	}
	count = 30
	f = requireFeatures(t, base)
	if f.NormalRequestedLimit || !slices.Contains(f.TerminationHints, "MI_LENGTH_FAR_BELOW_REQUEST") {
		t.Fatal("sample-only below-limit hint missing")
	}
	base.TokenizerQuality = tokenizer.Heuristic
	f = requireFeatures(t, base)
	if f.LengthComparisonAvailable || len(f.TerminationHints) != 0 {
		t.Fatal("heuristic used for precise termination contradiction")
	}
	base.TokenizerQuality = tokenizer.Exact
	base.ReasoningModel = true
	f = requireFeatures(t, base)
	if f.LengthComparisonAvailable || len(f.TerminationHints) != 0 || !slices.Contains(f.Warnings, "MI_REASONING_UNSEPARATED") {
		t.Fatal("unknown hidden reasoning was ignored")
	}
	reasoning := int64(98)
	base.ReasoningTokens = &reasoning
	f = requireFeatures(t, base)
	if !f.NormalRequestedLimit || len(f.TerminationHints) != 0 {
		t.Fatal("separable reasoning budget not accounted")
	}
	base.FinishReason = "stop"
	f = requireFeatures(t, base)
	if !slices.Contains(f.TerminationHints, "MI_STOP_WITH_INCOMPLETE_STRUCTURE") {
		t.Fatal("STOP/incomplete sample hint missing")
	}
}

func TestProtocolTerminationAndAlternativeExplanations(t *testing.T) {
	base := Input{Content: "nonce|1\nnonce|", Contract: Contract{Kind: Sequence, SequencePrefix: "nonce"}, FinishReason: "stop", Stream: true}
	f := requireFeatures(t, base)
	if !slices.Contains(f.TerminationHints, "MI_STREAM_TERMINATOR_MISSING") {
		t.Fatal("stream terminator loss ignored")
	}
	for _, cause := range []string{"canceled", "network", "timeout", "protocol", "http_error", "blocked", "client_safety_limit"} {
		input := base
		input.EndCause = cause
		f = requireFeatures(t, input)
		if len(f.TerminationHints) != 0 || !slices.Contains(f.Warnings, "MI_TERMINATION_NOT_APPLICABLE") {
			t.Fatalf("client/protocol cause %s became upstream claim", cause)
		}
	}
	for _, reason := range []string{"content_filter", "tool_calls"} {
		input := base
		input.FinishReason = reason
		if f := requireFeatures(t, input); len(f.TerminationHints) != 0 {
			t.Fatal("normal alternative stop produced contradiction")
		}
	}
	base.Refusal = true
	if f := requireFeatures(t, base); len(f.TerminationHints) != 0 {
		t.Fatal("refusal was scored as truncation")
	}
}

func TestFeatureProjectionDoesNotContainProbeText(t *testing.T) {
	const canary = "STRUCTURE-PRIVATE-CONTENT-CANARY"
	input := Input{Content: canary + "|1", Contract: Contract{Kind: Sequence, SequencePrefix: canary}, FinishReason: "stop"}
	f := requireFeatures(t, input)
	for _, value := range []any{input, input.Contract, f} {
		encoded, err := json.Marshal(value)
		if err != nil || bytes.Contains(encoded, []byte(canary)) || strings.Contains(fmt.Sprintf("%+v %#v", value, value), canary) {
			t.Fatal("feature/log projection leaked probe content")
		}
	}
}

func FuzzAnalyzeDoesNotPanic(f *testing.F) {
	for _, seed := range []string{"{}", "[", `{"x":"\\`, "nonce|1\nnonce|", "```\n", string([]byte{0xff, 0xe4, 0xb8}), "1. a\n2. b", "{\"n\":1}\n{\"n\":2}"} {
		f.Add(seed, uint8(0))
	}
	f.Fuzz(func(t *testing.T, text string, choice uint8) {
		kinds := []Kind{JSON, JSONL, Sequence, Markdown, Text}
		got, err := Analyze(Input{Content: text, Contract: Contract{Kind: kinds[int(choice)%len(kinds)], SequencePrefix: "nonce", JSONNumberKey: "n"}, FinishReason: "stop"})
		if err == nil && got.LimitExceeded {
			t.Fatal("limit was not explicit")
		}
		if got.StructureComplete && (!got.UTF8Valid || got.HardTruncation) {
			t.Fatal("contradictory structural features")
		}
	})
}
