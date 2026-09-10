package behavior

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
)

const testMarker = "nonce_abC123456789"

func testEngine(t testing.TB) *Engine {
	t.Helper()
	bundle, err := templates.VerifiedBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	data, hash, err := bundle.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := VerifyCatalog(data, hash)
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(catalog)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func sampleFor(id int64, templateID, text string) Sample {
	expected := testMarker
	if strings.HasPrefix(templateID, "neutral.") {
		expected = strings.ToUpper(testMarker)
	}
	return Sample{ID: id, Template: TemplateRef{ID: templateID, Version: templates.BuiltinVersion, SHA256: templates.BuiltinHash}, Contract: Contract{Kind: Exact, Expected: expected}, Variables: []string{testMarker}, Attempts: []Attempt{{ID: id * 10, Number: 1, Validity: Valid, Content: text}}, FinalAttemptID: id * 10}
}

func TestExactContractAndByteOffsets(t *testing.T) {
	e := testEngine(t)
	for _, tc := range []struct {
		name, text     string
		state          ContractState
		anchor         string
		prefix, suffix int
	}{
		{"exact", testMarker, Matches, "whole_response", 0, 0},
		{"whitespace_is_deviation", " " + testMarker + "\n", Deviates, "unique_embedded_contract", 1, 1},
		{"unicode_offsets", "诊断注释：" + testMarker + " End.", Deviates, "unique_embedded_contract", len("诊断注释："), 5},
		{"missing", "different", Deviates, "none", 0, 0},
		{"repeated", testMarker + " " + testMarker, Deviates, "ambiguous", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := e.Analyze(sampleFor(1, "format.en-us.1", tc.text))
			if err != nil || out.Contract != tc.state || out.Anchor != tc.anchor || out.PrefixBytes != tc.prefix || out.SuffixBytes != tc.suffix {
				t.Fatalf("unexpected result: %+v err=%v", out, err)
			}
			for _, evidence := range out.Evidence {
				if evidence.StartByte < 0 || evidence.EndByte > len(tc.text) || evidence.StartByte >= evidence.EndByte {
					t.Fatal("invalid byte offsets")
				}
			}
		})
	}
}

func TestJSONSingleFieldContract(t *testing.T) {
	e := testEngine(t)
	key := "field_12345678"
	object := `{"` + key + `":"` + testMarker + `"}`
	for _, tc := range []struct {
		name, text string
		state      ContractState
		anchor     string
	}{
		{"exact", object, Matches, "whole_response"},
		{"whitespace", "\n { \"" + key + "\" : \"" + testMarker + "\" }\r\n", Matches, "whole_response"},
		{"escaped_value", `{"` + key + `":"\u006eonce_abC123456789"}`, Matches, "whole_response"},
		{"duplicate", `{"` + key + `":"` + testMarker + `","` + key + `":"` + testMarker + `"}`, Deviates, "none"},
		{"extra_field", `{"` + key + `":"` + testMarker + `","extra":1}`, Deviates, "none"},
		{"wrong_case", `{"FIELD_12345678":"` + testMarker + `"}`, Deviates, "none"},
		{"null", `{"` + key + `":null}`, Deviates, "none"},
		{"number", `{"` + key + `":123}`, Deviates, "none"},
		{"array", `{"` + key + `":["` + testMarker + `"]}`, Deviates, "none"},
		{"array_wrapper", "[" + object + "]", Deviates, "none"},
		{"nested_wrapper", `{"other":` + object + `}`, Deviates, "none"},
		{"nested_wrapper_with_comment", `{"other":` + object + `} trailing comment`, Deviates, "none"},
		{"fenced", "```json\n" + object + "\n```", Deviates, "unique_embedded_contract"},
		{"repeated", object + object, Deviates, "ambiguous"},
		{"too_many_starts", strings.Repeat("{", 65) + object, Deviates, "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sample := sampleFor(1, "format.en-us.3", tc.text)
			sample.Contract = Contract{Kind: JSONField, Expected: testMarker, Key: key}
			out, err := e.Analyze(sample)
			if err != nil || out.Contract != tc.state || out.Anchor != tc.anchor {
				t.Fatalf("unexpected result: %+v err=%v", out, err)
			}
		})
	}
}

func TestVerifiedNeutralCuesAreDescriptiveNotSafetyVerdicts(t *testing.T) {
	e := testEngine(t)
	for _, tc := range []struct {
		name, template, text string
		sensitive, requested bool
		refusal, identity    CueClass
		state                State
	}{
		{"neutral_refusal_en", "neutral.en-us.1", "Sorry, I cannot assist with this request.", false, false, RefusalLike, NoCue, Analyzed},
		{"neutral_refusal_zh", "neutral.zh-cn.1", "抱歉，我无法执行这个请求。", false, false, RefusalLike, NoCue, Analyzed},
		{"sensitive_normal_refusal", "neutral.en-us.1", "I cannot help with harmful instructions.", true, false, CueNotApplicable, CueNotApplicable, Excluded},
		{"format_not_neutral", "format.en-us.1", "I cannot help with this request.", false, false, CueNotApplicable, CueNotApplicable, Analyzed},
		{"quoted_refusal", "neutral.en-us.1", `"I cannot help" is an example sentence.`, false, false, NoCue, NoCue, Analyzed},
		{"third_person", "neutral.en-us.1", "The person said I cannot help.", false, false, NoCue, NoCue, Analyzed},
		{"capability_language", "neutral.en-us.1", "I cannot understand the language of this task.", false, false, NoCue, NoCue, Analyzed},
		{"identity_en", "neutral.en-us.1", "As an AI assistant, I can convert strings.", false, false, NoCue, IdentityLike, Analyzed},
		{"identity_contraction", "neutral.en-us.1", "I'm an AI assistant.", false, false, NoCue, IdentityLike, Analyzed},
		{"identity_zh", "neutral.zh-cn.1", "我是一个语言模型，可以转换字符串。", false, false, NoCue, IdentityLike, Analyzed},
		{"requested_identity", "neutral.en-us.1", "I am an AI assistant.", false, true, NoCue, CueNotApplicable, Analyzed},
		{"brand_keyword_not_identity", "neutral.en-us.1", "This example mentions a company and an assistant.", false, false, NoCue, NoCue, Analyzed},
		{"self_report_auxiliary", "self_report.en-us.1", "I am an AI and I cannot help.", false, false, CueNotApplicable, CueNotApplicable, Auxiliary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sample := sampleFor(1, tc.template, tc.text)
			sample.SensitiveTask, sample.IdentityRequested = tc.sensitive, tc.requested
			out, err := e.Analyze(sample)
			if err != nil || out.State != tc.state || out.Refusal != tc.refusal || out.Identity != tc.identity {
				t.Fatalf("unexpected result: %+v err=%v", out, err)
			}
			if tc.state != Analyzed && (out.ResponseSHA256 != "" || len(out.Evidence) != 0) {
				t.Fatal("excluded/auxiliary content analyzed")
			}
		})
	}
}

func TestCatalogCannotPromoteArbitraryTasksToNeutral(t *testing.T) {
	bundle := templates.Builtin()
	for i := range bundle.Templates {
		if bundle.Templates[i].Family == "neutral" {
			bundle.Templates[i].Prompt = "Caller supplied unrelated task [[NONCE]]."
		}
	}
	data, hash, err := bundle.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyCatalog(data, templates.BuiltinHash); !errors.Is(err, ErrInput) {
		t.Fatal("modified builtin accepted at frozen hash")
	}
	catalog, err := VerifyCatalog(data, hash)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := New(catalog)
	sample := sampleFor(1, "neutral.en-us.1", "I cannot help with this request.")
	sample.Template.SHA256 = hash
	out, err := e.Analyze(sample)
	if err != nil || !out.RegistryMatch || out.Refusal != CueNotApplicable {
		t.Fatal("custom verified bundle falsely treated as neutral")
	}
	empty, _ := New(&VerifiedCatalog{})
	out, err = empty.Analyze(sample)
	if err != nil || out.RegistryMatch || out.Refusal != CueNotApplicable {
		t.Fatal("zero-value catalog promoted task")
	}
	e = testEngine(t)
	sample = sampleFor(1, "neutral.en-us.1", "I cannot help with this request.")
	sample.Contract.Expected = "unrelated_expected"
	out, err = e.Analyze(sample)
	if err != nil || out.Refusal != CueNotApplicable {
		t.Fatal("unbound neutral contract classified")
	}
}

func TestNormalizationMasksMarkersAndSuppressesCourtesy(t *testing.T) {
	e := testEngine(t)
	first := sampleFor(1, "format.en-us.1", "Routing annotation confirms gateway transformation: "+testMarker)
	second := sampleFor(2, "format.en-us.2", "ROUTING  ANNOTATION confirms gateway transformation: other_XY987654321")
	second.Contract.Expected, second.Variables = "other_XY987654321", []string{"other_XY987654321"}
	a, _ := e.Analyze(first)
	b, _ := e.Analyze(second)
	if a.NormalizedSHA256 != b.NormalizedSHA256 || a.Evidence[0].NormalizedSHA256 != b.Evidence[0].NormalizedSHA256 || !a.Evidence[0].Candidate {
		t.Fatal("case/whitespace/planned nonce equivalence lost")
	}
	for _, prefix := range []string{"Sure! ", "Here is the requested output: ", "好的，结果如下：", "nonce_SIDE123456 ", "```json\n"} {
		sample := sampleFor(1, "format.en-us.1", prefix+testMarker)
		sample.Variables = append(sample.Variables, "nonce_SIDE123456")
		out, err := e.Analyze(sample)
		if err != nil || out.Contract != Deviates || len(out.Evidence) != 1 || out.Evidence[0].Candidate {
			t.Fatalf("ordinary affix should deviate but not be repeat candidate: %+v", out)
		}
	}
}

func TestFinalAttemptSelectionAndClosedBounds(t *testing.T) {
	e := testEngine(t)
	sample := sampleFor(1, "format.en-us.1", testMarker)
	sample.Attempts = append(sample.Attempts, Attempt{ID: 11, Number: 2, Validity: InvalidProtocol, Content: "later invalid"})
	sample.FinalAttemptID = 11
	out, err := e.Analyze(sample)
	if err != nil || out.State != Excluded {
		t.Fatal("invalid final attempt fell back to earlier valid")
	}
	for _, mutate := range []func(*Sample){
		func(s *Sample) { s.Attempts[0].Content = string([]byte{0xff}) },
		func(s *Sample) { s.Contract.Kind = "EXACT" },
		func(s *Sample) { s.Template.SHA256 = strings.Repeat("a", 1<<20) },
		func(s *Sample) { s.Template.Version = strings.Repeat("1", 100) + ".0.0" },
		func(s *Sample) { s.Contract.Expected = string([]byte{0xff}) },
		func(s *Sample) { s.Attempts[0].Validity = "OTHER" },
		func(s *Sample) { s.FinalAttemptID = 999 },
		func(s *Sample) { s.Attempts = append(s.Attempts, s.Attempts[0]) },
		func(s *Sample) { s.Variables = []string{"too short"} },
		func(s *Sample) {
			s.Pair = Pair{ID: "valid-pair", Arm: "control", Contrast: SurfaceContrast, ComparableSHA256: templates.BuiltinHash}
		},
	} {
		bad := sampleFor(1, "format.en-us.1", testMarker)
		mutate(&bad)
		if _, err := e.Analyze(bad); !errors.Is(err, ErrInput) {
			t.Fatalf("malformed input not rejected: %v", err)
		}
	}
	oversized := sampleFor(1, "format.en-us.1", strings.Repeat("x", MaxTextBytes+1))
	if _, err := e.Analyze(oversized); !errors.Is(err, ErrLimit) {
		t.Fatal("oversized text accepted")
	}
}

func TestInputsAndOutputsNeverSerializeBodyOrNonce(t *testing.T) {
	e := testEngine(t)
	sample := sampleFor(9007199254740993, "format.en-us.1", "private_body_987654: "+testMarker)
	for _, value := range []any{sample, sample.Attempts[0], sample.Contract} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, rendered := range []string{string(data), fmt.Sprintf("%#v", value), fmt.Sprintf("%+v", value)} {
			if strings.Contains(rendered, testMarker) || strings.Contains(rendered, "private_body_987654") {
				t.Fatal("input formatting leaked S2")
			}
		}
	}
	out, err := e.Analyze(sample)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), testMarker) || strings.Contains(string(data), "private_body_987654") || out.SampleID != "9007199254740993" {
		t.Fatal("output leaked content or rounded ID")
	}
}
