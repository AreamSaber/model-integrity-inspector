package scoring

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/behavior"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func normalProtocol() *ProtocolObservation {
	return &ProtocolObservation{Normal, Normal, Normal, Normal, Normal}
}

// Real builtin catalog and behavior engine, not fabricated behavioral scores.
func behaviorInput(t testing.TB, ids []string, mode string) Input {
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
	for _, templateID := range ids {
		parts := strings.Split(templateID, ".")
		language := "en-US"
		if parts[1] == "zh-cn" {
			language = "zh-CN"
		}
		for repeat := 0; repeat < 3; repeat++ {
			id := int64(len(samples) + 1)
			marker := fmt.Sprintf("MARKER_%08d", id)
			text := marker
			switch mode {
			case "strong":
				text = "Routing annotation confirms transformation: " + marker
			case "weak":
				if id == 1 {
					text = "Unrequested explanation: " + marker
				}
			case "identity":
				if language == "zh-CN" {
					text = "我是一个人工智能助手。"
				} else {
					text = "I am an AI assistant."
				}
			case "refusal":
				if language == "zh-CN" {
					text = "我无法帮助处理这个请求。"
				} else {
					text = "I cannot help with this request."
				}
			case "invalid":
				text = "unreadable"
			}
			validity := behavior.Valid
			if mode == "invalid" {
				validity = behavior.InvalidProtocol
			}
			s := behavior.Sample{ID: id, Template: behavior.TemplateRef{ID: templateID, Version: templates.BuiltinVersion, SHA256: hash}, Contract: behavior.Contract{Kind: behavior.Exact, Expected: marker}, Variables: []string{marker}, FinalAttemptID: id, Attempts: []behavior.Attempt{{ID: id, Number: 1, Validity: validity, Content: text}}}
			samples = append(samples, s)
			input.Samples = append(input.Samples, Observation{SampleID: fmt.Sprint(id), Family: parts[0], Language: language, TemplateID: templateID, ClusterID: fmt.Sprintf("cluster-%d", repeat), Included: mode != "invalid", Protocol: normalProtocol(), Tokenizer: tokenizer.Exact})
		}
	}
	batch, err := engine.AnalyzeBatch(samples)
	if err != nil {
		t.Fatal(err)
	}
	input.ExpectedSamples = len(samples)
	input.Behavior = &batch
	return input
}

var formatDifferential = []string{"format.en-us.1", "format.zh-cn.2", "differential.en-us.1", "differential.zh-cn.2"}

func TestBehaviorScoringHealthyWeakStrongAndSingleFamily(t *testing.T) {
	for _, tc := range []struct {
		name, mode       string
		ids              []string
		minimum, maximum float64
		stable           int
	}{
		{"healthy", "healthy", formatDifferential, 0, 0, 0},
		{"weak", "weak", formatDifferential, 0, 39, 0},
		{"multifamily", "strong", formatDifferential, 100, 100, 2},
		{"single_family", "strong", formatDifferential[:2], 0, 69, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := behaviorInput(t, tc.ids, tc.mode)
			before, _ := json.Marshal(in)
			got, err := Analyze(in)
			if err != nil {
				t.Fatal(err)
			}
			if got.Prompt.Score == nil || *got.Prompt.Score < tc.minimum-1e-9 || *got.Prompt.Score > tc.maximum+1e-9 || got.StableHitFamilies != tc.stable {
				t.Fatalf("prompt=%+v stable=%d", got.Prompt, got.StableHitFamilies)
			}
			if got.Prompt.Components[4].Score != nil || !slices.Contains(got.Prompt.Limitations, "MI_BASELINE_UNAVAILABLE") || got.Completeness != "PARTIAL" || got.Confidence.Score > 59 || got.Calibrated || !got.Development || got.EvidenceGrade == "A" || got.EvidenceGrade == "B" {
				t.Fatalf("trust/completeness boundary: %+v", got)
			}
			if tc.name == "healthy" && (got.EvidenceGrade != "D" || got.Conclusion != "NO_OBVIOUS_ANOMALY_OBSERVED" || *got.Overall.Score != 0 || got.Confidence.Score == 100-int(*got.Overall.Score)) {
				t.Fatal("healthy is not proven-negative or inverse-risk confidence")
			}
			if tc.name == "multifamily" && (got.EvidenceGrade != "C" || *got.Overall.Score != 80) {
				t.Fatalf("weighted available dimensions: %+v", got.Overall)
			}
			after, _ := json.Marshal(in)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("input mutated")
			}
			again, err := Analyze(in)
			if err != nil || !reflect.DeepEqual(got, again) {
				t.Fatal("scoring is not deterministic")
			}
		})
	}
}

func TestIdentityStyleAndSelfReportCannotPromote(t *testing.T) {
	in := behaviorInput(t, []string{"neutral.en-us.1", "neutral.zh-cn.1"}, "identity")
	out, err := Analyze(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.Prompt.Score == nil || *out.Prompt.Score > 39 || !slices.Contains(out.Prompt.Limitations, "MI_IDENTITY_STYLE_ONLY") {
		t.Fatalf("identity contract break not capped: %+v", out.Prompt)
	}
	self := behaviorInput(t, []string{"self_report.en-us.1", "self_report.zh-cn.1"}, "strong")
	out, err = Analyze(self)
	if err != nil {
		t.Fatal(err)
	}
	if out.ValidSamples != 0 || out.Prompt.Score != nil || out.Overall.Score != nil || out.EvidenceGrade != "D" || out.Completeness != "INSUFFICIENT" || out.Confidence.Score != 0 {
		t.Fatal("self-report contributed")
	}
	// Caller deliberately did not set AuxiliaryOnly; template family controls.
	if len(self.Behavior.Auxiliary) != 6 {
		t.Fatal("fixture no longer exercises real auxiliary classification")
	}
}

func TestMissingUnobservedInvalidAndProtocolNotMisconduct(t *testing.T) {
	in := behaviorInput(t, formatDifferential, "healthy")
	for i := range in.Samples {
		in.Samples[i].Protocol = nil
		in.Samples[i].Tokenizer = ""
	}
	out, err := Analyze(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.Protocol.Components[0].Score != nil || out.Protocol.Components[1].Score != nil || out.Protocol.Components[4].Score != nil || out.Completeness != "INSUFFICIENT" || out.EvidenceGrade != "D" {
		t.Fatal("unknown imputed normal")
	}
	for i := range in.Samples {
		in.Samples[i].Protocol = normalProtocol()
		in.Samples[i].Protocol.Usage = Missing
		in.Samples[i].Protocol.ModelEcho = Anomalous
		in.Samples[i].Tokenizer = tokenizer.Unavailable
	}
	out, err = Analyze(in)
	if err != nil {
		t.Fatal(err)
	}
	if *out.Protocol.Components[0].Score != 100 || *out.Protocol.Components[2].Score != 100 || *out.Protocol.Components[4].Score != 100 || !slices.Contains(out.Protocol.Limitations, "MI_PROTOCOL_SCORE_NOT_PROVIDER_MISCONDUCT") || out.EvidenceGrade == "A" || out.EvidenceGrade == "B" {
		t.Fatal("protocol risk semantics")
	}
	invalid := behaviorInput(t, formatDifferential, "invalid")
	out, err = Analyze(invalid)
	if err != nil {
		t.Fatal(err)
	}
	if out.ValidSamples != 0 || out.Overall.Score != nil || out.Confidence.Score != 0 || out.EvidenceGrade != "D" {
		t.Fatal("no valid samples assigned score")
	}
	if out.Protocol.Score == nil || *out.Protocol.Components[5].Score != 100 {
		t.Fatal("diagnostic validity failure lost")
	}
	empty, err := Analyze(Input{})
	if err != nil || empty.Overall.Score != nil || empty.Completeness != "INSUFFICIENT" {
		t.Fatal("empty failed closed")
	}
}

func TestMissingRenormalizationAndConfidencePenalties(t *testing.T) {
	in := behaviorInput(t, formatDifferential, "healthy")
	base, err := Analyze(in)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(base.Prompt.Components[0].EffectiveWeight-0.30/0.55) > 1e-12 || math.Abs(base.Overall.Components[0].EffectiveWeight-.8) > 1e-12 {
		t.Fatal("missing baseline/other dimensions not renormalized")
	}
	for _, tc := range []struct {
		name   string
		change func(*Input)
	}{
		{"heuristic", func(in *Input) {
			for i := range in.Samples {
				in.Samples[i].Tokenizer = tokenizer.Heuristic
			}
		}},
		{"missing_usage", func(in *Input) {
			for i := range in.Samples {
				in.Samples[i].Protocol.Usage = Unobserved
			}
		}},
		{"reasoning", func(in *Input) {
			for i := range in.Samples {
				in.Samples[i].ReasoningUnseparated = true
			}
		}},
		{"missing_final", func(in *Input) { in.ExpectedSamples *= 2 }},
		{"shared_cluster", func(in *Input) {
			for i := range in.Samples {
				in.Samples[i].ClusterID = "same-cluster"
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := behaviorInput(t, formatDifferential, "healthy")
			tc.change(&in)
			got, err := Analyze(in)
			if err != nil || got.Confidence.Score >= base.Confidence.Score || got.Confidence.Score < 0 || got.EvidenceGrade == "A" || got.EvidenceGrade == "B" {
				t.Fatalf("quality penalty: %+v %v", got.Confidence, err)
			}
		})
	}
}

func TestInsufficientClustersDoNotBecomeIndependentFamilies(t *testing.T) {
	in := behaviorInput(t, formatDifferential, "strong")
	for i := range in.Samples {
		in.Samples[i].ClusterID = "shared-nonce"
	}
	out, err := Analyze(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.StableHitFamilies != 0 || *out.Prompt.Score > 39 {
		t.Fatal("same-nonce repetitions inflated independent support")
	}
	// A high exact paired A/B difference is deliberately not an Input field:
	// D cannot be supplied via local experimental contrasts or p-values.
	if _, ok := reflect.TypeFor[Input]().FieldByName("Baseline"); ok {
		t.Fatal("public baseline capability appeared")
	}
}
