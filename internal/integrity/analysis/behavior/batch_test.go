package behavior

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func repeatedSamples(prefix string) []Sample {
	samples := []Sample{}
	for _, templateID := range []string{"format.en-us.1", "format.zh-cn.2", "differential.en-us.1", "differential.zh-cn.2"} {
		for repeat := 0; repeat < 3; repeat++ {
			samples = append(samples, sampleFor(int64(len(samples)+1), templateID, prefix+testMarker))
		}
	}
	return samples
}

func TestRepeatRequiresTwoFamiliesThreeTemplatesTwoLanguages(t *testing.T) {
	e := testEngine(t)
	samples := repeatedSamples("Routing annotation confirms gateway transformation: ")
	out, err := e.AnalyzeBatch(samples)
	if err != nil || len(out.Patterns) != 1 || out.Patterns[0].State != StablePattern || out.Patterns[0].FamilyCount != 2 || out.Patterns[0].TemplateCount != 4 || out.Patterns[0].LanguageCount != 2 {
		t.Fatalf("unexpected repeat result: %+v err=%v", out, err)
	}
	if out.RuleStatus != "development_uncalibrated" || len(out.Patterns[0].Alternatives) < 3 {
		t.Fatal("repeat missing non-conclusive limits")
	}
	for _, tc := range []struct {
		name    string
		samples []Sample
	}{
		{"one_family", samples[:6]},
		{"too_few_repetitions", []Sample{samples[0], samples[3], samples[6], samples[9]}},
		{"one_language", []Sample{samples[0], samples[1], samples[2], samples[6], samples[7], samples[8]}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := e.AnalyzeBatch(tc.samples)
			if err != nil {
				t.Fatal(err)
			}
			for _, pattern := range out.Patterns {
				if pattern.State == StablePattern {
					t.Fatal("insufficient coverage promoted")
				}
			}
		})
	}
	// Missing matches count in the denominator; only finding the hits would
	// falsely report a 100% repeat rate for this less consistent family.
	for i := 0; i < 3; i++ {
		samples = append(samples, sampleFor(int64(20+i), "format.en-us.1", testMarker))
	}
	out, err = e.AnalyzeBatch(samples)
	if err != nil || out.Patterns[0].State != InsufficientPattern || out.Patterns[0].FamilyCount != 1 {
		t.Fatal("non-matching valid samples omitted from denominator")
	}
}

func TestOrdinaryCourtesyAndNonceDoNotProduceStablePatterns(t *testing.T) {
	e := testEngine(t)
	for _, prefix := range []string{"Here is the requested output: ", "Sure! Thanks! ", "好的，结果如下：", strings.Repeat("sure ", 32), strings.Repeat("好的结果如下", 16)} {
		out, err := e.AnalyzeBatch(repeatedSamples(prefix))
		if err != nil || len(out.Patterns) != 0 {
			t.Fatalf("ordinary phrase became fixed pattern: %+v err=%v", out, err)
		}
		for _, sample := range out.Samples {
			if sample.Contract != Deviates {
				t.Fatal("courtesy suppression hid actual format mismatch")
			}
		}
	}
	samples := repeatedSamples("")
	for i := range samples {
		marker := fmt.Sprintf("random_SIDE%012d", i)
		samples[i].Variables = append(samples[i].Variables, marker)
		samples[i].Attempts[0].Content = marker + " " + testMarker
	}
	out, err := e.AnalyzeBatch(samples)
	if err != nil || len(out.Patterns) != 0 {
		t.Fatal("nonce-only prefix became fixed pattern")
	}
}

func TestAuxiliaryInvalidAndUnknownSamplesCannotInflatePatterns(t *testing.T) {
	e := testEngine(t)
	samples := repeatedSamples("Routing annotation confirms gateway transformation: ")
	for i := 6; i < len(samples); i++ {
		samples[i].Template.ID = "self_report.en-us.1"
		samples[i].AuxiliaryOnly = false
	}
	out, err := e.AnalyzeBatch(samples)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Patterns) != 1 || out.Patterns[0].State != InsufficientPattern {
		t.Fatal("self report entered repeated-family support")
	}
	if len(out.Samples) != 6 || len(out.Auxiliary) != 6 {
		t.Fatal("auxiliary output not separated")
	}
	for _, sample := range out.Auxiliary {
		if sample.State != Auxiliary {
			t.Fatal("self report flag bypass")
		}
	}
	for i := range samples {
		samples[i].Template.SHA256 = strings.Repeat("0", 64)
	}
	out, err = e.AnalyzeBatch(samples)
	if err != nil || len(out.Patterns) != 0 {
		t.Fatal("unknown registry entered aggregate")
	}
	// Many attempts are still one logical observation, not several matches.
	samples = repeatedSamples("Routing annotation confirms gateway transformation: ")[:1]
	for i := 2; i <= MaxAttempts; i++ {
		samples[0].Attempts = append(samples[0].Attempts, Attempt{ID: int64(20 + i), Number: i, Validity: Valid, Content: samples[0].Attempts[0].Content})
	}
	out, err = e.AnalyzeBatch(samples)
	if err != nil || len(out.Patterns) != 1 || len(out.Patterns[0].Evidence) != 1 || out.Patterns[0].Coverage[0].MatchedSamples != 1 {
		t.Fatal("retry attempts inflated pattern sample size")
	}
}

func TestBatchResourceLimitsAndDuplicateLogicalSample(t *testing.T) {
	e := testEngine(t)
	sample := sampleFor(1, "format.en-us.1", testMarker)
	if _, err := e.AnalyzeBatch([]Sample{sample, sample}); !errors.Is(err, ErrInput) {
		t.Fatal("duplicate sample IDs accepted")
	}
	if _, err := e.AnalyzeBatch(make([]Sample, MaxSamples+1)); !errors.Is(err, ErrLimit) {
		t.Fatal("sample limit ignored")
	}
	samples := []Sample{}
	for i := 0; i < 129; i++ {
		samples = append(samples, sampleFor(int64(i+1), "format.en-us.1", strings.Repeat("x", MaxTextBytes)))
	}
	if _, err := e.AnalyzeBatch(samples); !errors.Is(err, ErrLimit) {
		t.Fatal("total batch byte limit ignored")
	}
	empty, err := e.AnalyzeBatch(nil)
	if err != nil || len(empty.Samples) != 0 || len(empty.Patterns) != 0 {
		t.Fatal("empty batch should be explicitly empty")
	}
}
