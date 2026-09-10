package tokenrisk

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func runtimeEngine(t *testing.T, mutate func(*Rules)) *Engine {
	t.Helper()
	r := Parameters()
	r.Version = "1.0.0-dev.2"
	if mutate != nil {
		mutate(&r)
	}
	e, err := NewDevelopment(r)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestDevelopmentRuntimeParametersAffectComputation(t *testing.T) {
	input := Input{OrganizationID: 1, RunID: 2, Samples: fixture([]int64{512, 1024}, 6, func(_ int64, repetition int) int64 { return 256 + int64(repetition%3)*10 })}
	base := runtimeEngine(t, nil)
	loose, err := base.Analyze(input)
	if err != nil {
		t.Fatal(err)
	}
	tight := runtimeEngine(t, func(r *Rules) { r.RobustCV = .01 })
	strict, err := tight.Analyze(input)
	if err != nil || len(loose.Plateaus) != 1 || !loose.Plateaus[0].Candidate || strict.Plateaus[0].Candidate || loose.RulesHash == strict.RulesHash {
		t.Fatal("CV knob did not govern real plateau", err)
	}
	if strict.Version != "1.0.0-dev.2" || !strict.Development || strict.Calibrated {
		t.Fatal("candidate falsely approved")
	}
	for i := range input.Samples {
		input.Samples[i].Usage = tokenizer.UsageComparison{Available: true, EligibleForAggregate: true, RelativeError: .5, Direction: 1}
		if i >= 10 {
			input.Samples[i].Usage.RelativeError, input.Samples[i].Usage.Direction = 0, 0
		}
	}
	loose, err = base.Analyze(input)
	if err != nil {
		t.Fatal(err)
	}
	strict, err = runtimeEngine(t, func(r *Rules) { r.UsageDirectionFraction = .9 }).Analyze(input)
	if err != nil || !loose.Usage.Candidate || strict.Usage.Candidate || loose.Usage.IncludedSamples != 12 || strict.Usage.Consistent != 10 {
		t.Fatal("usage denominator/fraction knob ignored", err)
	}
	short := runtimeEngine(t, func(r *Rules) { r.BootstrapReplicates = 128 })
	left, right := [][]float64{{1}, {5}, {8}, {37}, {91}}, [][]float64{{3}, {30}, {5}, {61}, {70}}
	a, b := short.bootstrap(left, right, false, "runtime-knob"), base.bootstrap(left, right, false, "runtime-knob")
	if !a.Available || a.Replicates != 128 || b.Replicates != 1024 || a.Lower == b.Lower && a.Upper == b.Upper || !reflect.DeepEqual(a, short.bootstrap(left, right, false, "runtime-knob")) {
		t.Fatal("resampling knob was metadata-only or nondeterministic", a, b)
	}
	copy := short.Rules()
	copy.RobustCV = 99
	if short.Rules().RobustCV == 99 {
		t.Fatal("caller mutated runtime")
	}
}

func TestDevelopmentRuntimeRejectsUnsupportedRules(t *testing.T) {
	for _, change := range []func(*Rules){
		func(r *Rules) { r.Version = Version; r.RobustCV = .05 },
		func(r *Rules) { r.Version = "1.0.0" },
		func(r *Rules) { r.Version = "unknown-implementation" },
		func(r *Rules) { r.RobustCV = math.NaN() }, func(r *Rules) { r.RobustCV = .001 }, func(r *Rules) { r.RobustCV = .21 },
		func(r *Rules) { r.UsageDirectionFraction = math.Inf(1) }, func(r *Rules) { r.UsageDirectionFraction = .79 }, func(r *Rules) { r.UsageDirectionFraction = 1.01 },
		func(r *Rules) { r.BootstrapReplicates = 127 }, func(r *Rules) { r.BootstrapReplicates = 8192 }, func(r *Rules) { r.BootstrapReplicates = 129 },
		func(r *Rules) { r.MinTierSamples = 1 }, func(r *Rules) { r.TokenWeights[0] = .9 }, func(r *Rules) { r.GrowthRatio = 2 }, func(r *Rules) { r.WeakCeiling = 100 },
	} {
		r := Parameters()
		r.Version = "1.0.0-dev.2"
		change(&r)
		if _, err := NewDevelopment(r); !errors.Is(err, ErrRules) {
			t.Fatal("unsupported rule admitted", err)
		}
	}
	for _, e := range []*Engine{nil, {}} {
		if _, err := e.Analyze(Input{}); !errors.Is(err, ErrRules) || e.Hash() != "" || e.Rules() != (Rules{}) {
			t.Fatal("zero runtime usable")
		}
	}
	engine, err := NewDevelopment(Parameters())
	if err != nil {
		t.Fatal(err)
	}
	input := Input{OrganizationID: 1, RunID: 2, Samples: fixture([]int64{512, 1024}, 6, func(_ int64, _ int) int64 { return 256 })}
	a, err := Analyze(input)
	if err != nil {
		t.Fatal(err)
	}
	b, err := engine.Analyze(input)
	if err != nil {
		t.Fatal(err)
	}
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if string(ab) != string(bb) || engine.Hash() != RulesHash() {
		t.Fatal("builtin path changed")
	}
	candidate := runtimeEngine(t, nil)
	renamed, err := candidate.Analyze(input)
	if err != nil {
		t.Fatal(err)
	}
	renamed.Version, renamed.RulesHash = a.Version, a.RulesHash
	if !reflect.DeepEqual(a, renamed) {
		t.Fatal("renaming identical rules selected different statistics")
	}
}
