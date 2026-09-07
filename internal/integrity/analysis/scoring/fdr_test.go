package scoring

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"
)

func TestBHKnownValuesTiesMissingAndEffectSeparation(t *testing.T) {
	family := []Hypothesis{{"a", number(.01), number(.8)}, {"b", number(.04), number(.01)}, {"c", number(.03), number(-.3)}, {"d", number(.002), number(0)}, {"unmeasured", nil, nil}}
	out, err := BenjaminiHochberg(family, .05)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []float64{.025, .05, .05, .01} {
		if math.Abs(*out.Tests[i].AdjustedP-want) > 1e-12 {
			t.Fatalf("i=%d got=%f want=%f", i, *out.Tests[i].AdjustedP, want)
		}
	}
	if out.FamilySize != 5 || out.Tested != 4 || out.Tests[4].AdjustedP != nil || out.Tests[4].Reject || *out.Tests[3].Effect != 0 || !out.Tests[3].Reject {
		t.Fatal("nil imputation/effect or hypothesis interpretation")
	}
	*out.Tests[0].PValue = .9
	*out.Tests[0].Effect = .9
	if *family[0].PValue != .01 || *family[0].Effect != .8 {
		t.Fatal("result aliases input")
	}
	tied, err := BenjaminiHochberg([]Hypothesis{{"z", number(.02), number(1)}, {"a", number(.02), number(-1)}, {"n", number(1), number(0)}}, .05)
	if err != nil || *tied.Tests[0].AdjustedP != .03 || *tied.Tests[1].AdjustedP != .03 {
		t.Fatal("ties not monotone")
	}
	allMissing, err := BenjaminiHochberg([]Hypothesis{{ID: "missing"}}, .05)
	if err != nil || allMissing.Tested != 0 || allMissing.Tests[0].AdjustedP != nil {
		t.Fatal("all missing")
	}
	empty, err := BenjaminiHochberg(nil, .05)
	if err != nil || len(empty.Tests) != 0 {
		t.Fatal("empty family")
	}
}

func TestBHInvalidNumbersBoundsDuplicatesAndNoSelection(t *testing.T) {
	for _, n := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -.1, 1.1} {
		if _, err := BenjaminiHochberg([]Hypothesis{{"x", number(n), number(1)}}, .05); !errors.Is(err, ErrInput) {
			t.Fatal("invalid p")
		}
	}
	for _, n := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := BenjaminiHochberg([]Hypothesis{{"x", number(.1), number(n)}}, .05); !errors.Is(err, ErrInput) {
			t.Fatal("invalid effect")
		}
	}
	for _, alpha := range []float64{0, -1, 2, math.NaN(), math.Inf(1)} {
		if _, err := BenjaminiHochberg(nil, alpha); !errors.Is(err, ErrInput) {
			t.Fatal("invalid alpha")
		}
	}
	for _, in := range [][]Hypothesis{{{ID: "duplicate"}, {ID: "duplicate"}}, {{"no-effect", number(.05), nil}}, {{ID: ""}}} {
		if _, err := BenjaminiHochberg(in, .05); !errors.Is(err, ErrInput) {
			t.Fatal("invalid family")
		}
	}
	large := make([]Hypothesis, MaxHypotheses+1)
	if _, err := BenjaminiHochberg(large, .05); !errors.Is(err, ErrLimit) {
		t.Fatal("unbounded family")
	}
	// All planned nulls count, not only the selected tiny p-values.
	family := []Hypothesis{{"tested", number(.01), number(.1)}}
	for i := 0; i < 9; i++ {
		family = append(family, Hypothesis{ID: fmt.Sprintf("missing-%d", i)})
	}
	out, err := BenjaminiHochberg(family, .05)
	if err != nil || out.Tests[0].Reject || *out.Tests[0].AdjustedP != .1 {
		t.Fatal("missing tests removed from multiplicity denominator")
	}
	again, _ := BenjaminiHochberg(family, .05)
	if !reflect.DeepEqual(out, again) {
		t.Fatal("not deterministic")
	}
}
