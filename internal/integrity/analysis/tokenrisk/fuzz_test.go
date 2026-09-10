package tokenrisk

import (
	"math"
	"reflect"
	"slices"
	"testing"
)

func FuzzAggregateDeterminismAndBounds(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5})
	f.Add([]byte{255, 128, 128, 255, 128, 128, 0, 0, 0, 1, 1, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 24 {
			return
		}
		samples := make([]Sample, 0, len(data))
		for i, value := range data {
			s := sample(int64(i+1), int64(512+(i%2)*512), int64(value))
			s.Stream = i%3 == 1
			s.ProtocolChecked = true
			s.ProtocolAnomaly = value%5 == 0
			if value%2 == 0 {
				s.Structure.HardTruncation = true
				s.Structure.StructureComplete = false
				s.Structure.TerminationHints = []string{"MI_STOP_WITH_INCOMPLETE_STRUCTURE"}
			}
			samples = append(samples, s)
		}
		before := analyzeTest(t, samples)
		slices.Reverse(samples)
		after := analyzeTest(t, samples)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("reordering changed deterministic result")
		}
		for _, a := range []Aggregate{before.Token, before.Response} {
			if a.Strength != nil && (math.IsNaN(*a.Strength) || math.IsInf(*a.Strength, 0) || *a.Strength < 0 || *a.Strength > 100) {
				t.Fatal("unbounded aggregate")
			}
			weight := 0.0
			for _, c := range a.Components {
				if !finite(c.Strength) || !finite(c.EffectiveWeight) || (!c.Available && c.EffectiveWeight != 0) {
					t.Fatal("invalid missing/finite component")
				}
				weight += c.EffectiveWeight
			}
			if a.Strength != nil && math.Abs(weight-1) > 1e-12 {
				t.Fatal("effective weights not normalized")
			}
		}
	})
}
