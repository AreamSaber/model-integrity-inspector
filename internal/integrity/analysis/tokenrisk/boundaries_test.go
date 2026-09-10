package tokenrisk

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestAdditionalConservativeBoundaries(t *testing.T) {
	random := deterministicRandom{}
	if random.index(0) != 0 || random.index(MaxSamples+1) != 0 {
		t.Fatal("unbounded random index")
	}
	ss := fixture([]int64{512, 1024}, 6, func(tier int64, rep int) int64 {
		if tier == 1024 && rep >= 4 {
			return 1024
		}
		return 256
	})
	r := analyzeTest(t, ss)
	if !r.Plateaus[0].Candidate || r.Plateaus[0].Strength > 39 || !slices.Contains(r.Plateaus[0].Limitations, "MI_NORMAL_GROWTH_WITHIN_INTERVAL") {
		t.Fatal("normal growth interval not an alternative")
	}
	conflict := ss[0]
	conflict.ID = 200
	if _, err := Analyze(Input{OrganizationID: 1, RunID: 2, Samples: append(ss, conflict)}); !errors.Is(err, ErrInput) {
		t.Fatal("same actual attempt assigned to different logical samples")
	}
	ss = fixture([]int64{512}, 6, func(int64, int) int64 { return 256 })
	different := sample(300, 1024, 256)
	different.SeriesID = testDigest("different-task")
	different.Family = "jsonl"
	separate := analyzeTest(t, append(ss, different))
	if !slices.Contains(separate.Token.Limitations, "MI_SINGLE_TIER_LIMIT") {
		t.Fatal("incomparable single tiers pooled")
	}
	for _, change := range []func(*Sample){func(s *Sample) { s.Local.Warnings = []string{strings.Repeat("x", 129)} }, func(s *Sample) { s.Structure.Warnings = make([]string, 17) }, func(s *Sample) { s.Local.BundleHash = "short" }, func(s *Sample) { s.Local.BundleVersion = strings.Repeat("v", 129) }} {
		s := sample(1, 512, 256)
		change(&s)
		if _, err := Analyze(Input{OrganizationID: 1, RunID: 2, Samples: []Sample{s}}); !errors.Is(err, ErrInput) {
			t.Fatal("unbounded metadata accepted")
		}
	}
	ss = fixture([]int64{512, 1024}, 6, func(int64, int) int64 { return 256 })
	for i := range ss {
		ss[i].Usage.Available = true
		ss[i].Usage.EligibleForAggregate = true
	}
	ss = ss[:len(ss)-1]
	r = analyzeTest(t, ss)
	if !slices.Contains(r.Token.Limitations, "MI_STREAM_PAIRS_INCOMPLETE") {
		t.Fatal("nested stream limitations lost in aggregate")
	}
}
