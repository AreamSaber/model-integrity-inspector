package report

import (
	"cmp"
	"slices"
	"sort"
)

func normalizeSet(values *[]string) {
	if *values == nil {
		*values = []string{}
	}
	sort.Strings(*values)
}

// These arrays have explicit set semantics in canonical-json.v1. Sample and
// attempt arrays are handled separately using ordinal and attempt_no.
func normalizeStatistics(result *Result) {
	if t := result.Token; t != nil {
		normalizeSet(&t.Limitations)
		if t.Tiers == nil {
			t.Tiers = []Tier{}
		}
		if t.Plateaus == nil {
			t.Plateaus = []Plateau{}
		}
		slices.SortFunc(t.Tiers, func(a, b Tier) int {
			return cmp.Or(cmp.Compare(a.SeriesID, b.SeriesID), cmp.Compare(a.RequestedMaxTokens, b.RequestedMaxTokens))
		})
		slices.SortFunc(t.Plateaus, func(a, b Plateau) int {
			return cmp.Or(cmp.Compare(a.SeriesID, b.SeriesID), cmp.Compare(a.LowRequested, b.LowRequested), cmp.Compare(a.HighRequested, b.HighRequested))
		})
		for i := range t.Plateaus {
			normalizeSet(&t.Plateaus[i].Limitations)
			normalizeSet(&t.Plateaus[i].SampleRefs)
		}
	}
	if b := result.Behavior; b != nil {
		normalizeSet(&b.Limitations)
		if b.Patterns == nil {
			b.Patterns = []Pattern{}
		}
		if b.Differences == nil {
			b.Differences = []Difference{}
		}
		slices.SortFunc(b.Patterns, func(a, b Pattern) int {
			return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Fingerprint, b.Fingerprint))
		})
		slices.SortFunc(b.Differences, func(a, b Difference) int { return cmp.Compare(a.Metric, b.Metric) })
		for i := range b.Patterns {
			normalizeSet(&b.Patterns[i].SampleRefs)
		}
	}
}
