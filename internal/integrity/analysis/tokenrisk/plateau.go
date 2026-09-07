package tokenrisk

import (
	"math"
	"slices"
	"strconv"
	"strings"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/structure"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func structureKnown(s Sample) bool {
	return s.Structure.Version == structure.Version && !s.Structure.LimitExceeded && !slices.Contains(s.Structure.Warnings, "MI_TERMINATION_NOT_APPLICABLE")
}
func metadataKnown(s Sample) bool {
	return structureKnown(s) && (s.Structure.FinishReason == "STOP" || s.Structure.FinishReason == "LENGTH" || terminationMismatch(s))
}
func abnormalSupport(s Sample) bool {
	if !structureKnown(s) || slices.Contains(s.Structure.Warnings, "MI_TERMINATION_NOT_APPLICABLE") {
		return false
	}
	if s.Structure.HardTruncation && !s.Structure.NormalRequestedLimit {
		return true
	}
	return terminationMismatch(s)
}
func terminationMismatch(s Sample) bool {
	if !structureKnown(s) || slices.Contains(s.Structure.Warnings, "MI_TERMINATION_NOT_APPLICABLE") {
		return false
	}
	for _, hint := range s.Structure.TerminationHints {
		if hint == "MI_STREAM_TERMINATOR_MISSING" || (!s.Structure.NormalRequestedLimit && (hint == "MI_STOP_WITH_INCOMPLETE_STRUCTURE" || hint == "MI_LENGTH_FAR_BELOW_REQUEST")) {
			return true
		}
	}
	return false
}
func cohort(s Sample) string {
	return strings.Join([]string{s.SeriesID, s.Local.TokenizerID, s.Local.TokenizerVersion}, "/")
}
func summarizeTier(samples []Sample) Tier {
	t := Tier{RequestedMaxTokens: samples[0].RequestedMaxTokens, Samples: len(samples)}
	groups := map[string]bool{}
	values := make([]float64, 0, len(samples))
	incomplete, abnormal, eos, heuristic, reasoning := 0, 0, 0, 0, 0
	for _, s := range samples {
		groups[s.GroupID] = true
		values = append(values, tokens(s))
		if abnormalSupport(s) {
			abnormal++
		}
		if structureKnown(s) && s.Structure.HardTruncation {
			incomplete++
		}
		if structureKnown(s) && s.Structure.CompleteEarlyStop {
			eos++
		}
		if s.Local.Quality == tokenizer.Heuristic {
			heuristic++
		}
		if s.ReasoningUnseparated {
			reasoning++
		}
	}
	t.IndependentGroups = len(groups)
	t.Median, t.MAD, t.RobustCV = median(values), mad(values), robustCV(values)
	t.IncompleteRate, t.NaturalEOSRate, t.HeuristicRate, t.ReasoningUnknownRate = ratio(incomplete, len(samples)), ratio(eos, len(samples)), ratio(heuristic, len(samples)), ratio(reasoning, len(samples))
	t.AbnormalSupportRate = ratio(abnormal, len(samples))
	return t
}

func summarizeModes(samples []Sample) ModeTier {
	left, right := []Sample{}, []Sample{}
	for _, s := range samples {
		if s.Stream {
			right = append(right, s)
		} else {
			left = append(left, s)
		}
	}
	m := ModeTier{}
	if len(left) > 0 {
		m.Nonstream = summarizeTier(left)
	}
	if len(right) > 0 {
		m.Stream = summarizeTier(right)
	}
	m.Covered = len(left) > 0 && len(right) > 0
	if m.Covered {
		m.RelativeMedianDifference = math.Abs(m.Stream.Median-m.Nonstream.Median) / math.Max(m.Nonstream.Median, 1)
		m.Comparable = m.RelativeMedianDifference <= Parameters().StreamEffect
	}
	return m
}

type groupData struct {
	values     []float64
	seed       *int64
	consistent bool
}

func grouped(samples []Sample) map[string]groupData {
	groups := map[string]groupData{}
	for _, s := range samples {
		g, ok := groups[s.GroupID]
		if !ok {
			g = groupData{seed: s.Seed, consistent: true}
		} else if !sameSeed(g.seed, s.Seed) {
			g.consistent = false
		}
		g.values = append(g.values, tokens(s))
		groups[s.GroupID] = g
	}
	return groups
}
func tierInterval(low, high []Sample, key string) (Interval, bool) {
	l, r := grouped(low), grouped(high)
	shared := []string{}
	for id := range l {
		if _, ok := r[id]; ok {
			shared = append(shared, id)
		}
	}
	slices.Sort(shared)
	left, right := [][]float64{}, [][]float64{}
	if len(shared) > 0 {
		for _, id := range shared {
			if l[id].consistent && r[id].consistent && sameSeed(l[id].seed, r[id].seed) {
				left = append(left, l[id].values)
				right = append(right, r[id].values)
			}
		}
		return bootstrap(left, right, true, key), len(left) != len(l) || len(right) != len(r)
	}
	for side, groups := range []map[string]groupData{l, r} {
		ids := []string{}
		for id := range groups {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			if !groups[id].consistent {
				return Interval{}, true
			}
			if side == 0 {
				left = append(left, groups[id].values)
			} else {
				right = append(right, groups[id].values)
			}
		}
	}
	return bootstrap(left, right, false, key), false
}

func plateauAnalysis(samples []Sample, input Input) ([]Series, []Plateau, error) {
	groups := map[string][]Sample{}
	for _, s := range samples {
		if countable(s) && ladder(s) {
			groups[cohort(s)] = append(groups[cohort(s)], s)
		}
	}
	if len(groups) > MaxSeries*2 {
		return nil, nil, ErrLimit
	}
	keys := []string{}
	for key := range groups {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	series, candidates := []Series{}, []Plateau{}
	rules := Parameters()
	for _, key := range keys {
		all := groups[key]
		first := all[0]
		entry := Series{ID: first.SeriesID, Family: first.Family, Language: first.Language, Variant: first.Variant, TokenizerID: first.Local.TokenizerID, TokenizerVersion: first.Local.TokenizerVersion, Tiers: []Tier{}, Modes: []ModeTier{}}
		tiers := map[int64][]Sample{}
		for _, s := range all {
			tiers[s.RequestedMaxTokens] = append(tiers[s.RequestedMaxTokens], s)
		}
		values := []int64{}
		for value := range tiers {
			values = append(values, value)
		}
		slices.Sort(values)
		for _, value := range values {
			entry.Tiers = append(entry.Tiers, summarizeTier(tiers[value]))
			entry.Modes = append(entry.Modes, summarizeModes(tiers[value]))
		}
		series = append(series, entry)
		for i := 1; i < len(values); i++ {
			low, high := entry.Tiers[i-1], entry.Tiers[i]
			if float64(high.RequestedMaxTokens)/float64(low.RequestedMaxTokens) < rules.TierRatio {
				continue
			}
			left, right := tiers[values[i-1]], tiers[values[i]]
			p := Plateau{SeriesID: first.SeriesID, Family: first.Family, Language: first.Language, Variant: first.Variant, Low: low, High: high, LowModes: entry.Modes[i-1], HighModes: entry.Modes[i], Limitations: []string{}, SampleIDs: []int64{}}
			combined := append(slices.Clone(left), right...)
			local := []float64{}
			support := 0
			for _, s := range combined {
				local = append(local, tokens(s))
				p.SampleIDs = append(p.SampleIDs, s.ID)
				if abnormalSupport(s) {
					support++
				}
			}
			p.GrowthRatio = high.Median / math.Max(low.Median, 1)
			p.CombinedRobustCV = robustCV(local)
			p.Responsiveness = (high.Median - low.Median) / float64(high.RequestedMaxTokens-low.RequestedMaxTokens)
			var incompletePairs bool
			p.DifferenceCI, incompletePairs = tierInterval(left, right, key+"/"+strconv.FormatInt(values[i], 10))
			p.Candidate = low.Median > 0 && high.Median > 0 && p.GrowthRatio < rules.GrowthRatio && p.CombinedRobustCV < rules.RobustCV && high.Median < rules.PlateauRatio*float64(high.RequestedMaxTokens) && support > 0
			if p.Candidate {
				p.Strength = rules.StrengthBase + rules.StrengthScale*ratio(support, len(combined))
			}
			limit := func(code string, cap float64) {
				p.Limited = true
				p.Limitations = append(p.Limitations, code)
				p.Strength = math.Min(p.Strength, cap)
			}
			if low.Samples < rules.MinTierSamples || high.Samples < rules.MinTierSamples || low.Samples+high.Samples < rules.MinHighSamples {
				limit("MI_HIGH_TIER_SAMPLES_INSUFFICIENT", rules.WeakCeiling)
			}
			if low.IndependentGroups < rules.MinIndependentGroups || high.IndependentGroups < rules.MinIndependentGroups {
				limit("MI_INDEPENDENT_GROUPS_INSUFFICIENT", 100)
			}
			if incompletePairs {
				limit("MI_LADDER_PAIRS_INCOMPLETE", rules.WeakCeiling)
			}
			if !p.DifferenceCI.Available {
				limit("MI_BOOTSTRAP_UNAVAILABLE", 100)
			} else if p.Candidate && p.DifferenceCI.Upper >= rules.NormalResponsiveness*float64(high.RequestedMaxTokens-low.RequestedMaxTokens) {
				limit("MI_NORMAL_GROWTH_WITHIN_INTERVAL", rules.WeakCeiling)
			}
			if !p.LowModes.Covered || !p.HighModes.Covered {
				limit("MI_MODE_TIER_COVERAGE_INSUFFICIENT", rules.WeakCeiling)
			} else if !p.LowModes.Comparable || !p.HighModes.Comparable {
				// Never hide a mode-specific truncation behind the majority arm's
				// median. Its paired stream diagnostic is reported independently.
				p.Candidate = false
				limit("MI_STREAM_MODES_NOT_COMPARABLE", 0)
			}
			if low.HeuristicRate > 0 || high.HeuristicRate > 0 {
				limit("MI_TOKENIZER_HEURISTIC_ONLY", rules.WeakCeiling)
			}
			if low.ReasoningUnknownRate > 0 || high.ReasoningUnknownRate > 0 {
				limit("MI_REASONING_UNSEPARATED", rules.WeakCeiling)
			}
			if low.NaturalEOSRate >= rules.NaturalEOSFraction || high.NaturalEOSRate >= rules.NaturalEOSFraction {
				limit("MI_NATURAL_EOS_ALTERNATIVE", rules.WeakCeiling)
			}
			if input.DeclaredModelOutputLimit != nil && high.RequestedMaxTokens > *input.DeclaredModelOutputLimit && math.Abs(high.Median-float64(*input.DeclaredModelOutputLimit)) <= rules.DeclaredLimitTolerance*float64(*input.DeclaredModelOutputLimit) {
				limit("MI_DECLARED_MODEL_OUTPUT_LIMIT", rules.WeakCeiling)
			}
			p.Strength = bounded(p.Strength)
			candidates = append(candidates, p)
		}
	}
	return series, candidates, nil
}
