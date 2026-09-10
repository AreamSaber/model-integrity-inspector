package tokenrisk

import (
	"math"
	"slices"
	"strconv"

	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func (e *Engine) streamAnalysis(samples []Sample) StreamResult {
	rules := e.rules
	result := StreamResult{Limitations: []string{}}
	groups := map[string][]Sample{}
	for _, s := range samples {
		if usable(s) && ladder(s) {
			key := s.SeriesID + "/" + s.GroupID + "/" + strconv.FormatInt(s.RequestedMaxTokens, 10)
			groups[key] = append(groups[key], s)
		}
	}
	keys := []string{}
	for key := range groups {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	differences := []float64{}
	// Shared nonce across tiers remains ONE resampling block, not one
	// independent pair per tier or one independent family per probe row.
	blocks := map[string][]float64{}
	tiers := map[int64]bool{}
	heuristic, reasoning, support, positive, negative := false, false, 0, 0, 0
	for _, key := range keys {
		group := groups[key]
		if len(group) < 2 {
			result.Unmatched++
			continue
		}
		if len(group) != 2 || group[0].Stream == group[1].Stream {
			result.Ambiguous++
			continue
		}
		left, right := group[0], group[1]
		if left.Stream {
			left, right = right, left
		}
		if !sameSeed(left.Seed, right.Seed) {
			result.SeedMismatch++
			continue
		}
		if !countable(left) || !countable(right) || left.Local.TokenizerID != right.Local.TokenizerID || left.Local.TokenizerVersion != right.Local.TokenizerVersion {
			result.Unmatched++
			continue
		}
		difference := (tokens(right) - tokens(left)) / math.Max(tokens(left), 1)
		differences = append(differences, difference)
		blocks[left.SeriesID+"/"+left.GroupID] = append(blocks[left.SeriesID+"/"+left.GroupID], difference)
		result.Pairs++
		tiers[left.RequestedMaxTokens] = true
		if difference > rules.StreamEffect {
			positive++
		} else if difference < -rules.StreamEffect {
			negative++
		}
		if abnormalSupport(left) || abnormalSupport(right) {
			support++
		}
		heuristic = heuristic || left.Local.Quality == tokenizer.Heuristic || right.Local.Quality == tokenizer.Heuristic
		reasoning = reasoning || left.ReasoningUnseparated || right.ReasoningUnseparated
	}
	result.Tiers = len(tiers)
	result.Available = result.Pairs > 0
	result.MedianRelativeDifference = median(differences)
	ids := []string{}
	for id := range blocks {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	left, right := [][]float64{}, [][]float64{}
	for _, id := range ids {
		values := blocks[id]
		left = append(left, make([]float64, len(values)))
		right = append(right, values)
	}
	result.DifferenceCI = e.bootstrap(left, right, true, "stream/nonstream")
	consistent := max(positive, negative)
	result.Candidate = result.Pairs >= rules.MinPairs && ratio(consistent, result.Pairs) >= rules.UsageDirectionFraction && math.Abs(result.MedianRelativeDifference) > rules.StreamEffect && result.DifferenceCI.Available && (result.DifferenceCI.Lower > rules.StreamIntervalEffect || result.DifferenceCI.Upper < -rules.StreamIntervalEffect)
	if result.Candidate {
		result.Strength = bounded(rules.StrengthBase + rules.StrengthScale*math.Min(math.Abs(result.MedianRelativeDifference), 1))
	}
	limit := func(code string, cap float64) {
		result.Limited = true
		result.Limitations = append(result.Limitations, code)
		result.Strength = math.Min(result.Strength, cap)
	}
	if result.Pairs < rules.MinPairs || len(blocks) < rules.MinIndependentGroups {
		limit("MI_STREAM_PAIRS_INSUFFICIENT", rules.WeakCeiling)
	}
	if result.Tiers < rules.MinStreamTiers {
		limit("MI_STREAM_TIER_COVERAGE_INSUFFICIENT", rules.WeakCeiling)
	}
	if result.Unmatched > 0 || result.Ambiguous > 0 || result.SeedMismatch > 0 {
		limit("MI_STREAM_PAIRS_INCOMPLETE", rules.WeakCeiling)
	}
	if heuristic {
		limit("MI_TOKENIZER_HEURISTIC_ONLY", rules.WeakCeiling)
	}
	if reasoning {
		limit("MI_REASONING_UNSEPARATED", rules.WeakCeiling)
	}
	if result.Candidate && support == 0 {
		limit("MI_STREAM_VARIATION_ALTERNATIVE", rules.WeakCeiling)
	}
	return result
}
