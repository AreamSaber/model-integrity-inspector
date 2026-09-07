package tokenrisk

import (
	"math"

	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func usageAnalysis(samples []Sample) UsageResult {
	rules := Parameters()
	result := UsageResult{Limitations: []string{}}
	trusted, heuristic := []Sample{}, []Sample{}
	groups := map[string]bool{}
	for _, s := range samples {
		if !countable(s) {
			continue
		}
		if s.ReasoningUnseparated || s.Usage.Warning == "MI_REASONING_UNSEPARATED" {
			result.SkippedReasoning++
			continue
		}
		if !s.Usage.Available {
			continue
		}
		if s.Local.Quality == tokenizer.Heuristic {
			heuristic = append(heuristic, s)
			continue
		}
		if !s.Usage.EligibleForAggregate {
			continue
		}
		trusted = append(trusted, s)
		groups[s.GroupID] = true
	}
	result.Samples, result.HeuristicSamples, result.IndependentGroups = len(trusted), len(heuristic), len(groups)
	result.Available = len(trusted) > 0 || len(heuristic) > 0
	chosen := trusted
	threshold := rules.UsageExactMismatch
	if len(chosen) < Parameters().MinUsageSamples && len(heuristic) >= Parameters().MinUsageSamples {
		chosen = heuristic
		threshold = rules.UsageHeuristicMismatch
	}
	result.IncludedSamples = len(chosen)
	groups = map[string]bool{}
	for _, s := range chosen {
		groups[s.GroupID] = true
	}
	result.IndependentGroups = len(groups)
	errors := []float64{}
	for _, s := range chosen {
		if s.Usage.RelativeError <= threshold {
			continue
		}
		if s.Usage.Direction > 0 {
			result.Positive++
		} else if s.Usage.Direction < 0 {
			result.Negative++
		}
	}
	result.Direction = 1
	result.Consistent = result.Positive
	if result.Negative > result.Positive {
		result.Direction = -1
		result.Consistent = result.Negative
	}
	if result.Consistent == 0 {
		result.Direction = 0
	}
	for _, s := range chosen {
		if s.Usage.Direction == result.Direction && s.Usage.RelativeError > threshold {
			errors = append(errors, s.Usage.RelativeError)
		}
	}
	result.ConsistentFraction = ratio(result.Consistent, len(chosen))
	result.MedianRelativeError = median(errors)
	result.Candidate = result.Consistent >= Parameters().MinUsageSamples && result.ConsistentFraction >= Parameters().UsageDirectionFraction
	if result.Candidate {
		result.Strength = bounded(rules.StrengthBase + rules.StrengthScale*math.Min(1, (result.MedianRelativeError-threshold)/rules.UsageStrengthRange))
		if threshold == rules.UsageHeuristicMismatch || result.IndependentGroups < rules.MinIndependentGroups {
			result.Strength = math.Min(result.Strength, rules.WeakCeiling)
		}
	}
	limit := func(code string) { result.Limited = true; result.Limitations = append(result.Limitations, code) }
	if len(chosen) < rules.MinUsageSamples {
		limit("MI_USAGE_SAMPLES_INSUFFICIENT")
	}
	if result.Available && len(groups) < rules.MinIndependentGroups {
		limit("MI_INDEPENDENT_GROUPS_INSUFFICIENT")
	}
	if threshold == rules.UsageHeuristicMismatch {
		limit("MI_TOKENIZER_HEURISTIC_ONLY")
	}
	if result.SkippedReasoning > 0 {
		limit("MI_REASONING_UNSEPARATED")
	}
	return result
}
