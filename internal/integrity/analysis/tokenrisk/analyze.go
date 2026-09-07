package tokenrisk

import (
	"math"
	"slices"

	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func aggregate(components []Component) Aggregate {
	result := Aggregate{Components: components, Limitations: []string{}}
	weight, total := 0.0, 0.0
	for _, c := range components {
		if c.Available {
			weight += c.Weight
			total += c.Strength * c.Weight
		}
	}
	if weight == 0 {
		result.Limited = true
		result.Limitations = append(result.Limitations, "MI_NO_ANALYZABLE_COMPONENTS")
		return result
	}
	score := bounded(total / weight)
	result.Strength = &score
	for i := range result.Components {
		if result.Components[i].Available {
			result.Components[i].EffectiveWeight = result.Components[i].Weight / weight
		} else {
			result.Limited = true
		}
	}
	if result.Limited {
		result.Limitations = append(result.Limitations, "MI_COMPONENTS_MISSING_RENORMALIZED")
	}
	return result
}
func capAggregate(result *Aggregate, code string, limit float64) {
	result.Limited = true
	if !slices.Contains(result.Limitations, code) {
		result.Limitations = append(result.Limitations, code)
	}
	if result.Strength != nil {
		*result.Strength = math.Min(*result.Strength, limit)
	}
}

func Analyze(input Input) (Result, error) {
	rules := Parameters()
	samples, result, err := normalize(input)
	if err != nil {
		return result, err
	}
	result.Series, result.Plateaus, err = plateauAnalysis(samples, input)
	if err != nil {
		return result, err
	}
	result.Usage = usageAnalysis(samples)
	result.Stream = streamAnalysis(samples)
	plateauStrength := 0.0
	for _, p := range result.Plateaus {
		plateauStrength = math.Max(plateauStrength, p.Strength)
	}
	validStructure, termination, streamCount, missingEnd, protocolCount, heuristic, reasoning := 0, 0, 0, 0, 0, 0, 0
	protocolChecked, suffixChecked, naturalEOS, ladderCount := 0, 0, 0, 0
	ladderStructure, ladderTermination := 0, 0
	hasComparableTiers := false
	for _, series := range result.Series {
		if len(series.Tiers) > 1 {
			hasComparableTiers = true
		}
	}
	suffixes := map[string][]Sample{}
	for _, s := range samples {
		if !usable(s) {
			continue
		}
		if countable(s) && ladder(s) {
			ladderCount++
			if structureKnown(s) && s.Structure.CompleteEarlyStop {
				naturalEOS++
			}
		}
		if s.Local.Quality == tokenizer.Heuristic {
			heuristic++
		}
		if s.ReasoningUnseparated {
			reasoning++
		}
		if s.ProtocolChecked {
			protocolChecked++
			if s.ProtocolAnomaly {
				protocolCount++
			}
		}
		if structureKnown(s) {
			if metadataKnown(s) {
				validStructure++
			}
			if ladder(s) && countable(s) && metadataKnown(s) {
				ladderStructure++
				if terminationMismatch(s) {
					ladderTermination++
				}
			}
			if terminationMismatch(s) {
				termination++
			}
			if s.Stream {
				streamCount++
				if slices.Contains(s.Structure.TerminationHints, "MI_STREAM_TERMINATOR_MISSING") {
					missingEnd++
				}
			}
			if s.Structure.StructureComplete && s.SuffixChecked {
				suffixChecked++
				if s.SuffixFingerprint != "" {
					suffixes[s.SuffixFingerprint] = append(suffixes[s.SuffixFingerprint], s)
				}
			}
		}
	}
	terminationStrength := 0.0
	if termination >= rules.MinTerminationSamples {
		terminationStrength = 100 * ratio(termination, validStructure)
	}
	ladderTerminationStrength := 0.0
	if ladderTermination >= rules.MinTerminationSamples {
		// A short complete format/neutral response is not evidence that a
		// continuous-generation ladder terminated consistently.
		ladderTerminationStrength = 100 * ratio(ladderTermination, ladderStructure)
	}
	result.Token = aggregate([]Component{
		{Name: "plateau", Available: len(result.Plateaus) > 0, Strength: plateauStrength, Weight: rules.TokenWeights[0]},
		{Name: "termination", Available: ladderStructure > 0, Strength: ladderTerminationStrength, Weight: rules.TokenWeights[1]},
		{Name: "usage", Available: result.Usage.Available, Strength: result.Usage.Strength, Weight: rules.TokenWeights[2]},
		{Name: "stream_difference", Available: result.Stream.Available, Strength: result.Stream.Strength, Weight: rules.TokenWeights[3]},
	})
	if !hasComparableTiers {
		capAggregate(&result.Token, "MI_SINGLE_TIER_LIMIT", rules.WeakCeiling)
	}
	if result.ValidSamples < rules.MinHighSamples {
		capAggregate(&result.Token, "MI_VALID_SAMPLES_INSUFFICIENT", rules.WeakCeiling)
	}
	if heuristic > 0 {
		capAggregate(&result.Token, "MI_TOKENIZER_HEURISTIC_ONLY", rules.WeakCeiling)
	}
	if reasoning > 0 {
		capAggregate(&result.Token, "MI_REASONING_UNSEPARATED", rules.WeakCeiling)
	}
	if ladderCount > 0 && ratio(naturalEOS, ladderCount) >= Parameters().NaturalEOSFraction {
		capAggregate(&result.Token, "MI_NATURAL_EOS_ALTERNATIVE", rules.WeakCeiling)
	}
	for _, p := range result.Plateaus {
		for _, code := range p.Limitations {
			// Preserve confidence limitations even when the observed strength
			// stays high. Missing cluster replication cannot become an implicit
			// high-confidence statement downstream.
			capAggregate(&result.Token, code, 100)
		}
		if slices.Contains(p.Limitations, "MI_DECLARED_MODEL_OUTPUT_LIMIT") {
			capAggregate(&result.Token, "MI_DECLARED_MODEL_OUTPUT_LIMIT", rules.WeakCeiling)
		}
	}
	if result.Partial {
		capAggregate(&result.Token, "MI_PARTIAL_RESULT", rules.PartialCeiling)
	}
	for _, code := range result.Usage.Limitations {
		capAggregate(&result.Token, code, 100)
	}
	for _, code := range result.Stream.Limitations {
		capAggregate(&result.Token, code, 100)
	}
	sse := 0.0
	if missingEnd >= rules.MinSSESamples {
		sse = 100 * ratio(missingEnd, streamCount) * result.SSEAttributionFactor
	}
	suffixStrength := 0.0
	for _, group := range suffixes {
		if len(group) < rules.MinSuffixSamples || ratio(len(group), suffixChecked) < rules.SuffixFraction {
			continue
		}
		families, groups := map[string]bool{}, map[string]bool{}
		for _, s := range group {
			families[s.Family] = true
			groups[s.GroupID] = true
		}
		strength := 100 * ratio(len(group), suffixChecked)
		if len(families) < 2 || len(groups) < rules.MinIndependentGroups {
			strength = math.Min(strength, rules.WeakCeiling)
		}
		suffixStrength = math.Max(suffixStrength, strength)
	}
	protocol := 0.0
	if protocolCount >= rules.MinProtocolSamples {
		protocol = 100 * ratio(protocolCount, protocolChecked)
	}
	result.Response = aggregate([]Component{
		{Name: "sse_termination", Available: streamCount > 0, Strength: sse, Weight: rules.ResponseWeights[0]},
		{Name: "fixed_suffix", Available: suffixChecked > 0, Strength: suffixStrength, Weight: rules.ResponseWeights[1]},
		{Name: "metadata_consistency", Available: validStructure > 0, Strength: terminationStrength, Weight: rules.ResponseWeights[2]},
		{Name: "protocol_anomaly", Available: protocolChecked > 0, Strength: protocol, Weight: rules.ResponseWeights[3]},
	})
	if result.ValidSamples < rules.MinHighSamples {
		capAggregate(&result.Response, "MI_VALID_SAMPLES_INSUFFICIENT", rules.WeakCeiling)
	}
	if result.Partial {
		capAggregate(&result.Response, "MI_PARTIAL_RESULT", rules.PartialCeiling)
	}
	return result, nil
}
