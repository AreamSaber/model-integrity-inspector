package tokenizer

import "model-integrity-inspector.local/mii/internal/integrity/domain"

// UsageComparison is one sample's feature, not a fraud verdict. An aggregate
// must still require >=6 same-direction samples and independent evidence.
type UsageComparison struct {
	Available            bool    `json:"available"`
	RelativeError        float64 `json:"relative_error"`
	Direction            int     `json:"direction"`
	Band                 string  `json:"band"`
	EligibleForAggregate bool    `json:"eligible_for_aggregate"`
	ReasoningSeparated   bool    `json:"reasoning_separated"`
	EvidenceCeiling      string  `json:"evidence_ceiling,omitempty"`
	Warning              string  `json:"warning,omitempty"`
}

func CompareUsage(response domain.NormalizedResponse, local Estimate, reasoningModel bool) UsageComparison {
	result := UsageComparison{Band: "unavailable"}
	if local.Scope != "visible_output" || local.Tokens == nil || *local.Tokens < 0 || local.Quality == Unavailable || response.CompletionTokens == nil || *response.CompletionTokens < 0 {
		result.Warning = "MI_USAGE_UNAVAILABLE"
		return result
	}
	if local.Quality != Exact && local.Quality != Compatible && local.Quality != Heuristic {
		result.Warning = "MI_USAGE_UNAVAILABLE"
		return result
	}
	if reasoningModel && response.ReasoningTokens == nil {
		result.Warning = "MI_REASONING_UNSEPARATED"
		return result
	}
	reported := *response.CompletionTokens
	if response.ReasoningTokens != nil {
		if *response.ReasoningTokens < 0 || *response.ReasoningTokens > reported {
			result.Warning = "MI_USAGE_INVALID"
			return result
		}
		reported -= *response.ReasoningTokens
		result.ReasoningSeparated = true
	}
	difference := float64(reported) - float64(*local.Tokens)
	if difference > 0 {
		result.Direction = 1
	} else if difference < 0 {
		result.Direction = -1
		difference = -difference
	}
	result.RelativeError = difference / float64(max(*local.Tokens, 1))
	result.Available = true
	result.EligibleForAggregate = local.Quality == Exact || local.Quality == Compatible
	normal, warning := 0.05, 0.15
	if local.Quality == Heuristic {
		normal, warning = 0.10, 0.30
		result.EvidenceCeiling = "C"
		result.Warning = "MI_TOKENIZER_HEURISTIC_ONLY"
	}
	result.Band = "normal"
	if result.RelativeError > warning {
		result.Band = "mismatch"
	} else if result.RelativeError > normal {
		result.Band = "warning"
	}
	return result
}
