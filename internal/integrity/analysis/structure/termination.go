package structure

import (
	"strings"

	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func normalizeFinish(value, endCause string) string {
	switch strings.ToLower(endCause) {
	case "client_cancel", "cancelled", "canceled":
		return "CLIENT_CANCEL"
	case "safety_limit", "client_limit", "response_limit", "client_safety_limit":
		return "CLIENT_LIMIT"
	case "network_error", "error", "timeout", "http_error", "blocked", "network", "protocol":
		return "ERROR"
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "stop", "eos", "end_turn":
		return "STOP"
	case "length", "max_tokens", "max_output_tokens":
		return "LENGTH"
	case "content_filter", "safety":
		return "CONTENT_FILTER"
	case "tool_calls", "function_call", "tool_call":
		return "TOOL_CALL"
	case "error":
		return "ERROR"
	case "client_cancel":
		return "CLIENT_CANCEL"
	default:
		return "UNKNOWN"
	}
}

func termination(input Input, f *Features) {
	f.FinishReason = normalizeFinish(input.FinishReason, input.EndCause)
	if input.Refusal || f.FinishReason == "CONTENT_FILTER" || f.FinishReason == "TOOL_CALL" || f.FinishReason == "ERROR" || f.FinishReason == "CLIENT_CANCEL" || f.FinishReason == "CLIENT_LIMIT" {
		f.Warnings = append(f.Warnings, "MI_TERMINATION_NOT_APPLICABLE")
		return
	}
	if f.FinishReason == "UNKNOWN" {
		f.Warnings = append(f.Warnings, "MI_FINISH_REASON_UNKNOWN")
	}
	if input.Stream && !input.StreamTerminated {
		f.TerminationHints = append(f.TerminationHints, "MI_STREAM_TERMINATOR_MISSING")
	}
	if f.FinishReason == "STOP" && f.HardTruncation {
		f.TerminationHints = append(f.TerminationHints, "MI_STOP_WITH_INCOMPLETE_STRUCTURE")
	}
	if f.FinishReason == "STOP" && f.StructureComplete && f.TaskComplete != nil && !*f.TaskComplete {
		// Natural completion at a whole-unit boundary is not hard truncation.
		f.CompleteEarlyStop = true
	}
	if input.RequestedMaxTokens == 0 || input.LocalCompletionTokens == nil || *input.LocalCompletionTokens < 0 || (input.TokenizerQuality != tokenizer.Exact && input.TokenizerQuality != tokenizer.Compatible) {
		return
	}
	if input.ReasoningModel && input.ReasoningTokens == nil {
		f.Warnings = append(f.Warnings, "MI_REASONING_UNSEPARATED")
		return
	}
	actual := float64(*input.LocalCompletionTokens)
	if input.ReasoningTokens != nil {
		if *input.ReasoningTokens < 0 {
			f.Warnings = append(f.Warnings, "MI_USAGE_INVALID")
			return
		}
		actual += float64(*input.ReasoningTokens)
	}
	f.LengthComparisonAvailable = true
	ratio := actual / float64(input.RequestedMaxTokens)
	if f.FinishReason == "LENGTH" {
		// Frozen v1 feature thresholds: ±10% allows compatible-tokenizer
		// variation. <70% is a sample hint only, never an aggregate verdict.
		f.NormalRequestedLimit = ratio >= 0.9 && ratio <= 1.1
		if ratio < 0.7 {
			f.TerminationHints = append(f.TerminationHints, "MI_LENGTH_FAR_BELOW_REQUEST")
		}
	}
}
