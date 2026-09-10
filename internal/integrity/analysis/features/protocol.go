package features

import (
	"mime"
	"slices"
	"strings"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func protocolObservations(r domain.NormalizedResponse, stream bool, model string) *ProtocolObservations {
	o := &ProtocolObservations{Usage: "unobserved", HTTP: "unobserved", ModelEcho: "unobserved", Finish: "unobserved", Termination: "unobserved"}
	if r.HTTPStatus == 0 {
		return o
	}
	kind, params, err := mime.ParseMediaType(r.ContentType)
	wanted := "application/json"
	if stream {
		wanted = "text/event-stream"
	}
	o.HTTP = "anomalous"
	if r.HTTPStatus != 200 || err != nil || kind != wanted || !slices.Contains([]string{"", "utf-8", "utf8"}, strings.ToLower(params["charset"])) {
		return o
	}
	o.HTTP = "normal"
	// Malformed/unsupported bodies do not establish whether semantic fields
	// were present. Keep them unobserved even when zero-value structs exist.
	if (r.ParseStatus != "valid" && r.ParseStatus != "partial") || r.ChoiceCount != 1 {
		return o
	}
	o.Usage = "normal"
	if r.PromptTokens == nil || r.CompletionTokens == nil || r.TotalTokens == nil {
		o.Usage = "missing"
	}
	for _, n := range []*int64{r.PromptTokens, r.CompletionTokens, r.TotalTokens, r.ReasoningTokens} {
		if n != nil && (*n < 0 || *n > 1_000_000_000) {
			o.Usage = "invalid"
		}
	}
	if r.PromptTokens != nil && r.CompletionTokens != nil && r.TotalTokens != nil && o.Usage != "invalid" && *r.PromptTokens+*r.CompletionTokens != *r.TotalTokens {
		o.Usage = "invalid"
	}
	if r.ReasoningTokens != nil && r.CompletionTokens != nil && *r.ReasoningTokens > *r.CompletionTokens {
		o.Usage = "invalid"
	}
	o.ModelEcho = "normal"
	if r.ModelReported == "" {
		o.ModelEcho = "missing"
	} else if r.ModelReported != model {
		o.ModelEcho = "anomalous"
	}
	o.Finish = "normal"
	switch strings.ToLower(strings.TrimSpace(r.FinishReason)) {
	case "stop", "eos", "end_turn", "length", "max_tokens", "max_output_tokens", "content_filter", "safety", "tool_calls", "function_call", "tool_call":
	case "":
		o.Finish = "missing"
	default:
		o.Finish = "invalid"
	}
	o.Termination = "normal"
	if stream {
		if !r.StreamTerminated || r.EndCause != "done" {
			o.Termination = "anomalous"
		}
	} else if r.EndCause != "complete" || r.ParseStatus != "valid" {
		o.Termination = "anomalous"
	}
	for _, warning := range r.ParseWarnings {
		switch warning {
		case "USAGE_CHANGED_WITHIN_STREAM", "USAGE_TOTAL_MISMATCH", "REASONING_EXCEEDS_COMPLETION":
			o.Usage = "invalid"
		case "MODEL_CHANGED_WITHIN_STREAM":
			o.ModelEcho = "anomalous"
		case "FINISH_REASON_UNKNOWN", "FINISH_REASON_CONFLICT":
			o.Finish = "invalid"
		}
	}
	return o
}
