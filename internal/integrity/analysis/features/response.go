package features

import (
	"mime"
	"slices"
	"strings"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func responseBounded(r domain.NormalizedResponse) bool {
	if len(r.Content) > MaxResponseBytes || !utf8.ValidString(r.Content) || len(r.ModelReported) > 128 || len(r.ProviderRequestID) > 128 || len(r.ContentType) > 512 || len(r.FinishReason) > 128 || len(r.ParseStatus) > 32 || len(r.EndCause) > 128 || len(r.ResponseHash) > 64 || len(r.ParseWarnings) > 32 || len(r.HeaderSummary) > 8 || len(r.Events) > 16 || r.RawResponseBytes < 0 || r.RawResponseBytes > 8<<20 || r.DurationMs < 0 || r.DurationMs > 3_600_000 || r.FirstByteMs < 0 || r.FirstByteMs > r.DurationMs || r.StreamChunkCount < 0 || r.StreamChunkCount > 8<<20 || (r.FirstTokenMs != nil && (*r.FirstTokenMs < 0 || *r.FirstTokenMs > r.DurationMs)) {
		return false
	}
	for _, code := range r.ParseWarnings {
		if len(code) > 128 {
			return false
		}
	}
	for k, v := range r.HeaderSummary {
		if len(k) > 64 || len(v) > 512 {
			return false
		}
	}
	for _, event := range r.Events {
		if len(event.Type) > 64 || event.Sequence < 0 || event.Bytes < 0 || event.Bytes > 1<<20 || event.ArrivalMs < 0 || event.ArrivalMs > r.DurationMs || event.IntervalMs < 0 || event.IntervalMs > r.DurationMs {
			return false
		}
	}
	return true
}

func protocolValid(r domain.NormalizedResponse, stream bool) bool {
	if r.HTTPStatus != 200 || r.ChoiceCount != 1 || (r.ParseStatus != "valid" && r.ParseStatus != "partial") {
		return false
	}
	kind, params, err := mime.ParseMediaType(r.ContentType)
	wanted := "application/json"
	if stream {
		wanted = "text/event-stream"
	}
	if err != nil || kind != wanted || !slices.Contains([]string{"", "utf-8", "utf8"}, strings.ToLower(params["charset"])) {
		return false
	}
	if !stream && (r.ParseStatus != "valid" || r.StreamTerminated || r.EndCause != "complete") {
		return false
	}
	if stream && ((r.ParseStatus == "valid" && (!r.StreamTerminated || r.EndCause != "done")) || (r.ParseStatus == "partial" && (r.StreamTerminated || r.EndCause != "eof"))) {
		return false
	}
	for _, count := range []*int64{r.PromptTokens, r.CompletionTokens, r.TotalTokens, r.ReasoningTokens} {
		if count != nil && (*count < 0 || *count > 1_000_000_000) {
			return false
		}
	}
	return true
}

// Never copy arbitrary parser/header strings into a feature or report. Known
// closed warnings are preserved; an unfamiliar warning is one generic class.
func protocolWarnings(raw []string) []string {
	out := []string{}
	for _, value := range raw {
		code := "MI_FEATURE_PROTOCOL_WARNING_UNKNOWN"
		switch value {
		case "OBJECT_MISSING", "MODEL_CHANGED_WITHIN_STREAM", "USAGE_CHANGED_WITHIN_STREAM", "USAGE_TOTAL_MISMATCH", "REASONING_EXCEEDS_COMPLETION", "FINISH_REASON_UNKNOWN", "FINISH_REASON_CONFLICT", "MODEL_MISSING", "FINISH_REASON_MISSING", "EMPTY_CONTENT", "USAGE_MISSING", "FIRST_EVENT_TIMEOUT", "STREAM_IDLE_TIMEOUT", "STREAM_EOF_BEFORE_DONE", "UNTERMINATED_EVENT", "STREAM_MALFORMED_EVENT", "CONTENT_AFTER_FINISH", "LOCAL_TOKENIZER_APPROXIMATE":
			code = "MI_PROTOCOL_" + value
		}
		if !slices.Contains(out, code) {
			out = append(out, code)
		}
	}
	return out
}
