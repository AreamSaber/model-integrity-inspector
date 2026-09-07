package mockupstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func (h *Handler) writeStream(ctx context.Context, w http.ResponseWriter, ordinal uint64, model, content, finish string, usage map[string]any, includeUsage bool) bool {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	emit := func(value any) bool {
		encoded, err := json.Marshal(value)
		if err != nil || ctx.Err() != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", encoded); err != nil {
			return false
		}
		if flusher != nil {
			flusher.Flush()
		}
		return true
	}
	chunk := func(delta map[string]string, reason any) map[string]any {
		response := envelope(ordinal, model, "chat.completion.chunk")
		response["choices"] = []any{map[string]any{"index": 0, "delta": delta, "finish_reason": reason}}
		return response
	}
	if !emit(chunk(map[string]string{"role": "assistant"}, nil)) {
		return false
	}
	if h.config.StreamMode == "malformed_event" {
		_, _ = fmt.Fprint(w, "data: {invalid-json\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		return false
	}
	// Chunk by Unicode code points so normal mode never corrupts a JSON string.
	// HTTP transport may still split the UTF-8 bytes at arbitrary boundaries.
	runes := []rune(content)
	chunkSize := h.config.StreamChunkTokens * 4
	for start := 0; start < len(runes); start += chunkSize {
		if h.config.StreamMode == "delay" {
			delay := h.config.Delay
			if delay == 0 {
				delay = 50 * time.Millisecond
			}
			if !pause(ctx, delay) {
				return false
			}
		}
		end := min(start+chunkSize, len(runes))
		if !emit(chunk(map[string]string{"content": string(runes[start:end])}, nil)) {
			return false
		}
	}
	if h.config.StreamMode == "truncate" {
		return false
	}
	var reason any
	if finish != "" {
		reason = finish
	}
	if !emit(chunk(map[string]string{}, reason)) {
		return false
	}
	if includeUsage && usage != nil {
		response := envelope(ordinal, model, "chat.completion.chunk")
		response["choices"] = []any{}
		response["usage"] = usage
		if !emit(response) {
			return false
		}
	}
	if h.config.StreamMode == "omit_done" || ctx.Err() != nil {
		return false
	}
	if _, err := fmt.Fprint(w, "data: [DONE]\n\n"); err != nil {
		return false
	}
	if flusher != nil {
		flusher.Flush()
	}
	return true
}
