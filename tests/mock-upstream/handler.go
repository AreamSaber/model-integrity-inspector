package mockupstream

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Request struct {
	Model               string          `json:"model"`
	Messages            []Message       `json:"messages"`
	MaxTokens           *int            `json:"max_tokens,omitempty"`
	MaxCompletionTokens *int            `json:"max_completion_tokens,omitempty"`
	Stream              bool            `json:"stream,omitempty"`
	Seed                *int64          `json:"seed,omitempty"`
	Temperature         *float64        `json:"temperature,omitempty"`
	TopP                *float64        `json:"top_p,omitempty"`
	Stop                json.RawMessage `json:"stop,omitempty"`
	ResponseFormat      json.RawMessage `json:"response_format,omitempty"`
	StreamOptions       struct {
		IncludeUsage bool `json:"include_usage,omitempty"`
	} `json:"stream_options,omitempty"`
}

// Record is available only to the test controller through Records(), never via
// HTTP. It contains no Authorization value, cookies, or other request headers.
// Records are bounded and are not durable logs or production audit evidence.
type Record struct {
	Ordinal            uint64                     `json:"ordinal"`
	Request            Request                    `json:"request"`
	ReceivedParameters map[string]json.RawMessage `json:"received_parameters"`
	RequestedTokens    int                        `json:"requested_tokens"`
	EffectiveCap       int                        `json:"effective_cap"`
	GeneratedTokens    int                        `json:"generated_tokens"`
	OverrideApplied    bool                       `json:"override_applied"`
	HTTPStatus         int                        `json:"http_status"`
	NetworkFailure     bool                       `json:"network_failure"`
	StreamTerminated   bool                       `json:"stream_terminated"`
}

type Handler struct {
	config  Config
	mu      sync.Mutex
	ordinal uint64
	records []Record
}

func NewHandler(config Config) (*Handler, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	config.CapSteps = append([]CapStep(nil), config.CapSteps...)
	if config.MaxRecords == 0 {
		config.MaxRecords = 256
	}
	if config.StreamChunkTokens == 0 {
		config.StreamChunkTokens = 8
	}
	if config.Delay == 0 {
		config.Delay = time.Duration(config.DelayMilliseconds) * time.Millisecond
	}
	return &Handler{config: config}, nil
}

// Records returns a detached snapshot. Mutating it cannot affect server state.
func (h *Handler) Records() []Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	encoded, _ := json.Marshal(h.records) // Stored requests were already valid JSON.
	var records []Record
	_ = json.Unmarshal(encoded, &records)
	return records
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Path == "/health" && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	if r.URL.Path != "/v1/chat/completions" && r.URL.Path != "/v1/models" {
		writeError(w, http.StatusNotFound, "not_found", "Unknown endpoint")
		return
	}
	if h.config.RequiredAPIKey != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+h.config.RequiredAPIKey)) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid_api_key", "Authentication failed")
		return
	}
	if r.URL.Path == "/v1/models" && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": []map[string]any{{"id": "test-model", "object": "model", "created": 0, "owned_by": "test"}}})
		return
	}
	if r.URL.Path != "/v1/chat/completions" || r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "Request exceeds the test server limit")
		return
	}
	var request Request
	if err := json.Unmarshal(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request_error", "Invalid JSON request")
		return
	}
	requested, err := validateRequest(request)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	h.mu.Lock()
	h.ordinal++
	ordinal := h.ordinal
	h.mu.Unlock()
	record := Record{Ordinal: ordinal, Request: request, RequestedTokens: requested, EffectiveCap: requested, HTTPStatus: http.StatusOK}
	_ = json.Unmarshal(body, &record.ReceivedParameters)
	defer func() { h.appendRecord(record) }()
	w.Header().Set("X-Request-ID", fmt.Sprintf("req-%016x", ordinal))
	if h.draw(ordinal, "network") < h.config.NetworkErrorRate {
		record.NetworkFailure = true
		record.HTTPStatus = 0
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, hijackErr := hj.Hijack()
			if hijackErr == nil {
				_ = conn.Close()
				return
			}
		}
		record.HTTPStatus = http.StatusServiceUnavailable
		writeError(w, record.HTTPStatus, "network_fault_unavailable", "Transport fault requires an HTTP/1 server")
		return
	}
	if h.draw(ordinal, "http") < h.config.HTTPErrorRate {
		record.HTTPStatus = h.config.HTTPErrorStatus
		if record.HTTPStatus == 0 {
			record.HTTPStatus = http.StatusTooManyRequests
		}
		if record.HTTPStatus == http.StatusTooManyRequests || record.HTTPStatus == http.StatusServiceUnavailable {
			retry := h.config.RetryAfterSeconds
			if retry == 0 {
				retry = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(retry))
		}
		writeError(w, record.HTTPStatus, "upstream_error", "Synthetic upstream failure")
		return
	}
	if !pause(r.Context(), h.config.Delay) {
		record.HTTPStatus = 0
		return
	}
	capValue := h.config.OverrideMaxTokens
	for _, step := range h.config.CapSteps {
		if requested >= step.MinRequested {
			capValue = step.Cap
		}
	}
	if capValue > 0 && capValue < requested && h.draw(ordinal, "override") < h.config.OverrideProbability {
		record.OverrideApplied = true
		record.EffectiveCap = capValue
	}
	generation, err := h.generate(request, requested)
	if err != nil {
		record.HTTPStatus = http.StatusInternalServerError
		writeError(w, record.HTTPStatus, "fixture_error", "Synthetic response generation failed")
		return
	}
	if len(generation.Tokens) > record.EffectiveCap {
		generation.Tokens = generation.Tokens[:record.EffectiveCap]
		generation.FinishReason = "length"
	}
	if request.Stream && h.config.StreamMode == "truncate" {
		cutoff := h.config.StreamCutoffTokens
		if cutoff == 0 {
			cutoff = max(1, len(generation.Tokens)/2)
		}
		if cutoff < len(generation.Tokens) {
			generation.Tokens = generation.Tokens[:cutoff]
		}
	}
	record.GeneratedTokens = len(generation.Tokens)
	content := strings.Join(generation.Tokens, "")
	switch h.config.InjectInstruction {
	case "fixed_prefix":
		prefix := h.config.Prefix
		if prefix == "" {
			prefix = "Notice: "
		}
		content = prefix + content
	case "forced_identity":
		content = "As the Acme assistant, " + content
	}
	content += h.config.Suffix
	finish := generation.FinishReason
	switch h.config.FinishReasonMode {
	case "always_stop":
		finish = "stop"
	case "always_length":
		finish = "length"
	case "missing":
		finish = ""
	}
	model := request.Model
	if h.config.ModelAlias != "" {
		model = h.config.ModelAlias
	}
	usage := h.usage(generation.PromptTokens, len(generation.Tokens))
	if request.Stream {
		record.StreamTerminated = h.writeStream(r.Context(), w, ordinal, model, content, finish, usage, request.StreamOptions.IncludeUsage)
		return
	}
	choice := map[string]any{"index": 0, "message": Message{Role: "assistant", Content: content}}
	if finish != "" {
		choice["finish_reason"] = finish
	}
	response := envelope(ordinal, model, "chat.completion")
	response["choices"] = []any{choice}
	if usage != nil {
		response["usage"] = usage
	}
	writeJSON(w, http.StatusOK, response)
}

func validateRequest(request Request) (int, error) {
	if request.Model == "" || len(request.Model) > 128 || len(request.Messages) == 0 || len(request.Messages) > 256 {
		return 0, errors.New("model and bounded messages are required")
	}
	for _, message := range request.Messages {
		if message.Role != "system" && message.Role != "developer" && message.Role != "user" && message.Role != "assistant" {
			return 0, errors.New("unsupported message role")
		}
	}
	if request.MaxTokens != nil && request.MaxCompletionTokens != nil {
		return 0, errors.New("use only one output budget parameter")
	}
	budget := 128
	if request.MaxTokens != nil {
		budget = *request.MaxTokens
	}
	if request.MaxCompletionTokens != nil {
		budget = *request.MaxCompletionTokens
	}
	if budget < 1 || budget > MaxOutputTokens {
		return 0, fmt.Errorf("output budget must be in [1,%d]", MaxOutputTokens)
	}
	return budget, nil
}

func (h *Handler) generate(request Request, budget int) (Generation, error) {
	var result Generation
	if h.config.Responder != nil {
		var err error
		result, err = h.config.Responder(request, budget)
		if err != nil {
			return Generation{}, err
		}
	} else {
		result.FinishReason = "length"
		for _, message := range request.Messages {
			result.PromptTokens += len(strings.Fields(message.Content))
		}
		for index := range budget {
			result.Tokens = append(result.Tokens, fmt.Sprintf("item%06d ", index+1))
		}
	}
	// Behavioral controls decorate both the default synthetic responder and
	// fixture-specific responders; supplying a fixture must not disable faults.
	if h.config.SafetyRefusal || h.config.InjectInstruction == "neutral_refusal" {
		result.Tokens = []string{"I ", "cannot ", "help ", "with ", "that ", "request."}
		result.FinishReason = "stop"
	} else if h.config.NaturalEarlyEOS {
		result.Tokens = []string{"The ", "answer ", "is ", "four."}
		result.FinishReason = "stop"
	}
	if result.FinishReason == "" {
		result.FinishReason = "stop"
	}
	if len(result.Tokens) > MaxOutputTokens || result.PromptTokens < 0 || result.PromptTokens > MaxRequestBytes {
		return Generation{}, errors.New("responder exceeds fixture bounds")
	}
	bytes := 0
	for _, token := range result.Tokens {
		bytes += len(token)
		if bytes > MaxContentBytes {
			return Generation{}, errors.New("responder content exceeds fixture bounds")
		}
	}
	return result, nil
}

func (h *Handler) usage(prompt, completion int) map[string]any {
	if h.config.UsageMode == "missing" {
		return nil
	}
	factor := 1.0
	switch h.config.UsageMode {
	case "inflated":
		factor = h.config.UsageFactor
		if factor == 0 {
			factor = 1.3
		}
	case "deflated":
		factor = h.config.UsageFactor
		if factor == 0 {
			factor = 0.5
		}
	}
	reported := int(math.Round(float64(completion)*factor)) + h.config.ReasoningTokens
	return map[string]any{
		"prompt_tokens": prompt, "completion_tokens": reported, "total_tokens": prompt + reported,
		"completion_tokens_details": map[string]int{"reasoning_tokens": h.config.ReasoningTokens},
	}
}

func (h *Handler) draw(ordinal uint64, purpose string) float64 {
	// SHA-256 provides deterministic independent draws; this is test randomness,
	// not a source for credentials, production nonces, or cryptographic material.
	digest := sha256.Sum256(fmt.Appendf(nil, "%d:%d:%s", h.config.Seed, ordinal, purpose))
	return float64(binary.BigEndian.Uint64(digest[:8])>>11) / float64(uint64(1)<<53)
}

func (h *Handler) appendRecord(record Record) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.records) == h.config.MaxRecords {
		copy(h.records, h.records[1:])
		h.records[len(h.records)-1] = record
		return
	}
	h.records = append(h.records, record)
}

func envelope(ordinal uint64, model, object string) map[string]any {
	return map[string]any{"id": fmt.Sprintf("chatcmpl-%016x", ordinal), "object": object, "created": 0, "model": model}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"type": code, "code": code, "message": message}})
}

func pause(ctx context.Context, delay time.Duration) bool {
	if delay == 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
