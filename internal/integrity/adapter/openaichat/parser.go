package openaichat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/safehttp"
)

type completion struct {
	ID      string          `json:"id"`
	Object  string          `json:"object"`
	Model   string          `json:"model"`
	Choices []choice        `json:"choices"`
	Usage   *usage          `json:"usage"`
	Error   json.RawMessage `json:"error"`
}
type choice struct {
	Index        *int     `json:"index"`
	Message      *message `json:"message"`
	Delta        *message `json:"delta"`
	FinishReason *string  `json:"finish_reason"`
}
type message struct {
	Role         string          `json:"role"`
	Content      *string         `json:"content"`
	Refusal      *string         `json:"refusal"`
	ToolCalls    json.RawMessage `json:"tool_calls"`
	FunctionCall json.RawMessage `json:"function_call"`
}
type usage struct {
	Prompt     *int64 `json:"prompt_tokens"`
	Completion *int64 `json:"completion_tokens"`
	Total      *int64 `json:"total_tokens"`
	Details    *struct {
		Reasoning *int64 `json:"reasoning_tokens"`
	} `json:"completion_tokens_details"`
}

func metadata(response *http.Response) domain.NormalizedResponse {
	result := domain.NormalizedResponse{ParseStatus: "invalid", EndCause: "protocol", HeaderSummary: map[string]string{}}
	if response == nil {
		return result
	}
	result.HTTPStatus = response.StatusCode
	for _, header := range []string{"Content-Type", "Retry-After", "X-Request-Id", "Request-Id", "Openai-Processing-Ms"} {
		values := response.Header.Values(header)
		if len(values) == 1 && len(values[0]) <= 512 && !strings.ContainsAny(values[0], "\r\n\x00") {
			result.HeaderSummary[header] = values[0]
		}
	}
	result.ContentType = result.HeaderSummary["Content-Type"]
	for _, header := range []string{"X-Request-Id", "Request-Id"} {
		if identifier := result.HeaderSummary[header]; opaqueMetadata(identifier, 128) {
			result.ProviderRequestID = identifier
			break
		}
	}
	return result
}

func opaqueMetadata(value string, limit int) bool {
	if value == "" || len(value) > limit {
		return false
	}
	for _, character := range value {
		if character <= 32 || character > 126 {
			return false
		}
	}
	return true
}

func contentType(response *http.Response, wanted string) bool {
	if len(response.Header.Values("Content-Type")) != 1 {
		return false
	}
	typeName, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || typeName != wanted {
		return false
	}
	charset := strings.ToLower(parameters["charset"])
	return charset == "" || charset == "utf-8" || charset == "utf8"
}

func warning(result *domain.NormalizedResponse, code string) {
	for _, existing := range result.ParseWarnings {
		if existing == code {
			return
		}
	}
	if len(result.ParseWarnings) < 32 {
		result.ParseWarnings = append(result.ParseWarnings, code)
	}
}

// checkJSON detects duplicate object keys and pathological nesting rather than
// relying on encoding/json's permissive last-key-wins and invalid-UTF8 handling.
func checkJSON(data []byte) error {
	if !utf8.Valid(data) {
		return failure("MI_PROTOCOL_INVALID")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return failure("MI_PROTOCOL_INVALID")
		}
		token, err := decoder.Token()
		if err != nil {
			return failure("MI_PROTOCOL_INVALID")
		}
		delimiter, isDelimiter := token.(json.Delim)
		if !isDelimiter {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return failure("MI_PROTOCOL_INVALID")
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return failure("MI_PROTOCOL_INVALID")
				}
				seen[name] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return failure("MI_PROTOCOL_INVALID")
		}
		_, err = decoder.Token()
		if err != nil {
			return failure("MI_PROTOCOL_INVALID")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return failure("MI_PROTOCOL_INVALID")
	}
	return nil
}

func decodeCompletion(data []byte) (completion, error) {
	var decoded completion
	if err := checkJSON(data); err != nil {
		return decoded, err
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return decoded, failure("MI_PROTOCOL_INVALID")
	}
	if len(decoded.Error) != 0 && string(decoded.Error) != "null" {
		return decoded, failure("MI_UPSTREAM_STREAM_ERROR")
	}
	if decoded.ID != "" && !opaqueMetadata(decoded.ID, 128) || decoded.Model != "" && !opaqueMetadata(decoded.Model, 128) {
		return decoded, failure("MI_PROTOCOL_INVALID")
	}
	return decoded, nil
}

func applyIdentity(result *domain.NormalizedResponse, decoded completion, streaming bool) error {
	wanted := "chat.completion"
	if streaming {
		wanted = "chat.completion.chunk"
	}
	if decoded.Object != "" && decoded.Object != wanted {
		return failure("MI_PROTOCOL_INVALID")
	}
	if decoded.Object == "" {
		warning(result, "OBJECT_MISSING")
	}
	if result.ModelReported != "" && decoded.Model != "" && result.ModelReported != decoded.Model {
		warning(result, "MODEL_CHANGED_WITHIN_STREAM")
	}
	if result.ModelReported == "" {
		result.ModelReported = decoded.Model
	}
	if result.ProviderRequestID == "" {
		result.ProviderRequestID = decoded.ID
	}
	return nil
}

func applyUsage(result *domain.NormalizedResponse, value *usage) error {
	if value == nil {
		return nil
	}
	var reasoning *int64
	if value.Details != nil {
		reasoning = value.Details.Reasoning
	}
	for _, count := range []*int64{value.Prompt, value.Completion, value.Total, reasoning} {
		if count != nil && (*count < 0 || *count > 1<<53-1) {
			return failure("MI_PROTOCOL_INVALID")
		}
	}
	if result.TotalTokens != nil && value.Total != nil && *result.TotalTokens != *value.Total {
		warning(result, "USAGE_CHANGED_WITHIN_STREAM")
	}
	result.PromptTokens, result.CompletionTokens, result.TotalTokens, result.ReasoningTokens = value.Prompt, value.Completion, value.Total, reasoning
	if value.Prompt != nil && value.Completion != nil && value.Total != nil && *value.Prompt+*value.Completion != *value.Total {
		warning(result, "USAGE_TOTAL_MISMATCH")
	}
	if reasoning != nil && value.Completion != nil && *reasoning > *value.Completion {
		warning(result, "REASONING_EXCEEDS_COMPLETION")
	}
	return nil
}

func finishReason(result *domain.NormalizedResponse, reason *string) {
	if reason == nil || *reason == "" {
		return
	}
	value := *reason
	switch value {
	case "stop", "length", "content_filter", "tool_calls", "function_call":
	default:
		value = "unknown"
		warning(result, "FINISH_REASON_UNKNOWN")
	}
	if result.FinishReason != "" && result.FinishReason != value {
		warning(result, "FINISH_REASON_CONFLICT")
		return
	}
	result.FinishReason = value
}

func textMessage(value *message, stream bool) (string, bool, error) {
	if value == nil || value.Role != "assistant" && (!stream || value.Role != "") {
		return "", false, failure("MI_PROTOCOL_INVALID")
	}
	if len(value.ToolCalls) != 0 && string(value.ToolCalls) != "null" && string(value.ToolCalls) != "[]" || len(value.FunctionCall) != 0 && string(value.FunctionCall) != "null" {
		return "", false, failure("MI_PROTOCOL_UNSUPPORTED_OUTPUT")
	}
	var content string
	if value.Content != nil {
		content = *value.Content
	}
	refusal := value.Refusal != nil && *value.Refusal != ""
	if refusal {
		content += *value.Refusal
	}
	if !stream && value.Content == nil && !refusal {
		return "", false, failure("MI_PROTOCOL_INVALID")
	}
	return content, refusal, nil
}

func completeWarnings(result *domain.NormalizedResponse) {
	if result.ModelReported == "" {
		warning(result, "MODEL_MISSING")
	}
	if result.FinishReason == "" {
		warning(result, "FINISH_REASON_MISSING")
	}
	if result.Content == "" {
		warning(result, "EMPTY_CONTENT")
	}
	if result.PromptTokens == nil || result.CompletionTokens == nil || result.TotalTokens == nil {
		warning(result, "USAGE_MISSING")
	}
}

func (a *Adapter) ParseNonStream(response *http.Response) (domain.NormalizedResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), a.config.RequestTimeout)
	defer cancel()
	return a.parseNonStream(ctx, response, a.config.Now())
}

func (a *Adapter) parseNonStream(ctx context.Context, response *http.Response, started time.Time) (result domain.NormalizedResponse, returned error) {
	result = metadata(response)
	if response == nil || response.Body == nil {
		return result, failure("MI_PROTOCOL_INVALID")
	}
	guard := a.guard(ctx, response.Body, false, started)
	defer guard.close()
	reader := newBoundedReader(guard, a.config.MaxResponseBytes, a.config.Now, started)
	defer func() {
		result.DurationMs = elapsed(a.config.Now(), started)
		result.RawResponseBytes = reader.count
		result.FirstByteMs = reader.firstByteMs
	}()
	if response.StatusCode != http.StatusOK {
		response.Body = reader
		result.EndCause = "http_error"
		return result, a.httpError(response)
	}
	if !contentType(response, "application/json") {
		return result, failure("MI_PROTOCOL_CONTENT_TYPE")
	}
	data, err := io.ReadAll(reader)
	result.ResponseHash = hex.EncodeToString(reader.digest.Sum(nil))
	if err != nil {
		result.EndCause = transportEnd(err)
		return result, transportFailure(err)
	}
	decoded, err := decodeCompletion(data)
	if err != nil {
		return result, err
	}
	result.ChoiceCount = len(decoded.Choices)
	if err := applyIdentity(&result, decoded, false); err != nil {
		return result, err
	}
	if len(decoded.Choices) != 1 || decoded.Choices[0].Index == nil || *decoded.Choices[0].Index != 0 {
		return result, failure("MI_PROTOCOL_INVALID")
	}
	selected := decoded.Choices[0]
	result.Content, result.Refusal, err = textMessage(selected.Message, false)
	if err != nil {
		return result, err
	}
	finishReason(&result, selected.FinishReason)
	if err := applyUsage(&result, decoded.Usage); err != nil {
		return result, err
	}
	completeWarnings(&result)
	result.ParseStatus, result.EndCause = "valid", "complete"
	return result, nil
}

type readGuard struct {
	body                      io.ReadCloser
	ctx                       context.Context
	firstTimer, idleTimer     *time.Timer
	firstExpired, idleExpired atomic.Bool
	stopContext               func() bool
	idle                      time.Duration
}

func (a *Adapter) guard(ctx context.Context, body io.ReadCloser, stream bool, started time.Time) *readGuard {
	guard := &readGuard{body: body, ctx: ctx, idle: a.config.StreamIdleTimeout}
	guard.stopContext = context.AfterFunc(ctx, func() { _ = body.Close() })
	guard.idleTimer = time.AfterFunc(guard.idle, func() { guard.idleExpired.Store(true); _ = body.Close() })
	if stream {
		remaining := a.config.FirstEventTimeout - a.config.Now().Sub(started)
		if remaining <= 0 {
			guard.firstExpired.Store(true)
			_ = body.Close()
		} else {
			guard.firstTimer = time.AfterFunc(remaining, func() { guard.firstExpired.Store(true); _ = body.Close() })
		}
	}
	return guard
}

func (guard *readGuard) err() error {
	if guard.firstExpired.Load() || guard.idleExpired.Load() {
		return safehttp.ErrTimeout
	}
	return guard.ctx.Err()
}
func (guard *readGuard) effective() {
	if guard.firstTimer != nil {
		guard.firstTimer.Stop()
	}
}
func (guard *readGuard) close() {
	guard.stopContext()
	guard.idleTimer.Stop()
	if guard.firstTimer != nil {
		guard.firstTimer.Stop()
	}
	_ = guard.body.Close()
}
func (guard *readGuard) Read(buffer []byte) (int, error) {
	if err := guard.err(); err != nil {
		return 0, err
	}
	n, err := guard.body.Read(buffer)
	if guardErr := guard.err(); guardErr != nil {
		return n, guardErr
	}
	if n > 0 {
		guard.idleTimer.Reset(guard.idle)
	}
	return n, err
}

type boundedReader struct {
	guard        *readGuard
	limit, count int64
	digest       hash.Hash
	now          func() time.Time
	started      time.Time
	firstRead    bool
	firstByteMs  int64
}

func newBoundedReader(guard *readGuard, limit int64, now func() time.Time, started time.Time) *boundedReader {
	return &boundedReader{guard: guard, limit: limit, digest: sha256.New(), now: now, started: started}
}
func (reader *boundedReader) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	remaining := reader.limit - reader.count
	if remaining < 0 {
		return 0, safehttp.ErrSafetyLimit
	}
	if int64(len(buffer)) > remaining+1 {
		buffer = buffer[:remaining+1]
	}
	n, err := reader.guard.Read(buffer)
	reader.count += int64(n)
	if n > 0 {
		_, _ = reader.digest.Write(buffer[:n])
		if !reader.firstRead {
			reader.firstRead = true
			reader.firstByteMs = elapsed(reader.now(), reader.started)
		}
	}
	if reader.count > reader.limit {
		return max(0, n-1), safehttp.ErrSafetyLimit
	}
	return n, err
}
func (reader *boundedReader) Close() error { reader.guard.close(); return nil }
