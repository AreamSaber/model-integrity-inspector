package openaichat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/safehttp"
)

const (
	MaxRequestBytes  = 1 << 20
	MaxOutputTokens  = 131072
	MaxEventBytes    = 1 << 20
	MaxResponseBytes = 8 << 20
)

type Doer interface {
	Do(*http.Request) (*http.Response, error)
}
type PrepareRequest func(*http.Request) error
type StreamEventSink func(domain.StreamEventSummary)

type Config struct {
	Endpoint           string
	MaxOutputParameter string
	Doer               Doer
	URLPolicy          safehttp.URLPolicy
	FirstEventTimeout  time.Duration
	StreamIdleTimeout  time.Duration
	RequestTimeout     time.Duration
	MaxEventBytes      int
	MaxResponseBytes   int64
	Now                func() time.Time
}

type Adapter struct {
	endpoint      *url.URL
	config        Config
	mu            sync.RWMutex
	parameter     string
	precheckMu    sync.Mutex
	fallbackTried bool
}

func New(config Config) (*Adapter, error) {
	if config.Doer == nil {
		return nil, failure("MI_ADAPTER_INVALID_CONFIG")
	}
	endpoint, err := safehttp.ValidateEndpoint(config.Endpoint, config.URLPolicy)
	if err != nil {
		return nil, transportFailure(err)
	}
	if !strings.HasSuffix(strings.TrimSuffix(endpoint.Path, "/"), "/chat/completions") {
		endpoint.Path = strings.TrimSuffix(endpoint.Path, "/") + "/chat/completions"
	} else {
		endpoint.Path = strings.TrimSuffix(endpoint.Path, "/")
	}
	if config.MaxOutputParameter == "" {
		config.MaxOutputParameter = "max_tokens"
	}
	if config.MaxOutputParameter != "max_tokens" && config.MaxOutputParameter != "max_completion_tokens" {
		return nil, failure("MI_ADAPTER_INVALID_CONFIG")
	}
	for _, option := range []struct {
		value    *time.Duration
		fallback time.Duration
	}{
		{&config.FirstEventTimeout, 60 * time.Second}, {&config.StreamIdleTimeout, 30 * time.Second}, {&config.RequestTimeout, 180 * time.Second},
	} {
		if *option.value < 0 || *option.value > 24*time.Hour {
			return nil, failure("MI_ADAPTER_INVALID_CONFIG")
		}
		if *option.value == 0 {
			*option.value = option.fallback
		}
	}
	if config.MaxEventBytes < 0 || config.MaxEventBytes > MaxEventBytes || config.MaxResponseBytes < 0 || config.MaxResponseBytes > MaxResponseBytes {
		return nil, failure("MI_ADAPTER_INVALID_CONFIG")
	}
	if config.MaxEventBytes == 0 {
		config.MaxEventBytes = MaxEventBytes
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = MaxResponseBytes
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Adapter{endpoint: endpoint, config: config, parameter: config.MaxOutputParameter}, nil
}

func (*Adapter) Capabilities() domain.AdapterCapabilities {
	return domain.AdapterCapabilities{Protocol: "openai-chat-completions", Streaming: true, StreamUsage: true, Seed: true,
		MaxOutputParameters: []string{"max_tokens", "max_completion_tokens"}, ResponseFormats: []string{"text", "json_object"},
		ExtraParameters: []string{"frequency_penalty", "presence_penalty"}, MaxOutputTokens: MaxOutputTokens}
}

func (a *Adapter) BuildRequest(ctx context.Context, input domain.NormalizedRequest) (*http.Request, domain.RequestSnapshot, error) {
	a.mu.RLock()
	parameter := a.parameter
	a.mu.RUnlock()
	return a.buildRequest(ctx, input, parameter)
}

func (a *Adapter) buildRequest(ctx context.Context, input domain.NormalizedRequest, parameter string) (*http.Request, domain.RequestSnapshot, error) {
	if ctx == nil {
		return nil, domain.RequestSnapshot{}, failure("MI_REQUEST_INVALID")
	}
	if err := validateInput(input); err != nil {
		return nil, domain.RequestSnapshot{}, err
	}
	payload := map[string]any{"model": input.Model, "messages": input.Messages, parameter: input.MaxOutputTokens, "stream": input.Stream}
	if input.Temperature != nil {
		payload["temperature"] = *input.Temperature
	}
	if input.TopP != nil {
		payload["top_p"] = *input.TopP
	}
	if input.Seed != nil {
		payload["seed"] = *input.Seed
	}
	if len(input.Stop) != 0 {
		payload["stop"] = input.Stop
	}
	if input.ResponseFormat != nil {
		payload["response_format"] = input.ResponseFormat
	}
	if input.Stream {
		payload["stream_options"] = map[string]bool{"include_usage": true}
	}
	for name, value := range input.ExtraAllowedParams {
		number, ok := finiteNumber(value)
		if !ok || (name != "frequency_penalty" && name != "presence_penalty") || number < -2 || number > 2 {
			return nil, domain.RequestSnapshot{}, failure("MI_REQUEST_INVALID")
		}
		payload[name] = number
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, domain.RequestSnapshot{}, failure("MI_REQUEST_INVALID")
	}
	if len(encoded) > MaxRequestBytes {
		return nil, domain.RequestSnapshot{}, failure("CLIENT_SAFETY_LIMIT")
	}
	digest := sha256.Sum256(encoded)
	snapshot := domain.RequestSnapshot{Model: input.Model, Stream: input.Stream, MaxOutputTokens: input.MaxOutputTokens, MaxOutputParameter: parameter,
		Payload: append(json.RawMessage(nil), encoded...), PayloadBytes: len(encoded), RequestHash: hex.EncodeToString(digest[:])}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint.String(), bytes.NewReader(encoded))
	if err != nil {
		return nil, domain.RequestSnapshot{}, failure("MI_REQUEST_INVALID")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if input.Stream {
		request.Header.Set("Accept", "text/event-stream")
	}
	return request, snapshot, nil
}

func validateInput(input domain.NormalizedRequest) error {
	if len(input.Model) == 0 || len(input.Model) > 128 || len(input.Messages) == 0 || len(input.Messages) > 256 || input.MaxOutputTokens < 1 || input.MaxOutputTokens > MaxOutputTokens || len(input.Stop) > 4 {
		return failure("MI_REQUEST_INVALID")
	}
	for _, character := range input.Model {
		valid := (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("-._/:@", character)
		if !valid {
			return failure("MI_REQUEST_INVALID")
		}
	}
	contentBytes := 0
	for _, message := range input.Messages {
		if message.Role != "system" && message.Role != "developer" && message.Role != "user" && message.Role != "assistant" {
			return failure("MI_REQUEST_INVALID")
		}
		contentBytes += len(message.Content)
		if !utf8.ValidString(message.Content) || strings.ContainsRune(message.Content, 0) || contentBytes > MaxRequestBytes {
			return failure("MI_REQUEST_INVALID")
		}
	}
	for _, value := range []struct {
		number       *float64
		lower, upper float64
	}{{input.Temperature, 0, 2}, {input.TopP, 0, 1}} {
		if value.number != nil && (math.IsNaN(*value.number) || math.IsInf(*value.number, 0) || *value.number < value.lower || *value.number > value.upper) {
			return failure("MI_REQUEST_INVALID")
		}
	}
	for _, stop := range input.Stop {
		if stop == "" || len(stop) > 256 || !utf8.ValidString(stop) || strings.ContainsRune(stop, 0) {
			return failure("MI_REQUEST_INVALID")
		}
	}
	if input.ResponseFormat != nil && input.ResponseFormat.Type != "text" && input.ResponseFormat.Type != "json_object" {
		return failure("MI_REQUEST_INVALID")
	}
	return nil
}

func finiteNumber(value any) (float64, bool) {
	var number float64
	switch typed := value.(type) {
	case float64:
		number = typed
	case float32:
		number = float64(typed)
	case int:
		number = float64(typed)
	case int64:
		number = float64(typed)
	case json.Number:
		var err error
		number, err = typed.Float64()
		if err != nil {
			return 0, false
		}
	default:
		return 0, false
	}
	return number, !math.IsNaN(number) && !math.IsInf(number, 0)
}

func (a *Adapter) Call(ctx context.Context, input domain.NormalizedRequest, prepare PrepareRequest, sink StreamEventSink) (domain.NormalizedResponse, domain.RequestSnapshot, error) {
	a.mu.RLock()
	parameter := a.parameter
	a.mu.RUnlock()
	return a.call(ctx, input, parameter, prepare, sink)
}

func (a *Adapter) call(ctx context.Context, input domain.NormalizedRequest, parameter string, prepare PrepareRequest, sink StreamEventSink) (domain.NormalizedResponse, domain.RequestSnapshot, error) {
	if ctx == nil {
		return domain.NormalizedResponse{}, domain.RequestSnapshot{}, failure("MI_REQUEST_INVALID")
	}
	ctx, cancel := context.WithTimeout(ctx, a.config.RequestTimeout)
	defer cancel()
	started := a.config.Now()
	var firstByte atomic.Int64
	trace := &httptrace.ClientTrace{GotFirstResponseByte: func() { firstByte.CompareAndSwap(0, max(1, a.config.Now().Sub(started).Nanoseconds())) }}
	request, snapshot, err := a.buildRequest(httptrace.WithClientTrace(ctx, trace), input, parameter)
	if err != nil {
		return domain.NormalizedResponse{}, snapshot, err
	}
	if prepare != nil {
		if err := prepare(request); err != nil {
			if request.Body != nil {
				_ = request.Body.Close()
			}
			return domain.NormalizedResponse{}, snapshot, failure("MI_AUTH_PREPARATION_FAILED")
		}
	}
	response, err := a.config.Doer.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return domain.NormalizedResponse{ParseStatus: "invalid", EndCause: transportEnd(err), DurationMs: elapsed(a.config.Now(), started)}, snapshot, transportFailure(err)
	}
	if response == nil || response.Body == nil {
		return domain.NormalizedResponse{ParseStatus: "invalid", EndCause: "protocol"}, snapshot, failure("MI_PROTOCOL_INVALID")
	}
	headersAt := a.config.Now()
	var result domain.NormalizedResponse
	if input.Stream {
		result, err = a.parseStream(ctx, response, sink, started)
	} else {
		result, err = a.parseNonStream(ctx, response, started)
	}
	if ns := firstByte.Load(); ns != 0 {
		result.FirstByteMs = time.Duration(ns).Milliseconds()
	} else {
		result.FirstByteMs = elapsed(headersAt, started)
	}
	return result, snapshot, err
}

type PrecheckResult struct {
	Ready              bool                      `json:"ready"`
	Attempts           int                       `json:"attempts"`
	MaxOutputParameter string                    `json:"max_output_parameter"`
	FallbackUsed       bool                      `json:"fallback_used"`
	Response           domain.NormalizedResponse `json:"response"`
}

// Precheck is capability detection, not a scored sample. Only an explicit
// max_tokens unsupported-parameter response permits one alternate mapping call.
func (a *Adapter) Precheck(ctx context.Context, input domain.NormalizedRequest, prepare PrepareRequest) (PrecheckResult, error) {
	a.precheckMu.Lock()
	defer a.precheckMu.Unlock()
	input.Stream = false
	input.MaxOutputTokens = min(max(input.MaxOutputTokens, 1), 16)
	a.mu.RLock()
	parameter := a.parameter
	a.mu.RUnlock()
	response, _, err := a.call(ctx, input, parameter, prepare, nil)
	result := PrecheckResult{Ready: err == nil, Attempts: 1, MaxOutputParameter: parameter, Response: response}
	var upstream *Error
	if err == nil || !errors.As(err, &upstream) || upstream.UnsupportedParameter != "max_tokens" || parameter != "max_tokens" || a.fallbackTried {
		return result, err
	}
	a.fallbackTried = true
	response, _, err = a.call(ctx, input, "max_completion_tokens", prepare, nil)
	result = PrecheckResult{Ready: err == nil, Attempts: 2, MaxOutputParameter: "max_completion_tokens", FallbackUsed: true, Response: response}
	if err == nil {
		a.mu.Lock()
		a.parameter = "max_completion_tokens"
		a.mu.Unlock()
	}
	return result, err
}

func elapsed(now, started time.Time) int64 { return max(0, now.Sub(started).Milliseconds()) }
