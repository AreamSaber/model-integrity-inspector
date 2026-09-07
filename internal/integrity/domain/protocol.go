package domain

import "encoding/json"

// Protocol DTOs contain probe inputs and untrusted model output, never credentials.
type NormalizedMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ResponseFormat struct {
	Type string `json:"type"`
}

type NormalizedRequest struct {
	Model              string              `json:"model"`
	Messages           []NormalizedMessage `json:"messages"`
	Temperature        *float64            `json:"temperature,omitempty"`
	TopP               *float64            `json:"top_p,omitempty"`
	Seed               *int64              `json:"seed,omitempty"`
	MaxOutputTokens    int                 `json:"max_output_tokens"`
	Stream             bool                `json:"stream"`
	Stop               []string            `json:"stop,omitempty"`
	ResponseFormat     *ResponseFormat     `json:"response_format,omitempty"`
	ExtraAllowedParams map[string]any      `json:"extra_allowed_params,omitempty"`
}

// RequestSnapshot is captured before the Worker attaches scoped auth headers.
// Payload is S2 probe content, not a log DTO; its hash covers only wire JSON.
type RequestSnapshot struct {
	Model              string          `json:"model"`
	Stream             bool            `json:"stream"`
	MaxOutputTokens    int             `json:"max_output_tokens"`
	MaxOutputParameter string          `json:"max_output_parameter"`
	Payload            json.RawMessage `json:"payload"`
	PayloadBytes       int             `json:"payload_bytes"`
	RequestHash        string          `json:"request_hash"`
}

type StreamEventSummary struct {
	Sequence   int    `json:"sequence"`
	Type       string `json:"type"`
	Bytes      int    `json:"bytes"`
	ArrivalMs  int64  `json:"arrival_ms"`
	IntervalMs int64  `json:"interval_ms"`
}

type NormalizedResponse struct {
	ProviderRequestID string               `json:"provider_request_id"`
	ModelReported     string               `json:"model_reported"`
	Content           string               `json:"content"`
	FinishReason      string               `json:"finish_reason"`
	PromptTokens      *int64               `json:"prompt_tokens"`
	CompletionTokens  *int64               `json:"completion_tokens"`
	TotalTokens       *int64               `json:"total_tokens"`
	ReasoningTokens   *int64               `json:"reasoning_tokens"`
	HTTPStatus        int                  `json:"http_status"`
	ContentType       string               `json:"content_type"`
	FirstByteMs       int64                `json:"first_byte_ms"`
	FirstTokenMs      *int64               `json:"first_token_ms"`
	DurationMs        int64                `json:"duration_ms"`
	StreamChunkCount  int                  `json:"stream_chunk_count"`
	StreamTerminated  bool                 `json:"stream_terminated"`
	ParseWarnings     []string             `json:"parse_warnings"`
	HeaderSummary     map[string]string    `json:"header_summary"`
	RawResponseBytes  int64                `json:"raw_response_bytes"`
	ResponseHash      string               `json:"response_hash"`
	ParseStatus       string               `json:"parse_status"`
	ChoiceCount       int                  `json:"choice_count"`
	Refusal           bool                 `json:"refusal"`
	EndCause          string               `json:"end_cause"`
	Events            []StreamEventSummary `json:"events,omitempty"`
}

type AdapterCapabilities struct {
	Protocol            string   `json:"protocol"`
	Streaming           bool     `json:"streaming"`
	StreamUsage         bool     `json:"stream_usage"`
	Seed                bool     `json:"seed"`
	MaxOutputParameters []string `json:"max_output_parameters"`
	ResponseFormats     []string `json:"response_formats"`
	ExtraParameters     []string `json:"extra_parameters"`
	MaxOutputTokens     int      `json:"max_output_tokens"`
}
