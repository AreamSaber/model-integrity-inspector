package evidencedisplay

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

// This is a closed decoder schema, not a second wire encoder. Production
// request encoding remains exclusively in the actual adapter. Redacted text
// may contain [REDACTED], so re-validating it as an original model ID is wrong.
type requestReproductionWire struct {
	Model               string                     `json:"model"`
	Messages            []domain.NormalizedMessage `json:"messages"`
	Stream              *bool                      `json:"stream"`
	MaxTokens           *int                       `json:"max_tokens"`
	MaxCompletionTokens *int                       `json:"max_completion_tokens"`
	Temperature         *float64                   `json:"temperature"`
	TopP                *float64                   `json:"top_p"`
	Seed                *int64                     `json:"seed"`
	Stop                []string                   `json:"stop"`
	ResponseFormat      *domain.ResponseFormat     `json:"response_format"`
	FrequencyPenalty    *float64                   `json:"frequency_penalty"`
	PresencePenalty     *float64                   `json:"presence_penalty"`
	StreamOptions       *struct {
		IncludeUsage bool `json:"include_usage"`
	} `json:"stream_options"`
}

func validReproductionRequest(value string) bool {
	if len(value) == 0 || len(value) > MaxTextBytes || !utf8.ValidString(value) {
		return false
	}
	var wire requestReproductionWire
	d := json.NewDecoder(strings.NewReader(value))
	d.DisallowUnknownFields()
	if d.Decode(&wire) != nil || wire.Model == "" || len(wire.Messages) < 1 || len(wire.Messages) > 256 || wire.Stream == nil || (wire.MaxTokens == nil) == (wire.MaxCompletionTokens == nil) || len(wire.Stop) > 4 {
		return false
	}
	for _, message := range wire.Messages {
		if message.Role != "system" && message.Role != "developer" && message.Role != "user" && message.Role != "assistant" || strings.ContainsRune(message.Content, 0) {
			return false
		}
	}
	for _, stop := range wire.Stop {
		if stop == "" || strings.ContainsRune(stop, 0) {
			return false
		}
	}
	for _, n := range []*int{wire.MaxTokens, wire.MaxCompletionTokens} {
		if n != nil && (*n < 1 || *n > 131072) {
			return false
		}
	}
	for _, n := range []struct {
		value     *float64
		low, high float64
	}{{wire.Temperature, 0, 2}, {wire.TopP, 0, 1}, {wire.FrequencyPenalty, -2, 2}, {wire.PresencePenalty, -2, 2}} {
		if n.value != nil && (*n.value < n.low || *n.value > n.high) {
			return false
		}
	}
	if wire.ResponseFormat != nil && wire.ResponseFormat.Type != "text" && wire.ResponseFormat.Type != "json_object" {
		return false
	}
	if *wire.Stream != (wire.StreamOptions != nil) || wire.StreamOptions != nil && !wire.StreamOptions.IncludeUsage {
		return false
	}
	// Keep numeric wire lexemes as RawMessage (never float64 seeds). Exact
	// re-encoding rejects duplicates, alternate escaping and trailing values;
	// typed nested checks retain the adapter's role/content field order.
	var canonical map[string]json.RawMessage
	d = json.NewDecoder(strings.NewReader(value))
	if d.Decode(&canonical) != nil {
		return false
	}
	for name, field := range canonical {
		if bytes.Equal(field, []byte("null")) {
			return false
		}
		var nested any
		switch name {
		case "messages":
			nested = wire.Messages
		case "stop":
			nested = wire.Stop
		case "response_format":
			nested = wire.ResponseFormat
		case "stream_options":
			nested = wire.StreamOptions
		case "model":
			nested = wire.Model
		case "stream", "max_tokens", "max_completion_tokens", "temperature", "top_p", "seed", "frequency_penalty", "presence_penalty":
		default:
			return false
		}
		if nested != nil {
			encoded, err := json.Marshal(nested)
			valid := err == nil && bytes.Equal(encoded, field)
			clear(encoded)
			if !valid {
				return false
			}
		}
	}
	encoded, err := json.Marshal(canonical)
	defer clear(encoded)
	return err == nil && bytes.Equal(encoded, []byte(value))
}
