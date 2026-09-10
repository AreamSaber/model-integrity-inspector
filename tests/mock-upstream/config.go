// Package mockupstream implements a bounded, synthetic Chat Completions server
// for protocol and algorithm tests. It never calls a real upstream model.
package mockupstream

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

const (
	MaxOutputTokens = 8192
	MaxRequestBytes = 1 << 20
	MaxContentBytes = 1 << 20
)

// CapStep applies a cap when the requested output budget reaches MinRequested.
// Steps must be strictly ordered by MinRequested. The last matching step wins.
type CapStep struct {
	MinRequested int `json:"min_requested"`
	Cap          int `json:"cap"`
}

// Config is test-controller data. It must not be supplied to a detector or
// serialized in responses. Probability is deterministic for a sequential replay
// of the same requests under the same seed, independent of wall-clock time.
type Config struct {
	Seed                int64         `json:"seed"`
	InjectInstruction   string        `json:"inject_system_instruction,omitempty"`
	Prefix              string        `json:"prefix,omitempty"`
	Suffix              string        `json:"response_suffix,omitempty"`
	OverrideMaxTokens   int           `json:"override_max_tokens,omitempty"`
	OverrideProbability float64       `json:"override_probability"`
	CapSteps            []CapStep     `json:"cap_steps,omitempty"`
	UsageMode           string        `json:"usage_mode,omitempty"`
	UsageFactor         float64       `json:"usage_factor,omitempty"`
	FinishReasonMode    string        `json:"finish_reason_mode,omitempty"`
	StreamMode          string        `json:"stream_mode,omitempty"`
	StreamCutoffTokens  int           `json:"stream_cutoff_tokens,omitempty"`
	StreamChunkTokens   int           `json:"stream_chunk_tokens,omitempty"`
	DelayMilliseconds   int           `json:"delay_milliseconds,omitempty"`
	ModelAlias          string        `json:"model_alias,omitempty"`
	HTTPErrorRate       float64       `json:"http_error_rate,omitempty"`
	HTTPErrorStatus     int           `json:"http_error_status,omitempty"`
	RetryAfterSeconds   int           `json:"retry_after_seconds,omitempty"`
	NetworkErrorRate    float64       `json:"network_error_rate,omitempty"`
	NaturalEarlyEOS     bool          `json:"natural_early_eos,omitempty"`
	SafetyRefusal       bool          `json:"safety_refusal,omitempty"`
	ReasoningTokens     int           `json:"reasoning_tokens,omitempty"`
	RequiredAPIKey      string        `json:"-"`
	MaxRecords          int           `json:"max_records,omitempty"`
	Responder           Responder     `json:"-"`
	Delay               time.Duration `json:"-"`
}

// Generation contains synthetic token pieces, not tokens from a production
// model vocabulary. A fixture-specific responder can supply exact token pieces.
// The server joins pieces without separators and clips at the effective cap.
type Generation struct {
	Tokens       []string
	PromptTokens int
	FinishReason string
}

type Responder func(Request, int) (Generation, error)

func (c Config) validate() error {
	for name, rate := range map[string]float64{
		"override_probability": c.OverrideProbability,
		"http_error_rate":      c.HTTPErrorRate,
		"network_error_rate":   c.NetworkErrorRate,
	} {
		if math.IsNaN(rate) || math.IsInf(rate, 0) || rate < 0 || rate > 1 {
			return fmt.Errorf("%s must be in [0,1]", name)
		}
	}
	for name, value := range map[string]int{
		"override_max_tokens":  c.OverrideMaxTokens,
		"stream_cutoff_tokens": c.StreamCutoffTokens,
		"stream_chunk_tokens":  c.StreamChunkTokens,
		"reasoning_tokens":     c.ReasoningTokens,
	} {
		if value < 0 || value > MaxOutputTokens {
			return fmt.Errorf("%s must be in [0,%d]", name, MaxOutputTokens)
		}
	}
	previous := 0
	for _, step := range c.CapSteps {
		if step.MinRequested <= previous || step.MinRequested > MaxOutputTokens || step.Cap < 1 || step.Cap > MaxOutputTokens {
			return errors.New("cap_steps must be ordered, unique and bounded")
		}
		previous = step.MinRequested
	}
	for name, option := range map[string]struct{ value, allowed string }{
		"inject_system_instruction": {c.InjectInstruction, "|fixed_prefix|forced_identity|neutral_refusal"},
		"usage_mode":                {c.UsageMode, "|honest|missing|inflated|deflated"},
		"finish_reason_mode":        {c.FinishReasonMode, "|honest|always_stop|always_length|missing"},
		"stream_mode":               {c.StreamMode, "|normal|truncate|omit_done|delay|malformed_event"},
	} {
		if !slices.Contains(strings.Split(option.allowed, "|"), option.value) {
			return fmt.Errorf("unsupported %s", name)
		}
	}
	if math.IsNaN(c.UsageFactor) || math.IsInf(c.UsageFactor, 0) || c.UsageFactor < 0 || c.UsageFactor > 100 {
		return errors.New("usage_factor must be finite and in [0,100]")
	}
	if c.UsageFactor != 0 && ((c.UsageMode == "inflated" && c.UsageFactor <= 1) || (c.UsageMode == "deflated" && c.UsageFactor >= 1)) {
		return errors.New("usage_factor contradicts the configured usage mode")
	}
	if c.Delay < 0 || c.Delay > 10*time.Second || c.DelayMilliseconds < 0 || c.DelayMilliseconds > 10000 || c.RetryAfterSeconds < 0 || c.RetryAfterSeconds > 60 {
		return errors.New("delay or retry-after outside safe bounds")
	}
	if c.HTTPErrorStatus != 0 && c.HTTPErrorStatus != 400 && c.HTTPErrorStatus != 401 && c.HTTPErrorStatus != 404 && c.HTTPErrorStatus != 429 && (c.HTTPErrorStatus < 500 || c.HTTPErrorStatus > 599) {
		return errors.New("http_error_status must be 400, 401, 404, 429 or 5xx")
	}
	if len(c.Prefix) > 1024 || len(c.Suffix) > 1024 || len(c.ModelAlias) > 128 || c.MaxRecords < 0 || c.MaxRecords > 10000 {
		return errors.New("text or record count outside safe bounds")
	}
	return nil
}
