package generator

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

const Version = "1.0.0-dev.1"
const maxManifestBytes = 2 << 20

var ErrConfiguration = errors.New("MI_PROBE_CONFIGURATION_INVALID")
var ErrBudget = errors.New("MI_PROBE_BUDGET_INSUFFICIENT")
var ErrIntegrity = errors.New("MI_PROBE_MANIFEST_INTEGRITY")

// Signer exposes a purpose-specific MAC, never a credential/master-key accessor.
type Signer interface {
	ActiveVersion() string
	ProbeMAC(version string, payload []byte) ([]byte, error)
}

// Options is trusted composition data after authorization/catalog lookup and
// administrator budget clamping. Never bind it or an ExecutionPlan from HTTP.
type Options struct {
	OrganizationID  int64                   `json:"organization_id,string"`
	Target          domain.ExecutionTarget  `json:"target"`
	Package         string                  `json:"package"`
	Budget          domain.ExecutionBudget  `json:"budget"`
	Pricing         domain.ExecutionPricing `json:"pricing"`
	RuleVersion     string                  `json:"rule_version"`
	ScoringVersion  string                  `json:"scoring_version"`
	StandardModel   string                  `json:"standard_model"`
	ContextWindow   int                     `json:"context_window"`
	MaxOutputTokens int                     `json:"max_output_tokens"`
	SupportsStream  bool                    `json:"supports_stream"`
	SupportsSeed    bool                    `json:"supports_seed"`
	Temperature     *float64                `json:"temperature"`
	Concurrency     int                     `json:"concurrency"`
	MaxRetries      int                     `json:"max_retries"`
	BaselineRunID   *int64                  `json:"baseline_run_id,omitempty"`
	Custom          *Custom                 `json:"custom,omitempty"`
}

type Custom struct {
	Families    []string `json:"families"`
	Tiers       []int    `json:"tiers"`
	Repetitions int      `json:"repetitions"`
	Languages   []string `json:"languages"`
}

type Variables struct {
	Nonce string `json:"nonce"`
	Label string `json:"label"`
	Count int    `json:"count"`
	Style string `json:"style,omitempty"`
}

type Sample struct {
	Ordinal         int                `json:"ordinal"`
	ConditionID     string             `json:"condition_id"`
	TemplateID      string             `json:"template_id"`
	TemplateVersion string             `json:"template_version"`
	Family          string             `json:"family"`
	Language        string             `json:"language"`
	Variant         int                `json:"variant"`
	Repetition      int                `json:"repetition"`
	GroupID         string             `json:"group_id"`
	PairID          string             `json:"pair_id,omitempty"`
	Arm             string             `json:"arm,omitempty"`
	Variables       Variables          `json:"variables"`
	NonceMAC        string             `json:"nonce_mac"`
	Seed            *int64             `json:"seed,omitempty"`
	Stream          bool               `json:"stream"`
	MaxOutputTokens int                `json:"max_output_tokens"`
	InputEstimate   tokenizer.Estimate `json:"input_estimate"`
	RequestHash     string             `json:"request_hash"`
	AuxiliaryOnly   bool               `json:"auxiliary_only"`
}

type Omission struct {
	Group   string `json:"group"`
	Reason  string `json:"reason"`
	Samples int    `json:"samples"`
}

type Projection struct {
	Requests              int    `json:"requests"`
	InputTokens           int64  `json:"input_tokens"`
	OutputTokens          int64  `json:"output_tokens"`
	ReservedTokens        int64  `json:"reserved_tokens"`
	EstimatedCostMicros   *int64 `json:"estimated_cost_micros"`
	TimeUpperBoundSeconds int64  `json:"time_upper_bound_seconds"`
	// No provider billing promise: ignored caps/hidden reasoning can exceed
	// estimates. Execution reserves every actual Attempt separately.
	RetryRequestsIncluded bool `json:"retry_requests_included"`
}

// Manifest is S2 replay data. Canonical is the explicit persistence path; normal
// formatting is redacted. Integrity authenticates its full unsigned contents.
type Manifest struct {
	GeneratorVersion string     `json:"generator_version"`
	Options          Options    `json:"options"`
	RunNonce         string     `json:"run_nonce"`
	KeyVersion       string     `json:"key_version"`
	TemplateVersion  string     `json:"template_version"`
	TemplateHash     string     `json:"template_hash"`
	TokenizerVersion string     `json:"tokenizer_version"`
	TokenizerHash    string     `json:"tokenizer_hash"`
	Samples          []Sample   `json:"samples"`
	Omissions        []Omission `json:"omissions"`
	Warnings         []string   `json:"warnings"`
	Completeness     string     `json:"completeness"`
	Projection       Projection `json:"projection"`
	Integrity        string     `json:"integrity"`
}

func (Manifest) String() string                { return "[S2 probe manifest]" }
func (m Manifest) Format(w fmt.State, _ rune)  { _, _ = io.WriteString(w, m.String()) }
func (Sample) String() string                  { return "[S2 probe sample]" }
func (s Sample) Format(w fmt.State, _ rune)    { _, _ = io.WriteString(w, s.String()) }
func (Variables) String() string               { return "[S2 probe variables]" }
func (v Variables) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (m Manifest) LogValue() slog.Value        { return slog.StringValue(m.String()) }
func (s Sample) LogValue() slog.Value          { return slog.StringValue(s.String()) }
func (v Variables) LogValue() slog.Value       { return slog.StringValue(v.String()) }

func (m Manifest) Canonical() ([]byte, string, error) {
	data, err := json.Marshal(m)
	if err != nil || len(data) > maxManifestBytes {
		return nil, "", ErrIntegrity
	}
	return data, digest(data), nil
}
