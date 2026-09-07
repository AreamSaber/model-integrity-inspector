package domain

import "encoding/json"

// ExecutionPlan is immutable S2 execution data, not an HTTP request DTO or log
// object. Credentials and custom headers have no representation in this type.
type ExecutionPlan struct {
	Target       ExecutionTarget `json:"target"`
	Package      string          `json:"package"`
	ManifestHash string          `json:"manifest_hash"`
	// Manifest is S2 reproduction metadata, never a log field. Low-level legacy
	// fixtures may omit it; the public service must require a verified compiler
	// manifest and derive the Plan from it, not accept an arbitrary HTTP Plan.
	Manifest      json.RawMessage  `json:"manifest,omitempty"`
	Versions      BundleVersions   `json:"versions"`
	Budget        ExecutionBudget  `json:"budget"`
	Pricing       ExecutionPricing `json:"pricing"`
	Concurrency   int              `json:"concurrency"`
	MaxRetries    int              `json:"max_retries"`
	BaselineRunID *int64           `json:"baseline_run_id,omitempty"`
	Probes        []ProbePlan      `json:"probes"`
}

type ExecutionTarget struct {
	ID                 int64  `json:"id"`
	Version            int64  `json:"version"`
	SecretID           int64  `json:"secret_id"`
	SecretVersion      int64  `json:"secret_version"`
	Endpoint           string `json:"endpoint"`
	Model              string `json:"model"`
	Protocol           string `json:"protocol"`
	MaxOutputParameter string `json:"max_output_parameter"`
}

type BundleVersions struct {
	Rule      string `json:"rule"`
	Template  string `json:"template"`
	Scoring   string `json:"scoring"`
	Tokenizer string `json:"tokenizer"`
}

type ExecutionBudget struct {
	MaxRequests    int64  `json:"max_requests"`
	MaxTokens      int64  `json:"max_tokens"`
	MaxCostMicros  *int64 `json:"max_cost_micros,omitempty"`
	TimeoutSeconds int64  `json:"timeout_seconds"`
}

type ExecutionPricing struct {
	InputMicrosPerMillion  *int64 `json:"input_micros_per_million,omitempty"`
	OutputMicrosPerMillion *int64 `json:"output_micros_per_million,omitempty"`
}

type ProbePlan struct {
	Type            string       `json:"type"`
	TemplateID      string       `json:"template_id"`
	TemplateVersion string       `json:"template_version"`
	Category        string       `json:"category"`
	Variant         string       `json:"variant"`
	Samples         []SamplePlan `json:"samples"`
}

type SamplePlan struct {
	Ordinal              int               `json:"ordinal"`
	PairID               string            `json:"pair_id,omitempty"`
	Nonce                string            `json:"nonce"`
	Request              NormalizedRequest `json:"request"`
	EstimatedInputTokens int64             `json:"estimated_input_tokens"`
}

// ExecutionLimits is server/administrator configuration; it must not be bound
// from user JSON. Scheduler Policy freezes a clamped copy in the Run snapshot.
type ExecutionLimits struct {
	Global             int   `json:"global"`
	Organization       int   `json:"organization"`
	Target             int   `json:"target"`
	Run                int   `json:"run"`
	TargetRPM          int   `json:"target_rpm"`
	MaxRequests        int64 `json:"max_requests"`
	MaxTokens          int64 `json:"max_tokens"`
	MaxCostMicros      int64 `json:"max_cost_micros"`
	MaxDurationSeconds int64 `json:"max_duration_seconds"`
}

// AttemptOutcome contains only bounded classifications and usage. Evidence
// bodies, provider strings and credentials are deliberately not accepted here.
type AttemptOutcome struct {
	Validity              string
	ErrorCode             string
	HTTPStatus            int
	PromptTokens          *int64
	CompletionTokens      *int64
	LocalCompletionTokens int64
	RetryAfterSeconds     int64
	DurationMillis        int64
}
