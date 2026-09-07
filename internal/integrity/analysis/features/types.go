// Package features assembles final-attempt features from authenticated replay
// data and trusted persistence projections. It is not a database authenticator.
package features

import (
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/behavior"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/structure"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

const Version = "1.0.0-dev.1"
const MaxResponseBytes = 1 << 20
const MaxBatchBytes = 8 << 20

var ErrConfiguration = errors.New("MI_FEATURE_CONFIGURATION_INVALID")
var ErrBinding = errors.New("MI_FEATURE_BINDING_INVALID")
var ErrLimit = errors.New("MI_FEATURE_RESOURCE_LIMIT")

type Config struct {
	Verifier            *generator.Generator
	Tokenizer           *tokenizer.Engine
	TemplateArtifact    []byte
	TrustedTemplateHash string
}

// Input and its nested projections are S2, not API or logging DTOs. The trusted
// Worker must read these under its organization/Run analysis lease and decrypt
// Evidence using exactly the persisted AAD scope. Consistent fabricated rows
// cannot be distinguished from genuine database rows by this pure package.
type Input struct {
	Run     RunBinding
	Samples []SampleBinding
}

type RunBinding struct {
	OrganizationID, ID int64
	Plan               domain.ExecutionPlan
	ExecutionClosedAt  time.Time
}

// All attempts (including unsuccessful retries) are required for identity and
// final-pointer validation. Ordinal is the persisted global manifest ordinal;
// completion order is deliberately not treated as experimental order.
type SampleBinding struct {
	OrganizationID, RunID, ID, ProbeInstanceID int64
	Ordinal, ExecutionOrdinal                  int
	RequestPlan                                domain.SamplePlan
	PairID                                     string
	AttemptCount                               int
	FinalAttemptID                             *int64
	Validity                                   string
	CompletedAt                                time.Time
	Attempts                                   []AttemptBinding
}

type AttemptBinding struct {
	OrganizationID, RunID, SampleID, ID, JobID int64
	Number                                     int
	Status, Validity, ErrorCode                string
	Snapshot                                   domain.RequestSnapshot
	RequestHash                                string
	StartedAt, FinishedAt                      time.Time
	Evidence                                   *Evidence
}

type EvidenceScope struct {
	OrganizationID, RunID, SampleID, AttemptID int64
	RequestHash                                string
}

// Evidence is a protected, already-decrypted projection, NOT proof of successful
// cryptographic verification. NewEvidence never replaces KeyRing AAD validation.
type Evidence struct {
	scope    EvidenceScope
	response domain.NormalizedResponse
}

// NewEvidence copies the response. It deliberately exposes no plaintext getter.
func NewEvidence(scope EvidenceScope, response domain.NormalizedResponse) (*Evidence, error) {
	if !responseBounded(response) {
		return nil, ErrLimit
	}
	data, err := json.Marshal(response)
	if err != nil || len(data) > MaxResponseBytes {
		return nil, ErrLimit
	}
	defer clear(data)
	var owned domain.NormalizedResponse
	if json.Unmarshal(data, &owned) != nil {
		return nil, ErrBinding
	}
	return &Evidence{scope: scope, response: owned}, nil
}

// Result contains classifications, identifiers, hashes and numeric features
// only. Missing/invalid observations have nil features, not effective zeroes.
type Result struct {
	Version        string          `json:"version"`
	OrganizationID string          `json:"organization_id"`
	RunID          string          `json:"run_id"`
	ManifestHash   string          `json:"manifest_hash"`
	Expected       int             `json:"expected_samples"`
	Included       int             `json:"included_samples"`
	Excluded       int             `json:"excluded_samples"`
	Partial        bool            `json:"partial"`
	Limitations    []string        `json:"limitations"`
	Samples        []SampleFeature `json:"samples"`
}

type SampleFeature struct {
	SampleID             string              `json:"sample_id"`
	AttemptID            string              `json:"attempt_id,omitempty"`
	Ordinal              int                 `json:"ordinal"`
	AttemptNumber        int                 `json:"attempt_number"`
	Validity             string              `json:"validity"`
	Included             bool                `json:"included"`
	AuxiliaryOnly        bool                `json:"auxiliary_only"`
	ReasoningUnseparated bool                `json:"reasoning_unseparated"`
	Family               string              `json:"family"`
	Language             string              `json:"language"`
	TemplateID           string              `json:"template_id"`
	TemplateVersion      string              `json:"template_version"`
	ConditionHash        string              `json:"condition_hash"`
	SeriesHash           string              `json:"series_hash"`
	ClusterHash          string              `json:"cluster_hash"`
	PairHash             string              `json:"pair_hash,omitempty"`
	ManifestRequestHash  string              `json:"manifest_request_hash"`
	WireRequestHash      string              `json:"wire_request_hash,omitempty"`
	RequestedMaxTokens   int                 `json:"requested_max_tokens"`
	Stream               bool                `json:"stream"`
	Protocol             *ProtocolFeature    `json:"protocol,omitempty"`
	Local                *tokenizer.Estimate `json:"local,omitempty"`
	Usage                *UsageFeature       `json:"usage,omitempty"`
	Structure            *structure.Features `json:"structure,omitempty"`
	Behavior             *behavior.Features  `json:"behavior,omitempty"`
	Limitations          []string            `json:"limitations"`
}

type ProtocolFeature struct {
	State            string   `json:"state"`
	HTTPStatus       int      `json:"http_status"`
	Partial          bool     `json:"partial"`
	StreamTerminated bool     `json:"stream_terminated"`
	ModelMismatch    bool     `json:"model_mismatch"`
	ModelEcho        string   `json:"model_echo"`
	DurationMillis   int64    `json:"duration_ms"`
	FirstByteMillis  int64    `json:"first_byte_ms"`
	FirstTokenMillis *int64   `json:"first_token_ms,omitempty"`
	ChunkCount       int      `json:"chunk_count"`
	Warnings         []string `json:"warnings"`
}

type UsageFeature struct {
	ReportedPrompt     *int64   `json:"reported_prompt,omitempty"`
	ReportedCompletion *int64   `json:"reported_completion,omitempty"`
	ReportedTotal      *int64   `json:"reported_total,omitempty"`
	ReportedReasoning  *int64   `json:"reported_reasoning,omitempty"`
	Available          bool     `json:"available"`
	RelativeError      *float64 `json:"relative_error,omitempty"`
	Direction          int      `json:"direction"`
	Band               string   `json:"band"`
	Eligible           bool     `json:"eligible_for_aggregate"`
	ReasoningSeparated bool     `json:"reasoning_separated"`
}

// Batch has no plaintext accessors. Features returns an independent S1 copy.
// Kernel inputs are ephemeral capabilities with only pure analysis methods.
type Batch struct {
	features Result
	tokens   tokenrisk.Input
	behavior []behavior.Sample
	engine   *behavior.Engine
}

func (b *Batch) Features() Result {
	if b == nil {
		return Result{}
	}
	data, _ := json.Marshal(b.features)
	var result Result
	_ = json.Unmarshal(data, &result)
	return result
}

type OpaqueTokenInput struct {
	batch  *Batch
	active *atomic.Bool
}
type OpaqueBehaviorInput struct {
	batch  *Batch
	active *atomic.Bool
}

func (b *Batch) WithTokenInput(fn func(OpaqueTokenInput) error) error {
	if b == nil || fn == nil {
		return ErrConfiguration
	}
	active := &atomic.Bool{}
	active.Store(true)
	defer active.Store(false)
	return fn(OpaqueTokenInput{batch: b, active: active})
}
func (b *Batch) WithBehaviorInput(fn func(OpaqueBehaviorInput) error) error {
	if b == nil || fn == nil {
		return ErrConfiguration
	}
	active := &atomic.Bool{}
	active.Store(true)
	defer active.Store(false)
	return fn(OpaqueBehaviorInput{batch: b, active: active})
}
func (i OpaqueTokenInput) Analyze() (tokenrisk.Result, error) {
	if i.batch == nil || i.active == nil || !i.active.Load() {
		return tokenrisk.Result{}, ErrConfiguration
	}
	return tokenrisk.Analyze(i.batch.tokens)
}
func (i OpaqueBehaviorInput) AnalyzeBatch() (behavior.Batch, error) {
	if i.batch == nil || i.active == nil || !i.active.Load() {
		return behavior.Batch{}, ErrConfiguration
	}
	return i.batch.engine.AnalyzeBatch(i.batch.behavior)
}
func (i OpaqueBehaviorInput) PairedDifference(metric behavior.Metric) (behavior.Difference, error) {
	if i.batch == nil || i.active == nil || !i.active.Load() {
		return behavior.Difference{}, ErrConfiguration
	}
	return i.batch.engine.PairedDifference(i.batch.behavior, metric)
}
