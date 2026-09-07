package repository

import (
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

type RunRecord struct {
	ID                     int64
	OrganizationID         int64
	TargetID               int64
	BaselineRunID          *int64
	Package                string
	ObservationMode        string
	Status                 string
	ConfigSnapshot         string `json:"-"`
	ManifestHash           string
	RuleBundleVersion      string
	TemplateBundleVersion  string
	ScoringVersion         string
	TokenizerBundleVersion string
	RequestBudget          int64
	TokenBudget            int64
	MoneyBudgetMicros      *int64
	RequestCount           int64
	TokenCount             int64
	EstimatedCostMicros    int64
	ReservedTokens         int64
	ReservedCostMicros     int64
	CostKnown              bool
	ValidSampleCount       int
	ErrorSummary           *string
	CancelRequestedAt      *time.Time
	ExecutionClosedAt      *time.Time
	CreatedBy              int64
	CreatedAt              time.Time
	StartedAt              *time.Time
	FinishedAt             *time.Time
	DeadlineAt             *time.Time
	Version                int64
	RequestKey             string `json:"-"`
	PlanJobID              *int64
	FinalizedSampleCount   int64
	CircuitBreakerCode     string
	CircuitBreakerOpenedAt *time.Time
}

func (RunRecord) TableName() string { return "integrity_runs" }

type ProbeRecord struct {
	ID              int64
	OrganizationID  int64
	RunID           int64
	ProbeType       string
	TemplateID      string
	TemplateVersion string
	Category        string
	Variant         string
	PlannedSamples  int
	ValidSamples    int
	Status          string
	ParametersJSON  string `gorm:"column:parameters_json" json:"-"`
	CreatedAt       time.Time
	FinishedAt      *time.Time
}

func (ProbeRecord) TableName() string { return "integrity_probe_instances" }

type LogicalSampleRecord struct {
	ID                 int64
	OrganizationID     int64
	RunID              int64
	ProbeInstanceID    int64
	Ordinal            int
	PairID             *string
	IdempotencyKey     string
	RequestPlan        string `json:"-"`
	FinalAttemptID     *int64
	Validity           string
	CreatedAt          time.Time
	CompletedAt        *time.Time
	JobID              *int64
	AttemptCount       int
	ExecutionOrdinal   int
	FailureCode        string
	CompletionSequence *int64
}

func (LogicalSampleRecord) TableName() string { return "integrity_logical_samples" }

type AttemptRecord struct {
	ID                    int64
	OrganizationID        int64
	LogicalSampleID       int64
	RunID                 int64
	JobID                 int64
	LeaseGeneration       int
	AttemptNo             int
	Status                string
	Validity              string
	RequestSnapshot       string `json:"-"`
	RequestHash           string
	ResponseMeta          string `json:"-"`
	ErrorCode             *string
	HTTPStatus            *int `gorm:"column:http_status"`
	PromptTokens          *int64
	CompletionTokens      *int64
	TotalTokens           *int64
	LocalCompletionTokens *int64
	TokenizerID           string
	TokenizerQuality      string
	DurationMS            *int64 `gorm:"column:duration_ms"`
	ReservedTokens        int64
	ReservedCostMicros    int64
	CostKnown             bool
	BilledEstimateMicros  int64
	StartedAt             *time.Time
	FinishedAt            *time.Time
}

func (AttemptRecord) TableName() string { return "integrity_sample_attempts" }

type executionSnapshot struct {
	Plan   domain.ExecutionPlan   `json:"plan"`
	Limits domain.ExecutionLimits `json:"limits"`
}
