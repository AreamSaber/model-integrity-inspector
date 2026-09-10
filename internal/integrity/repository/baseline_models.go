package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

var (
	ErrBaselineInvalid   = errors.New("MI_BASELINE_INVALID")
	ErrBaselineIntegrity = errors.New("MI_BASELINE_INTEGRITY")
	ErrBaselineState     = errors.New("MI_BASELINE_STATE_CONFLICT")
	ErrBaselineSource    = errors.New("MI_BASELINE_SOURCE_INVALID")
	ErrBaselineExpired   = errors.New("MI_BASELINE_EXPIRED")
)

type BaselineSigner interface {
	ActiveVersion() string
	BaselineMAC(version string, canonical []byte) ([]byte, error)
}

// Scope has no request/response text, endpoints, credentials or arbitrary JSON.
// Parameter/variable fingerprints come from the authenticated frozen manifest.
type BaselineSampleScope struct {
	TemplateID, TemplateVersion, Family, Language string
	Variant, Repetition                           int
	MaxOutputTokens                               int
	Stream                                        bool
	Seed                                          *int64
	VariablesHash                                 string
}
type BaselineScope struct {
	SchemaVersion                               string
	OrganizationID, RunID, TargetID             int64
	AnalysisRevision                            int
	Model, Protocol, MaxOutputParameter         string
	Versions                                    domain.BundleVersions
	TemplateHash, TokenizerHash, ParametersHash string
	ManifestHash, ResultHash                    string
	ExpectedSamples, ValidSamples               int
	OverallRisk                                 *float64
	Completeness                                string
	SampledAt                                   time.Time
	Samples                                     []BaselineSampleScope
}

type BaselineRecord struct {
	ID, OrganizationID, RunID                            int64
	AnalysisRevision                                     int
	Name, Model, Protocol, Status                        string
	ApplicableScopeJSON                                  string `gorm:"column:applicable_scope_json" json:"-"`
	ReviewedBy                                           *int64
	CreatedAt                                            time.Time
	ReviewedAt                                           *time.Time
	ExpiresAt                                            time.Time
	Version                                              int
	CreatedBy                                            *int64
	Source, Region                                       string
	UpdatedAt                                            time.Time
	RetiredAt                                            *time.Time
	SourceManifestHash, SourceResultHash, ParametersHash string
	SnapshotJSON                                         string `gorm:"column:snapshot_json" json:"-"`
	SnapshotHash                                         string
	ApprovalKeyVersion, ApprovalMAC                      *string `json:"-"`
	ReviewExplanation                                    string  `json:"-"`
	RetirementReason                                     string  `json:"-"`
}

func (BaselineRecord) TableName() string { return "integrity_baselines" }

// BaselineSource is minted by the scoped authenticated Repository. It binds
// the source row versions/content hashes for a later transaction recheck.
// Only trusted baseline service code inspects this transient S2 source.
type BaselineSource struct {
	store                             *Store
	organizationID, runID, runVersion int64
	revision                          int
	configHash, resultHash            string
	bindingHash                       string
	plan                              domain.ExecutionPlan
	result                            PublishedRead
	createdAt                         time.Time
}

func (*BaselineSource) String() string               { return "[redacted baseline source]" }
func (s *BaselineSource) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, s.String()) }
func (*BaselineSource) MarshalJSON() ([]byte, error) { return nil, ErrBaselineSource }
func (s *BaselineSource) Inspect(fn func(domain.ExecutionPlan, PublishedRead, time.Time) error) error {
	if s == nil || s.store == nil || fn == nil {
		return ErrBaselineSource
	}
	return fn(s.plan, s.result, s.createdAt)
}

type BaselineMutation struct {
	Name, Source, Region string
	ExpiresAt            time.Time
}
type BaselineApproval struct {
	Version                      int
	Reason, BusinessReview       string
	AcknowledgeDevelopmentLimits bool
}
type BaselineList struct {
	AfterID       int64
	Limit         int
	Query, Status string
}
type BaselineRepository struct {
	store  *Store
	signer BaselineSigner
}

func NewBaselineRepository(store *Store, signer BaselineSigner) (*BaselineRepository, error) {
	if store == nil || signer == nil {
		return nil, ErrBaselineInvalid
	}
	return &BaselineRepository{store, signer}, nil
}
func baselineHash(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func baselineJSON(value any) (string, error) {
	b, err := json.Marshal(value)
	if err != nil || len(b) > 200<<10 {
		return "", ErrBaselineInvalid
	}
	return string(b), nil
}
