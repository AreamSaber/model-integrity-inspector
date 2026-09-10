// Package baseline manages organization-reviewed comparison references. It
// never authenticates an official provider or mints calibrated scoring trust.
package baseline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"sort"
	"strconv"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

const ScopeVersion = "baseline.scope.v1"

type Verifier interface {
	Verify([]byte, string, int64) (generator.Manifest, error)
}
type Config struct {
	Store     *repository.Store
	Generator Verifier
	Signer    repository.BaselineSigner
}
type Service struct {
	store    *repository.Store
	repo     *repository.BaselineRepository
	verifier Verifier
}

func NewService(c Config) (*Service, error) {
	if c.Store == nil || c.Generator == nil || c.Signer == nil {
		return nil, repository.ErrBaselineInvalid
	}
	r, err := repository.NewBaselineRepository(c.Store, c.Signer)
	if err != nil {
		return nil, err
	}
	return &Service{c.Store, r, c.Generator}, nil
}

type CreateInput struct {
	RunID                int64
	AnalysisRevision     int
	Name, Source, Region string
	ExpiresAt            time.Time
}
type PatchInput struct {
	Version   int
	Name      *string
	ExpiresAt *time.Time
}
type ApprovalInput = repository.BaselineApproval
type ListInput = repository.BaselineList
type View struct {
	ID                 string     `json:"id"`
	RunID              string     `json:"run_id"`
	TargetID           string     `json:"target_id"`
	AnalysisRevision   int        `json:"analysis_revision"`
	Version            int        `json:"version"`
	Name               string     `json:"name"`
	Source             string     `json:"source"`
	SourceAssurance    string     `json:"source_assurance"`
	Region             string     `json:"region"`
	RegionAssurance    string     `json:"region_assurance"`
	Model              string     `json:"model"`
	Protocol           string     `json:"protocol"`
	ParametersHash     string     `json:"parameters_hash"`
	ManifestHash       string     `json:"manifest_hash"`
	RuleVersion        string     `json:"rule_version"`
	TemplateVersion    string     `json:"template_version"`
	ScoringVersion     string     `json:"scoring_version"`
	TokenizerVersion   string     `json:"tokenizer_version"`
	Status             string     `json:"status"`
	ExpectedSamples    int        `json:"expected_samples"`
	ValidSamples       int        `json:"valid_samples"`
	OverallRisk        *float64   `json:"overall_risk"`
	CreatedBy          string     `json:"created_by"`
	ApprovedBy         *string    `json:"approved_by"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	SampledAt          time.Time  `json:"sampled_at"`
	ApprovedAt         *time.Time `json:"approved_at"`
	ExpiresAt          time.Time  `json:"expires_at"`
	RetiredAt          *time.Time `json:"retired_at"`
	ApprovalMeaning    string     `json:"approval_meaning"`
	Development        bool       `json:"development"`
	Calibrated         bool       `json:"calibrated"`
	EligibleForScoring bool       `json:"eligible_for_scoring"`
	Limitations        []string   `json:"limitations"`
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func hashObject(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", repository.ErrBaselineSource
	}
	return digest(raw), nil
}
func (s *Service) authorize(ctx context.Context, orgID int64) error {
	return s.store.RequireControlAuthority(ctx, orgID)
}

func (s *Service) prepare(ctx context.Context, orgID, runID int64, revision int) (*repository.BaselineSource, repository.BaselineScope, error) {
	if err := s.authorize(ctx, orgID); err != nil {
		return nil, repository.BaselineScope{}, err
	}
	source, err := s.repo.Source(ctx, orgID, runID, revision)
	if err != nil {
		return nil, repository.BaselineScope{}, err
	}
	var scope repository.BaselineScope
	err = source.Inspect(func(plan domain.ExecutionPlan, published repository.PublishedRead, sampled time.Time) error {
		doc, err := runservice.ValidatePublishedSource(published)
		if err != nil {
			return repository.ErrBaselineSource
		}
		manifest, err := s.verifier.Verify(plan.Manifest, plan.ManifestHash, orgID)
		if err != nil {
			return repository.ErrBaselineSource
		}
		if manifest.Options.Target.ID != published.Run.TargetID || manifest.Options.Target.Model != plan.Target.Model || manifest.Options.Target.Protocol != plan.Target.Protocol || manifest.Options.RuleVersion != published.Run.RuleBundleVersion || manifest.Options.ScoringVersion != published.Run.ScoringVersion || manifest.TemplateVersion != published.Run.TemplateBundleVersion || manifest.TokenizerVersion != published.Run.TokenizerBundleVersion || len(manifest.Samples) != doc.Features.Expected {
			return repository.ErrBaselineSource
		}
		scope = repository.BaselineScope{SchemaVersion: ScopeVersion, OrganizationID: orgID, RunID: runID, TargetID: plan.Target.ID, AnalysisRevision: revision, Model: manifest.Options.Target.Model, Protocol: manifest.Options.Target.Protocol, MaxOutputParameter: manifest.Options.Target.MaxOutputParameter, Versions: domain.BundleVersions{Rule: manifest.Options.RuleVersion, Template: manifest.TemplateVersion, Scoring: manifest.Options.ScoringVersion, Tokenizer: manifest.TokenizerVersion}, TemplateHash: manifest.TemplateHash, TokenizerHash: manifest.TokenizerHash, ManifestHash: plan.ManifestHash, ResultHash: digest([]byte(published.Result.ConclusionJSON)), ExpectedSamples: doc.Scores.ExpectedSamples, ValidSamples: doc.Scores.ValidSamples, OverallRisk: doc.Scores.Overall.Score, Completeness: doc.Scores.Completeness, SampledAt: sampled, Samples: []repository.BaselineSampleScope{}}
		for _, sample := range manifest.Samples {
			variables, err := hashObject(sample.Variables)
			if err != nil {
				return err
			}
			scope.Samples = append(scope.Samples, repository.BaselineSampleScope{TemplateID: sample.TemplateID, TemplateVersion: sample.TemplateVersion, Family: sample.Family, Language: sample.Language, Variant: sample.Variant, Repetition: sample.Repetition, MaxOutputTokens: sample.MaxOutputTokens, Stream: sample.Stream, Seed: sample.Seed, VariablesHash: variables})
		}
		// Canonical condition ordering is independent of shuffled dispatch. A
		// distribution match excludes the experimental nonce and individual seed;
		// the separate paired check below requires those to match exactly.
		sort.Slice(scope.Samples, func(i, j int) bool {
			a, _ := json.Marshal(scope.Samples[i])
			b, _ := json.Marshal(scope.Samples[j])
			return bytes.Compare(a, b) < 0
		})
		fixed := slices.Clone(scope.Samples)
		for i := range fixed {
			fixed[i].VariablesHash = ""
			fixed[i].Seed = nil
		}
		scope.ParametersHash, err = hashObject(struct {
			Version, Model, Protocol, Parameter string
			Temperature                         *float64
			SupportsSeed                        bool
			Conditions                          []repository.BaselineSampleScope
		}{ScopeVersion, scope.Model, scope.Protocol, scope.MaxOutputParameter, manifest.Options.Temperature, manifest.Options.SupportsSeed, fixed})
		return err
	})
	return source, scope, err
}
func decodeScope(r repository.BaselineRecord) (repository.BaselineScope, error) {
	var scope repository.BaselineScope
	if len(r.SnapshotJSON) < 2 || len(r.SnapshotJSON) > 200<<10 || digest([]byte(r.SnapshotJSON)) != r.SnapshotHash {
		return scope, repository.ErrBaselineIntegrity
	}
	decoder := json.NewDecoder(bytes.NewBufferString(r.SnapshotJSON))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&scope) != nil || decoder.Decode(new(any)) != io.EOF {
		return scope, repository.ErrBaselineIntegrity
	}
	if scope.SchemaVersion != ScopeVersion || scope.OrganizationID != r.OrganizationID || scope.RunID != r.RunID || scope.AnalysisRevision != r.AnalysisRevision || scope.Model != r.Model || scope.Protocol != r.Protocol || scope.ManifestHash != r.SourceManifestHash || scope.ResultHash != r.SourceResultHash || scope.ParametersHash != r.ParametersHash || scope.ExpectedSamples != len(scope.Samples) || scope.ExpectedSamples < 1 || scope.ExpectedSamples > 150 || scope.ValidSamples < 0 || scope.ValidSamples > scope.ExpectedSamples || scope.Versions.Scoring != scoring.Version {
		return scope, repository.ErrBaselineIntegrity
	}
	return scope, nil
}
func view(r repository.BaselineRecord) (View, error) {
	scope, err := decodeScope(r)
	if err != nil {
		return View{}, err
	}
	status := r.Status
	limitations := []string{"MI_BASELINE_SOURCE_ORGANIZATION_DECLARED", "MI_BASELINE_REGION_UNVERIFIED", "MI_DEVELOPMENT_RULES_UNCALIBRATED", "MI_PUBLIC_DEVELOPMENT_TEMPLATES", "MI_BASELINE_SCORING_NOT_ENABLED"}
	if status != "retired" && !r.ExpiresAt.After(time.Now()) {
		status = "expired"
		limitations = append(limitations, "MI_BASELINE_EXPIRED_RESAMPLE")
	}
	if status == "draft" {
		limitations = append(limitations, "MI_BASELINE_NOT_APPROVED")
	}
	if scope.Completeness != "COMPLETE" {
		limitations = append(limitations, "MI_BASELINE_SOURCE_PARTIAL")
	}
	var approved *string
	if r.ReviewedBy != nil {
		value := strconv.FormatInt(*r.ReviewedBy, 10)
		approved = &value
	}
	return View{ID: strconv.FormatInt(r.ID, 10), RunID: strconv.FormatInt(r.RunID, 10), TargetID: strconv.FormatInt(scope.TargetID, 10), AnalysisRevision: r.AnalysisRevision, Version: r.Version, Name: r.Name, Source: r.Source, SourceAssurance: "organization_declared_unverified", Region: r.Region, RegionAssurance: "organization_declared_unverified", Model: r.Model, Protocol: r.Protocol, ParametersHash: r.ParametersHash, ManifestHash: r.SourceManifestHash, RuleVersion: scope.Versions.Rule, TemplateVersion: scope.Versions.Template, ScoringVersion: scope.Versions.Scoring, TokenizerVersion: scope.Versions.Tokenizer, Status: status, ExpectedSamples: scope.ExpectedSamples, ValidSamples: scope.ValidSamples, OverallRisk: scope.OverallRisk, CreatedBy: strconv.FormatInt(*r.CreatedBy, 10), ApprovedBy: approved, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, SampledAt: scope.SampledAt, ApprovedAt: r.ReviewedAt, ExpiresAt: r.ExpiresAt, RetiredAt: r.RetiredAt, ApprovalMeaning: "organization_reviewed_reference_only", Development: true, Calibrated: false, EligibleForScoring: false, Limitations: limitations}, nil
}
func (s *Service) Create(ctx context.Context, orgID int64, input CreateInput) (View, error) {
	source, scope, err := s.prepare(ctx, orgID, input.RunID, input.AnalysisRevision)
	if err != nil {
		return View{}, err
	}
	r, err := s.repo.Create(ctx, orgID, source, scope, repository.BaselineMutation{Name: input.Name, Source: input.Source, Region: input.Region, ExpiresAt: input.ExpiresAt})
	if err != nil {
		return View{}, err
	}
	return view(r)
}
func (s *Service) Get(ctx context.Context, orgID, id int64) (View, error) {
	r, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return View{}, err
	}
	return view(r)
}
func (s *Service) List(ctx context.Context, orgID int64, input ListInput) ([]View, error) {
	rows, err := s.repo.List(ctx, orgID, input)
	if err != nil {
		return nil, err
	}
	out := make([]View, 0, len(rows))
	for _, r := range rows {
		v, e := view(r)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (s *Service) Patch(ctx context.Context, orgID, id int64, input PatchInput) (View, error) {
	r, err := s.repo.Update(ctx, orgID, id, input.Version, input.Name, input.ExpiresAt)
	if err != nil {
		return View{}, err
	}
	return view(r)
}
func (s *Service) Approve(ctx context.Context, orgID, id int64, input ApprovalInput) (View, error) {
	r, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return View{}, err
	}
	source, scope, err := s.prepare(ctx, orgID, r.RunID, r.AnalysisRevision)
	if err != nil {
		return View{}, err
	}
	r, err = s.repo.Approve(ctx, orgID, id, source, scope, input)
	if err != nil {
		return View{}, err
	}
	return view(r)
}
func (s *Service) Retire(ctx context.Context, orgID, id int64, version int, reason string) (View, error) {
	r, err := s.repo.Retire(ctx, orgID, id, version, reason)
	if err != nil {
		return View{}, err
	}
	return view(r)
}

// Applicability is descriptive metadata compatibility, NOT a scoring capability.
// The supported development release has no calibrated baseline admission path.
type Applicability struct {
	BaselineID           string   `json:"baseline_id"`
	CandidateRunID       string   `json:"candidate_run_id"`
	MetadataCompatible   bool     `json:"metadata_compatible"`
	PairedVariablesMatch bool     `json:"paired_variables_match"`
	EligibleForScoring   bool     `json:"eligible_for_scoring"`
	Limitations          []string `json:"limitations"`
}

func (s *Service) CheckApplicability(ctx context.Context, orgID, id, candidateRunID int64, declaredRegion string) (Applicability, error) {
	r, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return Applicability{}, err
	}
	reference, err := decodeScope(r)
	if err != nil {
		return Applicability{}, err
	}
	_, candidate, err := s.prepare(ctx, orgID, candidateRunID, 1)
	if err != nil {
		return Applicability{}, err
	}
	return compare(r, reference, candidate, declaredRegion), nil
}
func compare(r repository.BaselineRecord, reference, candidate repository.BaselineScope, region string) Applicability {
	out := Applicability{BaselineID: strconv.FormatInt(r.ID, 10), CandidateRunID: strconv.FormatInt(candidate.RunID, 10), Limitations: []string{"MI_BASELINE_REGION_UNVERIFIED", "MI_BASELINE_SOURCE_ORGANIZATION_DECLARED", "MI_DEVELOPMENT_RULES_UNCALIBRATED", "MI_PUBLIC_DEVELOPMENT_TEMPLATES", "MI_BASELINE_SCORING_NOT_ENABLED"}}
	if r.Status != "approved" {
		out.Limitations = append(out.Limitations, "MI_BASELINE_NOT_APPROVED")
		return out
	}
	if !r.ExpiresAt.After(time.Now()) {
		out.Limitations = append(out.Limitations, "MI_BASELINE_EXPIRED_RESAMPLE")
		return out
	}
	if candidate.RunID == reference.RunID {
		out.Limitations = append(out.Limitations, "MI_BASELINE_SELF_COMPARISON")
		return out
	}
	if r.Region == "" || region == "" || r.Region != region {
		out.Limitations = append(out.Limitations, "MI_BASELINE_REGION_MISMATCH")
		return out
	}
	if candidate.OrganizationID != reference.OrganizationID || candidate.Model != reference.Model || candidate.Protocol != reference.Protocol || candidate.Versions != reference.Versions || candidate.ParametersHash != reference.ParametersHash || candidate.TemplateHash != reference.TemplateHash || candidate.TokenizerHash != reference.TokenizerHash || r.Source == "historical" && candidate.TargetID != reference.TargetID {
		out.Limitations = append(out.Limitations, "MI_BASELINE_SCOPE_MISMATCH")
		return out
	}
	out.MetadataCompatible = true
	a, _ := json.Marshal(reference.Samples)
	b, _ := json.Marshal(candidate.Samples)
	out.PairedVariablesMatch = bytes.Equal(a, b)
	if !out.PairedVariablesMatch {
		out.Limitations = append(out.Limitations, "MI_BASELINE_UNPAIRED_VARIABLES_OR_SEED")
	}
	return out
}

func IsUnavailable(err error) bool {
	return errors.Is(err, repository.ErrBaselineIntegrity) || errors.Is(err, repository.ErrResultDocument)
}
