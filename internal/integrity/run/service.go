// Package run composes authorized configuration into signed execution plans.
// Estimation has no network dependency and never obtains plaintext credentials.
package run

import (
	"context"
	"errors"
	"slices"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
	"model-integrity-inspector.local/mii/internal/integrity/target"
)

var ErrInvalid = errors.New("MI_RUN_INVALID")
var ErrPrecheckRequired = errors.New("MI_PRECHECK_REQUIRED")
var ErrExecutionNotReady = errors.New("MI_EXECUTION_NOT_READY")

// Ordinary runs receive a bounded default without granting high-cost authority.
// The repository independently enforces the matching high-cost permission line.
const defaultMoneyBudgetMicros int64 = 2_000_000

// Config is trusted composition, not an HTTP DTO. ExecutionReady remains nil
// until the complete execution AND analysis pipeline is installed.
type Config struct {
	Store                       *repository.Store
	Targets                     *target.Service
	Generator                   *generator.Generator
	Limits                      domain.ExecutionLimits
	RuleVersion, ScoringVersion string
	// Trusted deployment selection, never accepted from HTTP Options. Empty
	// preserves explicitly legacy plans until the full derived pipeline is ready.
	AnalysisSourceVersion string
	ExecutionReady        func(context.Context) bool
}
type Service struct{ cfg Config }

func NewService(cfg Config) (*Service, error) {
	if cfg.Store == nil || cfg.Targets == nil || cfg.Generator == nil || cfg.RuleVersion == "" || cfg.ScoringVersion == "" || (cfg.AnalysisSourceVersion != "" && cfg.AnalysisSourceVersion != domain.AnalysisSourceDerivedV1) {
		return nil, ErrInvalid
	}
	if _, err := scheduler.NewPolicy(cfg.Limits); err != nil {
		return nil, err
	}
	return &Service{cfg: cfg}, nil
}

// Input cannot set model identity, price, capabilities, privileged limits,
// templates, endpoint, random variables, or any other signed plan field.
type Input struct {
	TargetID      int64
	TargetVersion int64
	Package       string
	Options       Options
}
type Options struct {
	MaxRequests     *int64   `json:"max_requests"`
	MaxTokens       *int64   `json:"max_tokens"`
	MaxCostMicros   *int64   `json:"max_cost_micros"`
	MaxMinutes      *int     `json:"max_minutes"`
	Concurrency     *int     `json:"concurrency"`
	MaxRetries      *int     `json:"max_retries"`
	Repetitions     *int     `json:"repetitions"`
	MaxOutputLevels []int    `json:"max_output_levels"`
	ProbeTypes      []string `json:"probe_types"`
	Languages       []string `json:"languages"`
	StreamModes     []bool   `json:"stream_modes"`
}

// Quote contains only public projections, not prompts, seeds or raw manifests.
type Quote struct {
	ID                      int64
	TargetID, TargetVersion int64
	Package, ManifestHash   string
	Versions                domain.BundleVersions
	Projection              generator.Projection
	Warnings                []string
	Completeness            string
	ExpiresAt               time.Time
	Budget                  domain.ExecutionBudget
}

func (s *Service) tenant(ctx context.Context, orgID int64) (*repository.Tenant, error) {
	if err := s.cfg.Store.RequireControlAuthority(ctx, orgID); err != nil {
		return nil, err
	}
	return s.cfg.Store.WithOrganization(ctx, orgID)
}
func (s *Service) policy(snapshot target.Snapshot) (scheduler.Policy, error) {
	limits := s.cfg.Limits
	limits.Target = min(limits.Target, snapshot.Options.Concurrency)
	limits.Run = min(limits.Run, limits.Target)
	limits.TargetRPM = min(limits.TargetRPM, snapshot.Options.RPM)
	return scheduler.NewPolicy(limits)
}

func requested(input Input) (domain.ExecutionPlan, error) {
	p := domain.ExecutionPlan{Package: input.Package, Concurrency: 1, MaxRetries: 2, Budget: domain.ExecutionBudget{MaxRequests: 60, MaxTokens: 50000, TimeoutSeconds: 900}}
	switch input.Package {
	case "quick":
		p.Budget.MaxRequests, p.Budget.MaxTokens = 20, 15000
	case "standard", "custom":
	case "deep":
		p.Budget.MaxRequests, p.Budget.MaxTokens, p.Budget.TimeoutSeconds = 150, 200000, 2700
	default:
		return p, ErrInvalid
	}
	o := input.Options
	if o.MaxRequests != nil {
		p.Budget.MaxRequests = *o.MaxRequests
	}
	if o.MaxTokens != nil {
		p.Budget.MaxTokens = *o.MaxTokens
	}
	p.Budget.MaxCostMicros = o.MaxCostMicros
	if o.MaxMinutes != nil {
		if *o.MaxMinutes < 1 || *o.MaxMinutes > 45 {
			return p, ErrInvalid
		}
		p.Budget.TimeoutSeconds = int64(*o.MaxMinutes) * 60
	}
	if o.Concurrency != nil {
		p.Concurrency = *o.Concurrency
	}
	if o.MaxRetries != nil {
		p.MaxRetries = *o.MaxRetries
	}
	if p.Budget.MaxRequests < 1 || p.Budget.MaxRequests > 1000 || p.Budget.MaxTokens < 1 || p.Budget.MaxTokens > 10000000 || (o.MaxCostMicros != nil && (*o.MaxCostMicros < 0 || *o.MaxCostMicros > 1000000000)) || p.Concurrency < 1 || p.Concurrency > 100 || p.MaxRetries < 0 || p.MaxRetries > 2 {
		return p, ErrInvalid
	}
	if input.Package != "custom" && (o.Repetitions != nil || o.MaxOutputLevels != nil || o.ProbeTypes != nil || o.Languages != nil || o.StreamModes != nil) {
		return p, ErrInvalid
	}
	return p, nil
}

func (s *Service) Estimate(ctx context.Context, orgID int64, input Input) (Quote, error) {
	tenant, err := s.tenant(ctx, orgID)
	if err != nil {
		return Quote{}, err
	}
	p, err := requested(input)
	if err != nil || input.TargetID <= 0 || input.TargetVersion <= 0 {
		return Quote{}, ErrInvalid
	}
	snapshot, err := s.cfg.Targets.Snapshot(ctx, orgID, input.TargetID)
	if err != nil {
		return Quote{}, err
	}
	if snapshot.TargetVersion != input.TargetVersion {
		return Quote{}, repository.ErrConflict
	}
	precheck, err := s.cfg.Targets.GetPrecheck(ctx, orgID, input.TargetID, 0)
	if errors.Is(err, repository.ErrNotFound) {
		return Quote{}, ErrPrecheckRequired
	}
	if err != nil {
		return Quote{}, err
	}
	if precheck.TargetVersion != snapshot.TargetVersion {
		return Quote{}, repository.ErrPrecheckStale
	}
	if precheck.Status != "passed" {
		return Quote{}, ErrPrecheckRequired
	}
	supportsStream := false
	for _, check := range precheck.Checks {
		if check.Name == "stream" && check.Status == "passed" {
			supportsStream = true
		}
	}
	o := generator.Options{OrganizationID: orgID, PrecheckID: precheck.ID, Target: domain.ExecutionTarget{ID: snapshot.TargetID, Version: snapshot.TargetVersion, SecretID: snapshot.SecretID, SecretVersion: snapshot.SecretVersion, Endpoint: snapshot.Endpoint, Model: snapshot.Model, Protocol: snapshot.Protocol, MaxOutputParameter: precheck.MaxOutputParameter, AuthType: snapshot.AuthType, AuthHeaderName: snapshot.AuthHeaderName, TimeoutSeconds: snapshot.Options.TimeoutSeconds}, Package: input.Package, RuleVersion: s.cfg.RuleVersion, ScoringVersion: s.cfg.ScoringVersion, ContextWindow: 4096, MaxOutputTokens: 1024, ModelLimitsAssumed: true, SupportsStream: supportsStream, StreamModes: slices.Clone(input.Options.StreamModes)}
	o.AnalysisSourceVersion = s.cfg.AnalysisSourceVersion
	if snapshot.ModelProfileID != nil {
		profile, err := tenant.GetModelProfile(*snapshot.ModelProfileID)
		if err != nil {
			return Quote{}, err
		}
		if profile.Status != "active" || profile.Protocol != snapshot.Protocol {
			return Quote{}, repository.ErrConflict
		}
		capabilities, _, limits, err := repository.ModelCatalogMetadata(profile)
		if err != nil {
			return Quote{}, err
		}
		o.ModelProfile = &domain.ExecutionModelProfile{ID: profile.ID, Version: int64(profile.Version)}
		o.StandardModel, o.SupportsSeed, o.ReasoningModel = profile.Model, capabilities.SupportsSeed, capabilities.ReasoningModel
		o.SupportsStream = supportsStream && capabilities.SupportsStream
		p.Pricing = domain.ExecutionPricing{InputMicrosPerMillion: profile.InputPriceMicros, OutputMicrosPerMillion: profile.OutputPriceMicros}
		if limits.ContextWindow != nil {
			o.ContextWindow = int(*limits.ContextWindow)
		}
		if limits.MaxOutputTokens != nil {
			o.MaxOutputTokens = int(min(*limits.MaxOutputTokens, 131072))
		}
		o.ModelLimitsAssumed = limits.ContextWindow == nil || limits.MaxOutputTokens == nil
	}
	policy, err := s.policy(snapshot)
	if err != nil {
		return Quote{}, err
	}
	if p.Budget.MaxCostMicros == nil && p.Pricing.InputMicrosPerMillion != nil && p.Pricing.OutputMicrosPerMillion != nil {
		budget := min(s.cfg.Limits.MaxCostMicros, defaultMoneyBudgetMicros)
		p.Budget.MaxCostMicros = &budget
	}
	p, _, err = policy.Apply(p) // Clamp before compiling/signing or presenting the quote.
	if err != nil {
		return Quote{}, err
	}
	o.Budget, o.Pricing, o.Concurrency, o.MaxRetries = p.Budget, p.Pricing, p.Concurrency, p.MaxRetries
	if input.Package == "custom" {
		if input.Options.Repetitions == nil {
			return Quote{}, ErrInvalid
		}
		o.Custom = &generator.Custom{Families: slices.Clone(input.Options.ProbeTypes), Tiers: slices.Clone(input.Options.MaxOutputLevels), Repetitions: *input.Options.Repetitions, Languages: slices.Clone(input.Options.Languages)}
	}
	manifest, err := s.cfg.Generator.Generate(o)
	if err != nil {
		return Quote{}, err
	}
	data, hash, err := manifest.Canonical()
	if err != nil {
		return Quote{}, err
	}
	plan, err := s.cfg.Generator.ExecutionPlan(data, hash, orgID)
	if err != nil {
		return Quote{}, err
	}
	draft, err := tenant.SaveRunEstimate(plan, policy)
	if err != nil {
		return Quote{}, err
	}
	return quote(draft.ID, draft.ExpiresAt, plan, manifest), nil
}

func quote(id int64, expires time.Time, plan domain.ExecutionPlan, m generator.Manifest) Quote {
	completeness := "full"
	if m.Completeness != "COMPLETE" {
		completeness = "partial"
	}
	warnings := slices.Clone(m.Warnings)
	for _, omission := range m.Omissions {
		if !slices.Contains(warnings, omission.Reason) {
			warnings = append(warnings, omission.Reason)
		}
	}
	return Quote{ID: id, TargetID: plan.Target.ID, TargetVersion: plan.Target.Version, Package: plan.Package, ManifestHash: plan.ManifestHash, Versions: plan.Versions, Projection: m.Projection, Warnings: warnings, Completeness: completeness, ExpiresAt: expires, Budget: plan.Budget}
}

func (s *Service) Confirm(ctx context.Context, orgID, estimateID int64, hash string) (repository.RunRecord, error) {
	tenant, err := s.tenant(ctx, orgID)
	if err != nil {
		return repository.RunRecord{}, err
	}
	// A confirmed Run is the durable owner/hash-bound receipt. Its identity
	// survives deletion of the expired S2 preparation artifact.
	if existing, err := tenant.FindConfirmedEstimate(estimateID, hash); err == nil {
		return existing, nil
	} else if !errors.Is(err, repository.ErrNotFound) {
		return repository.RunRecord{}, err
	}
	draft, err := tenant.GetRunEstimate(estimateID)
	if err != nil {
		return repository.RunRecord{}, err
	}
	if draft.ManifestHash != hash {
		return repository.RunRecord{}, repository.ErrEstimateStale
	}
	stored, err := repository.DecodeRunEstimate(draft)
	if err != nil {
		return repository.RunRecord{}, err
	}
	verified, err := s.cfg.Generator.ExecutionPlan(stored.Manifest, hash, orgID)
	if err != nil {
		return repository.RunRecord{}, err
	}
	if existing, err := tenant.FindConfirmedEstimate(estimateID, hash); err == nil {
		return existing, nil
	} else if !errors.Is(err, repository.ErrNotFound) {
		return repository.RunRecord{}, err
	}
	if !time.Now().Before(draft.ExpiresAt) {
		return repository.RunRecord{}, repository.ErrEstimateExpired
	}
	// A deployment may have changed the active rule/scoring implementation while
	// this draft was open. Existing receipts above remain recoverable, but a new
	// Run must not be created against an unavailable implementation version.
	if verified.Versions.Rule != s.cfg.RuleVersion || verified.Versions.Scoring != s.cfg.ScoringVersion || verified.AnalysisSourceVersion != s.cfg.AnalysisSourceVersion {
		return repository.RunRecord{}, repository.ErrEstimateStale
	}
	snapshot, err := s.cfg.Targets.Snapshot(ctx, orgID, verified.Target.ID)
	if err != nil {
		return repository.RunRecord{}, err
	}
	policy, err := s.policy(snapshot)
	if err != nil {
		return repository.RunRecord{}, err
	}
	if s.cfg.ExecutionReady == nil || !s.cfg.ExecutionReady(ctx) {
		return repository.RunRecord{}, ErrExecutionNotReady
	}
	return tenant.ConfirmRunEstimate(estimateID, verified, policy)
}

func (s *Service) Get(ctx context.Context, orgID, id int64) (repository.RunRecord, Quote, int, int, error) {
	tenant, err := s.tenant(ctx, orgID)
	if err != nil {
		return repository.RunRecord{}, Quote{}, 0, 0, err
	}
	r, err := tenant.GetRun(id)
	if err != nil {
		return r, Quote{}, 0, 0, err
	}
	plan, err := tenant.GetExecutionPlan(id)
	if err != nil {
		return r, Quote{}, 0, 0, err
	}
	m, err := s.cfg.Generator.Verify(plan.Manifest, r.ManifestHash, orgID)
	if err != nil {
		return r, Quote{}, 0, 0, err
	}
	samples, err := tenant.ListExecutionSamples(id)
	if err != nil {
		return r, Quote{}, 0, 0, err
	}
	completed := 0
	for _, sample := range samples {
		if sample.CompletedAt != nil {
			completed++
		}
	}
	return r, quote(0, time.Time{}, plan, m), len(samples), completed, nil
}

func (s *Service) Cancel(ctx context.Context, orgID, id, version int64) (repository.RunRecord, error) {
	tenant, err := s.tenant(ctx, orgID)
	if err != nil {
		return repository.RunRecord{}, err
	}
	return tenant.CancelRun(id, version)
}
