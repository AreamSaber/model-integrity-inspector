// Package target owns target configuration and detached snapshots. It never
// obtains plaintext credentials, constructs network calls or performs analysis.
package target

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/safehttp"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

var ErrInvalid = errors.New("MI_TARGET_INVALID")

// Options has no proxy URL, insecure TLS, arbitrary adapter fields or URL-policy
// override. Network allowlists belong exclusively to administrator Config.
type Options struct {
	MaxOutputParameter string `json:"max_output_parameter"`
	TLSVerify          *bool  `json:"tls_verify"`
	TimeoutSeconds     int    `json:"timeout_seconds"`
	Concurrency        int    `json:"concurrency"`
	RPM                int    `json:"rpm"`
}

type Input struct {
	Name           string   `json:"name"`
	ProviderID     *int64   `json:"provider_id"`
	ModelProfileID *int64   `json:"model_profile_id"`
	Endpoint       string   `json:"endpoint"`
	Protocol       string   `json:"protocol"`
	Model          string   `json:"model"`
	Environment    string   `json:"environment"`
	ChannelID      string   `json:"channel_id"`
	Tags           []string `json:"tags"`
	Options        Options  `json:"options"`
}

// View is the only ordinary target response. Credentials, custom header names
// and values, fingerprints, wrapped keys and ciphertext cannot be projected.
// HTTP converts positive int64 IDs to decimal strings before serialization.
type View struct {
	ID int64 `json:"id"`
	Input
	Secret    repository.SecretMetadata `json:"secret"`
	Status    string                    `json:"status"`
	Version   int64                     `json:"version"`
	CreatedAt time.Time                 `json:"created_at"`
	UpdatedAt time.Time                 `json:"updated_at"`
}

// Snapshot owns all configuration, independent of later target edits/deletion.
// Only the Worker may resolve its versioned Secret reference. It contains no
// custom headers, credential values or ciphertext and is safe to persist.
type Snapshot struct {
	OrganizationID int64 `json:"organization_id"`
	TargetID       int64 `json:"target_id"`
	TargetVersion  int64 `json:"target_version"`
	Input
	AuthType       string `json:"auth_type"`
	AuthHeaderName string `json:"auth_header_name,omitempty"`
	SecretID       int64  `json:"secret_id"`
	SecretVersion  int64  `json:"secret_version"`
}

type Config struct {
	Store     *repository.Store
	Secrets   *secret.Service
	URLPolicy safehttp.URLPolicy
}

type Service struct {
	store   *repository.Store
	secrets *secret.Service
	policy  safehttp.URLPolicy
}

func NewService(config Config) (*Service, error) {
	if config.Store == nil || config.Secrets == nil {
		return nil, ErrInvalid
	}
	if _, err := safehttp.ValidateEndpoint("https://validation.invalid/v1", config.URLPolicy); err != nil {
		return nil, ErrInvalid
	}
	policy := config.URLPolicy
	policy.PrivateCIDRAllowlist = append([]string(nil), policy.PrivateCIDRAllowlist...)
	policy.BlockedCIDRs = append([]string(nil), policy.BlockedCIDRs...)
	return &Service{config.Store, config.Secrets, policy}, nil
}

func safeText(value string, limit int, required bool) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) <= limit && strings.IndexFunc(value, unicode.IsControl) < 0 && (!required || strings.TrimSpace(value) != "")
}

func normalizeOptions(options Options) (Options, error) {
	if options.MaxOutputParameter == "" {
		options.MaxOutputParameter = "auto"
	}
	if options.MaxOutputParameter != "auto" && options.MaxOutputParameter != "max_tokens" && options.MaxOutputParameter != "max_completion_tokens" {
		return Options{}, ErrInvalid
	}
	if options.TLSVerify != nil && !*options.TLSVerify {
		return Options{}, ErrInvalid
	}
	verify := true
	options.TLSVerify = &verify
	if options.TimeoutSeconds == 0 {
		options.TimeoutSeconds = 180
	}
	if options.Concurrency == 0 {
		options.Concurrency = 1
	}
	if options.RPM == 0 {
		options.RPM = 60
	}
	if options.TimeoutSeconds < 1 || options.TimeoutSeconds > 180 || options.Concurrency < 1 || options.Concurrency > 100 || options.RPM < 1 || options.RPM > 10000 {
		return Options{}, ErrInvalid
	}
	return options, nil
}

func cloneID(id *int64) *int64 {
	if id == nil {
		return nil
	}
	value := *id
	return &value
}

func (service *Service) normalize(orgID int64, input Input, auth secret.Auth, status string) (repository.TargetRecord, error) {
	if !safeText(input.Name, 128, true) || !safeText(input.Model, 128, true) || !safeText(input.Environment, 64, false) || !safeText(input.ChannelID, 128, false) ||
		!safeText(input.Endpoint, 1024, true) || input.Protocol != "openai_chat" || len(input.Tags) > 20 ||
		(input.ProviderID != nil && *input.ProviderID <= 0) || (input.ModelProfileID != nil && *input.ModelProfileID <= 0) || (status != "active" && status != "disabled") {
		return repository.TargetRecord{}, ErrInvalid
	}
	seen := make(map[string]bool, len(input.Tags))
	tags := make([]string, 0, len(input.Tags))
	for _, tag := range input.Tags {
		if !safeText(tag, 64, true) || seen[tag] {
			return repository.TargetRecord{}, ErrInvalid
		}
		seen[tag] = true
		tags = append(tags, tag)
	}
	endpoint, err := safehttp.ValidateEndpoint(input.Endpoint, service.policy)
	if err != nil {
		return repository.TargetRecord{}, ErrInvalid
	}
	options, err := normalizeOptions(input.Options)
	if err != nil {
		return repository.TargetRecord{}, err
	}
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return repository.TargetRecord{}, ErrInvalid
	}
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return repository.TargetRecord{}, ErrInvalid
	}
	fingerprint, err := service.secrets.EndpointFingerprint(orgID, endpoint.String())
	if err != nil {
		return repository.TargetRecord{}, err
	}
	return repository.TargetRecord{OrganizationID: orgID, ProviderID: cloneID(input.ProviderID), ModelProfileID: cloneID(input.ModelProfileID), Name: input.Name,
		Endpoint: endpoint.String(), EndpointFingerprint: fingerprint, Protocol: input.Protocol, Model: input.Model, Environment: input.Environment,
		ChannelID: input.ChannelID, TagsJSON: string(tagsJSON), OptionsJSON: string(optionsJSON), AuthType: auth.Type, AuthHeaderName: auth.HeaderName, Status: status}, nil
}

func view(state repository.TargetState) (View, error) {
	record := state.Target
	input := Input{Name: record.Name, ProviderID: cloneID(record.ProviderID), ModelProfileID: cloneID(record.ModelProfileID), Endpoint: record.Endpoint,
		Protocol: record.Protocol, Model: record.Model, Environment: record.Environment, ChannelID: record.ChannelID}
	if json.Unmarshal([]byte(record.TagsJSON), &input.Tags) != nil || json.Unmarshal([]byte(record.OptionsJSON), &input.Options) != nil {
		return View{}, repository.ErrUnavailable
	}
	return View{ID: record.ID, Input: input, Secret: state.Secret, Status: record.Status, Version: record.Version, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt}, nil
}

func (service *Service) Create(ctx context.Context, orgID int64, input Input, credentials secret.Input) (View, error) {
	if err := service.store.RequireControlAuthority(ctx, orgID); err != nil {
		return View{}, err
	}
	tenant, err := service.store.WithOrganization(ctx, orgID)
	if err != nil {
		return View{}, err
	}
	auth, err := secret.ValidateInput(credentials)
	if err != nil {
		return View{}, err
	}
	record, err := service.normalize(orgID, input, auth, "active")
	if err != nil {
		return View{}, err
	}
	prepared, err := service.secrets.PrepareCreate(orgID, credentials)
	if err != nil {
		return View{}, err
	}
	state, err := tenant.CreateTargetWithSecret(record, prepared)
	if err != nil {
		return View{}, err
	}
	return view(state)
}

func (service *Service) Get(ctx context.Context, orgID, id int64) (View, error) {
	tenant, err := service.store.WithOrganization(ctx, orgID)
	if err != nil {
		return View{}, err
	}
	state, err := tenant.GetTarget(id)
	if err != nil {
		return View{}, err
	}
	return view(state)
}

func (service *Service) List(ctx context.Context, orgID int64, options repository.ListOptions) ([]View, error) {
	tenant, err := service.store.WithOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}
	states, err := tenant.ListTargets(options)
	if err != nil {
		return nil, err
	}
	result := make([]View, len(states))
	for i, state := range states {
		value, err := view(state)
		if err != nil {
			return nil, err
		}
		result[i] = value
	}
	return result, nil
}

func (service *Service) Update(ctx context.Context, orgID, id, expectedVersion int64, input Input, status string) (View, error) {
	if err := service.store.RequireControlAuthority(ctx, orgID); err != nil {
		return View{}, err
	}
	tenant, err := service.store.WithOrganization(ctx, orgID)
	if err != nil {
		return View{}, err
	}
	current, err := tenant.GetTarget(id)
	if err != nil {
		return View{}, err
	}
	if current.Target.Version != expectedVersion {
		return View{}, repository.ErrConflict
	}
	record, err := service.normalize(orgID, input, secret.Auth{Type: current.Target.AuthType, HeaderName: current.Target.AuthHeaderName}, status)
	if err != nil {
		return View{}, err
	}
	state, err := tenant.UpdateTarget(id, expectedVersion, record)
	if err != nil {
		return View{}, err
	}
	return view(state)
}

func (service *Service) RotateSecret(ctx context.Context, orgID, id, expectedTargetVersion, expectedSecretVersion int64, credentials secret.Input) (View, error) {
	if err := service.store.RequireControlAuthority(ctx, orgID); err != nil {
		return View{}, err
	}
	tenant, err := service.store.WithOrganization(ctx, orgID)
	if err != nil {
		return View{}, err
	}
	current, err := tenant.GetTarget(id)
	if err != nil {
		return View{}, err
	}
	if current.Target.Version != expectedTargetVersion || current.Secret.Version != expectedSecretVersion || expectedSecretVersion >= math.MaxInt32 {
		return View{}, repository.ErrConflict
	}
	auth, err := secret.ValidateInput(credentials)
	if err != nil {
		return View{}, err
	}
	prepared, err := service.secrets.PrepareReplacement(secret.Scope{OrganizationID: orgID, SecretID: current.Secret.ID, SecretVersion: expectedSecretVersion + 1}, credentials)
	if err != nil {
		return View{}, err
	}
	state, err := tenant.ReplaceTargetSecret(id, expectedTargetVersion, expectedSecretVersion, auth.Type, auth.HeaderName, prepared)
	if err != nil {
		return View{}, err
	}
	return view(state)
}

func (service *Service) Delete(ctx context.Context, orgID, id, expectedVersion int64) error {
	if err := service.store.RequireControlAuthority(ctx, orgID); err != nil {
		return err
	}
	tenant, err := service.store.WithOrganization(ctx, orgID)
	if err != nil {
		return err
	}
	return tenant.DeleteTarget(id, expectedVersion)
}

// Snapshot is read-only preparation, not sufficient to commit a new Run. Run
// creation must recheck version/status while locking the target in its own tx.
func (service *Service) Snapshot(ctx context.Context, orgID, id int64) (Snapshot, error) {
	tenant, err := service.store.WithOrganization(ctx, orgID)
	if err != nil {
		return Snapshot{}, err
	}
	state, err := tenant.GetTarget(id)
	if err != nil {
		return Snapshot{}, err
	}
	if state.Target.Status != "active" {
		return Snapshot{}, repository.ErrConflict
	}
	value, err := view(state)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{OrganizationID: orgID, TargetID: id, TargetVersion: value.Version, Input: value.Input,
		AuthType: state.Target.AuthType, AuthHeaderName: state.Target.AuthHeaderName, SecretID: value.Secret.ID, SecretVersion: value.Secret.Version}, nil
}
