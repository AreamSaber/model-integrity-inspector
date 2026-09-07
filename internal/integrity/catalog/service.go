// Package catalog owns organization-scoped provider/model metadata. It does not
// perform network discovery, trust declared capabilities as probe evidence, or
// resolve credentials and tokenizer artifacts.
package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"

	"model-integrity-inspector.local/mii/internal/identity"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

var ErrInvalid = errors.New("MI_CATALOG_INVALID")

type Service struct {
	store    *repository.Store
	identity *identity.Service
}

func NewService(store *repository.Store, identities *identity.Service) (*Service, error) {
	if store == nil || identities == nil {
		return nil, ErrInvalid
	}
	return &Service{store, identities}, nil
}

type ProviderInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Contact     string `json:"contact"`
	Status      string `json:"status"`
}
type ProfileInput struct {
	ProviderID        int64  `json:"-"`
	Name              string `json:"name"`
	DisplayName       string `json:"display_name"`
	Protocol          string `json:"protocol"`
	Status            string `json:"status"`
	SupportsStream    bool   `json:"supports_stream"`
	SupportsSeed      bool   `json:"supports_seed"`
	ReasoningModel    bool   `json:"reasoning_model"`
	TokenizerID       string `json:"tokenizer_id"`
	TokenizerQuality  string `json:"tokenizer_quality"`
	MaxOutputTokens   *int64 `json:"max_output_tokens,omitempty"`
	ContextWindow     *int64 `json:"context_window,omitempty"`
	InputPriceMicros  *int64 `json:"input_price_micros_per_million"`
	OutputPriceMicros *int64 `json:"output_price_micros_per_million"`
}
type ProviderView struct {
	ID int64
	ProviderInput
	Version              int
	CreatedAt, UpdatedAt time.Time
}
type ProfileView struct {
	ID int64
	ProfileInput
	Version              int
	CreatedAt, UpdatedAt time.Time
}
type ProfileSummary = repository.ModelProfileSummary
type List = repository.CatalogList

func serviceError(err error) error {
	switch {
	case errors.Is(err, repository.ErrManagementPermission), errors.Is(err, repository.ErrOrganizationScope):
		return identity.ErrPermission
	case errors.Is(err, repository.ErrManagementSession):
		return identity.ErrSession
	case errors.Is(err, repository.ErrPasswordChangeRequired):
		return identity.ErrPasswordChangeRequired
	case errors.Is(err, repository.ErrConfiguration):
		return ErrInvalid
	default:
		return err
	}
}
func (s *Service) authorize(ctx context.Context, token string, orgID int64, permission string) (context.Context, repository.ManagementAuthority, error) {
	if orgID <= 0 {
		return ctx, repository.ManagementAuthority{}, identity.ErrPermission
	}
	p, err := s.identity.Principal(ctx, token, orgID)
	if err != nil {
		return ctx, repository.ManagementAuthority{}, err
	}
	if err := p.Authorize(permission); err != nil {
		return ctx, repository.ManagementAuthority{}, err
	}
	hash := sha256.Sum256([]byte(token))
	session, err := s.store.GetSession(ctx, hex.EncodeToString(hash[:]), time.Now())
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ctx, repository.ManagementAuthority{}, identity.ErrSession
		}
		return ctx, repository.ManagementAuthority{}, serviceError(err)
	}
	if session.UserID != p.UserID {
		return ctx, repository.ManagementAuthority{}, identity.ErrSession
	}
	if permission == "catalog.write" {
		actor, err := audit.ActorFromContext(ctx)
		if err != nil {
			return ctx, repository.ManagementAuthority{}, repository.ErrUnavailable
		}
		actor.ActorID = p.UserID
		actor.ReasonCode = "catalog.change"
		ctx = audit.WithActor(ctx, actor)
	}
	return ctx, repository.ManagementAuthority{UserID: p.UserID, SessionID: session.ID}, nil
}

func providerView(value repository.Provider) ProviderView {
	return ProviderView{value.ID, ProviderInput{value.Name, value.Description, value.Contact, value.Status}, value.Version, value.CreatedAt, value.UpdatedAt}
}
func providerRecord(value ProviderInput) repository.Provider {
	return repository.Provider{Name: value.Name, Description: value.Description, Contact: value.Contact, Status: value.Status}
}
func profileRecord(input ProfileInput) (repository.ModelProfile, error) {
	if input.Protocol != "openai_chat" {
		return repository.ModelProfile{}, ErrInvalid
	}
	encode := func(value any) string { data, _ := json.Marshal(value); return string(data) }
	return repository.ModelProfile{ModelProfileSummary: repository.ModelProfileSummary{ProviderID: input.ProviderID, Model: input.Name, DisplayName: input.DisplayName, Protocol: input.Protocol, Status: input.Status, InputPriceMicros: input.InputPriceMicros, OutputPriceMicros: input.OutputPriceMicros},
		CapabilitiesJSON: encode(repository.CatalogCapabilities{SupportsStream: input.SupportsStream, SupportsSeed: input.SupportsSeed, ReasoningModel: input.ReasoningModel}), TokenizerJSON: encode(repository.CatalogTokenizer{ID: input.TokenizerID, Quality: input.TokenizerQuality}), PublicLimitsJSON: encode(repository.CatalogLimits{MaxOutputTokens: input.MaxOutputTokens, ContextWindow: input.ContextWindow})}, nil
}
func profileView(value repository.ModelProfile) (ProfileView, error) {
	capabilities, tokenizer, limits, err := repository.ModelCatalogMetadata(value)
	if err != nil {
		return ProfileView{}, repository.ErrUnavailable
	}
	return ProfileView{value.ID, ProfileInput{ProviderID: value.ProviderID, Name: value.Model, DisplayName: value.DisplayName, Protocol: value.Protocol, Status: value.Status, SupportsStream: capabilities.SupportsStream, SupportsSeed: capabilities.SupportsSeed, ReasoningModel: capabilities.ReasoningModel, TokenizerID: tokenizer.ID, TokenizerQuality: tokenizer.Quality, MaxOutputTokens: limits.MaxOutputTokens, ContextWindow: limits.ContextWindow, InputPriceMicros: value.InputPriceMicros, OutputPriceMicros: value.OutputPriceMicros}, value.Version, value.CreatedAt, value.UpdatedAt}, nil
}

func (s *Service) ListProviders(ctx context.Context, token string, orgID int64, list List) ([]ProviderView, error) {
	ctx, auth, err := s.authorize(ctx, token, orgID, "read")
	if err != nil {
		return nil, err
	}
	rows, err := s.store.CatalogListProviders(ctx, auth, orgID, list)
	if err != nil {
		return nil, serviceError(err)
	}
	result := make([]ProviderView, len(rows))
	for i, row := range rows {
		result[i] = providerView(row)
	}
	return result, nil
}
func (s *Service) ListModels(ctx context.Context, token string, orgID int64, list List) ([]ProfileSummary, error) {
	ctx, auth, err := s.authorize(ctx, token, orgID, "read")
	if err != nil {
		return nil, err
	}
	rows, err := s.store.CatalogListModels(ctx, auth, orgID, list)
	return rows, serviceError(err)
}
func (s *Service) GetProvider(ctx context.Context, token string, orgID, id int64) (ProviderView, error) {
	ctx, auth, err := s.authorize(ctx, token, orgID, "read")
	if err != nil {
		return ProviderView{}, err
	}
	row, err := s.store.CatalogGetProvider(ctx, auth, orgID, id)
	return providerView(row), serviceError(err)
}
func (s *Service) GetModel(ctx context.Context, token string, orgID, id int64) (ProfileView, error) {
	ctx, auth, err := s.authorize(ctx, token, orgID, "read")
	if err != nil {
		return ProfileView{}, err
	}
	row, err := s.store.CatalogGetModel(ctx, auth, orgID, id)
	if err != nil {
		return ProfileView{}, serviceError(err)
	}
	return profileView(row)
}
func (s *Service) CreateProvider(ctx context.Context, token string, orgID int64, input ProviderInput) (ProviderView, error) {
	ctx, auth, err := s.authorize(ctx, token, orgID, "catalog.write")
	if err != nil {
		return ProviderView{}, err
	}
	row, err := s.store.CatalogCreateProvider(ctx, auth, orgID, providerRecord(input))
	return providerView(row), serviceError(err)
}
func (s *Service) CreateModel(ctx context.Context, token string, orgID int64, input ProfileInput) (ProfileView, error) {
	ctx, auth, err := s.authorize(ctx, token, orgID, "catalog.write")
	if err != nil {
		return ProfileView{}, err
	}
	record, err := profileRecord(input)
	if err != nil {
		return ProfileView{}, err
	}
	row, err := s.store.CatalogCreateModel(ctx, auth, orgID, record)
	if err != nil {
		return ProfileView{}, serviceError(err)
	}
	return profileView(row)
}
func (s *Service) UpdateProvider(ctx context.Context, token string, orgID, id int64, version int, input ProviderInput) (ProviderView, error) {
	if version <= 0 || version >= math.MaxInt32 {
		return ProviderView{}, ErrInvalid
	}
	ctx, auth, err := s.authorize(ctx, token, orgID, "catalog.write")
	if err != nil {
		return ProviderView{}, err
	}
	row, err := s.store.CatalogUpdateProvider(ctx, auth, orgID, id, version, providerRecord(input))
	return providerView(row), serviceError(err)
}
func (s *Service) UpdateModel(ctx context.Context, token string, orgID, id int64, version int, input ProfileInput) (ProfileView, error) {
	if version <= 0 || version >= math.MaxInt32 {
		return ProfileView{}, ErrInvalid
	}
	ctx, auth, err := s.authorize(ctx, token, orgID, "catalog.write")
	if err != nil {
		return ProfileView{}, err
	}
	record, err := profileRecord(input)
	if err != nil {
		return ProfileView{}, err
	}
	row, err := s.store.CatalogUpdateModel(ctx, auth, orgID, id, version, record)
	if err != nil {
		return ProfileView{}, serviceError(err)
	}
	return profileView(row)
}
func (s *Service) DeleteProvider(ctx context.Context, token string, orgID, id int64, version int) error {
	if version <= 0 || version >= math.MaxInt32 {
		return ErrInvalid
	}
	ctx, auth, err := s.authorize(ctx, token, orgID, "catalog.write")
	if err != nil {
		return err
	}
	return serviceError(s.store.CatalogDeleteProvider(ctx, auth, orgID, id, version))
}
func (s *Service) DeleteModel(ctx context.Context, token string, orgID, id int64, version int) error {
	if version <= 0 || version >= math.MaxInt32 {
		return ErrInvalid
	}
	ctx, auth, err := s.authorize(ctx, token, orgID, "catalog.write")
	if err != nil {
		return err
	}
	return serviceError(s.store.CatalogDeleteModel(ctx, auth, orgID, id, version))
}
