package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ListOptions uses stable primary-key cursor pagination, bounded to 100 rows.
type ListOptions struct {
	AfterID int64
	Limit   int
}

func (o ListOptions) normalized() ListOptions {
	if o.Limit < 1 || o.Limit > 100 {
		o.Limit = 50
	}
	if o.AfterID < 0 {
		o.AfterID = 0
	}
	return o
}

func (t *Tenant) CreateProvider(provider *Provider) error {
	if err := t.store.auditReady(t.ctx); err != nil {
		return err
	}
	if err := normalizeCatalogProvider(provider, t.orgID); err != nil {
		return err
	}
	return persistenceError(t.store.db.WithContext(t.ctx).Transaction(func(tx *gorm.DB) error {
		return t.store.createCatalogProvider(t.ctx, tx, t.orgID, provider)
	}))
}

func (t *Tenant) GetProvider(id int64) (Provider, error) {
	var provider Provider
	err := t.scoped().Where("id = ? AND deleted_at IS NULL", id).First(&provider).Error
	return provider, persistenceError(err)
}

func (t *Tenant) ListProviders(options ListOptions) ([]Provider, error) {
	options = options.normalized()
	var providers []Provider
	err := t.scoped().Where("id > ? AND deleted_at IS NULL", options.AfterID).
		Order("id").Limit(options.Limit).Find(&providers).Error
	return providers, persistenceError(err)
}

func (t *Tenant) CreateModelProfile(profile *ModelProfile) error {
	if err := t.store.auditReady(t.ctx); err != nil {
		return err
	}
	if err := normalizeCatalogProfile(profile, t.orgID); err != nil {
		return err
	}
	err := persistenceError(t.store.db.WithContext(t.ctx).Transaction(func(tx *gorm.DB) error {
		return t.store.createCatalogModel(t.ctx, tx, t.orgID, profile)
	}))
	if errors.Is(err, ErrNotFound) {
		return ErrConflict
	}
	return err
}

func (t *Tenant) GetModelProfile(id int64) (ModelProfile, error) {
	var profile ModelProfile
	err := t.scoped().Where("id = ? AND deleted_at IS NULL", id).First(&profile).Error
	return profile, persistenceError(err)
}

func (t *Tenant) ListModelProfiles(options ListOptions) ([]ModelProfileSummary, error) {
	options = options.normalized()
	var profiles []ModelProfileSummary
	err := t.scoped().Table("model_profiles").
		Select(modelSummaryColumns).
		Where("id > ? AND deleted_at IS NULL", options.AfterID).
		Order("id").Limit(options.Limit).Find(&profiles).Error
	return profiles, persistenceError(err)
}

type CatalogList = ManagementList

// Fixed metadata structures cannot carry arbitrary provider JSON or credentials.
// Declared tokenizer quality never substitutes for a verified runtime bundle.
type CatalogCapabilities struct {
	SupportsStream bool `json:"supports_stream"`
	SupportsSeed   bool `json:"supports_seed"`
	ReasoningModel bool `json:"reasoning_model"`
}
type CatalogTokenizer struct {
	ID      string `json:"id"`
	Quality string `json:"quality"`
}
type CatalogLimits struct {
	MaxOutputTokens *int64 `json:"max_output_tokens,omitempty"`
	ContextWindow   *int64 `json:"context_window,omitempty"`
}

const modelSummaryColumns = "id, organization_id, provider_id, model, display_name, protocol, input_price_micros, output_price_micros, status, version, created_at, updated_at, deleted_at"
const maxCatalogPrice int64 = 9007199254740991

func catalogText(value string, limit int, required bool) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) <= limit && strings.IndexFunc(value, unicode.IsControl) < 0 && (!required || strings.TrimSpace(value) != "")
}
func validCatalogStatus(status string) bool { return status == "active" || status == "disabled" }
func catalogJSON(value string, out any) error {
	if len(value) > 4096 || !json.Valid([]byte(value)) || !strings.HasPrefix(strings.TrimSpace(value), "{") {
		return ErrConfiguration
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(value), &fields) != nil {
		return ErrConfiguration
	}
	for _, v := range fields {
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return ErrConfiguration
		}
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		return ErrConfiguration
	}
	return nil
}

func ModelCatalogMetadata(profile ModelProfile) (CatalogCapabilities, CatalogTokenizer, CatalogLimits, error) {
	var capabilities CatalogCapabilities
	var tokenizer CatalogTokenizer
	var limits CatalogLimits
	if catalogJSON(profile.CapabilitiesJSON, &capabilities) != nil || catalogJSON(profile.TokenizerJSON, &tokenizer) != nil || catalogJSON(profile.PublicLimitsJSON, &limits) != nil {
		return capabilities, tokenizer, limits, ErrConfiguration
	}
	if tokenizer.Quality == "" {
		tokenizer.Quality = "unavailable"
	}
	if !catalogText(tokenizer.ID, 128, false) {
		return capabilities, tokenizer, limits, ErrConfiguration
	}
	switch tokenizer.Quality {
	case "unavailable":
		if tokenizer.ID != "" {
			return capabilities, tokenizer, limits, ErrConfiguration
		}
	case "exact", "compatible", "heuristic":
		if tokenizer.ID == "" {
			return capabilities, tokenizer, limits, ErrConfiguration
		}
	default:
		return capabilities, tokenizer, limits, ErrConfiguration
	}
	if limits.MaxOutputTokens != nil && (*limits.MaxOutputTokens < 1 || *limits.MaxOutputTokens > 1048576) {
		return capabilities, tokenizer, limits, ErrConfiguration
	}
	if limits.ContextWindow != nil && (*limits.ContextWindow < 1 || *limits.ContextWindow > 4194304) {
		return capabilities, tokenizer, limits, ErrConfiguration
	}
	if limits.MaxOutputTokens != nil && limits.ContextWindow != nil && *limits.MaxOutputTokens > *limits.ContextWindow {
		return capabilities, tokenizer, limits, ErrConfiguration
	}
	return capabilities, tokenizer, limits, nil
}
func normalizeCatalogProfile(profile *ModelProfile, orgID int64) error {
	if profile == nil || profile.ProviderID <= 0 || !catalogText(profile.Model, 128, true) || !catalogText(profile.DisplayName, 128, false) {
		return ErrConfiguration
	}
	if profile.OrganizationID != 0 && profile.OrganizationID != orgID {
		return ErrOrganizationScope
	}
	if profile.Protocol == "" {
		profile.Protocol = "openai_chat"
	}
	if profile.Protocol != "openai_chat" {
		return ErrConfiguration
	}
	if profile.Status == "" {
		profile.Status = "active"
	}
	if !validCatalogStatus(profile.Status) {
		return ErrConfiguration
	}
	for _, price := range []*int64{profile.InputPriceMicros, profile.OutputPriceMicros} {
		if price != nil && (*price < 0 || *price > maxCatalogPrice) {
			return ErrConfiguration
		}
	}
	if profile.CapabilitiesJSON == "" {
		profile.CapabilitiesJSON = "{}"
	}
	if profile.TokenizerJSON == "" {
		profile.TokenizerJSON = "{}"
	}
	if profile.PublicLimitsJSON == "" {
		profile.PublicLimitsJSON = "{}"
	}
	capabilities, tokenizer, limits, err := ModelCatalogMetadata(*profile)
	if err != nil {
		return err
	}
	encode := func(value any) string { data, _ := json.Marshal(value); return string(data) }
	profile.CapabilitiesJSON = encode(capabilities)
	profile.TokenizerJSON = encode(tokenizer)
	profile.PublicLimitsJSON = encode(limits)
	profile.Model = strings.TrimSpace(profile.Model)
	return nil
}
func normalizeCatalogProvider(provider *Provider, orgID int64) error {
	if provider == nil || !catalogText(provider.Name, 128, true) || !catalogText(provider.Description, 2048, false) || !catalogText(provider.Contact, 256, false) {
		return ErrConfiguration
	}
	if provider.OrganizationID != 0 && provider.OrganizationID != orgID {
		return ErrOrganizationScope
	}
	if provider.Status == "" {
		provider.Status = "active"
	}
	if !validCatalogStatus(provider.Status) {
		return ErrConfiguration
	}
	provider.Name = strings.TrimSpace(provider.Name)
	return nil
}
func (s *Store) catalogProviderLock(tx *gorm.DB, orgID, id int64, active bool, strength string) (Provider, error) {
	var provider Provider
	q := tx.Where("organization_id=? AND id=? AND deleted_at IS NULL", orgID, id)
	if active {
		q = q.Where("status='active'")
	}
	if s.driver == "postgres" {
		q = q.Clauses(clause.Locking{Strength: strength})
	}
	err := q.First(&provider).Error
	return provider, err
}
func (s *Store) catalogModelLock(tx *gorm.DB, orgID, id int64, strength string) (ModelProfile, error) {
	var profile ModelProfile
	q := tx.Where("organization_id=? AND id=? AND deleted_at IS NULL", orgID, id)
	if s.driver == "postgres" {
		q = q.Clauses(clause.Locking{Strength: strength})
	}
	err := q.First(&profile).Error
	return profile, err
}
func (s *Store) createCatalogProvider(ctx context.Context, tx *gorm.DB, orgID int64, provider *Provider) error {
	id, err := NewID()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	provider.ID, provider.OrganizationID, provider.Version = id, orgID, 1
	provider.CreatedAt, provider.UpdatedAt, provider.DeletedAt = now, now, nil
	if err := tx.Create(provider).Error; err != nil {
		return err
	}
	return s.appendAudit(ctx, tx, orgID, auditObject("provider.create", "provider", id), nil)
}
func (s *Store) createCatalogModel(ctx context.Context, tx *gorm.DB, orgID int64, profile *ModelProfile) error {
	if _, err := s.catalogProviderLock(tx, orgID, profile.ProviderID, true, "SHARE"); err != nil {
		return err
	}
	id, err := NewID()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	profile.ID, profile.OrganizationID, profile.Version = id, orgID, 1
	profile.CreatedAt, profile.UpdatedAt, profile.DeletedAt = now, now, nil
	if err := tx.Create(profile).Error; err != nil {
		return err
	}
	return s.appendAudit(ctx, tx, orgID, auditObject("model.create", "model_profile", id), nil)
}

func listCatalogProviders(tx *gorm.DB, orgID int64, list CatalogList) ([]Provider, error) {
	rows := []Provider{}
	q := tx.Where("organization_id=? AND id>? AND deleted_at IS NULL", orgID, list.AfterID)
	if list.Query != "" {
		q = q.Where("LOWER(name) LIKE ? ESCAPE '!'", managementLike(list.Query))
	}
	err := q.Order("id").Limit(list.Limit).Find(&rows).Error
	return rows, err
}
func listCatalogModels(tx *gorm.DB, orgID int64, list CatalogList) ([]ModelProfileSummary, error) {
	rows := []ModelProfileSummary{}
	q := tx.Table("model_profiles").Select(modelSummaryColumns).Where("organization_id=? AND id>? AND deleted_at IS NULL", orgID, list.AfterID)
	if list.Query != "" {
		q = q.Where("(LOWER(model) LIKE ? ESCAPE '!' OR LOWER(display_name) LIKE ? ESCAPE '!')", managementLike(list.Query), managementLike(list.Query))
	}
	err := q.Order("id").Limit(list.Limit).Scan(&rows).Error
	return rows, err
}
func (s *Store) CatalogListProviders(ctx context.Context, auth ManagementAuthority, orgID int64, list CatalogList) ([]Provider, error) {
	var result []Provider
	if !validManagementList(list) {
		return nil, ErrConfiguration
	}
	err := s.managementTransaction(ctx, auth, orgID, "read", false, func(tx *gorm.DB, _ User) error {
		var err error
		result, err = listCatalogProviders(tx, orgID, list)
		return err
	})
	return result, err
}
func (s *Store) CatalogListModels(ctx context.Context, auth ManagementAuthority, orgID int64, list CatalogList) ([]ModelProfileSummary, error) {
	var result []ModelProfileSummary
	if !validManagementList(list) {
		return nil, ErrConfiguration
	}
	err := s.managementTransaction(ctx, auth, orgID, "read", false, func(tx *gorm.DB, _ User) error {
		var err error
		result, err = listCatalogModels(tx, orgID, list)
		return err
	})
	return result, err
}
func (s *Store) CatalogGetProvider(ctx context.Context, auth ManagementAuthority, orgID, id int64) (Provider, error) {
	var result Provider
	err := s.managementTransaction(ctx, auth, orgID, "read", false, func(tx *gorm.DB, _ User) error {
		return tx.Where("organization_id=? AND id=? AND deleted_at IS NULL", orgID, id).First(&result).Error
	})
	return result, err
}
func (s *Store) CatalogGetModel(ctx context.Context, auth ManagementAuthority, orgID, id int64) (ModelProfile, error) {
	var result ModelProfile
	err := s.managementTransaction(ctx, auth, orgID, "read", false, func(tx *gorm.DB, _ User) error {
		return tx.Where("organization_id=? AND id=? AND deleted_at IS NULL", orgID, id).First(&result).Error
	})
	return result, err
}
func (s *Store) CatalogCreateProvider(ctx context.Context, auth ManagementAuthority, orgID int64, provider Provider) (Provider, error) {
	if err := normalizeCatalogProvider(&provider, orgID); err != nil {
		return Provider{}, err
	}
	err := s.managementTransaction(ctx, auth, orgID, "catalog.write", true, func(tx *gorm.DB, _ User) error { return s.createCatalogProvider(ctx, tx, orgID, &provider) })
	if err != nil {
		return Provider{}, err
	}
	return provider, nil
}
func (s *Store) CatalogCreateModel(ctx context.Context, auth ManagementAuthority, orgID int64, profile ModelProfile) (ModelProfile, error) {
	if err := normalizeCatalogProfile(&profile, orgID); err != nil {
		return ModelProfile{}, err
	}
	err := s.managementTransaction(ctx, auth, orgID, "catalog.write", true, func(tx *gorm.DB, _ User) error { return s.createCatalogModel(ctx, tx, orgID, &profile) })
	if err != nil {
		return ModelProfile{}, err
	}
	return profile, nil
}

func (s *Store) CatalogUpdateProvider(ctx context.Context, auth ManagementAuthority, orgID, id int64, version int, provider Provider) (Provider, error) {
	if version <= 0 || version >= math.MaxInt32 {
		return Provider{}, ErrConflict
	}
	if err := normalizeCatalogProvider(&provider, orgID); err != nil {
		return Provider{}, err
	}
	var result Provider
	err := s.managementTransaction(ctx, auth, orgID, "catalog.write", true, func(tx *gorm.DB, _ User) error {
		old, err := s.catalogProviderLock(tx, orgID, id, false, "UPDATE")
		if err != nil {
			return err
		}
		if old.Version != version {
			return ErrConflict
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		update := tx.Model(&Provider{}).Where("organization_id=? AND id=? AND version=? AND deleted_at IS NULL", orgID, id, version).Updates(map[string]any{"name": provider.Name, "description": provider.Description, "contact": provider.Contact, "status": provider.Status, "version": version + 1, "updated_at": now})
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected != 1 {
			return ErrConflict
		}
		if err := s.appendAudit(ctx, tx, orgID, auditObject("provider.update", "provider", id), nil); err != nil {
			return err
		}
		return tx.Where("organization_id=? AND id=?", orgID, id).First(&result).Error
	})
	return result, err
}
func (s *Store) CatalogUpdateModel(ctx context.Context, auth ManagementAuthority, orgID, id int64, version int, profile ModelProfile) (ModelProfile, error) {
	if version <= 0 || version >= math.MaxInt32 {
		return ModelProfile{}, ErrConflict
	}
	if err := normalizeCatalogProfile(&profile, orgID); err != nil {
		return ModelProfile{}, err
	}
	var result ModelProfile
	err := s.managementTransaction(ctx, auth, orgID, "catalog.write", true, func(tx *gorm.DB, _ User) error {
		if _, err := s.catalogProviderLock(tx, orgID, profile.ProviderID, profile.Status == "active", "SHARE"); err != nil {
			return err
		}
		old, err := s.catalogModelLock(tx, orgID, id, "UPDATE")
		if err != nil {
			return err
		}
		if old.Version != version {
			return ErrConflict
		}
		if old.ProviderID != profile.ProviderID || old.Model != profile.Model || old.Protocol != profile.Protocol {
			var count int64
			if err := tx.Table("integrity_targets").Where("organization_id=? AND model_profile_id=? AND deleted_at IS NULL", orgID, id).Count(&count).Error; err != nil {
				return err
			}
			if count > 0 {
				return ErrConflict
			}
		}
		updates := map[string]any{"provider_id": profile.ProviderID, "model": profile.Model, "display_name": profile.DisplayName, "protocol": profile.Protocol, "capabilities_json": profile.CapabilitiesJSON, "tokenizer_json": profile.TokenizerJSON, "public_limits_json": profile.PublicLimitsJSON, "input_price_micros": profile.InputPriceMicros, "output_price_micros": profile.OutputPriceMicros, "status": profile.Status, "version": version + 1, "updated_at": time.Now().UTC().Truncate(time.Microsecond)}
		update := tx.Model(&ModelProfile{}).Where("organization_id=? AND id=? AND version=? AND deleted_at IS NULL", orgID, id, version).Updates(updates)
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected != 1 {
			return ErrConflict
		}
		if err := s.appendAudit(ctx, tx, orgID, auditObject("model.update", "model_profile", id), nil); err != nil {
			return err
		}
		return tx.Where("organization_id=? AND id=?", orgID, id).First(&result).Error
	})
	return result, err
}
func (s *Store) CatalogDeleteProvider(ctx context.Context, auth ManagementAuthority, orgID, id int64, version int) error {
	if version <= 0 || version >= math.MaxInt32 {
		return ErrConflict
	}
	return s.managementTransaction(ctx, auth, orgID, "catalog.write", true, func(tx *gorm.DB, _ User) error {
		provider, err := s.catalogProviderLock(tx, orgID, id, false, "UPDATE")
		if err != nil {
			return err
		}
		if provider.Version != version {
			return ErrConflict
		}
		var models, targets int64
		if err := tx.Model(&ModelProfile{}).Where("organization_id=? AND provider_id=? AND deleted_at IS NULL", orgID, id).Count(&models).Error; err != nil {
			return err
		}
		if err := tx.Table("integrity_targets").Where("organization_id=? AND provider_id=? AND deleted_at IS NULL", orgID, id).Count(&targets).Error; err != nil {
			return err
		}
		if models+targets > 0 {
			return ErrConflict
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		if err := tx.Model(&Provider{}).Where("organization_id=? AND id=? AND version=?", orgID, id, version).Updates(map[string]any{"deleted_at": now, "status": "disabled", "updated_at": now, "version": version + 1}).Error; err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, orgID, auditObject("provider.delete", "provider", id), nil)
	})
}
func (s *Store) CatalogDeleteModel(ctx context.Context, auth ManagementAuthority, orgID, id int64, version int) error {
	if version <= 0 || version >= math.MaxInt32 {
		return ErrConflict
	}
	return s.managementTransaction(ctx, auth, orgID, "catalog.write", true, func(tx *gorm.DB, _ User) error {
		profile, err := s.catalogModelLock(tx, orgID, id, "UPDATE")
		if err != nil {
			return err
		}
		if profile.Version != version {
			return ErrConflict
		}
		var count int64
		if err := tx.Table("integrity_targets").Where("organization_id=? AND model_profile_id=? AND deleted_at IS NULL", orgID, id).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return ErrConflict
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		if err := tx.Model(&ModelProfile{}).Where("organization_id=? AND id=? AND version=?", orgID, id, version).Updates(map[string]any{"deleted_at": now, "status": "disabled", "updated_at": now, "version": version + 1}).Error; err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, orgID, auditObject("model.delete", "model_profile", id), nil)
	})
}
