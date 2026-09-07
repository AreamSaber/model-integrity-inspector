package repository

import (
	"strings"
	"time"

	"gorm.io/gorm"
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
	if provider == nil || strings.TrimSpace(provider.Name) == "" || len(provider.Name) > 128 {
		return ErrConfiguration
	}
	if provider.OrganizationID != 0 && provider.OrganizationID != t.orgID {
		return ErrOrganizationScope
	}
	id, err := NewID()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	provider.ID, provider.OrganizationID = id, t.orgID
	provider.Status, provider.CreatedAt, provider.UpdatedAt = "active", now, now
	provider.DeletedAt = nil
	return persistenceError(t.store.db.WithContext(t.ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(provider).Error; err != nil {
			return err
		}
		return t.store.appendAudit(t.ctx, tx, t.orgID, auditObject("provider.create", "provider", provider.ID), nil)
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
	if profile == nil || strings.TrimSpace(profile.Model) == "" || profile.ProviderID <= 0 {
		return ErrConfiguration
	}
	if profile.OrganizationID != 0 && profile.OrganizationID != t.orgID {
		return ErrOrganizationScope
	}
	id, err := NewID()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	profile.ID, profile.OrganizationID = id, t.orgID
	profile.Status, profile.CreatedAt, profile.UpdatedAt = "active", now, now
	profile.DeletedAt = nil
	if profile.Protocol == "" {
		profile.Protocol = "openai_chat"
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
	return persistenceError(t.store.db.WithContext(t.ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(profile).Error; err != nil {
			return err
		}
		return t.store.appendAudit(t.ctx, tx, t.orgID, auditObject("model.create", "model_profile", profile.ID), nil)
	}))
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
		Select("id, organization_id, provider_id, model, display_name, protocol, input_price_micros, output_price_micros, status, created_at, updated_at, deleted_at").
		Where("id > ? AND deleted_at IS NULL", options.AfterID).
		Order("id").Limit(options.Limit).Find(&profiles).Error
	return profiles, persistenceError(err)
}
