package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

var ErrBundleIntegrity = errors.New("MI_RUNTIME_BUNDLE_INTEGRITY")
var ErrBundleUnavailable = errors.New("MI_RUNTIME_BUNDLE_UNAVAILABLE")

// BootstrapArtifacts are installed application-controlled data, never an HTTP
// upload. Application startup verifies the release's expected hashes first;
// persistence independently checks bytes/hash/version and freezes each version.
// This initial path admits DEVELOPMENT only; it cannot publish calibrated rules.
type BootstrapArtifacts struct {
	RuleVersion, RuleHash, RuleJSON             string
	TemplateVersion, TemplateHash, TemplateJSON string
	ScoringVersion, TokenizerVersion            string
}

func validatedBootstrap(input *BootstrapArtifacts) (*BootstrapArtifacts, error) {
	if input == nil {
		return nil, nil
	}
	copy := *input
	for _, v := range []string{copy.RuleVersion, copy.TemplateVersion, copy.ScoringVersion, copy.TokenizerVersion} {
		if !executionLabel.MatchString(v) {
			return nil, ErrBundleIntegrity
		}
	}
	for _, item := range []struct{ data, hash, version string }{{copy.RuleJSON, copy.RuleHash, copy.RuleVersion}, {copy.TemplateJSON, copy.TemplateHash, copy.TemplateVersion}} {
		if len(item.data) > 1<<20 || !executionHash.MatchString(item.hash) {
			return nil, ErrBundleIntegrity
		}
		digest := sha256.Sum256([]byte(item.data))
		if hex.EncodeToString(digest[:]) != item.hash {
			return nil, ErrBundleIntegrity
		}
		var identity struct {
			Version string `json:"version"`
		}
		if json.Unmarshal([]byte(item.data), &identity) != nil || identity.Version != item.version {
			return nil, ErrBundleIntegrity
		}
	}
	var rules struct {
		Status   string `json:"status"`
		Template struct {
			Version string `json:"version"`
			SHA256  string `json:"sha256"`
		} `json:"template"`
		Tokenizer struct {
			Version string `json:"version"`
			SHA256  string `json:"sha256"`
		} `json:"tokenizer"`
		Scoring struct{ Version string } `json:"scoring"`
	}
	if json.Unmarshal([]byte(copy.RuleJSON), &rules) != nil || rules.Status != "development_uncalibrated" || rules.Template.Version != copy.TemplateVersion || rules.Template.SHA256 != copy.TemplateHash || rules.Tokenizer.Version != copy.TokenizerVersion || !executionHash.MatchString(rules.Tokenizer.SHA256) || rules.Scoring.Version != copy.ScoringVersion {
		return nil, ErrBundleIntegrity
	}
	return &copy, nil
}

type RuleBundleRecord struct {
	ID, OrganizationID           int64
	Version, Status, ContentHash string
	ContentJSON                  string  `gorm:"column:content_json" json:"-"`
	ReplayMetricsJSON            *string `gorm:"column:replay_metrics_json" json:"-"`
	CreatedBy                    int64
	CreatedAt                    time.Time
	PublishedAt                  *time.Time
}

func (RuleBundleRecord) TableName() string { return "integrity_rule_bundles" }

type TemplateBundleRecord struct {
	ID, OrganizationID                int64
	Version, Sensitivity, ContentHash string
	ContentJSON                       string `gorm:"column:content_json" json:"-"`
	CreatedAt                         time.Time
}

func (TemplateBundleRecord) TableName() string { return "integrity_template_bundles" }

// seedBootstrapBundles runs inside initialization/organization creation or the
// server's explicit startup reconciliation transaction. Existing rows are never
// overwritten, promoted or unretired. A same-version byte change is corruption.
func (s *Store) seedBootstrapBundles(ctx context.Context, tx *gorm.DB, orgID, creator int64, now time.Time) error {
	if s.bootstrap == nil {
		return nil
	}
	b := s.bootstrap
	var rule RuleBundleRecord
	q := tx.Model(&RuleBundleRecord{}).Where("organization_id = ? AND version = ?", orgID, b.RuleVersion)
	if err := analysisBoundedRows(q, s.driver, "content_json", 1, 1<<20); err != nil {
		return ErrBundleIntegrity
	}
	found := q.Session(&gorm.Session{}).Find(&rule)
	if found.Error != nil {
		return found.Error
	}
	changed := false
	if found.RowsAffected == 0 {
		id, err := NewID()
		if err != nil {
			return err
		}
		rule = RuleBundleRecord{ID: id, OrganizationID: orgID, Version: b.RuleVersion, Status: "development", ContentHash: b.RuleHash, ContentJSON: b.RuleJSON, CreatedBy: creator, CreatedAt: now}
		if err := tx.Create(&rule).Error; err != nil {
			return err
		}
		changed = true
	} else if rule.ContentHash != b.RuleHash || rule.ContentJSON != b.RuleJSON {
		return ErrBundleIntegrity
	}
	var template TemplateBundleRecord
	q = tx.Model(&TemplateBundleRecord{}).Where("organization_id = ? AND version = ?", orgID, b.TemplateVersion)
	if err := analysisBoundedRows(q, s.driver, "content_json", 1, 1<<20); err != nil {
		return ErrBundleIntegrity
	}
	found = q.Session(&gorm.Session{}).Find(&template)
	if found.Error != nil {
		return found.Error
	}
	if found.RowsAffected == 0 {
		id, err := NewID()
		if err != nil {
			return err
		}
		template = TemplateBundleRecord{ID: id, OrganizationID: orgID, Version: b.TemplateVersion, Sensitivity: "public", ContentHash: b.TemplateHash, ContentJSON: b.TemplateJSON, CreatedAt: now}
		if err := tx.Create(&template).Error; err != nil {
			return err
		}
		changed = true
	} else if template.ContentHash != b.TemplateHash || template.ContentJSON != b.TemplateJSON {
		return ErrBundleIntegrity
	}
	if changed {
		return s.appendAudit(ctx, tx, orgID, auditObject("runtime.bundle.seed", "rule_bundle", rule.ID), &creator)
	}
	return nil
}

// SyncBootstrapBundles backfills the current development artifact for existing
// organizations after server migrations. Worker-only startup does not mutate
// registry data. Attribution is automatic lifecycle ownership, never approval.
func (s *Store) SyncBootstrapBundles(ctx context.Context) error {
	if s.bootstrap == nil {
		return nil
	}
	// Keyset batches keep startup memory bounded. Each organization is its own
	// atomic unit; a restarted/overlapping server resumes idempotently under the
	// organization lock without loading the whole registry into memory.
	var after int64
	for {
		var orgs []int64
		if err := s.db.WithContext(ctx).Model(&Organization{}).Where("id > ?", after).Order("id").Limit(100).Pluck("id", &orgs).Error; err != nil {
			return persistenceError(err)
		}
		if len(orgs) == 0 {
			return nil
		}
		for _, orgID := range orgs {
			err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
				var org Organization
				if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", orgID).First(&org).Error; err != nil {
					return err
				}
				var member Membership
				if err := tx.Where("organization_id = ?", orgID).Order("created_at,user_id").First(&member).Error; err != nil {
					return err
				}
				now, err := queueTime(tx, s.driver)
				if err != nil {
					return err
				}
				actorCtx := audit.WithActor(ctx, audit.Actor{ActorID: member.UserID, ReasonCode: "runtime.bundle.install"})
				return s.seedBootstrapBundles(actorCtx, tx, orgID, member.UserID, now)
			})
			if err != nil {
				return bundlePersistenceError(err)
			}
			after = orgID
		}
	}
}

func bundlePersistenceError(err error) error {
	if errors.Is(err, ErrBundleIntegrity) {
		return ErrBundleIntegrity
	}
	if errors.Is(err, ErrBundleUnavailable) {
		return ErrBundleUnavailable
	}
	return persistenceError(err)
}

func (tx *TenantTransaction) validateBootstrapPlan(plan domain.ExecutionPlan) error {
	if tx.store.bootstrap == nil {
		return nil
	}
	b := tx.store.bootstrap
	if plan.Versions != (domain.BundleVersions{Rule: b.RuleVersion, Template: b.TemplateVersion, Scoring: b.ScoringVersion, Tokenizer: b.TokenizerVersion}) {
		return ErrBundleUnavailable
	}
	return tx.store.checkBootstrapRows(tx.db, tx.orgID, true)
}
func (s *Store) checkBootstrapRows(db *gorm.DB, orgID int64, lock bool) error {
	if s.bootstrap == nil {
		return ErrBundleUnavailable
	}
	b := s.bootstrap
	query := db
	if lock {
		query = query.Clauses(clause.Locking{Strength: "SHARE"})
	}
	var rule RuleBundleRecord
	if err := query.Session(&gorm.Session{}).Select("id,status,content_hash").Where("organization_id = ? AND version = ?", orgID, b.RuleVersion).First(&rule).Error; err != nil {
		return ErrBundleUnavailable
	}
	if rule.Status != "development" {
		return ErrBundleUnavailable
	}
	if rule.ContentHash != b.RuleHash {
		return ErrBundleIntegrity
	}
	var exact int64
	if err := db.Model(&RuleBundleRecord{}).Where("organization_id = ? AND id = ? AND content_json = ?", orgID, rule.ID, b.RuleJSON).Count(&exact).Error; err != nil {
		return err
	}
	if exact != 1 {
		return ErrBundleIntegrity
	}
	var template TemplateBundleRecord
	if err := query.Session(&gorm.Session{}).Select("id,content_hash").Where("organization_id = ? AND version = ?", orgID, b.TemplateVersion).First(&template).Error; err != nil {
		return ErrBundleUnavailable
	}
	if template.ContentHash != b.TemplateHash {
		return ErrBundleIntegrity
	}
	if err := db.Model(&TemplateBundleRecord{}).Where("organization_id = ? AND id = ? AND content_json = ?", orgID, template.ID, b.TemplateJSON).Count(&exact).Error; err != nil {
		return err
	}
	if exact != 1 {
		return ErrBundleIntegrity
	}
	return nil
}
func (t *Tenant) CheckBootstrapBundles() error {
	return bundlePersistenceError(t.store.checkBootstrapRows(t.store.db.WithContext(t.ctx), t.orgID, false))
}
