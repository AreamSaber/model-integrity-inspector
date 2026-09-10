package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/bundle"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

type failSeedAuditSigner struct{}

func (failSeedAuditSigner) ActiveVersion() string { return "test-v1" }
func (failSeedAuditSigner) AuditMAC(version string, data []byte) ([]byte, error) {
	if bytes.Contains(data, []byte("runtime.bundle.seed")) {
		return nil, audit.ErrUnavailable
	}
	return (testAuditSigner{}).AuditMAC(version, data)
}

func TestBootstrapInitializationRollsBackIfSeedAuditFails(t *testing.T) {
	eachDatabase(t, func(t *testing.T, _ *Store, cfg Config) {
		cfg.AuditSigner = failSeedAuditSigner{}
		s := bootstrapTestStore(t, cfg)
		requireMigrate(t, s)
		if _, err := s.Initialize(testActorContext(t, 0), initialState()); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatal("seed audit failure not propagated", err)
		}
		if initialized, err := s.SetupStatus(t.Context()); err != nil || initialized {
			t.Fatal("setup marker escaped failed seed")
		}
		for _, table := range []string{"users", "organizations", "integrity_rule_bundles", "integrity_template_bundles"} {
			var count int64
			if err := s.db.Table(table).Count(&count).Error; err != nil || count != 0 {
				t.Fatal("initialization partially persisted", table, err)
			}
		}
	})
}

func bootstrapTestArtifacts(t *testing.T) BootstrapArtifacts {
	t.Helper()
	a, err := bundle.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	return BootstrapArtifacts{RuleVersion: bundle.BuiltinVersion, RuleHash: bundle.BuiltinHash, RuleJSON: string(a.RuleBytes()), TemplateVersion: templates.BuiltinVersion, TemplateHash: templates.BuiltinHash, TemplateJSON: string(a.TemplateBytes()), ScoringVersion: scoring.Version, TokenizerVersion: tokenizer.BuiltinVersion}
}
func bootstrapTestStore(t *testing.T, cfg Config) *Store {
	t.Helper()
	b := bootstrapTestArtifacts(t)
	cfg.Bootstrap = &b
	s, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	// Open retained its own immutable configuration copy.
	b.RuleJSON = "caller-mutated-config"
	return s
}

func TestBootstrapInitializationAndNewOrganizationAreAtomicDevelopmentSeeds(t *testing.T) {
	eachDatabase(t, func(t *testing.T, _ *Store, cfg Config) {
		s := bootstrapTestStore(t, cfg)
		initial, auth, ctx := managementFixture(t, s)
		check := func(org int64) {
			t.Helper()
			tenant, _ := s.WithOrganization(t.Context(), org)
			if err := tenant.CheckBootstrapBundles(); err != nil {
				t.Fatal(err)
			}
			var rules []RuleBundleRecord
			if err := s.db.Where("organization_id = ?", org).Find(&rules).Error; err != nil || len(rules) != 1 {
				t.Fatal("missing rule seed", err)
			}
			if rules[0].Status != "development" || rules[0].PublishedAt != nil || rules[0].ReplayMetricsJSON != nil || rules[0].CreatedBy != initial.User.ID {
				t.Fatal("seed invented publication/replay/approval")
			}
			var templates []TemplateBundleRecord
			if err := s.db.Where("organization_id = ?", org).Find(&templates).Error; err != nil || len(templates) != 1 || templates[0].Sensitivity != "public" {
				t.Fatal("wrong template seed")
			}
			if _, err := tenant.VerifyAuditFull(); err != nil {
				t.Fatal(err)
			}
		}
		check(initial.Organization.ID)
		created, err := s.ManageCreateOrganization(ctx, auth, ManagedOrganizationCreate{Name: "Second seeded org", Timezone: "UTC", Roles: managementFixtureRoles()})
		if err != nil {
			t.Fatal(err)
		}
		check(created.ID)
		if err := s.SyncBootstrapBundles(context.Background()); err != nil {
			t.Fatal(err)
		}
		check(created.ID)
	})
}

func TestBootstrapSameVersionCannotChangeOrUnretireAndLiveBytesAreChecked(t *testing.T) {
	eachDatabase(t, func(t *testing.T, _ *Store, cfg Config) {
		s := bootstrapTestStore(t, cfg)
		tenant, _, plan, policy := executionFixture(t, s, 1)
		plan.Versions = domain.BundleVersions{Rule: bundle.BuiltinVersion, Template: templates.BuiltinVersion, Scoring: scoring.Version, Tokenizer: tokenizer.BuiltinVersion}
		if _, err := tenant.CreateRun(plan, policy, "bound-runtime"); err != nil {
			t.Fatal(err)
		}
		plan.Versions.Rule = "unconfigured"
		if _, err := tenant.CreateRun(plan, policy, "old-version"); !errors.Is(err, ErrBundleUnavailable) {
			t.Fatal("old runtime admitted", err)
		}
		plan.Versions.Rule = bundle.BuiltinVersion
		var original RuleBundleRecord
		if err := s.db.Where("organization_id = ?", tenant.orgID).First(&original).Error; err != nil {
			t.Fatal(err)
		}
		q := s.db.Model(&RuleBundleRecord{}).Where("organization_id = ? AND id = ?", tenant.orgID, original.ID)
		if err := q.Update("content_json", `{"tampered":true}`).Error; err != nil {
			t.Fatal(err)
		}
		if err := tenant.CheckBootstrapBundles(); !errors.Is(err, ErrBundleIntegrity) {
			t.Fatal("live altered bytes accepted under original hash", err)
		}
		if err := s.SyncBootstrapBundles(context.Background()); !errors.Is(err, ErrBundleIntegrity) {
			t.Fatal("same version silently overwritten", err)
		}
		if err := q.Updates(map[string]any{"content_json": original.ContentJSON, "status": "retired"}).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.SyncBootstrapBundles(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := tenant.CheckBootstrapBundles(); !errors.Is(err, ErrBundleUnavailable) {
			t.Fatal("startup unretired package", err)
		}
		if _, err := tenant.CreateRun(plan, policy, "retired-denied"); !errors.Is(err, ErrBundleUnavailable) {
			t.Fatal("retired package admitted new run", err)
		}
	})
}

func TestBootstrapBackfillIsIdempotentAndAudited(t *testing.T) {
	eachDatabase(t, func(t *testing.T, legacy *Store, cfg Config) {
		requireMigrate(t, legacy)
		initial := requireInitialize(t, legacy)
		s := bootstrapTestStore(t, cfg)
		if err := s.SyncBootstrapBundles(context.Background()); err != nil {
			t.Fatal(err)
		}
		var first RuleBundleRecord
		if err := s.db.Where("organization_id = ?", initial.Organization.ID).First(&first).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.SyncBootstrapBundles(context.Background()); err != nil {
			t.Fatal(err)
		}
		var second RuleBundleRecord
		if err := s.db.Where("organization_id = ?", initial.Organization.ID).First(&second).Error; err != nil {
			t.Fatal(err)
		}
		if first.ID != second.ID || first.ContentJSON != second.ContentJSON || !first.CreatedAt.Equal(second.CreatedAt) {
			t.Fatal("startup rewrote immutable version")
		}
		tenant, _ := s.WithOrganization(t.Context(), initial.Organization.ID)
		if _, err := tenant.VerifyAuditFull(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestBootstrapBackfillTraversesBoundedOrganizationPages(t *testing.T) {
	eachDatabase(t, func(t *testing.T, legacy *Store, cfg Config) {
		initial, auth, ctx := managementFixture(t, legacy)
		orgs := []int64{initial.Organization.ID}
		for i := 0; i < 100; i++ {
			created, err := legacy.ManageCreateOrganization(ctx, auth, ManagedOrganizationCreate{Name: fmt.Sprintf("Legacy org %03d", i), Timezone: "UTC", Roles: managementFixtureRoles()})
			if err != nil {
				t.Fatal(err)
			}
			orgs = append(orgs, created.ID)
		}
		s := bootstrapTestStore(t, cfg)
		if err := s.SyncBootstrapBundles(t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, org := range orgs {
			tenant, err := s.WithOrganization(t.Context(), org)
			if err != nil || tenant.CheckBootstrapBundles() != nil {
				t.Fatal("organization omitted by startup pagination", org, err)
			}
			if _, err := tenant.VerifyAuditFull(); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestBootstrapOrganizationCreationRollsBackOnSeedAuditFailure(t *testing.T) {
	eachDatabase(t, func(t *testing.T, _ *Store, cfg Config) {
		s := bootstrapTestStore(t, cfg)
		initial, auth, ctx := managementFixture(t, s)
		cfg.AuditSigner = failSeedAuditSigner{}
		failing := bootstrapTestStore(t, cfg)
		if _, err := failing.ManageCreateOrganization(ctx, auth, ManagedOrganizationCreate{Name: "Must roll back", Timezone: "UTC", Roles: managementFixtureRoles()}); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatal("seed audit failure not propagated", err)
		}
		for _, table := range []string{"organizations", "integrity_rule_bundles", "integrity_template_bundles"} {
			var count int64
			if err := s.db.Table(table).Count(&count).Error; err != nil || count != 1 {
				t.Fatal("partial organization escaped seed rollback", table, err)
			}
		}
		tenant, _ := s.WithOrganization(t.Context(), initial.Organization.ID)
		if _, err := tenant.VerifyAuditFull(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestBootstrapConfigRejectsMissingHashesVersionsAndFakePublishedStatus(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*BootstrapArtifacts)
	}{
		{"bad-hash", func(b *BootstrapArtifacts) { b.RuleHash = strings.Repeat("a", 64) }},
		{"wrong-version", func(b *BootstrapArtifacts) { b.RuleVersion = "different" }},
		{"fake-published", func(b *BootstrapArtifacts) {
			b.RuleJSON = strings.Replace(b.RuleJSON, "development_uncalibrated", "published", 1)
			digest := sha256.Sum256([]byte(b.RuleJSON))
			b.RuleHash = hex.EncodeToString(digest[:])
		}},
		{"wrong-scoring", func(b *BootstrapArtifacts) { b.ScoringVersion = "different" }},
		{"wrong-tokenizer", func(b *BootstrapArtifacts) { b.TokenizerVersion = "different" }},
		{"bad-template", func(b *BootstrapArtifacts) { b.TemplateJSON = `{}` }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := bootstrapTestArtifacts(t)
			tc.mutate(&b)
			if _, err := validatedBootstrap(&b); !errors.Is(err, ErrBundleIntegrity) {
				t.Fatal("invalid artifact accepted", err)
			}
		})
	}
}
