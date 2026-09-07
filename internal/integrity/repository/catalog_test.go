package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
)

func catalogFixture(t *testing.T, s *Store) (InitializationResult, ManagementAuthority, context.Context) {
	t.Helper()
	initial, auth, ctx := managementFixture(t, s)
	if err := s.db.Exec("INSERT INTO permissions (code,description) VALUES ('catalog.write','test') ON CONFLICT (code) DO NOTHING").Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Exec("INSERT INTO role_permissions (organization_id,role_id,permission_code) SELECT organization_id,id,'catalog.write' FROM roles WHERE organization_id=? AND name='admin'", initial.Organization.ID).Error; err != nil {
		t.Fatal(err)
	}
	for _, permission := range []string{"target.delete", "secret.replace", "target.precheck"} {
		if err := s.db.Exec("INSERT INTO permissions (code,description) VALUES (?,'test') ON CONFLICT (code) DO NOTHING", permission).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Exec("INSERT INTO role_permissions (organization_id,role_id,permission_code) SELECT organization_id,id,? FROM roles WHERE organization_id=? AND name='admin'", permission, initial.Organization.ID).Error; err != nil {
			t.Fatal(err)
		}
	}
	ctx = bindTargetTestSession(t, s, ctx, auth.SessionID, initial.Organization.ID)
	return initial, auth, ctx
}
func catalogProfileFixture(providerID int64) ModelProfile {
	// #nosec G101 -- Synthetic tokenizer/capability metadata; no credential or key material.
	return ModelProfile{ModelProfileSummary: ModelProfileSummary{ProviderID: providerID, Model: "example-model", Protocol: "openai_chat"}, CapabilitiesJSON: `{"supports_stream":true}`, TokenizerJSON: `{"id":"example-tokenizer-v1","quality":"compatible"}`, PublicLimitsJSON: `{"max_output_tokens":8192,"context_window":65536}`}
}

func TestCatalogCRUDMetadataAndReferenceProtection(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, auth, ctx := catalogFixture(t, s)
		orgID := initial.Organization.ID
		provider, err := s.CatalogCreateProvider(ctx, auth, orgID, Provider{Name: " Test provider ", Description: "Non-sensitive description", Contact: "ops@example.invalid"})
		if err != nil {
			t.Fatal(err)
		}
		if provider.Name != "Test provider" || provider.Version != 1 || provider.Status != "active" {
			t.Fatal("provider defaults invalid")
		}
		profile, err := s.CatalogCreateModel(ctx, auth, orgID, catalogProfileFixture(provider.ID))
		if err != nil {
			t.Fatal(err)
		}
		if profile.Version != 1 || profile.InputPriceMicros != nil || profile.OutputPriceMicros != nil {
			t.Fatal("unknown price was fabricated")
		}
		capabilities, tokenizer, limits, err := ModelCatalogMetadata(profile)
		if err != nil || !capabilities.SupportsStream || tokenizer.Quality != "compatible" || *limits.MaxOutputTokens != 8192 {
			t.Fatal("metadata round trip failed")
		}
		if err := s.CatalogDeleteProvider(ctx, auth, orgID, provider.ID, 1); !errors.Is(err, ErrConflict) {
			t.Fatal("provider with model reference deleted")
		}
		tenant, _ := s.WithOrganization(ctx, orgID)
		record := targetRecordFixture()
		record.ModelProfileID = &profile.ID
		target, err := tenant.CreateTargetWithSecret(record, encryptedFixture(t, orgID))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.CatalogDeleteModel(ctx, auth, orgID, profile.ID, 1); !errors.Is(err, ErrConflict) {
			t.Fatal("referenced model deleted")
		}
		changed := profile
		changed.Model = "another-model"
		if _, err := s.CatalogUpdateModel(ctx, auth, orgID, profile.ID, 1, changed); !errors.Is(err, ErrConflict) {
			t.Fatal("referenced model identity changed")
		}
		changed = profile
		changed.Status = "disabled"
		profile, err = s.CatalogUpdateModel(ctx, auth, orgID, profile.ID, 1, changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.CreateTargetWithSecret(record, encryptedFixture(t, orgID)); !errors.Is(err, ErrNotFound) {
			t.Fatal("disabled model accepted new target")
		}
		if _, err := tenant.GetTarget(target.Target.ID); err != nil {
			t.Fatal("disabling metadata destroyed target history")
		}
		if err := tenant.DeleteTarget(target.Target.ID, 1); err != nil {
			t.Fatal(err)
		}
		if err := s.CatalogDeleteModel(ctx, auth, orgID, profile.ID, profile.Version); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CatalogGetModel(ctx, auth, orgID, profile.ID); !errors.Is(err, ErrNotFound) {
			t.Fatal("soft-deleted model remains visible")
		}
		if err := s.CatalogDeleteProvider(ctx, auth, orgID, provider.ID, provider.Version); err != nil {
			t.Fatal(err)
		}
		rows, err := s.CatalogListProviders(ctx, auth, orgID, CatalogList{Limit: 25})
		if err != nil || len(rows) != 0 {
			t.Fatal("deleted provider remains in list")
		}
		var persisted Provider
		if err := s.db.Where("id=?", provider.ID).First(&persisted).Error; err != nil || persisted.DeletedAt == nil {
			t.Fatal("provider hard-deleted")
		}
		if err := s.VerifyAllAudit(ctx, true); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCatalogValidationTenantAndSessionGuards(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, auth, ctx := catalogFixture(t, s)
		orgID := initial.Organization.ID
		provider, err := s.CatalogCreateProvider(ctx, auth, orgID, Provider{Name: "Validation provider"})
		if err != nil {
			t.Fatal(err)
		}
		negative := int64(-1)
		tooHigh := maxCatalogPrice + 1
		bad := []func(*ModelProfile){
			func(p *ModelProfile) { p.Protocol = "arbitrary_protocol" }, func(p *ModelProfile) { p.Model = "" },
			func(p *ModelProfile) { p.InputPriceMicros = &negative }, func(p *ModelProfile) { p.OutputPriceMicros = &tooHigh },
			func(p *ModelProfile) { p.CapabilitiesJSON = `{"secret":"should-never-be-stored"}` },
			func(p *ModelProfile) { p.CapabilitiesJSON = `{"supports_stream":"yes"}` },
			func(p *ModelProfile) { p.CapabilitiesJSON = `{"supports_stream":null}` },
			func(p *ModelProfile) { p.TokenizerJSON = `{"id":"","quality":"exact"}` },
			func(p *ModelProfile) { p.TokenizerJSON = `{"id":"secret","quality":"unavailable"}` },
			func(p *ModelProfile) { p.PublicLimitsJSON = `{"max_output_tokens":0}` },
			func(p *ModelProfile) { p.PublicLimitsJSON = `{"max_output_tokens":1024,"context_window":128}` },
			func(p *ModelProfile) { p.PublicLimitsJSON = `{"context_window":4194305}` },
			func(p *ModelProfile) { p.Model = "line\nbreak" },
		}
		for i, change := range bad {
			p := catalogProfileFixture(provider.ID)
			change(&p)
			if _, err := s.CatalogCreateModel(ctx, auth, orgID, p); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("invalid profile %d accepted: %v", i, err)
			}
		}
		if _, err := s.CatalogCreateProvider(ctx, auth, orgID, Provider{Name: "Bad", Contact: strings.Repeat("x", 257)}); !errors.Is(err, ErrConfiguration) {
			t.Fatal("unbounded contact accepted")
		}
		foreignID, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.CatalogGetProvider(ctx, auth, foreignID, provider.ID); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("cross-tenant read accepted")
		}
		if _, err := s.CatalogCreateModel(ctx, auth, orgID, catalogProfileFixture(foreignID)); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign provider accepted")
		}
		if _, err := s.CatalogListModels(ctx, auth, orgID, CatalogList{Limit: 101}); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid public page silently normalized")
		}
		if err := s.db.Model(&Session{}).Where("id=?", auth.SessionID).Update("revoked_at", time.Now().UTC()).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := s.CatalogCreateProvider(ctx, auth, orgID, Provider{Name: "revoked request"}); !errors.Is(err, ErrManagementSession) {
			t.Fatal("stale service authorization wrote catalog")
		}
	})
}

func TestCatalogConcurrentVersionsAndAuditedRollback(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		initial, auth, ctx := catalogFixture(t, s)
		orgID := initial.Organization.ID
		provider, err := s.CatalogCreateProvider(ctx, auth, orgID, Provider{Name: "Original"})
		if err != nil {
			t.Fatal(err)
		}
		other, err := Open(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		var wg sync.WaitGroup
		results := make(chan error, 6)
		for i := range 6 {
			wg.Go(func() {
				candidate := s
				if i%2 == 1 {
					candidate = other
				}
				_, err := candidate.CatalogUpdateProvider(ctx, auth, orgID, provider.ID, 1, Provider{Name: fmt.Sprintf("writer-%d", i), Status: "active"})
				results <- err
			})
		}
		wg.Wait()
		close(results)
		success := 0
		for err := range results {
			if err == nil {
				success++
			} else if !errors.Is(err, ErrConflict) {
				t.Fatal(err)
			}
		}
		if success != 1 {
			t.Fatal("multiple version winners")
		}
		provider, err = s.CatalogGetProvider(ctx, auth, orgID, provider.ID)
		if err != nil {
			t.Fatal(err)
		}
		profile, err := s.CatalogCreateModel(ctx, auth, orgID, catalogProfileFixture(provider.ID))
		if err != nil {
			t.Fatal(err)
		}
		unused, err := s.CatalogCreateProvider(ctx, auth, orgID, Provider{Name: "Unused"})
		if err != nil {
			t.Fatal(err)
		}
		signer := &switchAuditSigner{}
		s.auditSigner = signer
		signer.fail.Store(true)
		updated := profile
		zero := int64(0)
		updated.InputPriceMicros = &zero
		ops := []func() error{
			func() error {
				_, e := s.CatalogCreateProvider(ctx, auth, orgID, Provider{Name: "Rolled back"})
				return e
			},
			func() error {
				_, e := s.CatalogCreateModel(ctx, auth, orgID, catalogProfileFixture(provider.ID))
				return e
			},
			func() error {
				_, e := s.CatalogUpdateProvider(ctx, auth, orgID, provider.ID, provider.Version, Provider{Name: "Rolled back", Status: "disabled"})
				return e
			},
			func() error {
				_, e := s.CatalogUpdateModel(ctx, auth, orgID, profile.ID, profile.Version, updated)
				return e
			},
			func() error { return s.CatalogDeleteModel(ctx, auth, orgID, profile.ID, profile.Version) },
			func() error { return s.CatalogDeleteProvider(ctx, auth, orgID, unused.ID, unused.Version) },
		}
		for i, op := range ops {
			if err := op(); err == nil {
				t.Fatalf("audit failure committed mutation %d", i)
			}
		}
		signer.fail.Store(false)
		current, err := s.CatalogGetModel(ctx, auth, orgID, profile.ID)
		if err != nil || current.Version != 1 || current.InputPriceMicros != nil {
			t.Fatal("model mutation escaped rollback")
		}
		currentProvider, err := s.CatalogGetProvider(ctx, auth, orgID, provider.ID)
		if err != nil || currentProvider.Version != 2 || currentProvider.Status != "active" {
			t.Fatal("provider mutation escaped rollback")
		}
		providers, err := s.CatalogListProviders(ctx, auth, orgID, CatalogList{Limit: 25})
		if err != nil || len(providers) != 2 {
			t.Fatal("create/delete rollback failed")
		}
		if err := s.VerifyAllAudit(ctx, true); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCatalogPostgresDisableWaitsForReferenceRead(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		if cfg.Driver != "postgres" {
			t.Skip("PostgreSQL MVCC/SHARE lock race; SQLite uses BEGIN IMMEDIATE")
		}
		initial, auth, ctx := catalogFixture(t, s)
		orgID := initial.Organization.ID
		provider, err := s.CatalogCreateProvider(ctx, auth, orgID, Provider{Name: "Race provider"})
		if err != nil {
			t.Fatal(err)
		}
		profile, err := s.CatalogCreateModel(ctx, auth, orgID, catalogProfileFixture(provider.ID))
		if err != nil {
			t.Fatal(err)
		}
		other, err := Open(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		tenant, _ := other.WithOrganization(rebindTargetTestSession(t, other, ctx), orgID)
		// An uncommitted disable is invisible to an unlocked MVCC read. The
		// reference operation must block, then reject the committed disabled row.
		tx := s.db.WithContext(ctx).Begin()
		if tx.Error != nil {
			t.Fatal(tx.Error)
		}
		defer func() { _ = tx.Rollback().Error }()
		if _, err := s.catalogProviderLock(tx, orgID, provider.ID, false, "UPDATE"); err != nil {
			t.Fatal(err)
		}
		if err := tx.Model(&Provider{}).Where("id=?", provider.ID).Update("status", "disabled").Error; err != nil {
			t.Fatal(err)
		}
		record := targetRecordFixture()
		record.ModelProfileID = &profile.ID
		credential := encryptedFixture(t, orgID)
		result := make(chan error, 1)
		go func() { _, err := tenant.CreateTargetWithSecret(record, credential); result <- err }()
		select {
		case err := <-result:
			t.Fatalf("target bypassed provider SHARE lock: %v", err)
		case <-time.After(150 * time.Millisecond):
		}
		if err := tx.Commit().Error; err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-result:
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("disabled provider accepted: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("target did not recover after provider lock release")
		}
	})
}

func TestCatalogPostgresDeletionSeesConcurrentTargetReference(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		if cfg.Driver != "postgres" {
			t.Skip("PostgreSQL inter-transaction reference race")
		}
		initial, auth, ctx := catalogFixture(t, s)
		orgID := initial.Organization.ID
		provider, err := s.CatalogCreateProvider(ctx, auth, orgID, Provider{Name: "Target race"})
		if err != nil {
			t.Fatal(err)
		}
		other, err := Open(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		tenant, _ := s.WithOrganization(ctx, orgID)
		entered := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		if err := s.db.Callback().Create().Before("gorm:create").Register("catalog_test_target_barrier", func(tx *gorm.DB) {
			if tx.Statement.Table == "integrity_targets" {
				once.Do(func() { close(entered); <-release })
			}
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.db.Callback().Create().Remove("catalog_test_target_barrier") })
		record := targetRecordFixture()
		record.ProviderID = &provider.ID
		credential := encryptedFixture(t, orgID)
		created := make(chan error, 1)
		go func() { _, err := tenant.CreateTargetWithSecret(record, credential); created <- err }()
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			close(release)
			t.Fatal("target did not reach reference barrier")
		}
		deleted := make(chan error, 1)
		go func() { deleted <- other.CatalogDeleteProvider(ctx, auth, orgID, provider.ID, 1) }()
		select {
		case err := <-deleted:
			close(release)
			t.Fatalf("catalog deletion bypassed target reference lock: %v", err)
		case <-time.After(150 * time.Millisecond):
		}
		close(release)
		select {
		case err := <-created:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("target transaction did not finish")
		}
		select {
		case err := <-deleted:
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("referenced provider deleted: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("catalog delete did not finish")
		}
	})
}
