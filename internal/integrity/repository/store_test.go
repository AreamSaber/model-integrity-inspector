package repository

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/migrations"
)

type testAuditSigner struct{}

func (testAuditSigner) ActiveVersion() string { return "test-v1" }
func (testAuditSigner) AuditMAC(_ string, message []byte) ([]byte, error) {
	h := hmac.New(sha256.New, []byte("deterministic-fixture-not-a-deployment-key"))
	_, _ = h.Write(message)
	return h.Sum(nil), nil
}

func testActorContext(t *testing.T, userID int64) context.Context {
	t.Helper()
	return audit.WithActor(t.Context(), audit.Actor{ActorID: userID, ReasonCode: "integration.test", IPSummary: "loopback-test", UserAgentSummary: "test-runner"})
}

// Every integration case runs against the embedded SQLite engine and a real,
// isolated PostgreSQL schema when MII_TEST_POSTGRES_DSN is configured.
func eachDatabase(t *testing.T, test func(*testing.T, *Store, Config)) {
	t.Helper()
	for _, driver := range []string{"sqlite", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			cfg := Config{Driver: driver, DSN: filepath.Join(t.TempDir(), "mii.db"), AuditSigner: testAuditSigner{}}
			if driver == "postgres" {
				dsn := os.Getenv("MII_TEST_POSTGRES_DSN")
				if dsn == "" {
					t.Skip("real PostgreSQL not configured: set MII_TEST_POSTGRES_DSN")
				}
				id, err := NewID()
				if err != nil {
					t.Fatal(err)
				}
				schema := fmt.Sprintf("mii_test_%d", id)
				admin, err := sql.Open("pgx", dsn)
				if err != nil {
					t.Fatal("open PostgreSQL test admin connection")
				}
				if _, err := admin.ExecContext(t.Context(), "CREATE SCHEMA "+schema); err != nil {
					_ = admin.Close()
					t.Fatal("create isolated PostgreSQL test schema")
				}
				t.Cleanup(func() {
					// schema is constructed exclusively from a fixed prefix + int64.
					if _, err := admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
						t.Error("cleanup isolated PostgreSQL test schema")
					}
					_ = admin.Close()
				})
				if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
					parsed, err := url.Parse(dsn)
					if err != nil {
						t.Fatal("invalid PostgreSQL test URL")
					}
					query := parsed.Query()
					query.Set("search_path", schema)
					parsed.RawQuery = query.Encode()
					cfg.DSN = parsed.String()
				} else {
					cfg.DSN = dsn + " search_path=" + schema
				}
			}
			store, err := Open(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			test(t, store, cfg)
		})
	}
}

func requireMigrate(t *testing.T, store *Store) {
	t.Helper()
	if err := store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func initialState() Initialization {
	return Initialization{OrganizationName: "Example", Username: "Admin", PasswordHash: "test-only-argon2-placeholder", AdminRole: "administrator",
		Roles: []InitialRole{{Name: "administrator", Permissions: []string{"target.read", "target.write", "run.create"}}, {Name: "viewer", Permissions: []string{"target.read"}}}}
}

func requireInitialize(t *testing.T, store *Store) InitializationResult {
	t.Helper()
	result, err := store.Initialize(testActorContext(t, 0), initialState())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestMigrateRepeatableAndWorkerReadOnly(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		if err := store.CheckSchema(t.Context()); !errors.Is(err, ErrSchemaMismatch) {
			t.Fatalf("worker accepted empty schema: %v", err)
		}
		if store.db.Migrator().HasTable("schema_migrations") {
			t.Fatal("read-only worker created schema")
		}
		requireMigrate(t, store)
		requireMigrate(t, store)
		status, err := store.SchemaStatus(t.Context())
		if err != nil || len(status) != 1 || status[0].Status != "applied" {
			t.Fatalf("schema status: %+v %v", status, err)
		}
		for _, table := range []string{"organizations", "users", "user_sessions", "providers", "model_profiles", "integrity_targets", "integrity_runs", "integrity_jobs", "integrity_sample_attempts", "integrity_reports", "integrity_audit_logs"} {
			if !store.db.Migrator().HasTable(table) {
				t.Errorf("missing table %s", table)
			}
		}
	})
}

func TestMigrationRollbackAndChecksumProtection(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		requireMigrate(t, store)
		set, err := migrations.ForDialect(store.driver)
		if err != nil {
			t.Fatal(err)
		}
		bad := migrations.Migration{Version: 2, Name: "rollback_probe", Checksum: strings.Repeat("b", 64), SQL: "CREATE TABLE rollback_probe (id BIGINT PRIMARY KEY);\nINSERT INTO missing_table (id) VALUES (1);"}
		if err := store.migrate(t.Context(), append(set, bad)); !errors.Is(err, ErrMigrationFailed) {
			t.Fatalf("bad migration accepted: %v", err)
		}
		if store.db.Migrator().HasTable("rollback_probe") {
			t.Fatal("transactional DDL was not rolled back")
		}
		if err := store.CheckSchema(t.Context()); err != nil {
			t.Fatalf("failed upgrade changed prior migration ledger: %v", err)
		}
		if err := store.db.Table("schema_migrations").Where("version = ?", 1).Update("checksum", strings.Repeat("0", 64)).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.Migrate(t.Context()); !errors.Is(err, ErrSchemaMismatch) {
			t.Fatalf("server accepted checksum drift: %v", err)
		}
		if err := store.CheckSchema(t.Context()); !errors.Is(err, ErrSchemaMismatch) {
			t.Fatalf("worker accepted checksum drift: %v", err)
		}
	})
}

func TestEmptyMigrationFailureLeavesNoPartialSchema(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		set := []migrations.Migration{{Version: 1, Name: "bad_first", Checksum: "test", SQL: "CREATE TABLE partial_object (id BIGINT);\nCREATE TABLE partial_object (id BIGINT);"}}
		if err := store.migrate(t.Context(), set); !errors.Is(err, ErrMigrationFailed) {
			t.Fatalf("expected rollback, got %v", err)
		}
		if store.db.Migrator().HasTable("partial_object") || store.db.Migrator().HasTable("schema_migrations") {
			t.Fatal("failed first migration left partial schema or ledger")
		}
		requireMigrate(t, store)
	})
}

func TestConcurrentMigrationAndInitialization(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, cfg Config) {
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for i := range 8 {
			wg.Go(func() {
				candidate := store
				if i%2 == 1 {
					candidate = other
				}
				errs <- candidate.Migrate(t.Context())
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Errorf("concurrent migration failed: %v", err)
			}
		}
		errs = make(chan error, 2)
		for _, candidate := range []*Store{store, other} {
			wg.Go(func() {
				_, err := candidate.Initialize(testActorContext(t, 0), initialState())
				errs <- err
			})
		}
		wg.Wait()
		close(errs)
		successes, rejected := 0, 0
		for err := range errs {
			switch {
			case err == nil:
				successes++
			case errors.Is(err, ErrAlreadyInitialized):
				rejected++
			default:
				t.Errorf("unexpected setup result: %v", err)
			}
		}
		if successes != 1 || rejected != 1 {
			t.Fatalf("setup winners=%d rejections=%d", successes, rejected)
		}
	})
}

func TestTenantBoundariesAndCompositeForeignKeys(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		requireMigrate(t, store)
		initial := requireInitialize(t, store)
		if _, err := store.WithOrganization(t.Context(), 0); !errors.Is(err, ErrOrganizationScope) {
			t.Fatal("empty tenant scope accepted")
		}
		orgB := Organization{ID: 2, Name: "Other", Status: "active", Timezone: "UTC", QuotaJSON: "{}", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
		if err := store.db.Create(&orgB).Error; err != nil {
			t.Fatal(err)
		}
		tenantA, _ := store.WithOrganization(testActorContext(t, initial.User.ID), initial.Organization.ID)
		tenantB, _ := store.WithOrganization(testActorContext(t, initial.User.ID), orgB.ID)
		provider := Provider{Name: "Tenant A Provider"}
		if err := tenantA.CreateProvider(&provider); err != nil {
			t.Fatal(err)
		}
		if _, err := tenantB.GetProvider(provider.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-tenant read: %v", err)
		}
		listed, err := tenantB.ListProviders(ListOptions{})
		if err != nil || len(listed) != 0 {
			t.Fatalf("cross-tenant list: %+v %v", listed, err)
		}
		if err := tenantB.CreateProvider(&Provider{Name: "Forged scope", OrganizationID: initial.Organization.ID}); !errors.Is(err, ErrOrganizationScope) {
			t.Fatalf("cross-tenant create accepted: %v", err)
		}
		profile := ModelProfile{ModelProfileSummary: ModelProfileSummary{ProviderID: provider.ID, Model: "model-a", DisplayName: "Example"}}
		if err := tenantB.CreateModelProfile(&profile); !errors.Is(err, ErrConflict) {
			t.Fatalf("composite provider FK accepted foreign organization: %v", err)
		}
		profile.OrganizationID = 0
		if err := tenantA.CreateModelProfile(&profile); err != nil {
			t.Fatal(err)
		}
		models, err := tenantA.ListModelProfiles(ListOptions{})
		if err != nil || len(models) != 1 || models[0].ID != profile.ID {
			t.Fatalf("model list: %+v %v", models, err)
		}
		permissions, err := tenantA.PermissionsForUser(initial.User.ID)
		if err != nil || !slices.Contains(permissions, "run.create") {
			t.Fatalf("missing administrator grant: %v %v", permissions, err)
		}
		permissions, err = tenantB.PermissionsForUser(initial.User.ID)
		if err != nil || len(permissions) != 0 {
			t.Fatalf("permission crossed tenant: %v %v", permissions, err)
		}
		var role Role
		if err := store.db.Where("organization_id = ?", initial.Organization.ID).First(&role).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.db.Exec("INSERT INTO role_permissions (organization_id, role_id, permission_code) VALUES (?, ?, ?)", orgB.ID, role.ID, "run.create").Error; err == nil {
			t.Fatal("composite role FK accepted foreign organization")
		}
	})
}

func TestSessionExpiryRevocationAndPasswordAtomicity(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		requireMigrate(t, store)
		initial := requireInitialize(t, store)
		now := time.Now().UTC().Truncate(time.Microsecond)
		user, err := store.FindUserForAuthentication(t.Context(), " ADMIN ")
		if err != nil || user.ID != initial.User.ID {
			t.Fatalf("normalized login: %v", err)
		}
		session := Session{UserID: user.ID, SessionHash: strings.Repeat("a", 64), CSRFHash: strings.Repeat("b", 64), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		if err := store.CreateSessionIfPasswordCurrent(testActorContext(t, user.ID), &session, user.PasswordHash, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GetSession(t.Context(), session.SessionHash, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GetSession(t.Context(), session.SessionHash, session.ExpiresAt); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expired session accepted: %v", err)
		}
		if err := store.ChangePassword(testActorContext(t, user.ID), user.ID, "wrong-old-hash", "new-hash", now); !errors.Is(err, ErrConflict) {
			t.Fatalf("password optimistic lock missing: %v", err)
		}
		if _, err := store.GetSession(t.Context(), session.SessionHash, now); err != nil {
			t.Fatal("failed password change revoked session")
		}
		if err := store.ChangePassword(testActorContext(t, user.ID), user.ID, user.PasswordHash, "new-hash", now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GetSession(t.Context(), session.SessionHash, now); !errors.Is(err, ErrNotFound) {
			t.Fatal("password change did not atomically revoke sessions")
		}
		encoded, err := json.Marshal(struct {
			User    User
			Session Session
		}{user, session})
		if err != nil || strings.Contains(string(encoded), user.PasswordHash) || strings.Contains(string(encoded), session.SessionHash) || strings.Contains(string(encoded), session.CSRFHash) {
			t.Fatal("credential hashes leaked through JSON")
		}
	})
}

func TestInitializationRollback(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		requireMigrate(t, store)
		input := initialState()
		input.AdminRole = "missing-admin-role"
		if _, err := store.Initialize(testActorContext(t, 0), input); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("invalid seed accepted: %v", err)
		}
		initialized, err := store.SetupStatus(t.Context())
		if err != nil || initialized {
			t.Fatalf("failed setup marked initialized: %v", err)
		}
		var count int64
		if err := store.db.Model(&Organization{}).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("failed setup left partial organization")
		}
		requireInitialize(t, store)
	})
}

func TestSQLiteSafetyPragmasCannotBeDisabled(t *testing.T) {
	cfg := Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "safety.db") + "?_pragma=foreign_keys(0)&_txlock=deferred"}
	store, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	var foreignKeys int
	if err := store.db.Raw("PRAGMA foreign_keys").Scan(&foreignKeys).Error; err != nil || foreignKeys != 1 {
		t.Fatalf("foreign keys disabled: %d %v", foreignKeys, err)
	}
	if store.sql.Stats().MaxOpenConnections != 1 {
		t.Fatal("SQLite allows multiple in-process writers")
	}
}

func TestPersistenceErrorsDoNotMisreportOutagesOrLeakValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{"cancelled", context.Canceled, ErrUnavailable},
		{"timeout", context.DeadlineExceeded, ErrUnavailable},
		{"connection", errors.New("connection failed with secret-value"), ErrUnavailable},
		{"postgres unique", &pgconn.PgError{Code: "23505", Detail: "secret-value"}, ErrConflict},
		{"postgres foreign key", &pgconn.PgError{Code: "23503", Detail: "secret-value"}, ErrConflict},
		{"postgres outage", &pgconn.PgError{Code: "08006", Detail: "secret-value"}, ErrUnavailable},
		{"postgres rollback", &pgconn.PgError{Code: "40001", Detail: "secret-value"}, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := persistenceError(tc.err)
			if !errors.Is(got, tc.want) || strings.Contains(got.Error(), "secret-value") {
				t.Errorf("classification = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClosedPoolIsUnavailable(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		requireMigrate(t, store)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := store.FindUserForAuthentication(t.Context(), "nobody"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("closed pool reported %v", err)
		}
	})
}

func TestMigrationRejectsUnknownAndMissingVersions(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		requireMigrate(t, store)
		row := SchemaVersion{Version: 2, Name: "future", Checksum: "future", Status: "applied", AppliedAt: time.Now().UTC()}
		if err := store.db.Table("schema_migrations").Create(&row).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.CheckSchema(t.Context()); !errors.Is(err, ErrSchemaMismatch) {
			t.Fatalf("worker accepted future schema: %v", err)
		}
		if err := store.Migrate(t.Context()); !errors.Is(err, ErrSchemaMismatch) {
			t.Fatalf("server accepted future schema: %v", err)
		}
		if err := store.db.Exec("DELETE FROM schema_migrations WHERE version = 1").Error; err != nil {
			t.Fatal(err)
		}
		if err := store.CheckSchema(t.Context()); !errors.Is(err, ErrSchemaMismatch) {
			t.Fatalf("worker accepted gap in ledger: %v", err)
		}
	})
}

func TestNullIDsAndRunSampleAttemptConstraints(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		requireMigrate(t, store)
		initial := requireInitialize(t, store)
		now, orgID := time.Now().UTC(), initial.Organization.ID
		if err := store.db.Exec("INSERT INTO organizations (id, name, created_at, updated_at) VALUES (NULL, ?, ?, ?)", "Invalid NULL ID", now, now).Error; err == nil {
			t.Fatal("database accepted a NULL primary key")
		}
		insert := func(table string, row map[string]any) {
			t.Helper()
			if err := store.db.Table(table).Create(row).Error; err != nil {
				t.Fatalf("fixture %s: %v", table, err)
			}
		}
		insert("integrity_secrets", map[string]any{"id": 10, "organization_id": orgID, "encrypted_data_key": []byte("fixture-envelope"), "ciphertext": []byte("fixture-ciphertext"), "nonce": []byte("fixture-nonce"), "key_version": "test", "payload_key_version": "test", "fingerprint": "fixture", "last_four": "test", "created_at": now})
		for _, id := range []int64{11, 12} {
			insert("integrity_targets", map[string]any{"id": id, "organization_id": orgID, "name": "fixture-target", "endpoint": "https://example.invalid/v1/chat/completions", "endpoint_fingerprint": "fixture", "model": "fixture", "auth_type": "bearer", "secret_id": 10, "created_by": initial.User.ID, "updated_by": initial.User.ID, "created_at": now, "updated_at": now})
		}
		for _, id := range []int64{21, 22} {
			insert("integrity_runs", map[string]any{"id": id, "organization_id": orgID, "target_id": 11, "package": "quick", "status": "PENDING", "config_snapshot": "{}", "rule_bundle_version": "v1", "template_bundle_version": "v1", "scoring_version": "v1", "tokenizer_bundle_version": "v1", "request_budget": 10, "token_budget": 100, "created_by": initial.User.ID, "created_at": now})
		}
		if err := store.db.Exec("UPDATE integrity_runs SET target_id = ? WHERE organization_id = ? AND id = ?", 12, orgID, 21).Error; err == nil {
			t.Fatal("run target was mutable")
		}
		insert("integrity_probe_instances", map[string]any{"id": 30, "organization_id": orgID, "run_id": 21, "probe_type": "token", "template_id": "fixture", "template_version": "v1", "category": "token", "variant": "test", "planned_samples": 2, "status": "PLANNED", "parameters_json": "{}", "created_at": now})
		if err := store.db.Exec("INSERT INTO integrity_logical_samples (id, organization_id, run_id, probe_instance_id, ordinal, idempotency_key, request_plan, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", 40, orgID, 22, 30, 1, "wrong-run", "{}", now).Error; err == nil {
			t.Fatal("sample linked to a probe from another run")
		}
		for _, id := range []int64{40, 41} {
			insert("integrity_logical_samples", map[string]any{"id": id, "organization_id": orgID, "run_id": 21, "probe_instance_id": 30, "ordinal": id - 40, "idempotency_key": fmt.Sprintf("fixture-%d", id), "request_plan": "{}", "created_at": now})
			insert("integrity_sample_attempts", map[string]any{"id": id + 10, "organization_id": orgID, "logical_sample_id": id, "attempt_no": 1, "request_snapshot": "{}", "request_hash": "fixture"})
		}
		if err := store.db.Exec("UPDATE integrity_logical_samples SET final_attempt_id = ? WHERE organization_id = ? AND id = ?", 51, orgID, 40).Error; err == nil {
			t.Fatal("sample accepted another sample's final attempt")
		}
		if err := store.db.Exec("UPDATE integrity_logical_samples SET final_attempt_id = ? WHERE organization_id = ? AND id = ?", 50, orgID, 40).Error; err != nil {
			t.Fatal("same-sample final attempt rejected")
		}
		if err := store.db.Exec("DELETE FROM integrity_sample_attempts WHERE organization_id = ? AND id = ?", orgID, 50).Error; err == nil {
			t.Fatal("referenced final attempt could be deleted")
		}
	})
}
