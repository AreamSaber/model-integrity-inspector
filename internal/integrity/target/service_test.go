package target

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/identity"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/safehttp"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

const keyCanary = "synthetic-target-key-canary-84c9"
const headerCanary = "synthetic-header-canary-79e2"

type serviceFixture struct {
	service *Service
	secrets *secret.Service
	store   *repository.Store
	db      *sql.DB
	ctx     context.Context
	orgID   int64
}

func eachServiceDatabase(t *testing.T, test func(*testing.T, serviceFixture)) {
	t.Helper()
	for _, driver := range []string{"sqlite", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			cfg := repository.Config{Driver: driver, DSN: filepath.Join(t.TempDir(), "targets.db")}
			if driver == "postgres" {
				dsn := os.Getenv("MII_TEST_POSTGRES_DSN")
				if dsn == "" {
					t.Skip("real PostgreSQL not configured")
				}
				id, err := repository.NewID()
				if err != nil {
					t.Fatal(err)
				}
				schema := fmt.Sprintf("mii_target_test_%d", id)
				admin, err := sql.Open("pgx", dsn)
				if err != nil {
					t.Fatal("test database connection failed")
				}
				if _, err := admin.ExecContext(t.Context(), "CREATE SCHEMA "+schema); err != nil {
					_ = admin.Close()
					t.Fatal("isolated schema creation failed")
				}
				t.Cleanup(func() {
					if _, err := admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
						t.Error("isolated schema cleanup failed")
					}
					_ = admin.Close()
				})
				if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
					parsed, err := url.Parse(dsn)
					if err != nil {
						t.Fatal("invalid test database configuration")
					}
					query := parsed.Query()
					query.Set("search_path", schema)
					parsed.RawQuery = query.Encode()
					cfg.DSN = parsed.String()
				} else {
					cfg.DSN = dsn + " search_path=" + schema
				}
			}
			ring, err := secret.NewKeyRing("v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x92}, 32)})
			if err != nil {
				t.Fatal(err)
			}
			cfg.AuditSigner = ring
			store, err := repository.Open(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			if err := store.Migrate(t.Context()); err != nil {
				t.Fatal(err)
			}
			ctx := audit.WithActor(t.Context(), audit.Actor{ActorID: 0, ReasonCode: "target.test"})
			identities, err := identity.NewService(ctx, store)
			if err != nil {
				t.Fatal(err)
			}
			const fixturePassword = "synthetic-target-login-password"
			if err := identities.Initialize(ctx, "Target tests", "admin", fixturePassword); err != nil {
				t.Fatal(err)
			}
			material, err := identities.Login(ctx, "admin", fixturePassword)
			if err != nil {
				t.Fatal(err)
			}
			orgID := material.Organizations[0].ID
			ctx = audit.WithActor(t.Context(), audit.Actor{ActorID: material.User.ID, ReasonCode: "target.test"})
			hash := sha256.Sum256([]byte(material.CookieValue()))
			ctx, err = store.BindControlAuthority(ctx, hex.EncodeToString(hash[:]), orgID)
			if err != nil {
				t.Fatal(err)
			}
			secrets, err := secret.NewService(store, ring)
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewService(Config{Store: store, Secrets: secrets})
			if err != nil {
				t.Fatal(err)
			}
			sqlDriver := "sqlite"
			if driver == "postgres" {
				sqlDriver = "pgx"
			}
			db, err := sql.Open(sqlDriver, cfg.DSN)
			if err != nil {
				t.Fatal("test inspection database failed")
			}
			t.Cleanup(func() { _ = db.Close() })
			test(t, serviceFixture{service, secrets, store, db, ctx, orgID})
		})
	}
}

func testInput() Input {
	return Input{Name: "Target", Endpoint: "https://EXAMPLE.com:443/v1", Protocol: "openai_chat", Model: "served-model", Environment: "test", ChannelID: "channel", Tags: []string{"tag"}}
}
func testCredentials() secret.Input {
	return secret.Input{Type: "bearer", APIKey: []byte(keyCanary), Headers: map[string]string{"X-Private-Header": headerCanary}}
}

func TestServiceEncryptedLifecycleAndImmutableSnapshot(t *testing.T) {
	eachServiceDatabase(t, func(t *testing.T, f serviceFixture) {
		created, err := f.service.Create(f.ctx, f.orgID, testInput(), testCredentials())
		if err != nil {
			t.Fatal(err)
		}
		if created.ID <= 0 || created.Secret.ID <= 0 || created.Secret.Version != 1 || created.Version != 1 || created.Secret.Mask != "********84c9" || created.Options.TLSVerify == nil || !*created.Options.TLSVerify || created.Options.TimeoutSeconds != 180 {
			t.Fatal("invalid safe response defaults")
		}
		encoded, err := json.Marshal(created)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{keyCanary, headerCanary, "X-Private-Header", "ciphertext", "fingerprint", "auth_header_name", "api_key"} {
			if bytes.Contains(encoded, []byte(forbidden)) {
				t.Fatal("public view leaked credentials")
			}
		}
		snapshot, err := f.service.Snapshot(f.ctx, f.orgID, created.ID)
		if err != nil {
			t.Fatal(err)
		}
		frozen, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		var borrowedKey []byte
		var borrowedHeader []byte
		err = f.secrets.WithCredentialsForWorker(f.ctx, secret.Scope{OrganizationID: f.orgID, SecretID: created.Secret.ID, SecretVersion: 1}, func(credentials secret.Credentials) error {
			return credentials.Use(func(key []byte, headers map[string][]byte) error {
				if string(key) != keyCanary || string(headers["x-private-header"]) != headerCanary {
					t.Fatal("encrypted roundtrip mismatch")
				}
				borrowedKey = key
				borrowedHeader = headers["x-private-header"]
				return nil
			})
		})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(borrowedKey, make([]byte, len(borrowedKey))) || !bytes.Equal(borrowedHeader, make([]byte, len(borrowedHeader))) {
			t.Fatal("worker borrowed plaintext retained")
		}
		var ciphertext, wrapped, nonce []byte
		var optionsJSON, tagsJSON string
		if err := f.db.QueryRowContext(f.ctx, "SELECT ciphertext, encrypted_data_key, nonce FROM integrity_secrets WHERE organization_id = $1 AND id = $2", f.orgID, created.Secret.ID).Scan(&ciphertext, &wrapped, &nonce); err != nil {
			t.Fatal("inspect encrypted record failed")
		}
		if len(ciphertext) < 16 || len(wrapped) == 0 || len(nonce) != 12 || bytes.Contains(ciphertext, []byte(keyCanary)) || bytes.Contains(ciphertext, []byte(headerCanary)) || bytes.Contains(wrapped, []byte(keyCanary)) {
			t.Fatal("plaintext persisted")
		}
		if err := f.db.QueryRowContext(f.ctx, "SELECT options_json, tags_json FROM integrity_targets WHERE organization_id = $1 AND id = $2", f.orgID, created.ID).Scan(&optionsJSON, &tagsJSON); err != nil {
			t.Fatal("inspect target configuration failed")
		}
		if strings.Contains(optionsJSON+tagsJSON, keyCanary) || strings.Contains(optionsJSON+tagsJSON, headerCanary) {
			t.Fatal("target configuration duplicated credentials")
		}
		input := created.Input
		input.Name = "Changed"
		input.Tags = []string{"new"}
		updated, err := f.service.Update(f.ctx, f.orgID, created.ID, 1, input, "disabled")
		if err != nil || updated.Version != 2 {
			t.Fatalf("update failed: %v", err)
		}
		if _, err := f.service.Snapshot(f.ctx, f.orgID, created.ID); !errors.Is(err, repository.ErrConflict) {
			t.Fatal("disabled target snapshot issued")
		}
		if err := f.secrets.WithCredentialsForWorker(f.ctx, secret.Scope{OrganizationID: f.orgID, SecretID: created.Secret.ID, SecretVersion: 1}, func(secret.Credentials) error { t.Fatal("disabled credentials callback"); return nil }); !errors.Is(err, secret.ErrUnavailable) {
			t.Fatal("disabled target secret read")
		}
		updated, err = f.service.Update(f.ctx, f.orgID, created.ID, 2, input, "active")
		if err != nil {
			t.Fatal(err)
		}
		rotation := secret.Input{Type: "custom_header", HeaderName: "X-API-Key", APIKey: []byte("replacement-synthetic-key-5678"), Headers: map[string]string{"X-New-Header": "replacement-private-header"}}
		rotated, err := f.service.RotateSecret(f.ctx, f.orgID, created.ID, updated.Version, 1, rotation)
		if err != nil || rotated.Version != 4 || rotated.Secret.Version != 2 || rotated.Secret.Mask != "********5678" {
			t.Fatalf("rotate failed: %v", err)
		}
		if _, err := f.service.RotateSecret(f.ctx, f.orgID, created.ID, updated.Version, 1, rotation); !errors.Is(err, repository.ErrConflict) {
			t.Fatal("stale rotation accepted")
		}
		if err := f.secrets.WithCredentialsForWorker(f.ctx, secret.Scope{OrganizationID: f.orgID, SecretID: created.Secret.ID, SecretVersion: 1}, func(secret.Credentials) error { t.Fatal("old version callback"); return nil }); !errors.Is(err, secret.ErrUnavailable) {
			t.Fatal("old version recoverable")
		}
		if err := f.secrets.WithCredentialsForWorker(f.ctx, secret.Scope{OrganizationID: f.orgID, SecretID: created.Secret.ID, SecretVersion: 2}, func(credentials secret.Credentials) error {
			return credentials.Use(func(key []byte, headers map[string][]byte) error {
				if !bytes.Equal(key, rotation.APIKey) || string(headers["x-new-header"]) != "replacement-private-header" {
					t.Fatal("rotation payload mismatch")
				}
				return nil
			})
		}); err != nil {
			t.Fatal(err)
		}
		if err := f.service.Delete(f.ctx, f.orgID, created.ID, rotated.Version); err != nil {
			t.Fatal(err)
		}
		if _, err := f.service.Get(f.ctx, f.orgID, created.ID); !errors.Is(err, repository.ErrNotFound) {
			t.Fatal("deleted target returned")
		}
		if err := f.secrets.WithCredentialsForWorker(f.ctx, secret.Scope{OrganizationID: f.orgID, SecretID: created.Secret.ID, SecretVersion: 2}, func(secret.Credentials) error { t.Fatal("deleted callback"); return nil }); !errors.Is(err, secret.ErrUnavailable) {
			t.Fatal("deleted secret available")
		}
		frozenAgain, err := json.Marshal(snapshot)
		if err != nil || !bytes.Equal(frozen, frozenAgain) {
			t.Fatal("historical snapshot mutated with live target")
		}
		if err := f.db.QueryRowContext(f.ctx, "SELECT ciphertext, encrypted_data_key, nonce FROM integrity_secrets WHERE organization_id = $1 AND id = $2", f.orgID, created.Secret.ID).Scan(&ciphertext, &wrapped, &nonce); err != nil || len(ciphertext) != 0 || len(wrapped) != 0 || len(nonce) != 0 {
			t.Fatal("delete failed to erase credential columns")
		}
	})
}

func TestServiceValidationRejectsUnsafeInputBeforePersistence(t *testing.T) {
	eachServiceDatabase(t, func(t *testing.T, f serviceFixture) {
		noTLS := false
		invalidID := int64(-1)
		cases := map[string]func(*Input){
			"empty-name": func(i *Input) { i.Name = " " }, "name-crlf": func(i *Input) { i.Name = "name\r\n" }, "long-name": func(i *Input) { i.Name = strings.Repeat("名", 129) },
			"metadata": func(i *Input) { i.Endpoint = "https://169.254.169.254/latest" }, "loopback": func(i *Input) { i.Endpoint = "https://127.0.0.1/v1" }, "query-key": func(i *Input) { i.Endpoint = "https://example.com/v1?key=" + keyCanary }, "userinfo": func(i *Input) { i.Endpoint = "https://user:password@example.com/v1" }, "plain-http": func(i *Input) { i.Endpoint = "http://example.com/v1" },
			"protocol": func(i *Input) { i.Protocol = "unsupported" }, "empty-model": func(i *Input) { i.Model = "" }, "invalid-model-utf8": func(i *Input) { i.Model = string([]byte{0xff}) }, "environment-control": func(i *Input) { i.Environment = "\x00" }, "channel-long": func(i *Input) { i.ChannelID = strings.Repeat("a", 129) },
			"duplicate-tags": func(i *Input) { i.Tags = []string{"same", "same"} }, "too-many-tags": func(i *Input) { i.Tags = make([]string, 21) }, "empty-tag": func(i *Input) { i.Tags = []string{""} }, "provider-id": func(i *Input) { i.ProviderID = &invalidID }, "model-profile-id": func(i *Input) { i.ModelProfileID = &invalidID },
			"insecure-tls": func(i *Input) { i.Options.TLSVerify = &noTLS }, "parameter": func(i *Input) { i.Options.MaxOutputParameter = "arbitrary" }, "timeout": func(i *Input) { i.Options.TimeoutSeconds = 181 }, "concurrency": func(i *Input) { i.Options.Concurrency = -1 }, "rpm": func(i *Input) { i.Options.RPM = 10001 },
		}
		for name, mutate := range cases {
			t.Run(name, func(t *testing.T) {
				input := testInput()
				mutate(&input)
				if _, err := f.service.Create(f.ctx, f.orgID, input, testCredentials()); !errors.Is(err, ErrInvalid) {
					t.Fatalf("unsafe input accepted: %v", err)
				}
			})
		}
		badCredentials := []secret.Input{{Type: "none", APIKey: []byte(keyCanary)}, {Type: "bearer"}, {Type: "bearer", APIKey: []byte("key\r\nHeader: value")}, {Type: "bearer", APIKey: []byte(keyCanary), Headers: map[string]string{"Authorization": "leak"}}, {Type: "bearer", APIKey: []byte(keyCanary), Headers: map[string]string{"Proxy-Authorization": "leak"}}, {Type: "bearer", APIKey: []byte(keyCanary), Headers: map[string]string{"X-Header": "a", "x-header": "b"}}, {Type: "custom_header", HeaderName: "Authorization", APIKey: []byte(keyCanary)}, {Type: "custom_header", HeaderName: "X-Key", APIKey: []byte(keyCanary), Headers: map[string]string{"x-key": "override"}}}
		for _, credentials := range badCredentials {
			if _, err := f.service.Create(f.ctx, f.orgID, testInput(), credentials); !errors.Is(err, secret.ErrInvalid) {
				t.Fatalf("unsafe credential accepted: %v", err)
			}
		}
		if _, err := f.service.Create(f.ctx, 0, testInput(), testCredentials()); !errors.Is(err, repository.ErrOrganizationScope) {
			t.Fatal("missing organization accepted")
		}
		for _, table := range []string{"integrity_targets", "integrity_secrets"} {
			var count int
			if err := f.db.QueryRowContext(f.ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil || count != 0 {
				t.Fatal("validation failure persisted data")
			}
		}
	})
}

func TestServiceTenantPaginationSnapshotOwnershipAndCanceledWorker(t *testing.T) {
	eachServiceDatabase(t, func(t *testing.T, f serviceFixture) {
		first, err := f.service.Create(f.ctx, f.orgID, testInput(), testCredentials())
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.service.Create(f.ctx, f.orgID, testInput(), testCredentials())
		if err != nil {
			t.Fatal(err)
		}
		values, err := f.service.List(f.ctx, f.orgID, repository.ListOptions{Limit: 1})
		if err != nil || len(values) != 1 {
			t.Fatal("pagination limit")
		}
		next, err := f.service.List(f.ctx, f.orgID, repository.ListOptions{AfterID: values[0].ID, Limit: 1})
		if err != nil || len(next) != 1 || next[0].ID <= values[0].ID {
			t.Fatal("pagination cursor")
		}
		foreignOrg, _ := repository.NewID()
		if _, err := f.service.Get(f.ctx, foreignOrg, first.ID); !errors.Is(err, repository.ErrNotFound) {
			t.Fatal("cross tenant read")
		}
		if _, err := f.service.Update(f.ctx, foreignOrg, first.ID, 1, testInput(), "active"); !errors.Is(err, repository.ErrManagementPermission) {
			t.Fatal("cross tenant update")
		}
		if _, err := f.service.RotateSecret(f.ctx, foreignOrg, first.ID, 1, 1, testCredentials()); !errors.Is(err, repository.ErrManagementPermission) {
			t.Fatal("cross tenant rotation")
		}
		if err := f.service.Delete(f.ctx, foreignOrg, first.ID, 1); !errors.Is(err, repository.ErrManagementPermission) {
			t.Fatal("cross tenant delete")
		}
		if _, err := f.service.Snapshot(f.ctx, foreignOrg, first.ID); !errors.Is(err, repository.ErrNotFound) {
			t.Fatal("cross tenant snapshot")
		}
		values, err = f.service.List(f.ctx, foreignOrg, repository.ListOptions{})
		if err != nil || len(values) != 0 {
			t.Fatal("cross tenant list")
		}
		snapshot, err := f.service.Snapshot(f.ctx, f.orgID, first.ID)
		if err != nil {
			t.Fatal(err)
		}
		snapshot.Tags[0] = "mutated"
		*snapshot.Options.TLSVerify = false
		read, err := f.service.Get(f.ctx, f.orgID, first.ID)
		if err != nil || read.Tags[0] != "tag" || !*read.Options.TLSVerify {
			t.Fatal("snapshot aliases persistent configuration")
		}
		ctx, cancel := context.WithCancel(f.ctx)
		cancel()
		if err := f.secrets.WithCredentialsForWorker(ctx, secret.Scope{OrganizationID: f.orgID, SecretID: first.Secret.ID, SecretVersion: 1}, func(secret.Credentials) error { t.Fatal("canceled callback"); return nil }); !errors.Is(err, secret.ErrUnavailable) {
			t.Fatal("canceled worker obtained credentials")
		}
		if err := f.secrets.WithCredentialsForWorker(f.ctx, secret.Scope{OrganizationID: f.orgID, SecretID: first.Secret.ID, SecretVersion: 1}, func(secret.Credentials) error { return fmt.Errorf("private %s", keyCanary) }); !errors.Is(err, secret.ErrConsumer) || strings.Contains(err.Error(), keyCanary) {
			t.Fatal("callback error leaked")
		}
		if err := f.secrets.WithCredentialsForWorker(f.ctx, secret.Scope{OrganizationID: f.orgID, SecretID: first.Secret.ID, SecretVersion: 1}, func(secret.Credentials) error { panic(keyCanary) }); !errors.Is(err, secret.ErrConsumer) {
			t.Fatal("callback panic not contained")
		}
	})
}

func TestServiceAdministratorPolicyIsCopied(t *testing.T) {
	eachServiceDatabase(t, func(t *testing.T, f serviceFixture) {
		policy := safehttp.URLPolicy{PrivateCIDRAllowlist: []string{"10.1.0.0/16"}}
		service, err := NewService(Config{Store: f.store, Secrets: f.secrets, URLPolicy: policy})
		if err != nil {
			t.Fatal(err)
		}
		policy.PrivateCIDRAllowlist[0] = "0.0.0.0/0"
		input := testInput()
		input.Endpoint = "https://10.1.2.3/v1"
		if _, err := service.Create(f.ctx, f.orgID, input, testCredentials()); err != nil {
			t.Fatal("administrator allowlist lost")
		}
		input.Endpoint = "https://10.2.2.3/v1"
		if _, err := service.Create(f.ctx, f.orgID, input, testCredentials()); !errors.Is(err, ErrInvalid) {
			t.Fatal("external policy mutation widened allowlist")
		}
		input.Endpoint = "https://169.254.169.254/v1"
		if _, err := service.Create(f.ctx, f.orgID, input, testCredentials()); !errors.Is(err, ErrInvalid) {
			t.Fatal("metadata allowed")
		}
	})
}

func TestServiceCorruptedCredentialFailsWithoutDiagnosticLeak(t *testing.T) {
	eachServiceDatabase(t, func(t *testing.T, f serviceFixture) {
		created, err := f.service.Create(f.ctx, f.orgID, testInput(), testCredentials())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_secrets SET ciphertext = $1 WHERE organization_id = $2 AND id = $3", []byte("corrupt-"+keyCanary), f.orgID, created.Secret.ID); err != nil {
			t.Fatal("test corrupt record setup failed")
		}
		err = f.secrets.WithCredentialsForWorker(f.ctx, secret.Scope{OrganizationID: f.orgID, SecretID: created.Secret.ID, SecretVersion: 1}, func(secret.Credentials) error { t.Fatal("corrupt secret reached Worker"); return nil })
		if !errors.Is(err, secret.ErrUnavailable) || strings.Contains(err.Error(), keyCanary) {
			t.Fatal("corrupt record diagnostic leaked")
		}
		// Ordinary reads never fetch/serialize even a malformed ciphertext.
		got, err := f.service.Get(f.ctx, f.orgID, created.ID)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(got)
		if err != nil || bytes.Contains(encoded, []byte(keyCanary)) {
			t.Fatal("metadata path exposed corrupt secret")
		}
	})
}
