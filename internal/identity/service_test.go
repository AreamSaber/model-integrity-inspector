package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

const testPassword = "synthetic-password-5db8-for-tests"

func newTestService(t *testing.T) (*Service, context.Context) {
	t.Helper()
	ctx := audit.WithActor(context.Background(), audit.Actor{ReasonCode: "test.request", IPSummary: "test-loopback", UserAgentSummary: "test-client"})
	key, err := secret.NewKeyRing("test", map[string][]byte{"test": bytes.Repeat([]byte{0x49}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	cfg := repository.Config{Driver: "sqlite", DSN: filepath.ToSlash(filepath.Join(t.TempDir(), "identity.db")), AuditSigner: key}
	if os.Getenv("MII_IDENTITY_TEST_DRIVER") == "postgres" {
		dsn := os.Getenv("MII_TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Fatal("PostgreSQL identity tests require explicit test DSN; cannot silently skip")
		}
		admin, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal("could not connect to isolated test PostgreSQL")
		}
		id, err := repository.NewID()
		if err != nil {
			t.Fatal(err)
		}
		schema := fmt.Sprintf("mii_identity_%d", id)
		quoted := pgx.Identifier{schema}.Sanitize()
		if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
			_ = admin.Close(ctx)
			t.Fatal("could not create isolated identity schema")
		}
		t.Cleanup(func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			// The exact new schema created above, never public or an existing schema.
			if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
				t.Error("could not remove isolated identity test schema")
			}
			if err := admin.Close(cleanupCtx); err != nil {
				t.Error("could not close test PostgreSQL connection")
			}
		})
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal("test DSN must be a URL")
		}
		query := u.Query()
		query.Set("search_path", schema)
		u.RawQuery = query.Encode()
		cfg.Driver = "postgres"
		cfg.DSN = u.String()
	}
	db, err := repository.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	s, err := NewService(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	return s, ctx
}

func initializedService(t *testing.T) (*Service, context.Context) {
	t.Helper()
	s, ctx := newTestService(t)
	if err := s.Initialize(ctx, "Test organization", "Admin", testPassword); err != nil {
		t.Fatal(err)
	}
	return s, ctx
}

func loginTest(t *testing.T, s *Service, ctx context.Context) SessionMaterial {
	t.Helper()
	material, err := s.Login(ctx, "ADMIN", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func TestSetupIsOneTimeAndRequiresAudit(t *testing.T) {
	s, ctx := newTestService(t)
	if ready, err := s.SetupStatus(ctx); err != nil || ready {
		t.Fatal("new system incorrectly initialized")
	}
	if _, err := s.Login(ctx, "admin", testPassword); !errors.Is(err, ErrSetupRequired) {
		t.Fatal("login allowed before setup")
	}
	if err := s.Initialize(context.Background(), "Test", "admin", testPassword); !errors.Is(err, ErrUnavailable) {
		t.Fatal("setup without audit metadata allowed")
	}
	if err := s.Initialize(ctx, "Test", "admin", testPassword); err != nil {
		t.Fatal(err)
	}
	if err := s.Initialize(ctx, "Replacement", "other", testPassword); !errors.Is(err, ErrSetupClosed) {
		t.Fatal("second initialization accepted")
	}
	material := loginTest(t, s, ctx)
	if len(material.Organizations) != 1 || material.Organizations[0].Name != "Test" {
		t.Fatal("setup overwritten")
	}
	tenant, err := s.store.WithOrganization(ctx, material.Organizations[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := tenant.VerifyAuditFull()
	if err != nil || verified.VerifiedCount < 2 {
		t.Fatalf("setup/login audit missing: %v", err)
	}
}

func TestSessionCSRFLogoutAndPasswordRevocation(t *testing.T) {
	s, ctx := initializedService(t)
	one := loginTest(t, s, ctx)
	two := loginTest(t, s, ctx)
	if one.CookieValue() == two.CookieValue() || one.CSRFToken == two.CSRFToken {
		t.Fatal("session fixation/reused randomness")
	}
	if _, err := json.Marshal(one); err == nil {
		t.Fatal("session material serialized")
	}
	if strings.Contains(fmt.Sprintf("%#v", one), one.CookieValue()) {
		t.Fatal("session logged")
	}
	saved, err := s.store.GetSession(ctx, tokenHash(one.CookieValue()), s.now())
	if err != nil {
		t.Fatal(err)
	}
	if saved.SessionHash == one.CookieValue() || saved.CSRFHash == one.CSRFToken {
		t.Fatal("session token persisted raw")
	}
	if err := s.CheckCSRF(ctx, one.CookieValue(), one.CSRFToken); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckCSRF(ctx, one.CookieValue(), two.CSRFToken); !errors.Is(err, ErrCSRF) {
		t.Fatal("cross-session CSRF accepted")
	}
	if err := s.CheckCSRF(ctx, one.CookieValue(), ""); !errors.Is(err, ErrCSRF) {
		t.Fatal("missing CSRF accepted")
	}
	if err := s.Logout(ctx, one.CookieValue()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Current(ctx, one.CookieValue()); !errors.Is(err, ErrSession) {
		t.Fatal("logged-out session accepted")
	}
	if _, err := s.Current(ctx, two.CookieValue()); err != nil {
		t.Fatal("logout revoked unrelated session")
	}
	if err := s.ChangePassword(ctx, two.CookieValue(), "wrong-old-password", "new-test-password-764"); !errors.Is(err, ErrAuthentication) {
		t.Fatal("wrong password changed account")
	}
	if err := s.ChangePassword(ctx, two.CookieValue(), testPassword, "new-test-password-764"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Current(ctx, two.CookieValue()); !errors.Is(err, ErrSession) {
		t.Fatal("password change retained session")
	}
	if _, err := s.Login(ctx, "admin", testPassword); !errors.Is(err, ErrAuthentication) {
		t.Fatal("old password accepted")
	}
	if _, err := s.Login(ctx, "admin", "new-test-password-764"); err != nil {
		t.Fatal("new password rejected")
	}
}

func TestPersistentAccountLockAndSessionExpiry(t *testing.T) {
	s, ctx := initializedService(t)
	for range 5 {
		if _, err := s.Login(ctx, "admin", "wrong-password"); !errors.Is(err, ErrAuthentication) {
			t.Fatal("bad password not rejected")
		}
	}
	if _, err := s.Login(ctx, "admin", testPassword); !errors.Is(err, ErrAuthentication) {
		t.Fatal("locked user logged in")
	}
	later := time.Now().Add(20 * time.Minute)
	s.now = func() time.Time { return later }
	material := loginTest(t, s, ctx)
	later = material.ExpiresAt.Add(time.Second)
	if _, err := s.Current(ctx, material.CookieValue()); !errors.Is(err, ErrSession) {
		t.Fatal("expired session accepted")
	}
}

func TestFailedLoginAuditAndTenantIsolation(t *testing.T) {
	s, ctx := initializedService(t)
	_, unknownErr := s.Login(ctx, "unknown-user", testPassword)
	_, wrongErr := s.Login(ctx, "admin", "wrong-password")
	if !errors.Is(unknownErr, ErrAuthentication) || !errors.Is(wrongErr, ErrAuthentication) || unknownErr.Error() != wrongErr.Error() {
		t.Fatal("login failures reveal account existence")
	}
	material := loginTest(t, s, ctx)
	orgID := material.Organizations[0].ID
	p, err := s.Principal(ctx, material.CookieValue(), orgID)
	if err != nil || p.Authorize("rules.manage") != nil {
		t.Fatal("admin authorization failed")
	}
	if _, err := s.Principal(ctx, material.CookieValue(), orgID-1); !errors.Is(err, ErrPermission) {
		t.Fatal("cross-tenant session accepted")
	}
	for _, token := range []string{"", strings.Repeat("x", 400), "invalid-token", strings.Repeat("%", 43)} {
		if _, err := s.Current(ctx, token); !errors.Is(err, ErrSession) {
			t.Fatal("malformed session accepted")
		}
	}
	tenant, err := s.store.WithOrganization(ctx, orgID)
	if err != nil {
		t.Fatal(err)
	}
	events, err := tenant.ListAudit(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	failures := 0
	for _, event := range events {
		if event.Action == "auth.login_failed" {
			failures++
		}
		if strings.Contains(event.DiffSummary, testPassword) || strings.Contains(event.DiffSummary, "unknown-user") {
			t.Fatal("credential/account probe logged")
		}
	}
	if failures != 2 {
		t.Fatalf("failed login audit count %d", failures)
	}
}
