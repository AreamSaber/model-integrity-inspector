package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"model-integrity-inspector.local/mii/internal/identity"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

const controlPassword = "synthetic-control-password-42"
const localOrigin = "http://127.0.0.1:8080"

type controlFixture struct {
	handler http.Handler
	cfg     ControlConfig
}

func newControlFixture(t *testing.T, change func(*ControlConfig)) controlFixture {
	t.Helper()
	ctx := context.Background()
	key, err := secret.NewKeyRing("test", map[string][]byte{"test": bytes.Repeat([]byte{0x13}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	dbcfg := repository.Config{Driver: "sqlite", DSN: filepath.ToSlash(filepath.Join(t.TempDir(), "control.db")), AuditSigner: key}
	if os.Getenv("MII_IDENTITY_TEST_DRIVER") == "postgres" {
		dsn := os.Getenv("MII_TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Fatal("explicit PostgreSQL test DSN required")
		}
		admin, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal("test PostgreSQL connection failed")
		}
		id, err := repository.NewID()
		if err != nil {
			t.Fatal(err)
		}
		schema := fmt.Sprintf("mii_control_%d", id)
		quoted := pgx.Identifier{schema}.Sanitize()
		if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
			_ = admin.Close(ctx)
			t.Fatal("test schema creation failed")
		}
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			// Remove only this exact newly created test schema, never public.
			if _, err := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
				t.Error("test schema cleanup failed")
			}
			if err := admin.Close(cleanup); err != nil {
				t.Error("test connection cleanup failed")
			}
		})
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal("test DSN must be URL")
		}
		query := u.Query()
		query.Set("search_path", schema)
		u.RawQuery = query.Encode()
		dbcfg.Driver, dbcfg.DSN = "postgres", u.String()
	}
	db, err := repository.Open(ctx, dbcfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	cfg := ControlConfig{Identity: service, Store: db, PublicOrigin: localOrigin, AllowInsecureLoopback: true, CursorSigner: key, Readiness: func(context.Context) bool { return true }}
	if change != nil {
		change(&cfg)
	}
	handler, err := NewControlHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return controlFixture{handler: handler, cfg: cfg}
}

func (f controlFixture) request(t *testing.T, method, path, body string, headers map[string]string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", strings.TrimSuffix(f.cfg.PublicOrigin, "/"))
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Header().Get("X-Request-ID") == "" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("security/request metadata missing")
	}
	return w
}

func expectControl(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("expected HTTP %d got %d: %s", status, w.Code, w.Body.String())
	}
	if code != "" {
		var envelope struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(w.Body.Bytes(), &envelope) != nil || envelope.Error.Code != code {
			t.Fatalf("incorrect error envelope: %s", w.Body.String())
		}
	}
}

func (f controlFixture) initialize(t *testing.T) {
	t.Helper()
	w := f.request(t, "POST", "/api/v1/setup/initialize", `{"organization_name":"Test Organization","username":"admin","password":"`+controlPassword+`"}`, map[string]string{"X-Setup-Token": f.cfg.SetupToken}, nil)
	expectControl(t, w, 201, "")
}

func (f controlFixture) login(t *testing.T) (*http.Cookie, string, string) {
	t.Helper()
	w := f.request(t, "POST", "/api/v1/auth/login", `{"username":"admin","password":"`+controlPassword+`"}`, nil, nil)
	expectControl(t, w, 200, "")
	var envelope struct {
		Data struct {
			CSRF string `json:"csrf_token"`
			User struct {
				ID string `json:"id"`
			} `json:"user"`
			Orgs []struct {
				ID string `json:"id"`
			} `json:"organizations"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Data.Orgs) != 1 || len(envelope.Data.CSRF) != 43 {
		t.Fatal("invalid session DTO")
	}
	if id, err := strconv.ParseInt(envelope.Data.User.ID, 10, 64); err != nil || id <= 0 {
		t.Fatal("ID not decimal string")
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookie {
		t.Fatal("session cookie missing")
	}
	cookie := cookies[0]
	if len(cookie.Value) != 43 || !cookie.HttpOnly || cookie.Path != "/" || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge < 43000 {
		t.Fatal("unsafe session cookie")
	}
	for _, forbidden := range []string{controlPassword, "password_hash", "session_hash", "csrf_hash", cookie.Value, "quota_json"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatal("sensitive data in session DTO")
		}
	}
	return cookie, envelope.Data.CSRF, envelope.Data.Orgs[0].ID
}

func TestControlInitializationGateAndSessionFlow(t *testing.T) {
	f := newControlFixture(t, nil)
	expectControl(t, f.request(t, "GET", "/api/v1/organizations", "", nil, nil), 409, "MI_SETUP_REQUIRED")
	expectControl(t, f.request(t, "GET", "/health", "", nil, nil), 200, "")
	f.initialize(t)
	expectControl(t, f.request(t, "POST", "/api/v1/setup/initialize", `{"organization_name":"Other","username":"other","password":"`+controlPassword+`"}`, nil, nil), 409, "MI_SETUP_CLOSED")
	cookie, csrf, orgID := f.login(t)
	if cookie.Secure {
		t.Fatal("explicit loopback HTTP cannot send Secure cookie")
	}
	expectControl(t, f.request(t, "GET", "/api/v1/auth/me", "", nil, cookie), 200, "")
	expectControl(t, f.request(t, "GET", "/api/v1/roles", "", map[string]string{"X-Organization-ID": orgID}, cookie), 200, "")
	expectControl(t, f.request(t, "GET", "/api/v1/roles", "", map[string]string{"X-Organization-ID": "1"}, cookie), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "GET", "/api/v1/roles", "", map[string]string{"X-Organization-ID": "+" + orgID}, cookie), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "POST", "/api/v1/auth/logout", "", nil, cookie), 403, "MI_CSRF_INVALID")
	w := f.request(t, "POST", "/api/v1/auth/logout", "", map[string]string{"X-CSRF-Token": csrf}, cookie)
	expectControl(t, w, 200, "")
	if cookies := w.Result().Cookies(); len(cookies) != 1 || cookies[0].MaxAge != -1 {
		t.Fatal("logout did not expire cookie")
	}
	expectControl(t, f.request(t, "GET", "/api/v1/auth/me", "", nil, cookie), 401, "MI_SESSION_REQUIRED")
}

func TestControlOriginBootstrapAndSecureCookies(t *testing.T) {
	f := newControlFixture(t, func(cfg *ControlConfig) {
		cfg.PublicOrigin = "https://mii.test"
		cfg.AllowInsecureLoopback = false
		cfg.SetupToken = strings.Repeat("s", 32)
	})
	body := `{"organization_name":"Test","username":"admin","password":"` + controlPassword + `"}`
	for _, headers := range []map[string]string{
		{"Origin": "https://attacker.test", "X-Setup-Token": f.cfg.SetupToken},
		{"Origin": "", "X-Setup-Token": f.cfg.SetupToken},
		{"Sec-Fetch-Site": "cross-site", "X-Setup-Token": f.cfg.SetupToken},
	} {
		expectControl(t, f.request(t, "POST", "/api/v1/setup/initialize", body, headers, nil), 403, "MI_CSRF_INVALID")
	}
	expectControl(t, f.request(t, "POST", "/api/v1/setup/initialize", body, nil, nil), 403, "MI_PERMISSION_DENIED")
	f.initialize(t)
	cookie, csrf, _ := f.login(t)
	if !cookie.Secure {
		t.Fatal("HTTPS cookie missing Secure")
	}
	expectControl(t, f.request(t, "POST", "/api/v1/auth/logout", "", map[string]string{"Origin": "https://attacker.test", "X-CSRF-Token": csrf}, cookie), 403, "MI_CSRF_INVALID")
	expectControl(t, f.request(t, "GET", "/api/v1/auth/me", "", nil, cookie), 200, "")
}

func TestControlRemoteBootstrapCannotTrustForwardedIP(t *testing.T) {
	f := newControlFixture(t, nil)
	r := httptest.NewRequestWithContext(t.Context(), "POST", "/api/v1/setup/initialize", strings.NewReader(`{}`))
	r.RemoteAddr = "198.51.100.23:44000"
	r.Header.Set("Origin", localOrigin)
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	expectControl(t, w, 403, "MI_PERMISSION_DENIED")
}

func TestControlPasswordChangeRevokesEverySessionAndAuditsDenied(t *testing.T) {
	f := newControlFixture(t, nil)
	f.initialize(t)
	one, csrf, orgID := f.login(t)
	two, _, _ := f.login(t)
	body := `{"current_password":"wrong-password","new_password":"new-control-password-75"}`
	expectControl(t, f.request(t, "POST", "/api/v1/auth/change-password", body, map[string]string{"X-CSRF-Token": csrf}, one), 401, "MI_LOGIN_FAILED")
	body = `{"current_password":"` + controlPassword + `","new_password":"new-control-password-75"}`
	expectControl(t, f.request(t, "POST", "/api/v1/auth/change-password", body, map[string]string{"X-CSRF-Token": csrf}, one), 200, "")
	for _, cookie := range []*http.Cookie{one, two} {
		expectControl(t, f.request(t, "GET", "/api/v1/auth/me", "", nil, cookie), 401, "MI_SESSION_REQUIRED")
	}
	id, _ := strconv.ParseInt(orgID, 10, 64)
	tenant, err := f.cfg.Store.WithOrganization(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	events, err := tenant.ListAudit(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Action == "auth.password_change_failed" && event.Result == "denied" {
			found = true
		}
	}
	if !found {
		t.Fatal("denied password change not audited")
	}
	if _, err := tenant.VerifyAuditFull(); err != nil {
		t.Fatal(err)
	}
}

func TestControlStrictBodyAndUniformLoginErrors(t *testing.T) {
	f := newControlFixture(t, nil)
	f.initialize(t)
	for _, body := range []string{`{"username":"admin","password":"x","extra":"x"}`, `{} {}`, `null {}`, `{"username":7}`, `{"username":`} {
		expectControl(t, f.request(t, "POST", "/api/v1/auth/login", body, nil, nil), 400, "MI_INVALID_REQUEST")
	}
	expectControl(t, f.request(t, "POST", "/api/v1/auth/login", `{"password":"`+strings.Repeat("x", 65<<10)+`"}`, nil, nil), 413, "MI_INVALID_REQUEST")
	for _, user := range []string{"admin", "does-not-exist"} {
		expectControl(t, f.request(t, "POST", "/api/v1/auth/login", `{"username":"`+user+`","password":"wrong"}`, nil, nil), 401, "MI_LOGIN_FAILED")
	}
}

func TestControlReadinessFailsClosed(t *testing.T) {
	f := newControlFixture(t, nil)
	expectControl(t, f.request(t, "GET", "/ready", "", nil, nil), 200, "")
	cfg := f.cfg
	cfg.Readiness = nil
	handler, err := NewControlHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.handler = handler
	expectControl(t, f.request(t, "GET", "/ready", "", nil, nil), 503, "")
	f.handler, err = NewControlHandler(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.cfg.Store.Close(); err != nil {
		t.Fatal(err)
	}
	expectControl(t, f.request(t, "GET", "/ready", "", nil, nil), 503, "")
	expectControl(t, f.request(t, "GET", "/api/v1/setup/status", "", nil, nil), 503, "MI_SERVICE_UNAVAILABLE")
}

func TestLoginLimiterExpiryAndCapacity(t *testing.T) {
	now := time.Now()
	limiter := loginLimiter{windows: map[string]loginWindow{}, now: func() time.Time { return now }}
	for range 20 {
		if limiter.check("one") != 0 {
			t.Fatal("premature rate limit")
		}
	}
	if limiter.check("one") <= 0 {
		t.Fatal("rate limit missing")
	}
	now = now.Add(16 * time.Minute)
	if limiter.check("one") != 0 {
		t.Fatal("expired limit not reset")
	}
	for i := range 4095 {
		if limiter.check(strconv.Itoa(i)) != 0 {
			t.Fatal("capacity prematurely exceeded")
		}
	}
	if limiter.check("overflow") == 0 || len(limiter.windows) != 4096 {
		t.Fatal("limiter memory unbounded")
	}
	now = now.Add(16 * time.Minute)
	if limiter.check("overflow") != 0 {
		t.Fatal("expired entries not reclaimed")
	}
}

func TestControlRejectsUnsafeOriginConfiguration(t *testing.T) {
	f := newControlFixture(t, nil)
	for _, origin := range []string{"http://mii.test", "http://localhost:8080", "https://user:pass@mii.test", "https://mii.test/subpath", "https://mii.test?token=x", "file:///etc/passwd"} {
		cfg := f.cfg
		cfg.PublicOrigin = origin
		if _, err := NewControlHandler(cfg); err == nil {
			t.Fatalf("accepted unsafe origin %s", origin)
		}
	}
}
