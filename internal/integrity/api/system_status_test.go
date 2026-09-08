package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/buildinfo"
	"model-integrity-inspector.local/mii/internal/identity"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func systemHTTPFixture(t *testing.T, ready func() bool) controlFixture {
	t.Helper()
	return newControlFixture(t, func(cfg *ControlConfig) {
		var err error
		cfg.SystemStatus, err = identity.NewSystemStatusService(cfg.Identity, identity.SystemRuntime{Role: "all", Build: buildinfo.Current(), Versions: domain.BundleVersions{Rule: "1.0.0-dev.1", Scoring: "1.0.0-dev.1", Template: "1.0.0-dev.1", Tokenizer: "1.0.0"}, StartupVerifiedAt: time.Now().UTC(), LocalWorkerReady: ready})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestSystemStatusHTTPRealScopeAndSafeDTO(t *testing.T) {
	var ready atomic.Bool
	f := systemHTTPFixture(t, ready.Load)
	f.initialize(t)
	cookie, csrf, org := f.login(t)
	headers := map[string]string{"X-Organization-ID": org}
	read := func() identity.SystemStatus {
		w := f.request(t, "GET", "/api/v1/system/health", "", headers, cookie)
		expectControl(t, w, 200, "")
		var dto identity.SystemStatus
		managementHTTPData(t, w, &dto)
		if w.Header().Get("Cache-Control") != "no-store" || w.Body.Len() > 32<<10 {
			t.Fatal("unsafe response envelope")
		}
		return dto
	}
	got := read()
	if got.OrganizationID != org || got.LocalWorker.State != "error" || got.ObservedState != "degraded" || got.Coverage != "partial" || got.Audit.State != "ok" || got.Key.State != "startup_verified" || got.Reports.State != "startup_verified" || got.Cleanup.State != "unavailable" || got.Jobs.Total == nil || *got.Jobs.Total != 0 {
		t.Fatal("false/incorrect status")
	}
	ready.Store(true)
	if got = read(); got.LocalWorker.State != "ok" || got.ObservedState != "ok" {
		t.Fatal("local observation not refreshed")
	}
	for _, request := range []struct {
		path, body string
		headers    map[string]string
		cookie     *http.Cookie
		status     int
		code       string
	}{
		{"/api/v1/system/health", "", headers, nil, 401, "MI_SESSION_REQUIRED"},
		{"/api/v1/system/health?unknown=secret-canary", "", headers, cookie, 400, "MI_INVALID_REQUEST"},
		{"/api/v1/system/health", "{}", headers, cookie, 400, "MI_INVALID_REQUEST"},
		{"/api/v1/system/health", "", nil, cookie, 400, "MI_INVALID_REQUEST"},
		{"/api/v1/system/health", "", map[string]string{"X-Organization-ID": "01"}, cookie, 400, "MI_INVALID_REQUEST"},
		{"/api/v1/system/health", "", map[string]string{"X-Organization-ID": "1"}, cookie, 403, "MI_PERMISSION_DENIED"},
	} {
		expectControl(t, f.request(t, "GET", request.path, request.body, request.headers, request.cookie), request.status, request.code)
	}
	_, ordinary, _ := managementHTTPUser(t, f, cookie, csrf, "status-reader")
	expectControl(t, f.request(t, "GET", "/api/v1/system/health", "", headers, ordinary), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "POST", "/api/v1/auth/logout", "", map[string]string{"X-CSRF-Token": csrf}, cookie), 200, "")
	expectControl(t, f.request(t, "GET", "/api/v1/system/health", "", headers, cookie), 401, "MI_SESSION_REQUIRED")
}

func TestSystemStatusHTTPRevocationBeforeResponse(t *testing.T) {
	var onRead func()
	f := systemHTTPFixture(t, func() bool {
		if onRead != nil {
			onRead()
		}
		return true
	})
	f.initialize(t)
	cookie, csrf, org := f.login(t)
	onRead = func() {
		expectControl(t, f.request(t, "POST", "/api/v1/auth/logout", "", map[string]string{"X-CSRF-Token": csrf}, cookie), 200, "")
	}
	expectControl(t, f.request(t, "GET", "/api/v1/system/health", "", map[string]string{"X-Organization-ID": org}, cookie), 401, "MI_SESSION_REQUIRED")
}

func TestSystemStatusHTTPAdmissionAndAuthenticationDeadline(t *testing.T) {
	f := systemHTTPFixture(t, func() bool { return true })
	f.initialize(t)
	cookie, _, org := f.login(t)
	id, err := strconv.ParseInt(org, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if !acquireSystemStatusOrganization(id) {
		t.Fatal("test organization already occupied")
	}
	expectControl(t, f.request(t, "GET", "/api/v1/system/health", "", map[string]string{"X-Organization-ID": org}, cookie), 429, "MI_SYSTEM_STATUS_BUSY")
	releaseSystemStatusOrganization(id)
	systemStatusAdmission.global <- struct{}{}
	systemStatusAdmission.global <- struct{}{}
	// Global admission precedes all authentication/database reads, even for an
	// anonymous request; it does not reveal whether an organization is occupied.
	expectControl(t, f.request(t, "GET", "/api/v1/system/health", "", nil, nil), 429, "MI_SYSTEM_STATUS_BUSY")
	<-systemStatusAdmission.global
	<-systemStatusAdmission.global
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	r := httptest.NewRequestWithContext(ctx, "GET", "/api/v1/system/health", nil)
	r.AddCookie(cookie)
	r.Header.Set("X-Organization-ID", org)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	expectControl(t, w, 503, "MI_SYSTEM_STATUS_TIMEOUT")
	r = httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/system/health", nil)
	r.AddCookie(cookie)
	r.Header.Set("X-Organization-ID", org)
	bounded := &systemDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	started := time.Now()
	f.handler.ServeHTTP(bounded, r)
	if bounded.deadline.IsZero() || bounded.deadline.Before(started) || bounded.deadline.After(started.Add(2*time.Second)) {
		t.Fatal("authentication/socket deadline not installed at entry")
	}
	r = httptest.NewRequestWithContext(t.Context(), "HEAD", "/api/v1/system/health", nil)
	r.AddCookie(cookie)
	r.Header.Set("X-Organization-ID", org)
	bounded = &systemDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	f.handler.ServeHTTP(bounded, r)
	if bounded.Code != 405 || bounded.deadline.IsZero() {
		t.Fatal("HEAD bypassed fixed route/middleware boundary")
	}
	if len(systemStatusAdmission.global) != 0 {
		t.Fatal("admission leaked after failure")
	}
	if err := f.cfg.Store.Close(); err != nil {
		t.Fatal(err)
	}
	w = f.request(t, "GET", "/api/v1/system/health", "", map[string]string{"X-Organization-ID": org}, cookie)
	expectControl(t, w, 503, "MI_SERVICE_UNAVAILABLE")
	if strings.Contains(w.Body.String(), "database_driver") || strings.Contains(w.Body.String(), "startup_verified") {
		t.Fatal("diagnostics served without current DB authorization")
	}
}

type systemDeadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (w *systemDeadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	return nil
}

func TestSystemStatusHTTPNeverSerializesPrivateRuntimeConfiguration(t *testing.T) {
	f := systemHTTPFixture(t, func() bool { return true })
	f.initialize(t)
	cookie, _, org := f.login(t)
	w := f.request(t, "GET", "/api/v1/system/health", "", map[string]string{"X-Organization-ID": org}, cookie)
	var raw map[string]any
	if json.Unmarshal(w.Body.Bytes(), &raw) != nil {
		t.Fatal("invalid JSON")
	}
	for _, forbidden := range []string{"dsn", "master_key_file", "event_hmac", "checksum", "wire_payload", "authorization", cookie.Value, controlPassword, "http://", "https://", "\\\\", ".db"} {
		if strings.Contains(strings.ToLower(w.Body.String()), strings.ToLower(forbidden)) {
			t.Fatal("private operational data serialized")
		}
	}
}
