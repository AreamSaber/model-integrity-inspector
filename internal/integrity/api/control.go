package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"model-integrity-inspector.local/mii/internal/buildinfo"
	"model-integrity-inspector.local/mii/internal/identity"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/baseline"
	"model-integrity-inspector.local/mii/internal/integrity/catalog"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
	"model-integrity-inspector.local/mii/internal/integrity/target"
)

const sessionCookie = "mii_session"

var ErrControlConfig = errors.New("MI_CONTROL_CONFIGURATION_INVALID")

type ControlConfig struct {
	SystemStatus          *identity.SystemStatusService
	Baselines             *baseline.Service
	Reports               *runservice.ReportService
	Evidence              *runservice.EvidenceService
	Runs                  *runservice.Service
	Catalog               *catalog.Service
	Identity              *identity.Service
	Store                 *repository.Store
	Build                 buildinfo.Info
	PublicOrigin          string
	AllowInsecureLoopback bool
	SetupToken            string `json:"-"`
	Frontend              http.Handler
	Readiness             func(context.Context) bool
	CursorSigner          CursorSigner
	Targets               *target.Service
}

type control struct {
	cfg           ControlConfig
	origin        string
	secure        bool
	setupHash     [32]byte
	hasSetupToken bool
	limiter       *loginLimiter
	evidenceSlots chan struct{}
}
type requestIDKey struct{}

func NewControlHandler(cfg ControlConfig) (http.Handler, error) {
	if cfg.Identity == nil || cfg.Store == nil {
		return nil, ErrControlConfig
	}
	u, err := url.Parse(cfg.PublicOrigin)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, ErrControlConfig
	}
	secure := u.Scheme == "https"
	if !secure && (u.Scheme != "http" || !cfg.AllowInsecureLoopback || !loopbackHost(u.Hostname())) {
		return nil, ErrControlConfig
	}
	if cfg.SetupToken != "" && (len(cfg.SetupToken) < 32 || len(cfg.SetupToken) > 256) {
		return nil, ErrControlConfig
	}
	c := &control{cfg: cfg, origin: u.Scheme + "://" + u.Host, secure: secure, hasSetupToken: cfg.SetupToken != "", setupHash: sha256.Sum256([]byte(cfg.SetupToken)), limiter: &loginLimiter{windows: map[string]loginWindow{}, now: time.Now}}
	c.cfg.SetupToken = "" // Retain only the hash, never a bootstrap credential.
	c.evidenceSlots = make(chan struct{}, 4)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, c.cfg.Build) })
	mux.HandleFunc("GET /ready", c.ready)
	mux.HandleFunc("GET /api/v1/setup/status", c.setupStatus)
	mux.HandleFunc("POST /api/v1/setup/initialize", c.initialize)
	mux.HandleFunc("POST /api/v1/auth/login", c.login)
	mux.HandleFunc("GET /api/v1/auth/me", c.me)
	mux.HandleFunc("GET /api/v1/auth/permissions", c.effectivePermissions)
	mux.HandleFunc("POST /api/v1/auth/logout", c.logout)
	mux.HandleFunc("POST /api/v1/auth/logout-all", c.logoutAll)
	mux.HandleFunc("POST /api/v1/auth/change-password", c.changePassword)
	c.registerManagementRoutes(mux)
	if cfg.Catalog != nil {
		c.registerCatalogRoutes(mux)
	}
	if cfg.Baselines != nil {
		c.registerBaselineRoutes(mux)
	}
	if cfg.Reports != nil {
		c.registerReportRoutes(mux)
	}
	if cfg.Evidence != nil {
		c.registerEvidenceDisplayRoutes(mux)
	}
	if cfg.Targets != nil {
		c.registerTargetRoutes(mux)
	}
	if cfg.Runs != nil {
		c.registerRunRoutes(mux)
		c.registerRunEventRoutes(mux)
		c.registerRunResultRoutes(mux)
		c.registerOverviewRoutes(mux)
		c.registerReviewRoutes(mux)
	}
	mux.HandleFunc("GET /api/v1/system/version", c.systemVersion)
	if cfg.SystemStatus != nil {
		c.registerSystemStatusRoutes(mux)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") && cfg.Frontend != nil && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			cfg.Frontend.ServeHTTP(w, r)
			return
		}
		c.failure(w, r, http.StatusNotFound, "MI_NOT_FOUND")
	})
	return c.middleware(mux), nil
}

func loopbackHost(host string) bool {
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}
func requestIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "unknown"
	}
	return host
}
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (c *control) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isEvidenceDisplayRequest(r) {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			r = r.WithContext(ctx)
		}
		isSystemStatus := (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.URL.Path == "/api/v1/system/health"
		if (r.Method == http.MethodGet && r.URL.Path == "/api/v1/overview") || isSystemStatus || (r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/logout-all") {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			r = r.WithContext(ctx)
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Cache-Control", "no-store")
		requestID := make([]byte, 16)
		if _, err := rand.Read(requestID); err != nil {
			writeJSON(w, 503, map[string]string{"error": "MI_SERVICE_UNAVAILABLE"})
			return
		}
		id := hex.EncodeToString(requestID)
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), requestIDKey{}, id)
		ctx = audit.WithActor(ctx, audit.Actor{ReasonCode: "http.request", IPSummary: digest(requestIP(r)), UserAgentSummary: digest(r.UserAgent())})
		r = r.WithContext(ctx)
		if isEvidenceDisplayRequest(r) {
			deadline, _ := r.Context().Deadline()
			if err := http.NewResponseController(w).SetWriteDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
				c.failure(w, r, 503, "MI_EVIDENCE_UNAVAILABLE")
				return
			}
			select {
			case c.evidenceSlots <- struct{}{}:
				defer func() { <-c.evidenceSlots }()
			default:
				w.Header().Set("Retry-After", "2")
				c.failure(w, r, 429, "MI_EVIDENCE_LIMIT")
				return
			}
		}
		if isSystemStatus {
			if !c.systemStatusEntry(w, r) {
				return
			}
			defer func() { <-systemStatusAdmission.global }()
		}
		defer func() {
			if recover() != nil {
				c.failure(w, r, http.StatusInternalServerError, "MI_SERVICE_UNAVAILABLE")
			}
		}()
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("Origin") != c.origin || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				c.failure(w, r, 403, "MI_CSRF_INVALID")
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/v1/setup/status" && r.URL.Path != "/api/v1/setup/initialize" {
			initialized, err := c.cfg.Identity.SetupStatus(r.Context())
			if err != nil {
				c.error(w, r, err)
				return
			}
			if !initialized {
				c.error(w, r, identity.ErrSetupRequired)
				return
			}
			if r.URL.Path != "/api/v1/auth/login" && r.URL.Path != "/api/v1/auth/me" && r.URL.Path != "/api/v1/auth/logout" && r.URL.Path != "/api/v1/auth/logout-all" && r.URL.Path != "/api/v1/auth/change-password" && token(r) != "" {
				material, err := c.cfg.Identity.Current(r.Context(), token(r))
				if err != nil {
					c.error(w, r, err)
					return
				}
				if material.User.MustChangePassword {
					c.error(w, r, identity.ErrPasswordChangeRequired)
					return
				}
			}
		}
		if r.URL.Path == "/api/v1/auth/login" || r.URL.Path == "/api/v1/setup/initialize" || r.URL.Path == "/api/v1/auth/change-password" {
			if wait := c.limiter.check(requestIP(r)); wait > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(wait))
				c.failure(w, r, 429, "MI_RATE_LIMITED")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (c *control) success(w http.ResponseWriter, r *http.Request, status int, data any) {
	id, _ := r.Context().Value(requestIDKey{}).(string)
	writeJSON(w, status, map[string]any{"data": data, "request_id": id})
}
func (c *control) failure(w http.ResponseWriter, r *http.Request, status int, code string) {
	id, _ := r.Context().Value(requestIDKey{}).(string)
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": code}, "request_id": id})
}
func (c *control) error(w http.ResponseWriter, r *http.Request, err error) {
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.URL.Path == "/api/v1/system/health" && errors.Is(r.Context().Err(), context.DeadlineExceeded) {
		c.failure(w, r, 503, "MI_SYSTEM_STATUS_TIMEOUT")
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/v1/overview" && errors.Is(r.Context().Err(), context.DeadlineExceeded) {
		c.failure(w, r, 503, "MI_OVERVIEW_TIMEOUT")
		return
	}
	status := 503
	code := "MI_SERVICE_UNAVAILABLE"
	switch {
	case errors.Is(err, identity.ErrSetupClosed):
		status = 409
		code = "MI_SETUP_CLOSED"
	case errors.Is(err, identity.ErrSetupRequired):
		status = 409
		code = "MI_SETUP_REQUIRED"
	case errors.Is(err, identity.ErrPasswordPolicy):
		status = 400
		code = "MI_INVALID_REQUEST"
	case errors.Is(err, identity.ErrAuthentication):
		status = 401
		code = "MI_LOGIN_FAILED"
	case errors.Is(err, identity.ErrSession), errors.Is(err, repository.ErrManagementSession):
		status = 401
		code = "MI_SESSION_REQUIRED"
	case errors.Is(err, identity.ErrCSRF):
		status = 403
		code = "MI_CSRF_INVALID"
	case errors.Is(err, identity.ErrPermission), errors.Is(err, repository.ErrManagementPermission):
		status = 403
		code = "MI_PERMISSION_DENIED"
	case errors.Is(err, identity.ErrPasswordChangeRequired), errors.Is(err, repository.ErrPasswordChangeRequired):
		status = 403
		code = "MI_PASSWORD_CHANGE_REQUIRED"
	}
	c.failure(w, r, status, code)
}

func (c *control) decode(w http.ResponseWriter, r *http.Request, out any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || r.URL.RawQuery != "" {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			c.failure(w, r, 413, "MI_INVALID_REQUEST")
		} else {
			c.failure(w, r, 400, "MI_INVALID_REQUEST")
		}
		return false
	}
	if err := strictJSON(raw, out); err != nil {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return false
	}
	return true
}

func token(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return cookie.Value
}
func (c *control) authorizeWrite(w http.ResponseWriter, r *http.Request) bool {
	if err := c.cfg.Identity.CheckCSRF(r.Context(), token(r), r.Header.Get("X-CSRF-Token")); err != nil {
		c.error(w, r, err)
		return false
	}
	return true
}

func (c *control) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if c.cfg.Store.Ping(ctx) != nil || c.cfg.Store.CheckSchema(ctx) != nil || c.cfg.Readiness == nil || !c.cfg.Readiness(ctx) {
		writeJSON(w, 503, map[string]string{"status": "not_ready"})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ready"})
}
func (c *control) setupStatus(w http.ResponseWriter, r *http.Request) {
	ready, err := c.cfg.Identity.SetupStatus(r.Context())
	if err != nil {
		c.error(w, r, err)
		return
	}
	c.success(w, r, 200, map[string]bool{"initialized": ready})
}
func (c *control) initialize(w http.ResponseWriter, r *http.Request) {
	if c.hasSetupToken {
		provided := sha256.Sum256([]byte(r.Header.Get("X-Setup-Token")))
		if subtle.ConstantTimeCompare(provided[:], c.setupHash[:]) != 1 {
			c.failure(w, r, 403, "MI_PERMISSION_DENIED")
			return
		}
	} else if c.secure || !loopbackHost(requestIP(r)) {
		c.failure(w, r, 403, "MI_PERMISSION_DENIED")
		return
	}
	var input struct {
		OrganizationName string `json:"organization_name"`
		Username         string `json:"username"`
		Password         string `json:"password"`
	}
	if !c.decode(w, r, &input) {
		return
	}
	if err := c.cfg.Identity.Initialize(r.Context(), input.OrganizationName, input.Username, input.Password); err != nil {
		c.error(w, r, err)
		return
	}
	c.success(w, r, 201, map[string]bool{"ok": true})
}

func sessionDTO(value identity.SessionMaterial) map[string]any {
	orgs := make([]map[string]any, 0, len(value.Organizations))
	for _, org := range value.Organizations {
		orgs = append(orgs, organizationDTO(org))
	}
	return map[string]any{"user": map[string]any{"id": strconv.FormatInt(value.User.ID, 10), "username": value.User.Username, "display_name": value.User.DisplayName, "status": value.User.Status, "system_admin": value.User.IsSystemAdmin, "must_change_password": value.User.MustChangePassword, "version": value.User.Version, "created_at": value.User.CreatedAt}, "organizations": orgs, "csrf_token": value.CSRFToken, "expires_at": value.ExpiresAt}
}
func organizationDTO(org repository.Organization) map[string]any {
	return map[string]any{"id": strconv.FormatInt(org.ID, 10), "name": org.Name, "timezone": org.Timezone, "status": org.Status, "version": org.Version, "full_response_retention_days": org.FullResponseRetentionDays}
}
func (c *control) setCookie(w http.ResponseWriter, value string, expires time.Time, maxAge int) {
	// #nosec G124 -- Secure is false only for explicitly enabled literal-loopback HTTP; constructor and HTTP regression tests enforce this boundary.
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: value, Path: "/", Expires: expires, MaxAge: maxAge, HttpOnly: true, Secure: c.secure, SameSite: http.SameSiteStrictMode})
}
func (c *control) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !c.decode(w, r, &input) {
		return
	}
	material, err := c.cfg.Identity.Login(r.Context(), input.Username, input.Password)
	input.Password = ""
	if err != nil {
		c.error(w, r, err)
		return
	}
	c.setCookie(w, material.CookieValue(), material.ExpiresAt, int(time.Until(material.ExpiresAt).Seconds()))
	c.success(w, r, 200, sessionDTO(material))
}
func (c *control) me(w http.ResponseWriter, r *http.Request) {
	material, err := c.cfg.Identity.Current(r.Context(), token(r))
	if err != nil {
		c.error(w, r, err)
		return
	}
	c.success(w, r, 200, sessionDTO(material))
}
func (c *control) logout(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	if err := c.cfg.Identity.Logout(r.Context(), token(r)); err != nil {
		c.error(w, r, err)
		return
	}
	c.setCookie(w, "", time.Time{}, -1)
	c.success(w, r, 200, map[string]bool{"ok": true})
}
func (c *control) changePassword(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	var input struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !c.decode(w, r, &input) {
		return
	}
	if err := c.cfg.Identity.ChangePassword(r.Context(), token(r), input.Current, input.New); err != nil {
		c.error(w, r, err)
		return
	}
	c.setCookie(w, "", time.Time{}, -1)
	c.success(w, r, 200, map[string]bool{"ok": true})
}
func (c *control) systemVersion(w http.ResponseWriter, r *http.Request) {
	if _, err := c.cfg.Identity.Current(r.Context(), token(r)); err != nil {
		c.error(w, r, err)
		return
	}
	c.success(w, r, 200, c.cfg.Build)
}

type loginWindow struct {
	count int
	until time.Time
}
type loginLimiter struct {
	mu      sync.Mutex
	windows map[string]loginWindow
	now     func() time.Time
}

func (l *loginLimiter) check(ip string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	key := digest(ip)
	window, exists := l.windows[key]
	if !exists || !now.Before(window.until) {
		if len(l.windows) >= 4096 {
			for candidate, w := range l.windows {
				if !now.Before(w.until) {
					delete(l.windows, candidate)
				}
			}
			if len(l.windows) >= 4096 {
				return 60
			}
		}
		window = loginWindow{until: now.Add(15 * time.Minute)}
	}
	if window.count >= 20 {
		return max(1, int(window.until.Sub(now).Seconds()))
	}
	window.count++
	l.windows[key] = window
	return 0
}
