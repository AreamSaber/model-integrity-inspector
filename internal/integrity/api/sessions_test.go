package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestControlLogoutAllSecurityAndRevocation(t *testing.T) {
	f := newControlFixture(t, nil)
	f.initialize(t)
	one, csrf, _ := f.login(t)
	two, _, _ := f.login(t)
	for _, tc := range []struct {
		name, path, body string
		headers          map[string]string
		cookie           *http.Cookie
		status           int
		code             string
	}{
		{"anonymous", "/api/v1/auth/logout-all", "{}", nil, nil, 401, "MI_SESSION_REQUIRED"},
		{"missing-csrf", "/api/v1/auth/logout-all", "{}", nil, one, 403, "MI_CSRF_INVALID"},
		{"bad-origin", "/api/v1/auth/logout-all", "{}", map[string]string{"Origin": "https://untrusted.example", "X-CSRF-Token": csrf}, one, 403, "MI_CSRF_INVALID"},
		{"cross-site", "/api/v1/auth/logout-all", "{}", map[string]string{"Sec-Fetch-Site": "cross-site", "X-CSRF-Token": csrf}, one, 403, "MI_CSRF_INVALID"},
		{"user-field", "/api/v1/auth/logout-all", `{"user_id":"1"}`, map[string]string{"X-CSRF-Token": csrf}, one, 400, "MI_INVALID_REQUEST"},
		{"query", "/api/v1/auth/logout-all?user_id=1", "{}", map[string]string{"X-CSRF-Token": csrf}, one, 400, "MI_INVALID_REQUEST"},
		{"null", "/api/v1/auth/logout-all", "null", map[string]string{"X-CSRF-Token": csrf}, one, 400, "MI_INVALID_REQUEST"},
		{"empty", "/api/v1/auth/logout-all", "", map[string]string{"X-CSRF-Token": csrf}, one, 400, "MI_INVALID_REQUEST"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := f.request(t, "POST", tc.path, tc.body, tc.headers, tc.cookie)
			expectControl(t, response, tc.status, tc.code)
			if len(response.Result().Cookies()) != 0 {
				t.Fatal("rejected logout-all expired browser cookie")
			}
			expectControl(t, f.request(t, "GET", "/api/v1/auth/me", "", nil, one), 200, "")
			expectControl(t, f.request(t, "GET", "/api/v1/auth/me", "", nil, two), 200, "")
		})
	}
	response := f.request(t, "POST", "/api/v1/auth/logout-all", "{}", map[string]string{"X-CSRF-Token": csrf}, one)
	expectControl(t, response, 200, "")
	if cookies := response.Result().Cookies(); len(cookies) != 1 || cookies[0].MaxAge != -1 || cookies[0].Value != "" || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("successful logout-all did not expire strict cookie")
	}
	var envelope struct {
		Data struct {
			OK bool `json:"ok"`
		} `json:"data"`
	}
	if json.Unmarshal(response.Body.Bytes(), &envelope) != nil || !envelope.Data.OK {
		t.Fatal("missing acknowledgment")
	}
	for _, forbidden := range []string{one.Value, two.Value, csrf, controlPassword, "session_hash", "revoked_count"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatal("logout-all exposed session material")
		}
	}
	expectControl(t, f.request(t, "GET", "/api/v1/auth/me", "", nil, one), 401, "MI_SESSION_REQUIRED")
	expectControl(t, f.request(t, "GET", "/api/v1/auth/me", "", nil, two), 401, "MI_SESSION_REQUIRED")
	fresh, _, _ := f.login(t)
	expectControl(t, f.request(t, "POST", "/api/v1/auth/logout-all", "{}", map[string]string{"X-CSRF-Token": csrf}, one), 401, "MI_SESSION_REQUIRED")
	expectControl(t, f.request(t, "GET", "/api/v1/auth/me", "", nil, fresh), 200, "")
}

func TestControlLogoutAllForcedPasswordWithoutOrganization(t *testing.T) {
	f := newControlFixture(t, nil)
	f.initialize(t)
	admin, csrf, _ := f.login(t)
	created := f.request(t, "POST", "/api/v1/users", `{"username":"temporary","password":"`+controlPassword+`"}`, map[string]string{"X-CSRF-Token": csrf}, admin)
	expectControl(t, created, 201, "")
	login := f.request(t, "POST", "/api/v1/auth/login", `{"username":"temporary","password":"`+controlPassword+`"}`, nil, nil)
	expectControl(t, login, 200, "")
	var session struct {
		Data struct {
			CSRF string `json:"csrf_token"`
			User struct {
				Forced bool `json:"must_change_password"`
			} `json:"user"`
		} `json:"data"`
	}
	if json.Unmarshal(login.Body.Bytes(), &session) != nil || !session.Data.User.Forced || len(login.Result().Cookies()) != 1 {
		t.Fatal("expected actual temporary session")
	}
	cookie := login.Result().Cookies()[0]
	expectControl(t, f.request(t, "POST", "/api/v1/auth/logout-all", "{}", map[string]string{"X-CSRF-Token": session.Data.CSRF}, cookie), 200, "")
	expectControl(t, f.request(t, "GET", "/api/v1/auth/me", "", nil, cookie), 401, "MI_SESSION_REQUIRED")
	expectControl(t, f.request(t, "GET", "/api/v1/auth/me", "", nil, admin), 200, "")
}
