package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

type managementHTTPObject struct {
	ID             string   `json:"id"`
	UserID         string   `json:"user_id"`
	OrganizationID string   `json:"org_id"`
	Username       string   `json:"username"`
	Status         string   `json:"status"`
	Version        int      `json:"version"`
	MustChange     bool     `json:"must_change_password"`
	Roles          []string `json:"roles"`
}
type managementHTTPPage struct {
	Items      []managementHTTPObject `json:"items"`
	NextCursor *string                `json:"next_cursor"`
}

func managementHTTPData(t *testing.T, w *httptest.ResponseRecorder, out any) {
	t.Helper()
	for _, forbidden := range []string{"password_hash", "PasswordHash", "session_hash", "csrf_hash", "argon2id", controlPassword, "synthetic-managed-new-password", "SELECT ", "INSERT INTO", "UPDATE users", "quota_json"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatal("management response disclosed sensitive material")
		}
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(w.Body.Bytes(), &envelope) != nil || json.Unmarshal(envelope.Data, out) != nil {
		t.Fatalf("invalid management envelope: %s", w.Body.String())
	}
}

func managementHTTPUser(t *testing.T, f controlFixture, admin *http.Cookie, csrf, name string) (managementHTTPObject, *http.Cookie, string) {
	t.Helper()
	w := f.request(t, "POST", "/api/v1/users", `{"username":"`+name+`","password":"`+controlPassword+`"}`, map[string]string{"X-CSRF-Token": csrf}, admin)
	expectControl(t, w, 201, "")
	var user managementHTTPObject
	managementHTTPData(t, w, &user)
	login := f.request(t, "POST", "/api/v1/auth/login", `{"username":"`+name+`","password":"`+controlPassword+`"}`, nil, nil)
	expectControl(t, login, 200, "")
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(login.Body.Bytes(), &envelope) != nil || json.Unmarshal(envelope.Data, &session) != nil {
		t.Fatal("invalid login")
	}
	cookie := login.Result().Cookies()[0]
	changed := f.request(t, "POST", "/api/v1/auth/change-password", `{"current_password":"`+controlPassword+`","new_password":"synthetic-managed-new-password"}`, map[string]string{"X-CSRF-Token": session.CSRF}, cookie)
	expectControl(t, changed, 200, "")
	login = f.request(t, "POST", "/api/v1/auth/login", `{"username":"`+name+`","password":"synthetic-managed-new-password"}`, nil, nil)
	expectControl(t, login, 200, "")
	if json.Unmarshal(login.Body.Bytes(), &envelope) != nil || json.Unmarshal(envelope.Data, &session) != nil {
		t.Fatal("invalid login")
	}
	return user, login.Result().Cookies()[0], session.CSRF
}

func TestManagementHTTPStrictUserDTOAndCursorIsolation(t *testing.T) {
	f := newControlFixture(t, nil)
	f.initialize(t)
	cookie, csrf, _ := f.login(t)
	expectControl(t, f.request(t, "GET", "/api/v1/users", "", nil, nil), 401, "MI_SESSION_REQUIRED")
	expectControl(t, f.request(t, "POST", "/api/v1/users", `{"username":"denied","password":"`+controlPassword+`"}`, nil, cookie), 403, "MI_CSRF_INVALID")
	for _, body := range []string{
		`{"username":"unknown-field","password":"` + controlPassword + `","system_admin":true}`,
		`{"username":"null-display","password":"` + controlPassword + `","display_name":null}`,
		`{"username":"duplicate-one","username":"duplicate-two","password":"` + controlPassword + `"}`,
		`{"Username":"case-alias","password":"` + controlPassword + `"}`,
		`null`,
	} {
		expectControl(t, f.request(t, "POST", "/api/v1/users", body, map[string]string{"X-CSRF-Token": csrf}, cookie), 400, "MI_INVALID_REQUEST")
	}
	user, otherCookie, _ := managementHTTPUser(t, f, cookie, csrf, "paged-user")
	if _, ok := managementID(user.ID); !ok || user.Version != 1 || !user.MustChange {
		t.Fatal("unsafe user DTO identity/defaults")
	}
	first := f.request(t, "GET", "/api/v1/users?limit=1", "", nil, cookie)
	expectControl(t, first, 200, "")
	var page managementHTTPPage
	managementHTTPData(t, first, &page)
	if len(page.Items) != 1 || page.NextCursor == nil {
		t.Fatal("first page missing scoped cursor")
	}
	next := *page.NextCursor
	second := f.request(t, "GET", "/api/v1/users?limit=1&cursor="+url.QueryEscape(next), "", nil, cookie)
	expectControl(t, second, 200, "")
	var secondPage managementHTTPPage
	managementHTTPData(t, second, &secondPage)
	if len(secondPage.Items) != 1 || secondPage.NextCursor != nil || secondPage.Items[0].ID == page.Items[0].ID {
		t.Fatal("pagination duplicate or spurious final cursor")
	}
	for _, path := range []string{"/api/v1/organizations?cursor=" + url.QueryEscape(next), "/api/v1/users?q=changed&cursor=" + url.QueryEscape(next), "/api/v1/users?cursor=" + url.QueryEscape(next+"tamper"), "/api/v1/users?limit=101", "/api/v1/users?limit=1&limit=2"} {
		expectControl(t, f.request(t, "GET", path, "", nil, cookie), 400, "MI_INVALID_REQUEST")
	}
	expectControl(t, f.request(t, "GET", "/api/v1/users?cursor="+url.QueryEscape(next), "", nil, otherCookie), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "GET", "/api/v1/users", "", nil, otherCookie), 403, "MI_PERMISSION_DENIED")
	filtered := f.request(t, "GET", "/api/v1/users?q=paged-user", "", nil, cookie)
	expectControl(t, filtered, 200, "")
	managementHTTPData(t, filtered, &page)
	if len(page.Items) != 1 || page.Items[0].ID != user.ID {
		t.Fatal("username search not scoped")
	}
	expectControl(t, f.request(t, "PATCH", "/api/v1/users/0"+user.ID, `{"version":2,"display_name":"Bad canonical ID"}`, map[string]string{"X-CSRF-Token": csrf}, cookie), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "PATCH", "/api/v1/users/"+user.ID, `{"display_name":"No version"}`, map[string]string{"X-CSRF-Token": csrf}, cookie), 400, "MI_INVALID_REQUEST")
	w := f.request(t, "PATCH", "/api/v1/users/"+user.ID, `{"version":2,"display_name":"Updated"}`, map[string]string{"X-CSRF-Token": csrf}, cookie)
	expectControl(t, w, 200, "")
	managementHTTPData(t, w, &user)
	if user.Version != 3 {
		t.Fatal("updated DTO missing version")
	}
	expectControl(t, f.request(t, "PATCH", "/api/v1/users/"+user.ID, `{"version":2,"display_name":"Stale"}`, map[string]string{"X-CSRF-Token": csrf}, cookie), 409, "MI_VERSION_CONFLICT")
}

func TestManagementHTTPOrganizationMemberScopeAndLastAdmin(t *testing.T) {
	f := newControlFixture(t, nil)
	f.initialize(t)
	cookie, csrf, orgID := f.login(t)
	user, delegateCookie, delegateCSRF := managementHTTPUser(t, f, cookie, csrf, "http-delegate")
	headers := map[string]string{"X-CSRF-Token": csrf, "X-Organization-ID": orgID}
	path := "/api/v1/organizations/" + orgID + "/members"
	expectControl(t, f.request(t, "GET", path, "", nil, cookie), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "GET", path, "", map[string]string{"X-Organization-ID": "1"}, cookie), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "POST", path, `{"user_id":`+user.ID+`,"roles":["viewer"]}`, headers, cookie), 400, "MI_INVALID_REQUEST")
	created := f.request(t, "POST", path, `{"user_id":"`+user.ID+`","roles":["viewer"],"permissions":["member.write"]}`, headers, cookie)
	expectControl(t, created, 201, "")
	var member managementHTTPObject
	managementHTTPData(t, created, &member)
	if member.UserID != user.ID || member.OrganizationID != orgID || member.Version != 1 {
		t.Fatal("member DTO numeric ID or wrong scope")
	}
	listed := f.request(t, "GET", path, "", headers, cookie)
	expectControl(t, listed, 200, "")
	var page managementHTTPPage
	managementHTTPData(t, listed, &page)
	var adminID string
	for _, m := range page.Items {
		if m.Username == "admin" {
			adminID = m.ID
		}
	}
	if adminID == "" {
		t.Fatal("missing initial administrator")
	}
	lastAdmin := f.request(t, "PATCH", path+"/"+adminID, `{"version":1,"status":"disabled"}`, map[string]string{"X-CSRF-Token": delegateCSRF, "X-Organization-ID": orgID}, delegateCookie)
	expectControl(t, lastAdmin, 409, "MI_LAST_ADMINISTRATOR")
	if strings.Contains(lastAdmin.Body.String(), controlPassword) || strings.Contains(lastAdmin.Body.String(), "SELECT") {
		t.Fatal("last-admin error leaked internal data")
	}
	expectControl(t, f.request(t, "PATCH", path+"/"+adminID, `{"version":1,"status":"disabled"}`, headers, cookie), 409, "MI_SELF_LOCKOUT_FORBIDDEN")
	expectControl(t, f.request(t, "PATCH", path+"/"+member.ID, `{"version":1,"permissions":["system.users"]}`, headers, cookie), 403, "MI_PERMISSION_DENIED")
	orgResponse := f.request(t, "POST", "/api/v1/organizations", `{"name":"Another organization","timezone":"UTC"}`, headers, cookie)
	expectControl(t, orgResponse, 201, "")
	var org managementHTTPObject
	managementHTTPData(t, orgResponse, &org)
	expectControl(t, f.request(t, "PATCH", "/api/v1/organizations/"+org.ID, `{"version":1,"name":"Wrong header"}`, headers, cookie), 400, "MI_INVALID_REQUEST")
	headers2 := map[string]string{"X-CSRF-Token": csrf, "X-Organization-ID": org.ID}
	expectControl(t, f.request(t, "PATCH", "/api/v1/organizations/"+org.ID, `{"version":1,"full_response_retention_days":0}`, headers2, cookie), 200, "")
	expectControl(t, f.request(t, "GET", "/api/v1/organizations/"+org.ID, "", headers2, delegateCookie), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "PATCH", "/api/v1/organizations/"+org.ID+"/members/"+member.ID, `{"version":1,"status":"disabled"}`, headers2, cookie), 404, "MI_NOT_FOUND")
	roles := f.request(t, "GET", "/api/v1/roles?limit=1", "", headers, cookie)
	expectControl(t, roles, 200, "")
	var rolePage struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
		Next *string `json:"next_cursor"`
	}
	managementHTTPData(t, roles, &rolePage)
	if len(rolePage.Items) != 1 || rolePage.Next == nil {
		t.Fatal("roles do not honor pagination")
	}
	expectControl(t, f.request(t, "GET", "/api/v1/roles?cursor="+url.QueryEscape(*rolePage.Next), "", headers2, cookie), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "PATCH", path+"/"+member.ID, `{"version":1,"status":"disabled"}`, headers, cookie), 200, "")
	expectControl(t, f.request(t, "GET", path, "", map[string]string{"X-Organization-ID": orgID}, delegateCookie), 403, "MI_PERMISSION_DENIED")
	if err := f.cfg.Store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}

func TestManagementHTTPResetUnlockDisableAndTemporarySessionGate(t *testing.T) {
	f := newControlFixture(t, nil)
	f.initialize(t)
	cookie, csrf, _ := f.login(t)
	user, otherCookie, _ := managementHTTPUser(t, f, cookie, csrf, "http-reset")
	headers := map[string]string{"X-CSRF-Token": csrf}
	path := "/api/v1/users/" + user.ID
	reset := f.request(t, "POST", path+"/reset-password", `{"version":2,"password":"`+controlPassword+`"}`, headers, cookie)
	expectControl(t, reset, 200, "")
	managementHTTPData(t, reset, &user)
	if user.Version != 3 || !user.MustChange {
		t.Fatal("reset omitted temporary-password flag/version")
	}
	expectControl(t, f.request(t, "GET", "/api/v1/auth/me", "", nil, otherCookie), 401, "MI_SESSION_REQUIRED")
	login := f.request(t, "POST", "/api/v1/auth/login", `{"username":"http-reset","password":"`+controlPassword+`"}`, nil, nil)
	expectControl(t, login, 200, "")
	temporaryCookie := login.Result().Cookies()[0]
	expectControl(t, f.request(t, "GET", "/api/v1/organizations", "", nil, temporaryCookie), 403, "MI_PASSWORD_CHANGE_REQUIRED")
	expectControl(t, f.request(t, "GET", "/api/v1/system/version", "", nil, temporaryCookie), 403, "MI_PASSWORD_CHANGE_REQUIRED")
	expectControl(t, f.request(t, "GET", "/api/v1/auth/me", "", nil, temporaryCookie), 200, "")
	unlock := f.request(t, "POST", path+"/unlock", `{"version":3}`, headers, cookie)
	expectControl(t, unlock, 200, "")
	managementHTTPData(t, unlock, &user)
	if user.Version != 4 {
		t.Fatal("unlock did not return new version")
	}
	disabled := f.request(t, "PATCH", path, `{"version":`+strconv.Itoa(user.Version)+`,"status":"disabled"}`, headers, cookie)
	expectControl(t, disabled, 200, "")
	managementHTTPData(t, disabled, &user)
	if user.Status != "disabled" {
		t.Fatal("account not disabled")
	}
	expectControl(t, f.request(t, "GET", "/api/v1/auth/me", "", nil, temporaryCookie), 401, "MI_SESSION_REQUIRED")
}
