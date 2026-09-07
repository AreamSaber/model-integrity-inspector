package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const targetHTTPKey = "synthetic-http-target-key-never-return"
const targetHTTPBody = `{"name":"Synthetic target","endpoint":"https://example.com/v1","protocol":"openai_chat","model":"synthetic-model","auth":{"type":"bearer","api_key":"` + targetHTTPKey + `"}}`

type targetHTTPView struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version int64  `json:"version"`
	Status  string `json:"status"`
	Secret  struct {
		ID      string `json:"id"`
		Version int64  `json:"version"`
		Mask    string `json:"mask"`
	} `json:"secret"`
}

func targetHTTPData(t *testing.T, w *httptest.ResponseRecorder, out any) {
	t.Helper()
	for _, forbidden := range []string{targetHTTPKey, "synthetic-rotated-key", "api_key", "ciphertext", "fingerprint", "wrapped_dek", "headers", "auth", "SELECT ", "INSERT INTO"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatalf("target response disclosed %q", forbidden)
		}
	}
	managementHTTPData(t, w, out)
}

func TestTargetHTTPLifecycleVersionSecretAndDeletion(t *testing.T) {
	f := newControlFixture(t, nil)
	f.initialize(t)
	cookie, csrf, org := f.login(t)
	headers := map[string]string{"X-CSRF-Token": csrf, "X-Organization-ID": org}
	w := f.request(t, "POST", "/api/v1/targets", targetHTTPBody, headers, cookie)
	expectControl(t, w, 201, "")
	var value targetHTTPView
	targetHTTPData(t, w, &value)
	if _, ok := managementID(value.ID); !ok || value.Version != 1 || value.Secret.Version != 1 || value.Secret.Mask == "" {
		t.Fatal("invalid public target identity/version/mask")
	}
	path := "/api/v1/targets/" + value.ID
	w = f.request(t, "PATCH", path, `{"version":1,"name":"Updated target"}`, headers, cookie)
	expectControl(t, w, 200, "")
	targetHTTPData(t, w, &value)
	if value.Version != 2 || value.Name != "Updated target" || value.Secret.Version != 1 {
		t.Fatal("patch lost fields/version")
	}
	expectControl(t, f.request(t, "PATCH", path, `{"version":1,"name":"Stale"}`, headers, cookie), 409, "MI_VERSION_CONFLICT")
	rotation := `{"version":2,"secret_version":1,"auth":{"type":"bearer","api_key":"synthetic-rotated-key"}}`
	w = f.request(t, "POST", path+"/rotate-secret", rotation, headers, cookie)
	expectControl(t, w, 200, "")
	targetHTTPData(t, w, &value)
	if value.Version != 3 || value.Secret.Version != 2 {
		t.Fatal("rotation did not advance both versions")
	}
	expectControl(t, f.request(t, "POST", path+"/rotate-secret", rotation, headers, cookie), 409, "MI_VERSION_CONFLICT")
	expectControl(t, f.request(t, "DELETE", path, `{"version":2}`, headers, cookie), 409, "MI_VERSION_CONFLICT")
	expectControl(t, f.request(t, "DELETE", path, `{"version":3}`, headers, cookie), 200, "")
	expectControl(t, f.request(t, "GET", path, "", headers, cookie), 404, "MI_NOT_FOUND")
	if err := f.cfg.Store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}

func TestTargetHTTPAuthorizationScopeCursorAndNoSecretRead(t *testing.T) {
	f := newControlFixture(t, nil)
	f.initialize(t)
	admin, csrf, org := f.login(t)
	headers := map[string]string{"X-CSRF-Token": csrf, "X-Organization-ID": org}
	expectControl(t, f.request(t, "POST", "/api/v1/targets", targetHTTPBody, map[string]string{"X-Organization-ID": org}, admin), 403, "MI_CSRF_INVALID")
	expectControl(t, f.request(t, "GET", "/api/v1/targets", "", nil, admin), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "GET", "/api/v1/targets", "", headers, nil), 401, "MI_SESSION_REQUIRED")
	var created targetHTTPView
	for index := range 2 {
		body := strings.Replace(targetHTTPBody, "Synthetic target", fmt.Sprintf("Synthetic target %d", index), 1)
		w := f.request(t, "POST", "/api/v1/targets", body, headers, admin)
		expectControl(t, w, 201, "")
		targetHTTPData(t, w, &created)
	}
	var page struct {
		Items []targetHTTPView `json:"items"`
		Next  *string          `json:"next_cursor"`
	}
	w := f.request(t, "GET", "/api/v1/targets?limit=1", "", headers, admin)
	expectControl(t, w, 200, "")
	targetHTTPData(t, w, &page)
	if len(page.Items) != 1 || page.Next == nil {
		t.Fatal("missing target cursor")
	}
	cursor := *page.Next
	firstID := page.Items[0].ID
	w = f.request(t, "GET", "/api/v1/targets?limit=1&cursor="+url.QueryEscape(cursor), "", headers, admin)
	expectControl(t, w, 200, "")
	targetHTTPData(t, w, &page)
	if len(page.Items) != 1 || page.Next != nil || page.Items[0].ID == firstID {
		t.Fatal("duplicate/final cursor")
	}
	newOrg := f.request(t, "POST", "/api/v1/organizations", `{"name":"Other tenant"}`, headers, admin)
	expectControl(t, newOrg, 201, "")
	var other managementHTTPObject
	managementHTTPData(t, newOrg, &other)
	otherHeaders := map[string]string{"X-CSRF-Token": csrf, "X-Organization-ID": other.ID}
	expectControl(t, f.request(t, "GET", "/api/v1/targets/"+created.ID, "", otherHeaders, admin), 404, "MI_NOT_FOUND")
	expectControl(t, f.request(t, "GET", "/api/v1/targets?cursor="+url.QueryEscape(cursor), "", otherHeaders, admin), 400, "MI_INVALID_REQUEST")
	user, viewer, viewerCSRF := managementHTTPUser(t, f, admin, csrf, "target-viewer")
	w = f.request(t, "POST", "/api/v1/organizations/"+org+"/members", `{"user_id":"`+user.ID+`","roles":["viewer"]}`, headers, admin)
	expectControl(t, w, 201, "")
	viewerHeaders := map[string]string{"X-CSRF-Token": viewerCSRF, "X-Organization-ID": org}
	w = f.request(t, "GET", "/api/v1/targets/"+created.ID, "", viewerHeaders, viewer)
	expectControl(t, w, 200, "")
	targetHTTPData(t, w, &created)
	expectControl(t, f.request(t, "POST", "/api/v1/targets", targetHTTPBody, viewerHeaders, viewer), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "POST", "/api/v1/targets/"+created.ID+"/rotate-secret", `{}`, viewerHeaders, viewer), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "DELETE", "/api/v1/targets/"+created.ID, `{"version":1}`, viewerHeaders, viewer), 403, "MI_PERMISSION_DENIED")
}

func TestTargetHTTPRejectsAmbiguousUnsafeAndUnknownInputs(t *testing.T) {
	f := newControlFixture(t, nil)
	f.initialize(t)
	cookie, csrf, org := f.login(t)
	headers := map[string]string{"X-CSRF-Token": csrf, "X-Organization-ID": org}
	for _, body := range []string{
		strings.Replace(targetHTTPBody, `"name":`, `"Name":`, 1),
		strings.Replace(targetHTTPBody, `"name":"Synthetic target"`, `"name":"one","name":"two"`, 1),
		strings.Replace(targetHTTPBody, `"type":"bearer"`, `"type":"bearer","type":"bearer"`, 1),
		strings.Replace(targetHTTPBody, "https://example.com/v1", "http://example.com/v1", 1),
		strings.Replace(targetHTTPBody, "https://example.com/v1", "https://127.0.0.1/v1", 1),
		strings.Replace(targetHTTPBody, `"auth":`, `"options":{"tls_verify":false},"auth":`, 1),
		strings.Replace(targetHTTPBody, `"auth":`, `"provider_id":12,"auth":`, 1),
		strings.Replace(targetHTTPBody, `"auth":`, `"version":1,"auth":`, 1),
	} {
		expectControl(t, f.request(t, "POST", "/api/v1/targets", body, headers, cookie), 400, "MI_INVALID_REQUEST")
	}
	w := f.request(t, "POST", "/api/v1/targets", targetHTTPBody, headers, cookie)
	expectControl(t, w, 201, "")
	var value targetHTTPView
	targetHTTPData(t, w, &value)
	path := "/api/v1/targets/" + value.ID
	for _, patch := range []string{`{"version":1,"status":null}`, `{"version":1,"auth":{}}`, `{"version":1,"options":{"RPM":2}}`, `{"version":1,"version":1}`, `{"version":1,"name":null}`, `{"name":"missing version"}`} {
		expectControl(t, f.request(t, "PATCH", path, patch, headers, cookie), 400, "MI_INVALID_REQUEST")
	}
	for _, route := range []string{path + "?ignored=1", "/api/v1/targets?q=unsupported", "/api/v1/targets?limit=1&limit=2"} {
		expectControl(t, f.request(t, "GET", route, "", headers, cookie), 400, "MI_INVALID_REQUEST")
	}
	r := httptest.NewRequestWithContext(t.Context(), "GET", path, nil)
	r.AddCookie(cookie)
	r.Header.Add("X-Organization-ID", org)
	r.Header.Add("X-Organization-ID", org)
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	expectControl(t, w, 400, "MI_INVALID_REQUEST")
	w = f.request(t, "GET", path, "", headers, cookie)
	expectControl(t, w, 200, "")
	targetHTTPData(t, w, &value)
	if value.Version != 1 {
		t.Fatal("invalid mutation changed target")
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(w.Body.Bytes(), &raw) != nil {
		t.Fatal("invalid JSON")
	}
}
