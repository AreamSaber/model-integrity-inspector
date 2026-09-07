package api

import (
	"slices"
	"testing"
)

func TestEffectivePermissionsAreSessionAndOrganizationScoped(t *testing.T) {
	f := newControlFixture(t, nil)
	f.initialize(t)
	cookie, csrf, org := f.login(t)
	headers := map[string]string{"X-Organization-ID": org}
	w := f.request(t, "GET", "/api/v1/auth/permissions", "", headers, cookie)
	expectControl(t, w, 200, "")
	var data struct {
		OrganizationID string   `json:"organization_id"`
		UserID         string   `json:"user_id"`
		Permissions    []string `json:"permissions"`
	}
	managementHTTPData(t, w, &data)
	if data.OrganizationID != org || data.UserID == "" || !slices.Contains(data.Permissions, "run.create") || !slices.Contains(data.Permissions, "run.high-cost") || !slices.Contains(data.Permissions, "run.custom") {
		t.Fatal("effective organization grants missing")
	}
	expectControl(t, f.request(t, "GET", "/api/v1/auth/permissions", "", headers, nil), 401, "MI_SESSION_REQUIRED")
	expectControl(t, f.request(t, "GET", "/api/v1/auth/permissions", "", nil, cookie), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "GET", "/api/v1/auth/permissions", "", map[string]string{"X-Organization-ID": "1"}, cookie), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "GET", "/api/v1/auth/permissions?user_id=1", "", headers, cookie), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "POST", "/api/v1/auth/logout", "", map[string]string{"X-CSRF-Token": csrf}, cookie), 200, "")
	expectControl(t, f.request(t, "GET", "/api/v1/auth/permissions", "", headers, cookie), 401, "MI_SESSION_REQUIRED")
}
