package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func catalogHTTPFixture(t *testing.T) (controlFixture, *http.Cookie, map[string]string) {
	t.Helper()
	f := newControlFixture(t, nil)
	f.initialize(t)
	cookie, csrf, orgID := f.login(t)
	return f, cookie, map[string]string{"X-Organization-ID": orgID, "X-CSRF-Token": csrf}
}
func catalogHTTPProvider(t *testing.T, f controlFixture, cookie *http.Cookie, headers map[string]string, name string) managementHTTPObject {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"name": name, "description": "Public metadata only", "contact": "ops@example.invalid"})
	w := f.request(t, "POST", "/api/v1/providers", string(body), headers, cookie)
	expectControl(t, w, 201, "")
	var result managementHTTPObject
	managementHTTPData(t, w, &result)
	return result
}

func TestCatalogHTTPCRUDDTOAndNullablePrices(t *testing.T) {
	f, cookie, headers := catalogHTTPFixture(t)
	provider := catalogHTTPProvider(t, f, cookie, headers, "Canonical provider")
	if provider.Version != 1 || provider.Status != "active" {
		t.Fatal("provider read DTO missing version/status")
	}
	expectControl(t, f.request(t, "GET", "/api/v1/providers/"+provider.ID, "", headers, cookie), 200, "")
	created := f.request(t, "POST", "/api/v1/model-profiles", `{"provider_id":"`+provider.ID+`","name":"model-x","protocol":"openai_chat","supports_stream":true,"supports_seed":true,"reasoning_model":false,"tokenizer_id":"example-v1","tokenizer_quality":"compatible","max_output_tokens":8192,"context_window":65536,"input_price_micros_per_million":0,"output_price_micros_per_million":null}`, headers, cookie)
	expectControl(t, created, 201, "")
	var model managementHTTPObject
	managementHTTPData(t, created, &model)
	var detail map[string]any
	managementHTTPData(t, created, &detail)
	if detail["name"] != "model-x" || detail["provider_id"] != provider.ID || detail["input_price_micros_per_million"] != float64(0) || detail["output_price_micros_per_million"] != nil {
		t.Fatal("model DTO name/string ID/unknown price wrong")
	}
	if _, exists := detail["capabilities_json"]; exists {
		t.Fatal("raw model metadata leaked")
	}
	listed := f.request(t, "GET", "/api/v1/model-profiles", "", headers, cookie)
	expectControl(t, listed, 200, "")
	if strings.Contains(listed.Body.String(), "tokenizer_id") || strings.Contains(listed.Body.String(), "supports_stream") {
		t.Fatal("list loaded detailed metadata")
	}
	expectControl(t, f.request(t, "DELETE", "/api/v1/providers/"+provider.ID, `{"version":1}`, headers, cookie), 409, "MI_VERSION_CONFLICT")
	patched := f.request(t, "PATCH", "/api/v1/model-profiles/"+model.ID, `{"version":1,"input_price_micros_per_million":null,"output_price_micros_per_million":1500000,"display_name":"Display name"}`, headers, cookie)
	expectControl(t, patched, 200, "")
	managementHTTPData(t, patched, &detail)
	if detail["version"] != float64(2) || detail["input_price_micros_per_million"] != nil || detail["output_price_micros_per_million"] != float64(1500000) || detail["supports_stream"] != true {
		t.Fatal("partial patch erased metadata or failed to clear price")
	}
	expectControl(t, f.request(t, "PATCH", "/api/v1/model-profiles/"+model.ID, `{"version":1,"name":"stale"}`, headers, cookie), 409, "MI_VERSION_CONFLICT")
	expectControl(t, f.request(t, "PATCH", "/api/v1/model-profiles/"+model.ID, `{"version":2,"status":"disabled"}`, headers, cookie), 200, "")
	expectControl(t, f.request(t, "DELETE", "/api/v1/model-profiles/"+model.ID, `{"version":3}`, headers, cookie), 200, "")
	expectControl(t, f.request(t, "GET", "/api/v1/model-profiles/"+model.ID, "", headers, cookie), 404, "MI_NOT_FOUND")
	expectControl(t, f.request(t, "PATCH", "/api/v1/providers/"+provider.ID, `{"version":1,"name":"Updated provider","status":"disabled"}`, headers, cookie), 200, "")
	expectControl(t, f.request(t, "DELETE", "/api/v1/providers/"+provider.ID, `{"version":2}`, headers, cookie), 200, "")
	expectControl(t, f.request(t, "GET", "/api/v1/providers/"+provider.ID, "", headers, cookie), 404, "MI_NOT_FOUND")
	if err := f.cfg.Store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogHTTPValidationRBACScopeAndPagination(t *testing.T) {
	f, cookie, headers := catalogHTTPFixture(t)
	provider := catalogHTTPProvider(t, f, cookie, headers, "Paging provider one")
	_ = catalogHTTPProvider(t, f, cookie, headers, "Paging provider two")
	for _, body := range []string{
		`{"provider_id":"` + provider.ID + `","name":"bad","protocol":"openai_chat","input_price_micros_per_million":-1}`,
		`{"provider_id":"` + provider.ID + `","name":"bad","protocol":"openai_chat","input_price_micros_per_million":9007199254740992}`,
		`{"provider_id":"` + provider.ID + `","name":"bad","protocol":"openai_chat","output_price_micros_per_million":1.5}`,
		`{"provider_id":"` + provider.ID + `","name":"bad","protocol":"openai_chat","supports_seed":null}`,
		`{"provider_id":"` + provider.ID + `","name":"bad","protocol":"openai_chat","capabilities_json":"{}"}`,
		`{"provider_id":"` + provider.ID + `","name":"bad","protocol":"openai_chat","tokenizer_quality":"exact"}`,
		`{"provider_id":"` + provider.ID + `","name":"bad","protocol":"openai_chat","tokenizer_quality":"unavailable","tokenizer_id":"claimed"}`,
		`{"provider_id":"` + provider.ID + `","name":"bad","protocol":"openai_chat","tokenizer_quality":""}`,
		`{"provider_id":"` + provider.ID + `","name":"bad","protocol":"openai_chat","max_output_tokens":1024,"context_window":512}`,
		`{"provider_id":"` + provider.ID + `","name":"bad","protocol":"openai_chat","max_output_tokens":null}`,
		`{"provider_id":` + provider.ID + `,"name":"bad","protocol":"openai_chat"}`,
		`{"provider_id":"` + provider.ID + `","name":"bad","protocol":"unknown"}`,
	} {
		expectControl(t, f.request(t, "POST", "/api/v1/model-profiles", body, headers, cookie), 400, "MI_INVALID_REQUEST")
	}
	expectControl(t, f.request(t, "POST", "/api/v1/providers", `{"name":"No CSRF"}`, map[string]string{"X-Organization-ID": headers["X-Organization-ID"]}, cookie), 403, "MI_CSRF_INVALID")
	expectControl(t, f.request(t, "POST", "/api/v1/providers", `{"name":"bad","status":""}`, headers, cookie), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "POST", "/api/v1/providers", `{"name":"bad","contact":null}`, headers, cookie), 400, "MI_INVALID_REQUEST")
	pageOne := f.request(t, "GET", "/api/v1/providers?limit=1", "", headers, cookie)
	expectControl(t, pageOne, 200, "")
	var page managementHTTPPage
	managementHTTPData(t, pageOne, &page)
	if page.NextCursor == nil {
		t.Fatal("providers not paginated")
	}
	expectControl(t, f.request(t, "GET", "/api/v1/model-profiles?cursor="+url.QueryEscape(*page.NextCursor), "", headers, cookie), 400, "MI_INVALID_REQUEST")
	pageTwo := f.request(t, "GET", "/api/v1/providers?limit=1&cursor="+url.QueryEscape(*page.NextCursor), "", headers, cookie)
	expectControl(t, pageTwo, 200, "")
	managementHTTPData(t, pageTwo, &page)
	if len(page.Items) != 1 || page.NextCursor != nil {
		t.Fatal("incorrect provider final page")
	}
	orgResponse := f.request(t, "POST", "/api/v1/organizations", `{"name":"Isolated catalog"}`, headers, cookie)
	expectControl(t, orgResponse, 201, "")
	var otherOrg managementHTTPObject
	managementHTTPData(t, orgResponse, &otherOrg)
	otherHeaders := map[string]string{"X-Organization-ID": otherOrg.ID, "X-CSRF-Token": headers["X-CSRF-Token"]}
	expectControl(t, f.request(t, "GET", "/api/v1/providers/"+provider.ID, "", otherHeaders, cookie), 404, "MI_NOT_FOUND")
	expectControl(t, f.request(t, "POST", "/api/v1/model-profiles", `{"provider_id":"`+provider.ID+`","name":"foreign","protocol":"openai_chat"}`, otherHeaders, cookie), 404, "MI_NOT_FOUND")
	user, viewer, viewerCSRF := managementHTTPUser(t, f, cookie, headers["X-CSRF-Token"], "catalog-viewer")
	expectControl(t, f.request(t, "POST", "/api/v1/organizations/"+headers["X-Organization-ID"]+"/members", `{"user_id":"`+user.ID+`","roles":["viewer"]}`, headers, cookie), 201, "")
	viewerHeaders := map[string]string{"X-Organization-ID": headers["X-Organization-ID"], "X-CSRF-Token": viewerCSRF}
	expectControl(t, f.request(t, "GET", "/api/v1/providers", "", viewerHeaders, viewer), 200, "")
	expectControl(t, f.request(t, "POST", "/api/v1/providers", `{"name":"Forbidden"}`, viewerHeaders, viewer), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "PATCH", "/api/v1/providers/"+provider.ID, `{"version":1,"name":"Forbidden"}`, viewerHeaders, viewer), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "DELETE", "/api/v1/providers/"+provider.ID, `{"version":1}`, viewerHeaders, viewer), 403, "MI_PERMISSION_DENIED")
}
