package api

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/baseline"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
)

func newBaselineHTTPFixture(t *testing.T) resultHTTPFixture {
	t.Helper()
	f := newResultHTTPFixture(t)
	artifact, hash, err := templates.Builtin().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := generator.New(artifact, hash, f.engine, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	f.cfg.Baselines, err = baseline.NewService(baseline.Config{Store: f.cfg.Store, Generator: compiler, Signer: f.keys})
	if err != nil {
		t.Fatal(err)
	}
	f.handler, err = NewControlHandler(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func baselineHTTPBody(runID int64, name string) string {
	return `{"name":"` + name + `","run_id":"` + strconv.FormatInt(runID, 10) + `","source":"official","region":"organization-declared-test-region","expires_at":"` + time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339) + `"}`
}
func baselineNoSecrets(t *testing.T, body string) {
	t.Helper()
	resultNoS2(t, body)
	for _, key := range []string{"approval_mac", "approval_key_version", "snapshot_json", "review_explanation", "retirement_reason", "applicable_scope_json", "private-business-review-canary", "RunNonce", "VariablesHash"} {
		if strings.Contains(body, key) {
			t.Fatal("baseline private data leaked", key)
		}
	}
}
func TestBaselineHTTPRealPublishedSourceApprovalAndLifecycle(t *testing.T) {
	f := newBaselineHTTPFixture(t)
	w := f.request(t, "POST", "/api/v1/baselines", baselineHTTPBody(f.runID, "Before publication"), f.headers, f.cookie)
	expectControl(t, w, 409, "MI_BASELINE_SOURCE_INVALID")
	f.publish(t)
	w = f.request(t, "POST", "/api/v1/baselines", baselineHTTPBody(f.runID, "Organization reference"), f.headers, f.cookie)
	expectControl(t, w, 201, "")
	baselineNoSecrets(t, w.Body.String())
	var record baseline.View
	managementHTTPData(t, w, &record)
	if record.Status != "draft" || record.EligibleForScoring || record.Calibrated || !record.Development || record.ApprovedBy != nil || record.SourceAssurance != "organization_declared_unverified" || record.ValidSamples < 6 {
		t.Fatal("draft trust semantics")
	}
	path := "/api/v1/baselines/" + record.ID
	expectControl(t, f.request(t, "POST", path+"/approve", `{"version":1,"reason":"explicit reviewer statement"}`, f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
	approve := `{"version":1,"reason":"explicit organization reviewer statement","business_review":"private-business-review-canary","acknowledge_development_limits":true}`
	w = f.request(t, "POST", path+"/approve", approve, f.headers, f.cookie)
	expectControl(t, w, 200, "")
	baselineNoSecrets(t, w.Body.String())
	managementHTTPData(t, w, &record)
	if record.Status != "approved" || record.Version != 2 || record.ApprovedBy == nil || record.ApprovedAt == nil || record.EligibleForScoring || record.Calibrated {
		t.Fatal("approval falsely grants scoring trust")
	}
	expectControl(t, f.request(t, "PATCH", path, `{"version":2,"name":"silent overwrite"}`, f.headers, f.cookie), 409, "MI_BASELINE_STATE_CONFLICT")
	expectControl(t, f.request(t, "POST", path+"/approve", approve, f.headers, f.cookie), 409, "")
	w = f.request(t, "GET", path, "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	baselineNoSecrets(t, w.Body.String())
	w = f.request(t, "POST", path+"/retire", `{"version":2,"reason":"reference withdrawn by organization"}`, f.headers, f.cookie)
	expectControl(t, w, 200, "")
	baselineNoSecrets(t, w.Body.String())
	managementHTTPData(t, w, &record)
	if record.Status != "retired" || record.Version != 3 || record.RetiredAt == nil || record.ApprovedBy == nil {
		t.Fatal("retirement erased approval history")
	}
	expectControl(t, f.request(t, "POST", path+"/approve", strings.Replace(approve, `"version":1`, `"version":3`, 1), f.headers, f.cookie), 409, "MI_BASELINE_STATE_CONFLICT")
	if err := f.cfg.Store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}

func TestBaselineHTTPPermissionsStrictInputAndCursor(t *testing.T) {
	f := newBaselineHTTPFixture(t)
	f.publish(t)
	org, csrf := f.headers["X-Organization-ID"], f.headers["X-CSRF-Token"]
	operator := runAuthorizationMember(t, f.controlFixture, f.cookie, csrf, org, "baseline-operator", "operator", nil)
	viewer := runAuthorizationMember(t, f.controlFixture, f.cookie, csrf, org, "baseline-viewer", "viewer", nil)
	operatorHeaders, viewerHeaders := runAuthorizationHeaders(org, operator.csrf), runAuthorizationHeaders(org, viewer.csrf)
	expectControl(t, f.request(t, "POST", "/api/v1/baselines", baselineHTTPBody(f.runID, "Viewer cannot write"), viewerHeaders, viewer.cookie), 403, "MI_PERMISSION_DENIED")
	var first baseline.View
	for _, name := range []string{"Reference one", "Reference two"} {
		w := f.request(t, "POST", "/api/v1/baselines", baselineHTTPBody(f.runID, name), operatorHeaders, operator.cookie)
		expectControl(t, w, 201, "")
		managementHTTPData(t, w, &first)
	}
	path := "/api/v1/baselines/" + first.ID
	for _, suffix := range []string{"approve", "retire"} {
		expectControl(t, f.request(t, "POST", path+"/"+suffix, `{"version":1,"reason":"unauthorized reviewer","acknowledge_development_limits":true}`, operatorHeaders, operator.cookie), 403, "MI_PERMISSION_DENIED")
	}
	expectControl(t, f.request(t, "GET", path, "", viewerHeaders, viewer.cookie), 200, "")
	for _, body := range []string{`{"name":"bad","run_id":1}`, strings.TrimSuffix(baselineHTTPBody(f.runID, "bad"), "}") + `,"eligible_for_scoring":true}`, strings.TrimSuffix(baselineHTTPBody(f.runID, "bad"), "}") + `,"approval_mac":"fabricated"}`, strings.TrimSuffix(baselineHTTPBody(f.runID, "bad"), "}") + `,"source":"historical"}`} {
		expectControl(t, f.request(t, "POST", "/api/v1/baselines", body, f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
	}
	for _, revision := range []string{"0", "-1", "2", "null"} {
		body := strings.TrimSuffix(baselineHTTPBody(f.runID, "bad revision"), "}") + `,"analysis_revision":` + revision + `}`
		expectControl(t, f.request(t, "POST", "/api/v1/baselines", body, f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
	}
	expectControl(t, f.request(t, "POST", "/api/v1/baselines", baselineHTTPBody(f.runID, "No CSRF"), map[string]string{"X-Organization-ID": org}, f.cookie), 403, "MI_CSRF_INVALID")
	w := f.request(t, "GET", "/api/v1/baselines?limit=1", "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	var page struct {
		Items []baseline.View `json:"items"`
		Next  *string         `json:"next_cursor"`
	}
	managementHTTPData(t, w, &page)
	if len(page.Items) != 1 || page.Next == nil {
		t.Fatal("baseline list cursor")
	}
	expectControl(t, f.request(t, "GET", "/api/v1/baselines?cursor="+*page.Next, "", viewerHeaders, viewer.cookie), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "GET", "/api/v1/baselines?q=other&cursor="+*page.Next, "", f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "GET", "/api/v1/baselines?limit=101", "", f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
	w = f.request(t, "POST", "/api/v1/organizations", `{"name":"Other baseline tenant","timezone":"UTC"}`, f.headers, f.cookie)
	expectControl(t, w, 201, "")
	var other managementHTTPObject
	managementHTTPData(t, w, &other)
	otherHeaders := runAuthorizationHeaders(other.ID, csrf)
	expectControl(t, f.request(t, "GET", path, "", otherHeaders, f.cookie), 404, "MI_NOT_FOUND")
	expectControl(t, f.request(t, "POST", "/api/v1/baselines", baselineHTTPBody(f.runID, "Cross tenant source"), otherHeaders, f.cookie), 404, "MI_NOT_FOUND")
	w = f.request(t, "PATCH", "/api/v1/organizations/"+org+"/members/"+operator.member.ID, `{"version":1,"status":"disabled"}`, f.headers, f.cookie)
	expectControl(t, w, 200, "")
	expectControl(t, f.request(t, "PATCH", path, `{"version":1,"name":"revoked"}`, operatorHeaders, operator.cookie), 403, "MI_PERMISSION_DENIED")
	if err := f.cfg.Store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}
