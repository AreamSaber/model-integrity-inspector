package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// These regressions use the real HTTP authorization, persistent membership and
// queue paths against either database. No execution Worker or upstream runs.
type runAuthorizationActor struct {
	cookie *http.Cookie
	csrf   string
	user   managementHTTPObject
	member managementHTTPObject
}

func runAuthorizationHeaders(org, csrf string) map[string]string {
	return map[string]string{"X-Organization-ID": org, "X-CSRF-Token": csrf}
}

func runAuthorizationJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func runAuthorizationMember(t *testing.T, f controlFixture, admin *http.Cookie, csrf, org, name, role string, permissions []string) runAuthorizationActor {
	t.Helper()
	user, cookie, memberCSRF := managementHTTPUser(t, f, admin, csrf, name)
	if permissions == nil {
		permissions = []string{}
	}
	w := f.request(t, "POST", "/api/v1/organizations/"+org+"/members", runAuthorizationJSON(t, map[string]any{"user_id": user.ID, "roles": []string{role}, "permissions": permissions}), runAuthorizationHeaders(org, csrf), admin)
	expectControl(t, w, 201, "")
	var member managementHTTPObject
	managementHTTPData(t, w, &member)
	return runAuthorizationActor{cookie, memberCSRF, user, member}
}

func runAuthorizationChange(t *testing.T, f controlFixture, admin *http.Cookie, csrf, org string, actor *runAuthorizationActor, role string, permissions []string) {
	t.Helper()
	if permissions == nil {
		permissions = []string{}
	}
	w := f.request(t, "PATCH", "/api/v1/organizations/"+org+"/members/"+actor.member.ID, runAuthorizationJSON(t, map[string]any{"version": actor.member.Version, "roles": []string{role}, "permissions": permissions}), runAuthorizationHeaders(org, csrf), admin)
	expectControl(t, w, 200, "")
	managementHTTPData(t, w, &actor.member)
}

func runAuthorizationTarget(t *testing.T, f controlFixture, admin *http.Cookie, csrf, org string) string {
	t.Helper()
	headers := runAuthorizationHeaders(org, csrf)
	w := f.request(t, "POST", "/api/v1/targets", targetHTTPBody, headers, admin)
	expectControl(t, w, 201, "")
	var target targetHTTPView
	managementHTTPData(t, w, &target)
	// The fixture's persisted terminal precheck is controlled test data, not
	// successful contact with a real model or a production end-to-end check.
	runHTTPPassedPrecheck(t, f, admin, headers, target.ID)
	return target.ID
}

func runAuthorizationQuick(target string) string {
	return `{"target_id":"` + target + `","target_version":1,"package":"quick","options":{}}`
}

func runAuthorizationEstimate(t *testing.T, f controlFixture, cookie *http.Cookie, csrf, org, body string) runHTTPQuote {
	t.Helper()
	w := f.request(t, "POST", "/api/v1/runs/estimate", body, runAuthorizationHeaders(org, csrf), cookie)
	expectControl(t, w, 200, "")
	runHTTPAssertNoS2(t, w.Body.String())
	var quote runHTTPQuote
	managementHTTPData(t, w, &quote)
	return quote
}

func runAuthorizationConfirm(t *testing.T, f controlFixture, cookie *http.Cookie, csrf, org string, quote runHTTPQuote) runHTTPView {
	t.Helper()
	w := f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(quote), runAuthorizationHeaders(org, csrf), cookie)
	expectControl(t, w, 202, "")
	runHTTPAssertNoS2(t, w.Body.String())
	var record runHTTPView
	managementHTTPData(t, w, &record)
	if record.Status != "QUEUED" || record.Version != 1 || record.RequestCount != 0 || record.Completed != 0 {
		t.Fatal("control-plane confirmation unexpectedly executed work")
	}
	return record
}

func TestRunHTTPAuthorizationTenantAndDraftOwnership(t *testing.T) {
	f := newRunHTTPFixture(t, true)
	f.initialize(t)
	admin, csrf, org := f.login(t)
	headers := runAuthorizationHeaders(org, csrf)
	operator := runAuthorizationMember(t, f, admin, csrf, org, "run-scope-operator", "operator", nil)
	operatorHeaders := runAuthorizationHeaders(org, operator.csrf)
	targetID := runAuthorizationTarget(t, f, admin, csrf, org)
	quote := runAuthorizationEstimate(t, f, admin, csrf, org, runAuthorizationQuick(targetID))

	w := f.request(t, "POST", "/api/v1/organizations", `{"name":"Run isolated organization","timezone":"UTC"}`, headers, admin)
	expectControl(t, w, 201, "")
	var other managementHTTPObject
	managementHTTPData(t, w, &other)
	otherHeaders := runAuthorizationHeaders(other.ID, csrf)

	// An authenticated creator in the same org still cannot confirm somebody
	// else's draft. Drafts have no public GET API and are not Run resources.
	expectControl(t, f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(quote), operatorHeaders, operator.cookie), 404, "MI_NOT_FOUND")
	expectControl(t, f.request(t, "GET", "/api/v1/runs/"+quote.ID, "", operatorHeaders, operator.cookie), 404, "MI_NOT_FOUND")
	expectControl(t, f.request(t, "GET", "/api/v1/runs/estimates/"+quote.ID, "", headers, admin), 404, "MI_NOT_FOUND")
	expectControl(t, f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(quote), otherHeaders, admin), 404, "MI_NOT_FOUND")
	expectControl(t, f.request(t, "POST", "/api/v1/runs/estimate", runAuthorizationQuick(targetID), otherHeaders, admin), 404, "MI_NOT_FOUND")
	record := runAuthorizationConfirm(t, f, admin, csrf, org, quote)

	// A committed Run is organization-readable, unlike its creator-private
	// draft/receipt. Do not accidentally impose an owner-only read policy.
	w = f.request(t, "GET", "/api/v1/runs/"+record.ID, "", operatorHeaders, operator.cookie)
	expectControl(t, w, 200, "")
	runHTTPAssertNoS2(t, w.Body.String())
	expectControl(t, f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(quote), operatorHeaders, operator.cookie), 404, "MI_NOT_FOUND")
	expectControl(t, f.request(t, "GET", "/api/v1/runs/"+record.ID, "", otherHeaders, admin), 404, "MI_NOT_FOUND")
	expectControl(t, f.request(t, "POST", "/api/v1/runs/"+record.ID+"/cancel", `{"version":1}`, otherHeaders, admin), 404, "MI_NOT_FOUND")

	operatorOther := runAuthorizationHeaders(other.ID, operator.csrf)
	expectControl(t, f.request(t, "GET", "/api/v1/runs/"+record.ID, "", operatorOther, operator.cookie), 403, "MI_PERMISSION_DENIED")
	w = f.request(t, "POST", "/api/v1/organizations/"+other.ID+"/members", runAuthorizationJSON(t, map[string]any{"user_id": operator.user.ID, "roles": []string{"operator"}}), otherHeaders, admin)
	expectControl(t, w, 201, "")
	for _, request := range []struct{ method, path, body string }{
		{"GET", "/api/v1/runs/" + record.ID, ""},
		{"POST", "/api/v1/runs", runHTTPConfirm(quote)},
		{"POST", "/api/v1/runs/" + record.ID + "/cancel", `{"version":1}`},
	} {
		expectControl(t, f.request(t, request.method, request.path, request.body, operatorOther, operator.cookie), 404, "MI_NOT_FOUND")
	}
	if err := f.cfg.Store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}

func TestRunHTTPAuthorizationReadCreateAndCancellationMatrix(t *testing.T) {
	f := newRunHTTPFixture(t, true)
	f.initialize(t)
	admin, csrf, org := f.login(t)
	viewer := runAuthorizationMember(t, f, admin, csrf, org, "run-matrix-viewer", "viewer", nil)
	operator := runAuthorizationMember(t, f, admin, csrf, org, "run-matrix-operator", "operator", nil)
	targetID := runAuthorizationTarget(t, f, admin, csrf, org)
	body := runAuthorizationQuick(targetID)
	adminQuote := runAuthorizationEstimate(t, f, admin, csrf, org, body)
	adminRun := runAuthorizationConfirm(t, f, admin, csrf, org, adminQuote)
	viewerHeaders := runAuthorizationHeaders(org, viewer.csrf)
	operatorHeaders := runAuthorizationHeaders(org, operator.csrf)
	expectControl(t, f.request(t, "GET", "/api/v1/runs/"+adminRun.ID, "", viewerHeaders, viewer.cookie), 200, "")
	expectControl(t, f.request(t, "POST", "/api/v1/runs/estimate", body, viewerHeaders, viewer.cookie), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(adminQuote), viewerHeaders, viewer.cookie), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "POST", "/api/v1/runs/"+adminRun.ID+"/cancel", `{"version":1}`, viewerHeaders, viewer.cookie), 403, "MI_PERMISSION_DENIED")

	// run.create supplements viewer reads but does not imply cancellation, even
	// for this user's own freshly created Run.
	runAuthorizationChange(t, f, admin, csrf, org, &viewer, "viewer", []string{"run.create"})
	viewerQuote := runAuthorizationEstimate(t, f, viewer.cookie, viewer.csrf, org, body)
	viewerRun := runAuthorizationConfirm(t, f, viewer.cookie, viewer.csrf, org, viewerQuote)
	expectControl(t, f.request(t, "POST", "/api/v1/runs/"+viewerRun.ID+"/cancel", `{"version":1}`, viewerHeaders, viewer.cookie), 403, "MI_PERMISSION_DENIED")

	operatorQuote := runAuthorizationEstimate(t, f, operator.cookie, operator.csrf, org, body)
	operatorRun := runAuthorizationConfirm(t, f, operator.cookie, operator.csrf, org, operatorQuote)
	for _, version := range []string{"1", "999"} {
		expectControl(t, f.request(t, "POST", "/api/v1/runs/"+adminRun.ID+"/cancel", `{"version":`+version+`}`, operatorHeaders, operator.cookie), 403, "MI_PERMISSION_DENIED")
	}
	w := f.request(t, "POST", "/api/v1/runs/"+operatorRun.ID+"/cancel", `{"version":1}`, operatorHeaders, operator.cookie)
	expectControl(t, w, 200, "")
	var cancelled runHTTPView
	managementHTTPData(t, w, &cancelled)
	if cancelled.Status != "CANCELLING" || cancelled.Version != 2 || cancelled.RequestCount != 0 {
		t.Fatal("own cancellation did not persist the expected non-executed state")
	}

	// cancel-any is independent of create. A viewer explicitly granted only
	// cancel-any can cancel another creator, but still cannot estimate a Run.
	runAuthorizationChange(t, f, admin, csrf, org, &viewer, "viewer", []string{"run.cancel-any"})
	expectControl(t, f.request(t, "POST", "/api/v1/runs/estimate", body, viewerHeaders, viewer.cookie), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "POST", "/api/v1/runs/"+adminRun.ID+"/cancel", `{"version":1}`, viewerHeaders, viewer.cookie), 200, "")
	runAuthorizationChange(t, f, admin, csrf, org, &viewer, "viewer", nil)
	expectControl(t, f.request(t, "POST", "/api/v1/runs/"+viewerRun.ID+"/cancel", `{"version":1}`, viewerHeaders, viewer.cookie), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "GET", "/api/v1/runs/"+viewerRun.ID, "", viewerHeaders, viewer.cookie), 200, "")
	if err := f.cfg.Store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}

func TestRunHTTPAuthorizationRevokedCreatorAndSpecialGrants(t *testing.T) {
	f := newRunHTTPFixture(t, true)
	f.initialize(t)
	admin, csrf, org := f.login(t)
	actor := runAuthorizationMember(t, f, admin, csrf, org, "run-revoked-operator", "operator", []string{"run.custom", "run.high-cost"})
	targetID := runAuthorizationTarget(t, f, admin, csrf, org)
	headers := runAuthorizationHeaders(org, actor.csrf)
	basic := runAuthorizationEstimate(t, f, actor.cookie, actor.csrf, org, runAuthorizationQuick(targetID))
	custom := runAuthorizationEstimate(t, f, actor.cookie, actor.csrf, org, `{"target_id":"`+targetID+`","target_version":1,"package":"custom","options":{"probe_types":["format"],"languages":["en-US"],"repetitions":3,"stream_modes":[false]}}`)
	highCost := runAuthorizationEstimate(t, f, actor.cookie, actor.csrf, org, `{"target_id":"`+targetID+`","target_version":1,"package":"quick","options":{"max_requests":61}}`)
	runAuthorizationChange(t, f, admin, csrf, org, &actor, "operator", nil)
	for _, quote := range []runHTTPQuote{custom, highCost} {
		expectControl(t, f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(quote), headers, actor.cookie), 403, "MI_PERMISSION_DENIED")
	}
	runAuthorizationChange(t, f, admin, csrf, org, &actor, "viewer", nil)
	expectControl(t, f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(basic), headers, actor.cookie), 403, "MI_PERMISSION_DENIED")
	// Restoring just ordinary creation can still confirm the original basic
	// draft; rejected attempts neither consumed it nor started paid work.
	runAuthorizationChange(t, f, admin, csrf, org, &actor, "operator", nil)
	record := runAuthorizationConfirm(t, f, actor.cookie, actor.csrf, org, basic)
	runAuthorizationChange(t, f, admin, csrf, org, &actor, "viewer", nil)
	expectControl(t, f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(basic), headers, actor.cookie), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "GET", "/api/v1/runs/"+record.ID, "", headers, actor.cookie), 200, "")
}

func TestRunHTTPAuthorizationStrictRequestsAndSessionBoundary(t *testing.T) {
	f := newRunHTTPFixture(t, true)
	f.initialize(t)
	admin, csrf, org := f.login(t)
	headers := runAuthorizationHeaders(org, csrf)
	targetID := runAuthorizationTarget(t, f, admin, csrf, org)
	quote := runAuthorizationEstimate(t, f, admin, csrf, org, runAuthorizationQuick(targetID))
	confirm := runHTTPConfirm(quote)
	for name, body := range map[string]string{
		"missing_acknowledgement":   strings.Replace(confirm, `,"confirm_cost":true`, "", 1),
		"null_acknowledgement":      strings.Replace(confirm, `true`, `null`, 1),
		"string_acknowledgement":    strings.Replace(confirm, `true`, `"true"`, 1),
		"unknown_owner":             strings.TrimSuffix(confirm, "}") + `,"created_by":"1"}`,
		"case_alias":                strings.Replace(confirm, `estimate_id`, `Estimate_id`, 1),
		"duplicate_acknowledgement": strings.TrimSuffix(confirm, "}") + `,"confirm_cost":false}`,
		"numeric_id":                strings.Replace(confirm, `"`+quote.ID+`"`, quote.ID, 1),
		"short_hash":                strings.Replace(confirm, quote.Hash, "short", 1),
	} {
		t.Run(name, func(t *testing.T) {
			expectControl(t, f.request(t, "POST", "/api/v1/runs", body, headers, admin), 400, "MI_INVALID_REQUEST")
		})
	}
	wrongHash := quote
	wrongHash.Hash = strings.Repeat("a", 64)
	if wrongHash.Hash == quote.Hash {
		wrongHash.Hash = strings.Repeat("b", 64)
	}
	expectControl(t, f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(wrongHash), headers, admin), 409, "MI_RUN_ESTIMATE_STALE")
	unknown := quote
	unknown.ID = "1"
	expectControl(t, f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(unknown), headers, admin), 404, "MI_NOT_FOUND")
	record := runAuthorizationConfirm(t, f, admin, csrf, org, quote)
	runPath := "/api/v1/runs/" + record.ID
	cancelPath := runPath + "/cancel"
	for index, body := range []string{`{}`, `null`, `{"version":null}`, `{"version":"1"}`, `{"version":1,"version":2}`, `{"Version":1}`, `{"version":1,"force":true}`} {
		t.Run("strict_cancel_"+strconv.Itoa(index), func(t *testing.T) {
			expectControl(t, f.request(t, "POST", cancelPath, body, headers, admin), 400, "MI_INVALID_REQUEST")
		})
	}
	for _, request := range []struct{ method, path, body string }{
		{"POST", "/api/v1/runs/estimate", runAuthorizationQuick(targetID)},
		{"POST", "/api/v1/runs", confirm},
		{"POST", cancelPath, `{"version":1}`},
	} {
		t.Run("csrf_"+request.path, func(t *testing.T) {
			expectControl(t, f.request(t, request.method, request.path, request.body, map[string]string{"X-Organization-ID": org}, admin), 403, "MI_CSRF_INVALID")
			expectControl(t, f.request(t, request.method, request.path, request.body, map[string]string{"X-Organization-ID": org, "X-CSRF-Token": csrf, "Origin": "https://cross-site.invalid"}, admin), 403, "MI_CSRF_INVALID")
			expectControl(t, f.request(t, request.method, request.path, request.body, headers, nil), 401, "MI_SESSION_REQUIRED")
			expectControl(t, f.request(t, request.method, request.path+"?unexpected=1", request.body, headers, admin), 400, "MI_INVALID_REQUEST")
		})
	}
	expectControl(t, f.request(t, "GET", runPath+"?unexpected=1", "", headers, admin), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "GET", runPath, "", nil, admin), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "GET", runPath, "", headers, nil), 401, "MI_SESSION_REQUIRED")
	expectControl(t, f.request(t, "GET", "/api/v1/runs/0"+record.ID, "", headers, admin), 400, "MI_INVALID_REQUEST")
	w := f.request(t, "GET", runPath, "", headers, admin)
	expectControl(t, w, 200, "")
	var unchanged runHTTPView
	managementHTTPData(t, w, &unchanged)
	if unchanged.Status != "QUEUED" || unchanged.Version != 1 || unchanged.RequestCount != 0 {
		t.Fatal("rejected requests mutated or executed the Run")
	}
	expectControl(t, f.request(t, "POST", "/api/v1/auth/logout", `{}`, headers, admin), 200, "")
	expectControl(t, f.request(t, "GET", runPath, "", headers, admin), 401, "MI_SESSION_REQUIRED")
	expectControl(t, f.request(t, "POST", cancelPath, `{"version":1}`, headers, admin), 401, "MI_SESSION_REQUIRED")
}
