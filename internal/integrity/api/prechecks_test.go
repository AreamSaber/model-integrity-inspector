package api

import (
	"testing"
)

func TestPrecheckHTTPAsyncIdempotencyScopeAndWritePermission(t *testing.T) {
	f := newControlFixture(t, nil)
	f.initialize(t)
	cookie, csrf, org := f.login(t)
	headers := map[string]string{"X-CSRF-Token": csrf, "X-Organization-ID": org}
	w := f.request(t, "POST", "/api/v1/targets", targetHTTPBody, headers, cookie)
	expectControl(t, w, 201, "")
	var value targetHTTPView
	targetHTTPData(t, w, &value)
	path := "/api/v1/targets/" + value.ID
	expectControl(t, f.request(t, "GET", path+"/precheck", "", headers, cookie), 404, "MI_NOT_FOUND")
	for _, body := range []string{`{}`, `{"version":0}`, `{"version":1,"cost":0}`, `{"version":null}`} {
		expectControl(t, f.request(t, "POST", path+"/precheck", body, headers, cookie), 400, "MI_INVALID_REQUEST")
	}
	expectControl(t, f.request(t, "POST", path+"/precheck", `{"version":2}`, headers, cookie), 409, "MI_VERSION_CONFLICT")
	headers["Idempotency-Key"] = "synthetic-precheck-http-1"
	w = f.request(t, "POST", path+"/precheck", `{"version":1}`, headers, cookie)
	expectControl(t, w, 202, "")
	var result struct {
		ID           string `json:"id"`
		JobID        string `json:"job_id"`
		TargetID     string `json:"target_id"`
		Status       string `json:"status"`
		RequestCount int    `json:"request_count"`
	}
	targetHTTPData(t, w, &result)
	if result.Status != "queued" || result.RequestCount != 0 || result.TargetID != value.ID {
		t.Fatal("HTTP performed an upstream call or did not queue")
	}
	if _, ok := managementID(result.JobID); !ok {
		t.Fatal("job ID not canonical string")
	}
	id := result.ID
	w = f.request(t, "POST", path+"/precheck", `{"version":1}`, headers, cookie)
	expectControl(t, w, 202, "")
	targetHTTPData(t, w, &result)
	if result.ID != id {
		t.Fatal("idempotent request enqueued another precheck")
	}
	for _, route := range []string{path + "/precheck", path + "/prechecks/" + id} {
		w = f.request(t, "GET", route, "", headers, cookie)
		expectControl(t, w, 200, "")
		targetHTTPData(t, w, &result)
		if result.ID != id || result.Status != "queued" {
			t.Fatal("read did not report authoritative queued state")
		}
	}
	expectControl(t, f.request(t, "DELETE", path, `{"version":1}`, headers, cookie), 409, "MI_VERSION_CONFLICT")
	w = f.request(t, "POST", "/api/v1/targets", targetHTTPBody, headers, cookie)
	expectControl(t, w, 201, "")
	targetHTTPData(t, w, &value)
	otherPath := "/api/v1/targets/" + value.ID
	expectControl(t, f.request(t, "GET", otherPath+"/prechecks/"+id, "", headers, cookie), 404, "MI_NOT_FOUND")
	expectControl(t, f.request(t, "POST", otherPath+"/precheck", `{"version":1}`, headers, cookie), 409, "MI_VERSION_CONFLICT")
	user, viewer, viewerCSRF := managementHTTPUser(t, f, cookie, csrf, "precheck-viewer")
	w = f.request(t, "POST", "/api/v1/organizations/"+org+"/members", `{"user_id":"`+user.ID+`","roles":["viewer"]}`, headers, cookie)
	expectControl(t, w, 201, "")
	viewerHeaders := map[string]string{"X-CSRF-Token": viewerCSRF, "X-Organization-ID": org}
	expectControl(t, f.request(t, "POST", path+"/precheck", `{"version":1}`, viewerHeaders, viewer), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "GET", path+"/precheck", "", viewerHeaders, viewer), 200, "")
	if err := f.cfg.Store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}
