package api

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"

	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

func reviewHTTPBody(previous, conclusion, note string) string {
	input := map[string]any{"analysis_revision": 1, "conclusion": conclusion, "explanation": note}
	if previous != "" {
		input["previous_review_id"] = previous
	}
	raw, _ := json.Marshal(input)
	return string(raw)
}
func TestReviewHTTPAppendHistoryCASAndAuthorization(t *testing.T) {
	f := newResultHTTPFixture(t)
	path := "/api/v1/runs/" + strconv.FormatInt(f.runID, 10)
	headers := map[string]string{}
	for k, v := range f.headers {
		headers[k] = v
	}
	headers["Idempotency-Key"] = "http-review-request-0001"
	firstBody := reviewHTTPBody("", "watch", "Synthetic human observation. This is not release approval.")
	expectControl(t, f.request(t, "POST", path+"/reviews", firstBody, headers, f.cookie), 404, "MI_NOT_FOUND")
	f.publish(t)
	w := f.request(t, "GET", path+"/result", "", f.headers, f.cookie)
	var original runservice.ResultView
	managementHTTPData(t, w, &original)
	w = f.request(t, "GET", path+"/reviews", "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	var page struct {
		Items []runservice.ReviewView `json:"items"`
		Next  *string                 `json:"next_cursor"`
	}
	managementHTTPData(t, w, &page)
	if len(page.Items) != 0 || page.Next != nil {
		t.Fatal("unreviewed result fabricated human history")
	}
	w = f.request(t, "POST", path+"/reviews", firstBody, headers, f.cookie)
	expectControl(t, w, 201, "")
	var first runservice.ReviewView
	managementHTTPData(t, w, &first)
	if first.ID == "" || first.Conclusion != "watch" || first.RunID != original.RunID || first.AnalysisRevision != 1 {
		t.Fatal("review scope/identity")
	}
	w = f.request(t, "POST", path+"/reviews", firstBody, headers, f.cookie)
	expectControl(t, w, 201, "")
	var retry runservice.ReviewView
	managementHTTPData(t, w, &retry)
	if retry.ID != first.ID {
		t.Fatal("HTTP retry duplicated review")
	}
	expectControl(t, f.request(t, "POST", path+"/reviews", reviewHTTPBody("", "confirmed", "Changed content"), headers, f.cookie), 409, "MI_REVIEW_CONFLICT")
	headers["Idempotency-Key"] = "http-review-request-0002"
	expectControl(t, f.request(t, "POST", path+"/reviews", firstBody, headers, f.cookie), 409, "MI_REVIEW_CONFLICT")
	w = f.request(t, "POST", path+"/reviews", reviewHTTPBody(first.ID, "false_positive", "<script>inert human note</script>"), headers, f.cookie)
	expectControl(t, w, 201, "")
	var second runservice.ReviewView
	managementHTTPData(t, w, &second)
	if second.ID == first.ID || second.Explanation != "<script>inert human note</script>" || strings.Contains(w.Body.String(), "<script>") {
		t.Fatal("history identity or JSON HTML escaping")
	}
	w = f.request(t, "GET", path+"/reviews?limit=1", "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	managementHTTPData(t, w, &page)
	if len(page.Items) != 1 || page.Items[0].ID != second.ID || page.Next == nil {
		t.Fatal("latest page not stable")
	}
	cursor := *page.Next
	w = f.request(t, "GET", path+"/reviews?limit=1&cursor="+url.QueryEscape(cursor), "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	managementHTTPData(t, w, &page)
	if len(page.Items) != 1 || page.Items[0].ID != first.ID || page.Next != nil {
		t.Fatal("old review was overwritten")
	}
	for _, suffix := range []string{"/reviews?q=x", "/reviews?unknown=1", "/reviews?analysis_revision=01", "/reviews?analysis_revision=1&analysis_revision=1", "/reviews?limit=101", "/findings?cursor=" + url.QueryEscape(cursor)} {
		expectControl(t, f.request(t, "GET", path+suffix, "", f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
	}
	expectControl(t, f.request(t, "GET", path+"/reviews?analysis_revision=2", "", f.headers, f.cookie), 404, "MI_NOT_FOUND")
	viewer := runAuthorizationMember(t, f.controlFixture, f.cookie, f.headers["X-CSRF-Token"], f.headers["X-Organization-ID"], "review-viewer", "viewer", nil)
	viewerHeaders := runAuthorizationHeaders(f.headers["X-Organization-ID"], viewer.csrf)
	viewerHeaders["Idempotency-Key"] = "viewer-review-request"
	expectControl(t, f.request(t, "GET", path+"/reviews", "", viewerHeaders, viewer.cookie), 200, "")
	expectControl(t, f.request(t, "POST", path+"/reviews", reviewHTTPBody(second.ID, "confirmed", "Unprivileged reviewer"), viewerHeaders, viewer.cookie), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "GET", path+"/reviews?cursor="+url.QueryEscape(cursor), "", viewerHeaders, viewer.cookie), 400, "MI_INVALID_REQUEST")
	missingCSRF := map[string]string{"X-Organization-ID": f.headers["X-Organization-ID"], "Idempotency-Key": "missing-csrf-request"}
	expectControl(t, f.request(t, "POST", path+"/reviews", firstBody, missingCSRF, f.cookie), 403, "MI_CSRF_INVALID")
	wrongOrg := map[string]string{"X-Organization-ID": "9223372036854775807"}
	expectControl(t, f.request(t, "GET", path+"/reviews", "", wrongOrg, f.cookie), 403, "MI_PERMISSION_DENIED")
	w = f.request(t, "GET", path+"/result", "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	var after runservice.ResultView
	managementHTTPData(t, w, &after)
	beforeJSON, _ := json.Marshal(original)
	afterJSON, _ := json.Marshal(after)
	if string(beforeJSON) != string(afterJSON) {
		t.Fatal("human review rewrote machine analysis")
	}
	if err := f.cfg.Store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}

func TestReviewHTTPStrictInputDoesNotMutate(t *testing.T) {
	f := newResultHTTPFixture(t)
	f.publish(t)
	path := "/api/v1/runs/" + strconv.FormatInt(f.runID, 10) + "/reviews"
	f.headers["Idempotency-Key"] = "strict-review-request-0001"
	for _, body := range []string{
		`{}`, `{"analysis_revision":1,"conclusion":"approved","explanation":"wrong enum"}`,
		`{"analysis_revision":1,"conclusion":"watch","explanation":"note","previous_review_id":null}`,
		`{"analysis_revision":1,"conclusion":"watch","explanation":"note","previous_review_id":"0"}`,
		`{"analysis_revision":1,"conclusion":"watch","explanation":"note","created_by":"1"}`,
		`{"analysis_revision":1,"conclusion":"watch","explanation":"note","overall_risk":0}`,
		`{"analysis_revision":1,"conclusion":"watch","explanation":"a","explanation":"b"}`,
		`{"analysis_revision":1,"conclusion":"watch","explanation":"note","Conclusion":"confirmed"}`,
		reviewHTTPBody("", "watch", strings.Repeat("x", 4097)), reviewHTTPBody("", "watch", "\u202eunsafe"),
	} {
		expectControl(t, f.request(t, "POST", path, body, f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
	}
	delete(f.headers, "Idempotency-Key")
	expectControl(t, f.request(t, "POST", path, reviewHTTPBody("", "watch", "No retry key"), f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
}
