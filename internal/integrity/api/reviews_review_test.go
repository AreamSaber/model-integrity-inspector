package api

import (
	"net/url"
	"strconv"
	"strings"
	"testing"

	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

// The UI rejects unpaired UTF-16 code units. The HTTP boundary must not silently
// turn the same invalid human explanation into a different persisted statement.
func TestReviewHTTPRejectsUnpairedSurrogateExplanation(t *testing.T) {
	f := newResultHTTPFixture(t)
	f.publish(t)
	path := "/api/v1/runs/" + strconv.FormatInt(f.runID, 10) + "/reviews"
	f.headers["Idempotency-Key"] = "surrogate-review-request-001"
	w := f.request(t, "POST", path, `{"analysis_revision":1,"conclusion":"watch","explanation":"observation \ud800"}`, f.headers, f.cookie)
	if w.Code != 400 {
		t.Errorf("invalid Unicode explanation should fail closed before append: got status %d", w.Code)
	}
	w = f.request(t, "GET", path, "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	var page struct {
		Items []runservice.ReviewView `json:"items"`
	}
	managementHTTPData(t, w, &page)
	if len(page.Items) != 0 {
		t.Error("invalid Unicode explanation produced persisted human history")
	}
}

func TestReviewHTTPMultibyteBoundariesAndCursorSurviveNewAppend(t *testing.T) {
	f := newResultHTTPFixture(t)
	f.publish(t)
	path := "/api/v1/runs/" + strconv.FormatInt(f.runID, 10) + "/reviews"
	f.headers["Idempotency-Key"] = "review-byte-limit-0001"
	w := f.request(t, "POST", path, reviewHTTPBody("", "watch", strings.Repeat("界", 1366)), f.headers, f.cookie)
	expectControl(t, w, 400, "MI_INVALID_REQUEST")
	maximum := strings.Repeat("界", 1365) + "a"
	f.headers["Idempotency-Key"] = "review-byte-limit-0002"
	w = f.request(t, "POST", path, reviewHTTPBody("", "watch", maximum), f.headers, f.cookie)
	expectControl(t, w, 201, "")
	var first runservice.ReviewView
	managementHTTPData(t, w, &first)
	if first.Explanation != maximum || len(first.Explanation) != 4096 {
		t.Fatal("accepted maximum-byte note was modified")
	}
	f.headers["Idempotency-Key"] = "review-byte-limit-0003"
	validEscaped := `{"analysis_revision":1,"previous_review_id":"` + first.ID + `","conclusion":"confirmed","explanation":"paired \ud83d\ude00\n<script>text only</script>"}`
	w = f.request(t, "POST", path, validEscaped, f.headers, f.cookie)
	expectControl(t, w, 201, "")
	var second runservice.ReviewView
	managementHTTPData(t, w, &second)
	if second.Explanation != "paired 😀\n<script>text only</script>" || strings.Contains(w.Body.String(), "<script>") {
		t.Fatal("valid paired Unicode or safe JSON escaping changed")
	}
	w = f.request(t, "GET", path+"?limit=1&analysis_revision=1", "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	var page struct {
		Items []runservice.ReviewView `json:"items"`
		Next  *string                 `json:"next_cursor"`
	}
	managementHTTPData(t, w, &page)
	if page.Next == nil || len(page.Items) != 1 || page.Items[0].ID != second.ID {
		t.Fatal("initial cursor page was not newest-first")
	}
	cursor := *page.Next
	f.headers["Idempotency-Key"] = "review-byte-limit-0004"
	w = f.request(t, "POST", path, reviewHTTPBody(second.ID, "watch", "Later review must not disturb old page anchor"), f.headers, f.cookie)
	expectControl(t, w, 201, "")
	w = f.request(t, "GET", path+"?limit=1&analysis_revision=1&cursor="+url.QueryEscape(cursor), "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	managementHTTPData(t, w, &page)
	if len(page.Items) != 1 || page.Items[0].ID != first.ID || page.Next != nil {
		t.Fatal("new append changed existing descending page anchor")
	}
}
