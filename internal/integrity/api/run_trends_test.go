package api

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

type trendHTTPPage struct {
	Items            []runservice.TrendItem `json:"items"`
	Next             *string                `json:"next_cursor"`
	Scope            string                 `json:"scope"`
	AnalysisRevision int                    `json:"analysis_revision"`
	SuccessRateBasis string                 `json:"success_rate_basis"`
	LatencyBasis     string                 `json:"latency_basis"`
	Development      bool                   `json:"development"`
	Calibrated       bool                   `json:"calibrated"`
}

func trendHTTPPath(t *testing.T, f resultHTTPFixture) (string, string) {
	t.Helper()
	rows, err := f.cfg.Runs.History(f.ctx, f.org, repository.ListOptions{Limit: 1}, repository.RunFilters{})
	if err != nil || len(rows) != 1 {
		t.Fatal("history fixture unavailable", err)
	}
	return "/api/v1/runs/trends?target_id=" + rows[0].TargetID, rows[0].TargetID
}

func TestRunTrendsHTTPRealPublicationMissingValuesAndNoS2(t *testing.T) {
	f := newResultHTTPFixture(t)
	path, _ := trendHTTPPath(t, f)
	w := f.request(t, "GET", path, "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	var page trendHTTPPage
	managementHTTPData(t, w, &page)
	if len(page.Items) != 1 || page.Next != nil || page.Items[0].Run.Result != nil || page.Items[0].Attempts.Dispatched != 0 || page.Items[0].Attempts.SuccessRatePercent != nil || page.Items[0].Attempts.LatencyMeanMS != nil {
		t.Fatal("queued run fabricated outcome or zero latency")
	}
	if page.Scope != "run_page" || page.AnalysisRevision != 1 || page.SuccessRateBasis != "confirmed_successes_over_all_dispatches_percent" || page.LatencyBasis != "completed_attempts_with_observed_duration" || !page.Development || page.Calibrated {
		t.Fatal("scope/basis disclaimer absent")
	}
	f.publish(t)
	w = f.request(t, "GET", path, "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	resultNoS2(t, w.Body.String())
	managementHTTPData(t, w, &page)
	if len(page.Items) != 1 || page.Items[0].Run.Result == nil || page.Items[0].Run.Result.AnalysisRevision != 1 {
		t.Fatal("frozen revision absent")
	}
	a := page.Items[0].Attempts
	if a.Dispatched != 18 || a.Succeeded != 18 || a.SuccessRateDenominator != 18 || a.SuccessRatePercent == nil || *a.SuccessRatePercent != 100 || a.Failed != 0 || a.InFlight != 0 || a.Uncertain != 0 || a.LogicalSamples != 18 || a.RetryAttempts != 0 || a.LatencySamples != 18 || a.LatencyMeanMS == nil || *a.LatencyMeanMS != 1 {
		t.Fatal("actual persisted attempt statistics mismatch")
	}
	for _, suffix := range []string{"&status=COMPLETED", "&package=quick", "&q=model", "&limit=100", "&date_from=" + time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), "&date_to=" + time.Now().UTC().Add(time.Hour).Format(time.RFC3339)} {
		w := f.request(t, "GET", path+suffix, "", f.headers, f.cookie)
		expectControl(t, w, 200, "")
		resultNoS2(t, w.Body.String())
	}
	w = f.request(t, "GET", path+"&status=QUEUED", "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	managementHTTPData(t, w, &page)
	if len(page.Items) != 0 || page.Next != nil {
		t.Fatal("empty filter became aggregate")
	}
	for _, endpoint := range []string{"/api/v1/runs/trends", "/api/v1/runs/trends?target_id=0", "/api/v1/runs/trends?target_id=01", path + "&target_id=2", path + "&analysis_revision=1", path + "&limit=101", path + "&q=x&q=y", path + "&cursor=invalid", path + "&risk_level=attention", path + "&date_from=2026-09-08T00:00:00Z&date_to=2026-09-07T00:00:00Z"} {
		expectControl(t, f.request(t, "GET", endpoint, "", f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
	}
	if err := f.cfg.Store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}

func TestRunTrendsHTTPSignedCursorFiltersReaderAndRevocation(t *testing.T) {
	f := newResultHTTPFixture(t)
	path, targetID := trendHTTPPath(t, f)
	org, csrf := f.headers["X-Organization-ID"], f.headers["X-CSRF-Token"]
	for range 2 {
		quote := runAuthorizationEstimate(t, f.controlFixture, f.cookie, csrf, org, runAuthorizationQuick(targetID))
		runAuthorizationConfirm(t, f.controlFixture, f.cookie, csrf, org, quote)
	}
	reader := runAuthorizationMember(t, f.controlFixture, f.cookie, csrf, org, "trend-reader", "viewer", nil)
	readerHeaders := runAuthorizationHeaders(org, reader.csrf)
	w := f.request(t, "GET", path+"&limit=1&status=QUEUED", "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	var first trendHTTPPage
	managementHTTPData(t, w, &first)
	if len(first.Items) != 1 || first.Next == nil {
		t.Fatal("cursor missing")
	}
	anchor, cursor := first.Items[0].Run, *first.Next
	// A normal state transition must not destroy the signed immutable anchor.
	expectControl(t, f.request(t, "POST", "/api/v1/runs/"+anchor.ID+"/cancel", `{"version":`+strconv.FormatInt(anchor.Version, 10)+`}`, f.headers, f.cookie), 200, "")
	w = f.request(t, "GET", path+"&status=QUEUED&cursor="+cursor, "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	var next trendHTTPPage
	managementHTTPData(t, w, &next)
	if len(next.Items) != 2 || next.Items[0].Run.ID == anchor.ID || next.Items[1].Run.ID == anchor.ID || next.Next != nil {
		t.Fatal("pagination repeated/omitted filtered run")
	}
	for _, endpoint := range []string{path + "&status=RUNNING&cursor=" + cursor, path + "&status=QUEUED&q=x&cursor=" + cursor, path + "&status=QUEUED&package=quick&cursor=" + cursor, "/api/v1/runs/trends?target_id=1&status=QUEUED&cursor=" + cursor, "/api/v1/runs?target_id=" + targetID + "&status=QUEUED&cursor=" + cursor} {
		expectControl(t, f.request(t, "GET", endpoint, "", f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
	}
	expectControl(t, f.request(t, "GET", path+"&status=QUEUED&cursor="+cursor, "", readerHeaders, reader.cookie), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "GET", path, "", readerHeaders, reader.cookie), 200, "")
	expectControl(t, f.request(t, "GET", path, "", f.headers, nil), 401, "MI_SESSION_REQUIRED")
	expectControl(t, f.request(t, "GET", path, "", nil, f.cookie), 400, "MI_INVALID_REQUEST")
	w = f.request(t, "POST", "/api/v1/organizations", `{"name":"Trend isolation","timezone":"UTC"}`, f.headers, f.cookie)
	expectControl(t, w, 201, "")
	var other managementHTTPObject
	managementHTTPData(t, w, &other)
	otherHeaders := runAuthorizationHeaders(other.ID, csrf)
	w = f.request(t, "GET", path, "", otherHeaders, f.cookie)
	expectControl(t, w, 200, "")
	managementHTTPData(t, w, &next)
	if len(next.Items) != 0 {
		t.Fatal("foreign target statistics disclosed")
	}
	expectControl(t, f.request(t, "GET", path+"&status=QUEUED&cursor="+cursor, "", otherHeaders, f.cookie), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "GET", path, "", runAuthorizationHeaders(other.ID, reader.csrf), reader.cookie), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "PATCH", "/api/v1/organizations/"+org+"/members/"+reader.member.ID, `{"version":1,"status":"disabled"}`, f.headers, f.cookie), 200, "")
	expectControl(t, f.request(t, "GET", path, "", readerHeaders, reader.cookie), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "POST", "/api/v1/auth/logout", `{}`, f.headers, f.cookie), 200, "")
	expectControl(t, f.request(t, "GET", path, "", f.headers, f.cookie), 401, "MI_SESSION_REQUIRED")
}

func TestRunTrendsHTTPDatabaseFailureDoesNotReturnEmptySuccess(t *testing.T) {
	f := newResultHTTPFixture(t)
	path, _ := trendHTTPPath(t, f)
	if err := f.cfg.Store.Close(); err != nil {
		t.Fatal(err)
	}
	w := f.request(t, http.MethodGet, path, "", f.headers, f.cookie)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal("database fault looked like empty history", w.Code)
	}
	resultNoS2(t, w.Body.String())
}
