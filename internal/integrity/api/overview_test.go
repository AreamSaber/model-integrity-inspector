package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

func TestOverviewHTTPRealPublicationClosedDTOAndEmptyOrganization(t *testing.T) {
	f := newResultHTTPFixture(t)
	w := f.request(t, "GET", "/api/v1/overview", "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	var view runservice.OverviewView
	managementHTTPData(t, w, &view)
	if view.SchemaVersion != "overview-v1" || view.Scope != "organization_window" || view.OrganizationID != f.headers["X-Organization-ID"] || !view.Development || view.Calibrated || view.AnalysisRevision != 1 || view.Window.Days != 7 || len(view.Daily) != 7 || view.Runs.Total != 1 || view.Runs.ByStatus.Queued != 1 || view.Runs.PublishedRuns != 0 || view.Runs.UnpublishedRuns != 1 || view.Targets.Total != 1 {
		t.Fatal("queued aggregate fabricated results")
	}
	f.publish(t)
	w = f.request(t, "GET", "/api/v1/overview?days=30", "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	resultNoS2(t, w.Body.String())
	managementHTTPData(t, w, &view)
	if view.Window.Days != 30 || len(view.Daily) != 30 || view.Runs.Total != 1 || view.Runs.PublishedRuns != 1 || len(view.RiskCohorts) != 1 || view.Runs.ByStatus.Completed+view.Runs.ByStatus.Partial+view.Runs.ByStatus.ReviewRequired != 1 || !view.Daily[29].Partial || !view.Daily[29].EndUTC.Equal(view.Window.AsOf) {
		t.Fatalf("real publication not aggregated: %+v", view)
	}
	for _, canary := range []string{"manifest_hash", "config_snapshot", "conclusion_json", "endpoint", "current_target_name", "success_rate"} {
		if strings.Contains(w.Body.String(), `"`+canary+`"`) {
			t.Fatal("unexpected data in S1 aggregate", canary)
		}
	}
	for _, query := range []string{"days=", "days=07", "days=6", "days=31", "days=7&days=30", "days=7&target_id=1", "timezone=UTC", "days=7;days=30", "days=%zz", "cursor=x", "days=%207"} {
		expectControl(t, f.request(t, "GET", "/api/v1/overview?"+query, "", f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
	}
	w = f.request(t, "POST", "/api/v1/organizations", `{"name":"Empty overview organization","timezone":"UTC"}`, f.headers, f.cookie)
	expectControl(t, w, 201, "")
	var org managementHTTPObject
	managementHTTPData(t, w, &org)
	w = f.request(t, "GET", "/api/v1/overview", "", runAuthorizationHeaders(org.ID, ""), f.cookie)
	expectControl(t, w, 200, "")
	managementHTTPData(t, w, &view)
	if view.Runs.Total != 0 || view.Targets.Total != 0 || view.Costs.KnownSubtotalMicros != nil || view.Costs.CompleteTotalMicros != nil || len(view.RiskCohorts) != 0 || len(view.Daily) != 7 {
		t.Fatal("empty org invented observed data")
	}
}

func TestOverviewHTTPPermissionsRevocationAndTimezoneFailure(t *testing.T) {
	f := newRunHTTPFixture(t, true)
	f.initialize(t)
	admin, csrf, org := f.login(t)
	headers := runAuthorizationHeaders(org, csrf)
	reader := runAuthorizationMember(t, f, admin, csrf, org, "overview-reader", "viewer", nil)
	readerHeaders := runAuthorizationHeaders(org, reader.csrf)
	expectControl(t, f.request(t, "GET", "/api/v1/overview", "", readerHeaders, reader.cookie), 200, "")
	expectControl(t, f.request(t, "GET", "/api/v1/overview", "", headers, nil), 401, "MI_SESSION_REQUIRED")
	expectControl(t, f.request(t, "GET", "/api/v1/overview", "", nil, admin), 400, "MI_INVALID_REQUEST")
	w := f.request(t, "PATCH", "/api/v1/organizations/"+org, `{"version":1,"timezone":"Local"}`, headers, admin)
	expectControl(t, w, 200, "")
	expectControl(t, f.request(t, "GET", "/api/v1/overview", "", headers, admin), 503, "MI_OVERVIEW_TIMEZONE_INVALID")
	expectControl(t, f.request(t, "PATCH", "/api/v1/organizations/"+org, `{"version":2,"timezone":"UTC"}`, headers, admin), 200, "")
	expectControl(t, f.request(t, "PATCH", "/api/v1/organizations/"+org+"/members/"+reader.member.ID, `{"version":1,"status":"disabled"}`, headers, admin), 200, "")
	expectControl(t, f.request(t, "GET", "/api/v1/overview", "", readerHeaders, reader.cookie), 403, "MI_PERMISSION_DENIED")
	expectControl(t, f.request(t, "POST", "/api/v1/auth/logout", `{}`, headers, admin), 200, "")
	expectControl(t, f.request(t, "GET", "/api/v1/overview", "", headers, admin), 401, "MI_SESSION_REQUIRED")
}

func TestOverviewHTTPMiddlewareDeadlineCancellationAndNoFalseEmpty(t *testing.T) {
	f := newRunHTTPFixture(t, true)
	f.initialize(t)
	cookie, _, org := f.login(t)
	for _, deadline := range []bool{true, false} {
		ctx, cancel := context.WithCancel(t.Context())
		if deadline {
			cancel()
			ctx, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		} else {
			cancel()
		}
		r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/overview", nil)
		r.AddCookie(cookie)
		r.Header.Set("X-Organization-ID", org)
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		cancel()
		code := "MI_SERVICE_UNAVAILABLE"
		if deadline {
			code = "MI_OVERVIEW_TIMEOUT"
		}
		expectControl(t, w, 503, code)
		if strings.Contains(w.Body.String(), `"data"`) {
			t.Fatal("deadline returned fake empty success")
		}
	}
	expectControl(t, f.request(t, "GET", "/api/v1/overview", "", runAuthorizationHeaders(org, ""), cookie), 200, "")
	if err := f.cfg.Store.Close(); err != nil {
		t.Fatal(err)
	}
	expectControl(t, f.request(t, "GET", "/api/v1/overview", "", runAuthorizationHeaders(org, ""), cookie), 503, "MI_SERVICE_UNAVAILABLE")
}

func TestOverviewAdmissionBoundsAndHTTPBusy(t *testing.T) {
	l := overviewLimiter{active: map[int64]bool{}}
	if !l.acquire(1) || l.acquire(1) || !l.acquire(2) || l.acquire(3) {
		t.Fatal("not two global/one per organization")
	}
	l.release(1)
	if !l.acquire(3) {
		t.Fatal("slot leaked")
	}
	l.release(2)
	l.release(3)
	if len(l.active) != 0 {
		t.Fatal("retained organization IDs")
	}
	f := newResultHTTPFixture(t)
	if !overviewAdmission.acquire(f.org) {
		t.Fatal("fixture slot unavailable")
	}
	defer overviewAdmission.release(f.org)
	w := f.request(t, "GET", "/api/v1/overview", "", f.headers, f.cookie)
	expectControl(t, w, 429, "MI_OVERVIEW_BUSY")
	if w.Header().Get("Retry-After") != "2" {
		t.Fatal("missing bounded retry hint")
	}
}
