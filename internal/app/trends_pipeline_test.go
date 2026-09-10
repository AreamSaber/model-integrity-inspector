package app

import (
	"net/url"
	"testing"

	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

type pipelineTrendPage struct {
	Items            []runservice.TrendItem `json:"items"`
	Next             *string                `json:"next_cursor"`
	Scope            string                 `json:"scope"`
	AnalysisRevision int                    `json:"analysis_revision"`
	SuccessRateBasis string                 `json:"success_rate_basis"`
	LatencyBasis     string                 `json:"latency_basis"`
	Development      bool                   `json:"development"`
	Calibrated       bool                   `json:"calibrated"`
}

// These counts come from the preceding real TLS/Worker runs, including real
// observed durations. The separate precheck is not an integrity Run attempt.
func exerciseActualRunTrends(t *testing.T, p *pipelineHTTP, targetID, originalID, repeatedID string) {
	t.Helper()
	path := "/api/v1/runs/trends?target_id=" + targetID
	read := func(suffix string) pipelineTrendPage {
		t.Helper()
		var page pipelineTrendPage
		p.request(t, "GET", path+suffix, nil, 200, &page)
		if page.Scope != "run_page" || page.AnalysisRevision != 1 || page.SuccessRateBasis != "confirmed_successes_over_all_dispatches_percent" || page.LatencyBasis != "completed_attempts_with_observed_duration" || !page.Development || page.Calibrated {
			t.Fatal("actual trend lost its bounded development/statistical scope")
		}
		return page
	}
	page := read("")
	if len(page.Items) != 2 || page.Next != nil || page.Items[0].Run.ID != repeatedID || page.Items[1].Run.ID != originalID {
		t.Fatal("actual target trend did not retain both independent published runs")
	}
	for i, item := range page.Items {
		want := []int64{9, 18}[i]
		a := item.Attempts
		if item.Run.TargetID != targetID || item.Run.Result == nil || item.Run.Result.AnalysisRevision != 1 || a.Dispatched != want || a.LogicalSamples != want || a.RetryAttempts != 0 || a.Succeeded != want || a.Failed != 0 || a.Uncertain != 0 || a.InFlight != 0 || a.SuccessRateDenominator != want || a.SuccessRatePercent == nil || *a.SuccessRatePercent != 100 {
			t.Fatal("trend invented outcomes, included precheck calls, or lost real dispatches")
		}
		if a.LatencySamples != want || a.LatencyMeanMS == nil || a.LatencyMinMS == nil || a.LatencyMaxMS == nil || *a.LatencyMinMS < 0 || *a.LatencyMeanMS < float64(*a.LatencyMinMS) || *a.LatencyMeanMS > float64(*a.LatencyMaxMS) {
			t.Fatal("trend lost the actual completed-attempt latency denominator")
		}
	}
	first := read("&limit=1")
	if len(first.Items) != 1 || first.Items[0].Run.ID != repeatedID || first.Next == nil {
		t.Fatal("actual trend first page or signed continuation missing")
	}
	next := read("&limit=1&cursor=" + url.QueryEscape(*first.Next))
	if len(next.Items) != 1 || next.Items[0].Run.ID != originalID || next.Next != nil {
		t.Fatal("actual trend continuation duplicated or lost a run")
	}
	filtered := read("&package=custom")
	if len(filtered.Items) != 1 || filtered.Items[0].Run.ID != repeatedID || filtered.Next != nil {
		t.Fatal("actual frozen package filter changed")
	}
	empty := read("&status=QUEUED")
	if len(empty.Items) != 0 || empty.Next != nil {
		t.Fatal("actual terminal runs leaked into a queued-only trend")
	}
	p.request(t, "GET", path+"&package=custom&cursor="+url.QueryEscape(*first.Next), nil, 400, nil)
}
