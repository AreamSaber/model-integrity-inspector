package app

import (
	"strconv"
	"testing"

	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

// The only upstream calls are the already completed real Quick/Custom runs.
// Overview must aggregate their published rows, never count 27 HTTP attempts as
// 27 runs or include the separate target precheck as a detection.
func exerciseActualOrganizationOverview(t *testing.T, p *pipelineHTTP) {
	t.Helper()
	for _, days := range []int{7, 30} {
		var view runservice.OverviewView
		p.request(t, "GET", "/api/v1/overview?days="+strconv.Itoa(days), nil, 200, &view)
		if view.OrganizationID != p.orgID || view.Scope != "organization_window" || !view.Development || view.Calibrated || view.AnalysisRevision != 1 || view.Window.Days != days || len(view.Daily) != days || !view.Window.AsOf.Equal(view.Window.EndUTC) {
			t.Fatal("actual overview lost its organization/calendar/development scope")
		}
		if view.Targets.Total != 1 || view.Targets.Active != 1 || view.Targets.Disabled != 0 || view.Runs.Total != 2 || view.Runs.PublishedRuns != 2 || view.Runs.UnpublishedRuns != 0 || view.Runs.ScoredRuns != 2 || view.Runs.UnscoredRuns != 0 {
			t.Fatal("actual overview did not count the two independent published detections")
		}
		if view.Runs.ByStatus.Completed+view.Runs.ByStatus.Partial+view.Runs.ByStatus.ReviewRequired != 2 || len(view.RiskCohorts) != 2 || view.RiskCohorts[0].Package != "custom" || view.RiskCohorts[1].Package != "quick" {
			t.Fatal("actual overview merged distinct package cohorts or misclassified terminal states")
		}
		for _, cohort := range view.RiskCohorts {
			d := cohort.Distribution
			if cohort.PublishedRuns != 1 || cohort.ScoredRuns != 1 || cohort.UnscoredRuns != 0 || d.Low+d.Watch+d.Medium+d.High+d.Critical+d.Insufficient != 1 {
				t.Fatal("actual risk cohort denominator lost its one published scored Run")
			}
		}
		if view.Costs.Basis != "persisted_run_estimate" || view.Costs.KnownRuns != 0 || view.Costs.UnknownRuns != 2 || view.Costs.KnownSubtotalMicros != nil || view.Costs.CompleteTotalMicros != nil {
			t.Fatal("unknown model prices became invented zero expenses")
		}
		var count int64
		for i, day := range view.Daily {
			count += day.RunCount
			if day.Partial != (i == days-1) || day.EndUTC.Before(day.StartUTC) || i > 0 && !day.StartUTC.Equal(view.Daily[i-1].EndUTC) {
				t.Fatal("actual daily timeline lost continuity or partial-day scope")
			}
		}
		if count != 2 || !view.Daily[days-1].EndUTC.Equal(view.Window.AsOf) {
			t.Fatal("daily counts do not cover the exact overview window")
		}
	}
}
