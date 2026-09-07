package run

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

type OverviewWindow struct {
	Days     int       `json:"days"`
	Timezone string    `json:"timezone"`
	AsOf     time.Time `json:"as_of"`
	StartUTC time.Time `json:"start_utc"`
	EndUTC   time.Time `json:"end_utc"`
}
type OverviewTargets struct {
	Total    int64 `json:"total"`
	Active   int64 `json:"active"`
	Disabled int64 `json:"disabled"`
}
type OverviewStatuses struct {
	Draft          int64 `json:"DRAFT"`
	Prechecking    int64 `json:"PRECHECKING"`
	Queued         int64 `json:"QUEUED"`
	Running        int64 `json:"RUNNING"`
	Analyzing      int64 `json:"ANALYZING"`
	Completed      int64 `json:"COMPLETED"`
	Partial        int64 `json:"PARTIAL"`
	Failed         int64 `json:"FAILED"`
	ReviewRequired int64 `json:"REVIEW_REQUIRED"`
	Cancelling     int64 `json:"CANCELLING"`
	Cancelled      int64 `json:"CANCELLED"`
}
type OverviewRuns struct {
	Total           int64            `json:"total"`
	ByStatus        OverviewStatuses `json:"by_status"`
	UnpublishedRuns int64            `json:"unpublished_runs"`
	PublishedRuns   int64            `json:"published_runs"`
	ScoredRuns      int64            `json:"scored_runs"`
	UnscoredRuns    int64            `json:"unscored_runs"`
}
type OverviewCosts struct {
	Currency            string `json:"currency"`
	Basis               string `json:"basis"`
	KnownRuns           int64  `json:"known_runs"`
	UnknownRuns         int64  `json:"unknown_runs"`
	KnownSubtotalMicros *int64 `json:"known_subtotal_micros"`
	CompleteTotalMicros *int64 `json:"complete_total_micros"`
}
type OverviewDistribution struct {
	Low          int64 `json:"low"`
	Watch        int64 `json:"watch"`
	Medium       int64 `json:"medium"`
	High         int64 `json:"high"`
	Critical     int64 `json:"critical"`
	Insufficient int64 `json:"insufficient"`
}
type OverviewRiskCounts struct {
	PublishedRuns int64                `json:"published_runs"`
	ScoredRuns    int64                `json:"scored_runs"`
	UnscoredRuns  int64                `json:"unscored_runs"`
	Distribution  OverviewDistribution `json:"distribution"`
}
type OverviewCohort struct {
	ID       string       `json:"id"`
	Package  string       `json:"package"`
	Versions VersionsView `json:"versions"`
	OverviewRiskCounts
}
type OverviewDailyCohort struct {
	CohortID string `json:"cohort_id"`
	OverviewRiskCounts
}
type OverviewDay struct {
	LocalDate   string                `json:"local_date"`
	StartUTC    time.Time             `json:"start_utc"`
	EndUTC      time.Time             `json:"end_utc"`
	Partial     bool                  `json:"partial"`
	RunCount    int64                 `json:"run_count"`
	RiskCohorts []OverviewDailyCohort `json:"risk_cohorts"`
}
type OverviewView struct {
	SchemaVersion    string           `json:"schema_version"`
	Scope            string           `json:"scope"`
	OrganizationID   string           `json:"organization_id"`
	AnalysisRevision int              `json:"analysis_revision"`
	Development      bool             `json:"development"`
	Calibrated       bool             `json:"calibrated"`
	Window           OverviewWindow   `json:"window"`
	Targets          OverviewTargets  `json:"targets"`
	Runs             OverviewRuns     `json:"runs"`
	Costs            OverviewCosts    `json:"costs"`
	RiskCohorts      []OverviewCohort `json:"risk_cohorts"`
	Daily            []OverviewDay    `json:"daily"`
}

func (s *Service) Overview(ctx context.Context, orgID int64, days int) (OverviewView, error) {
	t, err := s.tenant(ctx, orgID)
	if err != nil {
		return OverviewView{}, err
	}
	r, err := t.Overview(days)
	if err != nil {
		return OverviewView{}, err
	}
	return overviewView(r)
}

func overviewView(r repository.OverviewRecord) (OverviewView, error) {
	bad := func() (OverviewView, error) { return OverviewView{}, repository.ErrResultDocument }
	w := r.Window
	if r.OrganizationID <= 0 || w.Days != 7 && w.Days != 30 || len(w.Buckets) != w.Days || w.Timezone == "Local" || w.Timezone == "" || len(w.Timezone) > 128 || w.AsOf.IsZero() || !w.AsOf.Equal(w.EndUTC) || !w.EndUTC.After(w.StartUTC) {
		return bad()
	}
	loc, err := time.LoadLocation(w.Timezone)
	if err != nil {
		return bad()
	}
	for _, n := range []int64{r.RunCount, r.Targets.Total, r.Targets.Active, r.Targets.Disabled} {
		if !overviewCount(n) {
			return bad()
		}
	}
	if r.Targets.Total != r.Targets.Active+r.Targets.Disabled || len(r.Runs) > w.Days*11 || len(r.Risks) > repository.OverviewMaxCohorts*30*7 {
		return bad()
	}
	out := OverviewView{SchemaVersion: "overview-v1", Scope: "organization_window", OrganizationID: decimal(r.OrganizationID), AnalysisRevision: 1, Development: true, Window: OverviewWindow{w.Days, w.Timezone, w.AsOf, w.StartUTC, w.EndUTC}, Targets: OverviewTargets{r.Targets.Total, r.Targets.Active, r.Targets.Disabled}, Costs: OverviewCosts{Currency: "USD", Basis: "persisted_run_estimate"}, RiskCohorts: []OverviewCohort{}, Daily: make([]OverviewDay, 0, w.Days)}
	for i, b := range w.Buckets {
		if b.LocalDate != b.StartUTC.In(loc).Format("2006-01-02") || b.EndUTC.Before(b.StartUTC) || b.Partial != (i == w.Days-1) || i == 0 && !b.StartUTC.Equal(w.StartUTC) || i > 0 && !b.StartUTC.Equal(w.Buckets[i-1].EndUTC) || i == w.Days-1 && !b.EndUTC.Equal(w.EndUTC) {
			return bad()
		}
		out.Daily = append(out.Daily, OverviewDay{LocalDate: b.LocalDate, StartUTC: b.StartUTC, EndUTC: b.EndUTC, Partial: b.Partial, RiskCohorts: []OverviewDailyCohort{}})
	}
	var costQuotient, costRemainder int64
	seenRun := map[struct {
		day    int
		status string
	}]bool{}
	for _, g := range r.Runs {
		key := struct {
			day    int
			status string
		}{g.Day, g.Status}
		if g.Day < 0 || g.Day >= w.Days || seenRun[key] || !overviewCount(g.Total) || g.Total == 0 || g.Known < 0 || g.Known > g.Total || g.CostQuotient < 0 || g.CostQuotient > repository.OverviewMaxInteger || g.CostRemainder < 0 || g.CostRemainder > 9999*g.Known {
			return bad()
		}
		seenRun[key] = true
		if !out.Runs.ByStatus.add(g.Status, g.Total) {
			return bad()
		}
		out.Runs.Total += g.Total
		out.Daily[g.Day].RunCount += g.Total
		out.Costs.KnownRuns += g.Known
		if costQuotient > repository.OverviewMaxInteger-g.CostQuotient {
			return bad()
		}
		costQuotient += g.CostQuotient
		costRemainder += g.CostRemainder
	}
	if out.Runs.Total != r.RunCount || costQuotient > repository.OverviewMaxInteger/10000 || costRemainder > repository.OverviewMaxInteger-costQuotient*10000 {
		return bad()
	}
	out.Costs.UnknownRuns = r.RunCount - out.Costs.KnownRuns
	if out.Costs.KnownRuns > 0 {
		n := costQuotient*10000 + costRemainder
		out.Costs.KnownSubtotalMicros = &n
		if out.Costs.UnknownRuns == 0 {
			total := n
			out.Costs.CompleteTotalMicros = &total
		}
	} else if costQuotient != 0 || costRemainder != 0 {
		return bad()
	}
	type tuple [5]string
	cohorts := map[tuple]*OverviewCohort{}
	daily := make([]map[tuple]*OverviewDailyCohort, w.Days)
	seenRisk := map[struct {
		key   tuple
		day   int
		level string
	}]bool{}
	for _, g := range r.Risks {
		key := tuple{g.Package, g.Rule, g.Template, g.Scoring, g.Tokenizer}
		rowKey := struct {
			key   tuple
			day   int
			level string
		}{key, g.Day, g.Level}
		if g.Day < 0 || g.Day >= w.Days || seenRisk[rowKey] || !overviewCount(g.Published) || !overviewCount(g.Scored) || !overviewCount(g.Unscored) || g.Published == 0 || g.Published != g.Scored+g.Unscored || g.Rule != scoring.Version || g.Template != templates.BuiltinVersion || g.Scoring != scoring.Version || g.Tokenizer != tokenizer.BuiltinVersion || !slices.Contains([]string{"quick", "standard", "deep", "custom"}, g.Package) {
			return bad()
		}
		seenRisk[rowKey] = true
		if cohorts[key] == nil {
			cohorts[key] = &OverviewCohort{Package: g.Package, Versions: VersionsView{g.Rule, g.Template, g.Scoring, g.Tokenizer}}
		}
		if daily[g.Day] == nil {
			daily[g.Day] = map[tuple]*OverviewDailyCohort{}
		}
		if daily[g.Day][key] == nil {
			daily[g.Day][key] = &OverviewDailyCohort{}
		}
		for _, counts := range []*OverviewRiskCounts{&cohorts[key].OverviewRiskCounts, &daily[g.Day][key].OverviewRiskCounts} {
			if !counts.Distribution.add(g.Level, g.Scored) {
				return bad()
			}
			counts.PublishedRuns += g.Published
			counts.ScoredRuns += g.Scored
			counts.UnscoredRuns += g.Unscored
		}
		out.Runs.PublishedRuns += g.Published
		out.Runs.ScoredRuns += g.Scored
		out.Runs.UnscoredRuns += g.Unscored
	}
	if len(cohorts) > repository.OverviewMaxCohorts {
		return OverviewView{}, repository.ErrOverviewLimit
	}
	if out.Runs.PublishedRuns > out.Runs.Total {
		return bad()
	}
	out.Runs.UnpublishedRuns = out.Runs.Total - out.Runs.PublishedRuns
	keys := make([]tuple, 0, len(cohorts))
	for key := range cohorts {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		for k := range keys[i] {
			if keys[i][k] != keys[j][k] {
				return keys[i][k] < keys[j][k]
			}
		}
		return false
	})
	for i, key := range keys {
		c := cohorts[key]
		c.ID = fmt.Sprintf("c%d", i+1)
		out.RiskCohorts = append(out.RiskCohorts, *c)
		for d := range out.Daily {
			if item := daily[d][key]; item != nil {
				item.CohortID = c.ID
				out.Daily[d].RiskCohorts = append(out.Daily[d].RiskCohorts, *item)
			}
		}
	}
	for _, d := range out.Daily {
		var published int64
		for _, c := range d.RiskCohorts {
			published += c.PublishedRuns
		}
		if published > d.RunCount {
			return bad()
		}
	}
	return out, nil
}

func overviewCount(n int64) bool { return n >= 0 && n <= repository.OverviewMaxRows }
func (s *OverviewStatuses) add(status string, n int64) bool {
	var dest *int64
	switch status {
	case "DRAFT":
		dest = &s.Draft
	case "PRECHECKING":
		dest = &s.Prechecking
	case "QUEUED":
		dest = &s.Queued
	case "RUNNING":
		dest = &s.Running
	case "ANALYZING":
		dest = &s.Analyzing
	case "COMPLETED":
		dest = &s.Completed
	case "PARTIAL":
		dest = &s.Partial
	case "FAILED":
		dest = &s.Failed
	case "REVIEW_REQUIRED":
		dest = &s.ReviewRequired
	case "CANCELLING":
		dest = &s.Cancelling
	case "CANCELLED":
		dest = &s.Cancelled
	default:
		return false
	}
	*dest += n
	return true
}
func (d *OverviewDistribution) add(level string, n int64) bool {
	var dest *int64
	switch level {
	case "low":
		dest = &d.Low
	case "attention":
		dest = &d.Watch
	case "medium":
		dest = &d.Medium
	case "high":
		dest = &d.High
	case "severe_black_box_statistical_judgment":
		dest = &d.Critical
	case "insufficient":
		dest = &d.Insufficient
	default:
		return false
	}
	*dest += n
	return true
}
