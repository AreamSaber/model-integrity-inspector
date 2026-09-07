package run

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func overviewRecord() repository.OverviewRecord {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	r := repository.OverviewRecord{OrganizationID: 9007199254740993, Window: repository.OverviewWindow{Days: 7, Timezone: "UTC", AsOf: now, StartUTC: start, EndUTC: now}, Targets: repository.OverviewTargets{Total: 3, Active: 2, Disabled: 1}, RunCount: 3, Runs: []repository.OverviewRunGroup{{Day: 6, Status: "COMPLETED", Total: 2, Known: 1, CostQuotient: 1, CostRemainder: 23}, {Day: 5, Status: "FAILED", Total: 1, Known: 0}}}
	for i := range 7 {
		end := start.AddDate(0, 0, i+1)
		if i == 6 {
			end = now
		}
		r.Window.Buckets = append(r.Window.Buckets, repository.OverviewDay{LocalDate: start.AddDate(0, 0, i).Format("2006-01-02"), StartUTC: start.AddDate(0, 0, i), EndUTC: end, Partial: i == 6})
	}
	r.Risks = []repository.OverviewRiskGroup{{Day: 6, Package: "quick", Rule: scoring.Version, Template: templates.BuiltinVersion, Scoring: scoring.Version, Tokenizer: tokenizer.BuiltinVersion, Level: "medium", Published: 1, Scored: 1}, {Day: 6, Package: "custom", Rule: scoring.Version, Template: templates.BuiltinVersion, Scoring: scoring.Version, Tokenizer: tokenizer.BuiltinVersion, Level: "insufficient", Published: 1, Unscored: 1}}
	return r
}

func TestOverviewProjectionMissingDenominatorsCohortOrderAndSafeID(t *testing.T) {
	r := overviewRecord()
	v, err := overviewView(r)
	if err != nil {
		t.Fatal(err)
	}
	if v.OrganizationID != "9007199254740993" || v.Runs.Total != 3 || v.Runs.UnpublishedRuns != 1 || v.Runs.ScoredRuns != 1 || v.Runs.UnscoredRuns != 1 || v.Costs.KnownRuns != 1 || v.Costs.UnknownRuns != 2 || v.Costs.KnownSubtotalMicros == nil || *v.Costs.KnownSubtotalMicros != 10023 || v.Costs.CompleteTotalMicros != nil {
		t.Fatal("projection lost scope/nulls")
	}
	if len(v.RiskCohorts) != 2 || v.RiskCohorts[0].ID != "c1" || v.RiskCohorts[0].Package != "custom" || v.RiskCohorts[0].Distribution.Insufficient != 0 || v.RiskCohorts[1].Distribution.Medium != 1 || v.Daily[6].RiskCohorts[0].CohortID != "c1" {
		t.Fatal("cohort grouping/unscored denominator")
	}
	data, err := json.Marshal(v)
	if err != nil || strings.Contains(string(data), "success_rate") {
		t.Fatal("invented success rate", err)
	}
	r.Runs = nil
	r.Risks = nil
	r.RunCount = 0
	v, err = overviewView(r)
	if err != nil || v.Costs.KnownSubtotalMicros != nil || v.Costs.CompleteTotalMicros != nil || len(v.Daily) != 7 {
		t.Fatal("empty window made up observed zeros", err)
	}
	r.RunCount = 1
	r.Runs = []repository.OverviewRunGroup{{Day: 6, Status: "QUEUED", Total: 1, Known: 1}}
	v, err = overviewView(r)
	if err != nil || v.Costs.CompleteTotalMicros == nil || *v.Costs.CompleteTotalMicros != 0 {
		t.Fatal("real known zero lost", err)
	}
}

func TestOverviewProjectionRejectsDamageDuplicatesOverflow(t *testing.T) {
	for name, mutate := range map[string]func(*repository.OverviewRecord){
		"total":                func(r *repository.OverviewRecord) { r.RunCount++ },
		"targets":              func(r *repository.OverviewRecord) { r.Targets.Total++ },
		"unknown state":        func(r *repository.OverviewRecord) { r.Runs[0].Status = "PRIVATE" },
		"duplicate run group":  func(r *repository.OverviewRecord) { r.Runs = append(r.Runs, r.Runs[0]) },
		"duplicate risk group": func(r *repository.OverviewRecord) { r.Risks = append(r.Risks, r.Risks[0]) },
		"bad cohort version":   func(r *repository.OverviewRecord) { r.Risks[0].Rule = "PRIVATE" },
		"unknown level":        func(r *repository.OverviewRecord) { r.Risks[0].Level = "healthy" },
		"scored denominator":   func(r *repository.OverviewRecord) { r.Risks[0].Scored++ },
		"window gap": func(r *repository.OverviewRecord) {
			r.Window.Buckets[2].StartUTC = r.Window.Buckets[2].StartUTC.Add(time.Second)
		},
		"cost overflow":  func(r *repository.OverviewRecord) { r.Runs[0].CostQuotient = repository.OverviewMaxInteger },
		"negative cost":  func(r *repository.OverviewRecord) { r.Runs[0].CostRemainder = -1 },
		"invented known": func(r *repository.OverviewRecord) { r.Runs[0].Known = 3 },
	} {
		t.Run(name, func(t *testing.T) {
			r := overviewRecord()
			mutate(&r)
			if _, err := overviewView(r); !errors.Is(err, repository.ErrResultDocument) {
				t.Fatal("invalid aggregate accepted", err)
			}
		})
	}
}
