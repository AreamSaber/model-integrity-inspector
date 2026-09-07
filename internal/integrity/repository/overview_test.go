package repository

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func overviewFixture(t *testing.T, store *Store) (*Tenant, RunRecord) {
	t.Helper()
	tenant, _, plan, policy := executionFixture(t, store, 1)
	readPermissions(t, tenant)
	plan.Versions.Rule = scoring.Version
	plan.Versions.Scoring = scoring.Version
	plan.Versions.Template = templates.BuiltinVersion
	plan.Versions.Tokenizer = tokenizer.BuiltinVersion
	r, err := tenant.CreateRun(plan, policy, "overview-run")
	if err != nil {
		t.Fatal(err)
	}
	return tenant, r
}

func TestOverviewCalendarDSTLeapMidnightAndZoneFailures(t *testing.T) {
	for _, tc := range []struct {
		zone, now, date string
		hours           int
	}{
		{"America/New_York", "2026-03-09T16:00:00Z", "2026-03-08", 23},
		{"America/New_York", "2026-11-02T17:00:00Z", "2026-11-01", 25},
		{"Asia/Shanghai", "2024-03-01T12:00:00Z", "2024-02-29", 24},
	} {
		now, _ := time.Parse(time.RFC3339, tc.now)
		for _, days := range []int{7, 30} {
			w, err := overviewWindow(tc.zone, days, now)
			if err != nil || len(w.Buckets) != days {
				t.Fatal(err)
			}
			found := false
			for i, d := range w.Buckets {
				if d.Partial != (i == days-1) {
					t.Fatal("partial day")
				}
				if d.LocalDate == tc.date {
					found = true
					if d.EndUTC.Sub(d.StartUTC) != time.Duration(tc.hours)*time.Hour {
						t.Fatal("DST treated as 24h")
					}
				}
			}
			if !found || !w.Buckets[days-1].EndUTC.Equal(now) || !w.EndUTC.Equal(now) {
				t.Fatal("calendar window mismatch")
			}
		}
	}
	now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	w, err := overviewWindow("UTC", 7, now)
	if err != nil || !w.Buckets[6].StartUTC.Equal(w.Buckets[6].EndUTC) {
		t.Fatal("midnight partial must be empty", err)
	}
	for _, zone := range []string{"Local", "", "not/a-zone", strings.Repeat("x", 129), "UTC\nPRIVATE"} {
		if _, err := overviewWindow(zone, 7, now); !errors.Is(err, ErrOverviewTimezone) {
			t.Fatal("invalid zone accepted", err)
		}
	}
	for _, days := range []int{0, 6, 31} {
		if _, err := overviewWindow("UTC", days, now); !errors.Is(err, ErrConfiguration) {
			t.Fatal("bad days", err)
		}
	}
}

func TestOverviewRealSnapshotCountsCostUnknownAndDeletedTargets(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, run := overviewFixture(t, store)
		first, err := tenant.Overview(7)
		if err != nil {
			t.Fatal("overview query", err)
		}
		if first.RunCount != 1 || first.Targets.Total != 1 || len(first.Runs) != 1 || len(first.Risks) != 0 {
			t.Fatal("wrong queued aggregate", first)
		}
		now := time.Now().UTC()
		old := run
		old.ID, _ = NewID()
		old.RequestKey = "old"
		old.PlanJobID = nil
		old.CreatedAt = now.AddDate(0, 0, -40)
		if err := store.db.Create(&old).Error; err != nil {
			t.Fatal(err)
		}
		statuses := []string{"DRAFT", "PRECHECKING", "RUNNING", "ANALYZING", "COMPLETED", "PARTIAL", "FAILED", "REVIEW_REQUIRED", "CANCELLING", "CANCELLED"}
		for i, status := range statuses {
			r := run
			r.ID, _ = NewID()
			r.RequestKey = fmt.Sprintf("overview-%d", i)
			r.PlanJobID = nil
			r.Status = status
			r.CostKnown = i%2 == 0
			r.EstimatedCostMicros = int64(i + 1)
			r.CreatedAt = now.Add(-time.Hour)
			if err := store.db.Create(&r).Error; err != nil {
				t.Fatal(err)
			}
		}
		if err := store.db.Table("integrity_targets").Where("id=?", run.TargetID).Updates(map[string]any{"status": "disabled", "deleted_at": now}).Error; err != nil {
			t.Fatal(err)
		}
		got, err := tenant.Overview(7)
		if err != nil {
			t.Fatal(err)
		}
		if got.RunCount != 11 || got.Targets.Total != 0 || len(got.Runs) != 11 {
			t.Fatal("deleted target hid history or old run included", got)
		}
		var total, known, q, r int64
		for _, g := range got.Runs {
			total += g.Total
			known += g.Known
			q += g.CostQuotient
			r += g.CostRemainder
		}
		if total != 11 || known != 6 || q*10000+r != 25 {
			t.Fatalf("cost grouping mismatch %d %d %d", total, known, q*10000+r)
		}
		if err := store.db.Model(&Organization{}).Where("id=?", tenant.orgID).Update("timezone", "Local").Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.Overview(7); !errors.Is(err, ErrOverviewTimezone) {
			t.Fatal("host Local accepted", err)
		}
	})
}

func TestOverviewPublishedRevisionAndDamagedMetadataFailClosed(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, queue, run, samples, lease := analysisReadyFixture(t, store, 1)
		readPermissions(t, tenant)
		// The existing queue fixture uses generic versions. Pin supported release
		// labels before publication; no production code accepts caller versions.
		updates := map[string]any{"rule_bundle_version": scoring.Version, "template_bundle_version": templates.BuiltinVersion, "scoring_version": scoring.Version, "tokenizer_bundle_version": tokenizer.BuiltinVersion}
		if err := store.db.Model(&RunRecord{}).Where("id=?", run.ID).Updates(updates).Error; err != nil {
			t.Fatal(err)
		}
		run.RuleBundleVersion = scoring.Version
		run.TemplateBundleVersion = templates.BuiltinVersion
		run.ScoringVersion = scoring.Version
		run.TokenizerBundleVersion = tokenizer.BuiltinVersion
		source, err := queue.LoadRunAnalysis(t.Context(), lease)
		if err != nil {
			t.Fatal(err)
		}
		if err := queue.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error {
			return tx.PublishRunAnalysis(source, analysisPublicationFixture(t, run, samples))
		}); err != nil {
			t.Fatal(err)
		}
		got, err := tenant.Overview(30)
		if err != nil || len(got.Risks) != 1 || got.Risks[0].Scored != 1 || got.Risks[0].Level != "medium" {
			t.Fatal("published snapshot", err, got.Risks)
		}
		var original RunResultRecord
		if err := store.db.Where("organization_id=? AND run_id=?", tenant.orgID, run.ID).Take(&original).Error; err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			field string
			value any
		}{
			{"risk_level", strings.Repeat("PRIVATE_CANARY", 1000)}, {"confidence", 75}, {"confidence", 50.25}, {"overall_risk", 101}, {"evidence_grade", "A"}, {"completeness", "APPROVED"}, {"risk_level", "low"},
		} {
			if err := store.db.Model(&RunResultRecord{}).Where("organization_id=? AND run_id=?", tenant.orgID, run.ID).Update(tc.field, tc.value).Error; err != nil {
				t.Fatal(err)
			}
			if _, err := tenant.Overview(7); !errors.Is(err, ErrResultDocument) {
				t.Fatalf("damaged %s accepted: %v", tc.field, err)
			}
			if err := store.db.Model(&RunResultRecord{}).Where("organization_id=? AND run_id=?", tenant.orgID, run.ID).Select("*").Updates(original).Error; err != nil {
				t.Fatal(err)
			}
		}
		if err := store.db.Model(&RunResultRecord{}).Where("organization_id=? AND run_id=?", tenant.orgID, run.ID).Updates(map[string]any{"overall_risk": nil, "risk_level": "insufficient", "completeness": "INSUFFICIENT", "evidence_grade": "D"}).Error; err != nil {
			t.Fatal(err)
		}
		got, err = tenant.Overview(7)
		if err != nil || got.Risks[0].Scored != 0 || got.Risks[0].Unscored != 1 {
			t.Fatal("unscored treated as low", err)
		}
		if err := store.db.Model(&RunRecord{}).Where("id=?", run.ID).Update("rule_bundle_version", strings.Repeat("PRIVATE", 1000)).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.Overview(7); !errors.Is(err, ErrResultDocument) {
			t.Fatal("untrusted version leaked", err)
		}
	})
}
