package repository

import (
	"errors"
	"strings"
	"time"
	_ "time/tzdata" // Stable IANA data for the single-binary deployment.

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

const OverviewMaxRows = 10000
const OverviewMaxCohorts = 16
const OverviewMaxInteger int64 = 9007199254740991

// This is the frozen revision-1 read compatibility boundary, not the current
// application runtime selector. Persistence must not import the analysis engine
// (whose real tests also exercise persistence). Cross-layer tests bind these
// independent identities to the installed rule/scoring versions; future runtime
// changes require an explicit read-compatibility decision, never silent drift.
const overviewRuleVersion = "1.0.0-dev.1"
const overviewScoringVersion = "1.0.0-dev.1"

var ErrOverviewLimit = errors.New("MI_OVERVIEW_LIMIT")
var ErrOverviewTimezone = errors.New("MI_OVERVIEW_TIMEZONE_INVALID")

type OverviewDay struct {
	LocalDate        string
	StartUTC, EndUTC time.Time
	Partial          bool
}
type OverviewWindow struct {
	Days                   int
	Timezone               string
	AsOf, StartUTC, EndUTC time.Time
	Buckets                []OverviewDay
}
type OverviewTargets struct{ Total, Active, Disabled int64 }
type OverviewRunGroup struct {
	Day                                       int
	Status                                    string
	Total, Known, CostQuotient, CostRemainder int64
}
type OverviewRiskGroup struct {
	Day                                                int
	Package, Rule, Template, Scoring, Tokenizer, Level string
	Published, Scored, Unscored                        int64
}
type OverviewRecord struct {
	OrganizationID int64
	Window         OverviewWindow
	Targets        OverviewTargets
	RunCount       int64
	Runs           []OverviewRunGroup
	Risks          []OverviewRiskGroup
}

// overviewWindow uses calendar boundaries, not rolling 24-hour intervals.
// Local depends on the host and is deliberately not a supported organization zone.
func overviewWindow(zone string, days int, now time.Time) (OverviewWindow, error) {
	if days != 7 && days != 30 {
		return OverviewWindow{}, ErrConfiguration
	}
	if zone == "" || zone == "Local" || len(zone) > 128 || strings.ContainsAny(zone, "\x00\r\n") {
		return OverviewWindow{}, ErrOverviewTimezone
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		return OverviewWindow{}, ErrOverviewTimezone
	}
	if now.IsZero() || now.Year() < 2000 || now.Year() > 9998 {
		return OverviewWindow{}, ErrConfiguration
	}
	local := now.In(loc)
	today := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
	out := OverviewWindow{Days: days, Timezone: zone, AsOf: now.UTC(), EndUTC: now.UTC(), Buckets: make([]OverviewDay, 0, days)}
	for i := 1 - days; i <= 0; i++ {
		start := today.AddDate(0, 0, i)
		end := today.AddDate(0, 0, i+1)
		if i == 0 {
			end = now
		}
		// Some historical IANA changes skip an entire local date. Reject an
		// ambiguous calendar instead of duplicating a day or inventing a count.
		want := time.Date(today.Year(), today.Month(), today.Day()+i, 0, 0, 0, 0, time.UTC).Format("2006-01-02")
		if start.Format("2006-01-02") != want || end.Before(start) || i != 0 && !end.After(start) {
			return OverviewWindow{}, ErrOverviewTimezone
		}
		out.Buckets = append(out.Buckets, OverviewDay{want, start.UTC(), end.UTC(), i == 0})
	}
	out.StartUTC = out.Buckets[0].StartUTC
	return out, nil
}

// Overview is a bounded aggregate, never a page masquerading as an organization
// total. Its single read-only snapshot revalidates BOTH fixed read permissions.
func (t *Tenant) Overview(days int) (OverviewRecord, error) {
	if days != 7 && days != 30 {
		return OverviewRecord{}, ErrConfiguration
	}
	out := OverviewRecord{OrganizationID: t.orgID, Runs: []OverviewRunGroup{}, Risks: []OverviewRiskGroup{}}
	var ownError error
	err := t.resultReadTransaction(false, func(tx *gorm.DB) error {
		fail := func(err error) error { ownError = err; return err }
		auth := t.ctx.Value(controlAuthorityKey{}).(controlAuthority).identity
		var granted int
		if err := tx.Raw(`SELECT COUNT(*) FROM (
		 SELECT rp.permission_code FROM role_permissions rp
		 JOIN member_roles mr ON mr.organization_id=rp.organization_id AND mr.role_id=rp.role_id
		 JOIN organization_members om ON om.organization_id=mr.organization_id AND om.id=mr.member_id
		 JOIN organizations o ON o.id=om.organization_id
		 WHERE om.organization_id=? AND om.user_id=? AND om.status='active' AND o.status='active' AND rp.permission_code='target.read'
		 UNION SELECT mp.permission_code FROM member_permissions mp
		 JOIN organization_members om ON om.organization_id=mp.organization_id AND om.id=mp.member_id
		 JOIN organizations o ON o.id=om.organization_id
		 WHERE om.organization_id=? AND om.user_id=? AND om.status='active' AND o.status='active' AND mp.permission_code='target.read'
		) overview_permission`, t.orgID, auth.UserID, t.orgID, auth.UserID).Scan(&granted).Error; err != nil {
			return err
		}
		if granted != 1 {
			return ErrManagementPermission
		}
		var zone string
		if err := tx.Table("organizations").Select(readBoundedText(tx, "timezone", "timezone", 128)).Where("id=?", t.orgID).Scan(&zone).Error; err != nil {
			return err
		}
		window, err := overviewWindow(zone, days, time.Now().UTC())
		if err != nil {
			return fail(err)
		}
		out.Window = window
		var targetCounts struct {
			OverviewTargets `gorm:"embedded"`
			Invalid         int64
		}
		if err := tx.Raw(`SELECT COUNT(*) AS total,
		 COALESCE(SUM(CASE WHEN status='active' THEN 1 ELSE 0 END),0) AS active,
		 COALESCE(SUM(CASE WHEN status='disabled' THEN 1 ELSE 0 END),0) AS disabled,
		 COALESCE(SUM(CASE WHEN status IN ('active','disabled') THEN 0 ELSE 1 END),0) AS invalid
		 FROM (SELECT status FROM integrity_targets WHERE organization_id=? AND deleted_at IS NULL LIMIT 10001) current_targets`, t.orgID).Scan(&targetCounts).Error; err != nil {
			return err
		}
		if targetCounts.Total > OverviewMaxRows {
			return fail(ErrOverviewLimit)
		}
		if targetCounts.Invalid != 0 {
			return ErrResultDocument
		}
		out.Targets = targetCounts.OverviewTargets
		// The guard reads at most cap+1 scalar rows and checks each source row
		// in SQL. No variable-length source string is transferred into Go.
		guard := `SELECT COUNT(*) AS total,COALESCE(SUM(CASE WHEN ` + overviewValidRun + ` AND ` + overviewValidResult + ` THEN 0 ELSE 1 END),0) AS invalid
		 FROM (SELECT id,organization_id,status,package,cost_known,estimated_cost_micros,valid_sample_count,
		 rule_bundle_version,template_bundle_version,scoring_version,tokenizer_bundle_version
		 FROM integrity_runs WHERE organization_id=? AND created_at>=? AND created_at<? LIMIT 10001) r
		 LEFT JOIN integrity_run_results rr ON rr.organization_id=r.organization_id AND rr.run_id=r.id AND rr.analysis_revision=1 AND rr.is_published=TRUE`
		var counts struct{ Total, Invalid int64 }
		if err := tx.Raw(guard, overviewRuleVersion, templates.BuiltinVersion, overviewScoringVersion, tokenizer.BuiltinVersion, t.orgID, window.StartUTC, window.EndUTC).Scan(&counts).Error; err != nil {
			return err
		}
		if counts.Total > OverviewMaxRows {
			return fail(ErrOverviewLimit)
		}
		if counts.Invalid != 0 {
			return ErrResultDocument
		}
		out.RunCount = counts.Total
		bounds, args := overviewBounds(window, t.store.driver == "postgres")
		args = append(args, t.orgID, window.StartUTC, window.EndUTC)
		const source = ` FROM integrity_runs r JOIN days d ON r.created_at>=d.start_at AND r.created_at<d.end_at
		 WHERE r.organization_id=? AND r.created_at>=? AND r.created_at<?`
		// Quotient/remainder integer sums cannot overflow even when every one
		// of 10,000 source costs is JS_MAX_SAFE_INTEGER. Projection rejects a
		// total outside that bound, without floating point or integer wrap.
		query := bounds + `SELECT d.day,r.status,COUNT(*) AS total,
		 SUM(CASE WHEN r.cost_known=TRUE THEN 1 ELSE 0 END) AS known,
		 SUM(CASE WHEN r.cost_known=TRUE THEN r.estimated_cost_micros/10000 ELSE 0 END) AS cost_quotient,
		 SUM(CASE WHEN r.cost_known=TRUE THEN r.estimated_cost_micros%10000 ELSE 0 END) AS cost_remainder` + source + ` GROUP BY d.day,r.status ORDER BY d.day,r.status`
		if err := tx.Raw(query, args...).Scan(&out.Runs).Error; err != nil {
			return err
		}
		query = bounds + `SELECT d.day,r.package,r.rule_bundle_version AS rule,r.template_bundle_version AS template,
		 r.scoring_version AS scoring,r.tokenizer_bundle_version AS tokenizer,rr.risk_level AS level,
		 COUNT(*) AS published,SUM(CASE WHEN rr.overall_risk IS NOT NULL THEN 1 ELSE 0 END) AS scored,
		 SUM(CASE WHEN rr.overall_risk IS NULL THEN 1 ELSE 0 END) AS unscored
		 FROM integrity_runs r JOIN days d ON r.created_at>=d.start_at AND r.created_at<d.end_at
		 JOIN integrity_run_results rr ON rr.organization_id=r.organization_id AND rr.run_id=r.id AND rr.analysis_revision=1 AND rr.is_published=TRUE
		 WHERE r.organization_id=? AND r.created_at>=? AND r.created_at<?
		 GROUP BY d.day,r.package,r.rule_bundle_version,r.template_bundle_version,r.scoring_version,r.tokenizer_bundle_version,rr.risk_level
		 ORDER BY r.package,r.rule_bundle_version,r.template_bundle_version,r.scoring_version,r.tokenizer_bundle_version,d.day,rr.risk_level LIMIT 3361`
		if err := tx.Raw(query, args...).Scan(&out.Risks).Error; err != nil {
			return err
		}
		if len(out.Risks) > OverviewMaxCohorts*30*7 {
			return fail(ErrOverviewLimit)
		}
		cohorts := map[[5]string]bool{}
		for _, r := range out.Risks {
			cohorts[[5]string{r.Package, r.Rule, r.Template, r.Scoring, r.Tokenizer}] = true
		}
		if len(cohorts) > OverviewMaxCohorts {
			return fail(ErrOverviewLimit)
		}
		return nil
	})
	if err != nil {
		if ownError != nil {
			return OverviewRecord{}, ownError
		}
		return OverviewRecord{}, err
	}
	return out, nil
}

const overviewValidRun = `r.status IN ('DRAFT','PRECHECKING','QUEUED','RUNNING','ANALYZING','COMPLETED','PARTIAL','FAILED','REVIEW_REQUIRED','CANCELLING','CANCELLED')
 AND r.package IN ('quick','standard','deep','custom') AND r.cost_known IN (TRUE,FALSE)
 AND r.estimated_cost_micros BETWEEN 0 AND 9007199254740991 AND r.estimated_cost_micros=CAST(r.estimated_cost_micros AS BIGINT)
 AND r.valid_sample_count BETWEEN 0 AND 1000
 AND r.rule_bundle_version=? AND r.template_bundle_version=? AND r.scoring_version=? AND r.tokenizer_bundle_version=?`

// Fixed development release constraints, not a claim to validate arbitrary
// published rule bundles or to independently reanalyze the excluded S2 body.
const overviewValidResult = `(rr.run_id IS NULL OR (
 rr.confidence BETWEEN 0 AND 74 AND rr.confidence=CAST(rr.confidence AS INTEGER)
 AND rr.evidence_grade IN ('C','D') AND rr.completeness IN ('COMPLETE','PARTIAL','INSUFFICIENT')
 AND (rr.completeness='COMPLETE' OR rr.confidence<=59)
 AND rr.risk_level IN ('low','attention','medium','high','severe_black_box_statistical_judgment','insufficient')
 AND (rr.overall_risk IS NULL OR rr.overall_risk BETWEEN 0 AND 100)
 AND (rr.completeness!='INSUFFICIENT' OR (rr.evidence_grade='D' AND rr.risk_level='insufficient'))
 AND (r.valid_sample_count>0 OR (rr.overall_risk IS NULL AND rr.completeness='INSUFFICIENT' AND rr.evidence_grade='D' AND rr.risk_level='insufficient'))
 AND ((rr.overall_risk IS NULL AND rr.risk_level='insufficient') OR (rr.overall_risk IS NOT NULL AND
 ((rr.overall_risk<20 AND rr.risk_level='low') OR (rr.overall_risk>=20 AND rr.overall_risk<40 AND rr.risk_level='attention')
 OR (rr.overall_risk>=40 AND rr.overall_risk<70 AND rr.risk_level='medium') OR (rr.overall_risk>=70 AND rr.overall_risk<90 AND rr.risk_level='high')
 OR (rr.overall_risk>=90 AND rr.risk_level='severe_black_box_statistical_judgment') OR (rr.completeness='INSUFFICIENT' AND rr.risk_level='insufficient'))))))`

func overviewBounds(w OverviewWindow, postgres bool) (string, []any) {
	rows := make([]string, 0, len(w.Buckets))
	args := make([]any, 0, len(w.Buckets)*3)
	for i, b := range w.Buckets {
		// CAST timestamps on SQLite would coerce them to a year. PostgreSQL,
		// conversely, needs explicit CTE types before comparison to timestamps.
		row := "SELECT ? AS day, ? AS start_at, ? AS end_at"
		if postgres {
			row = "SELECT CAST(? AS INTEGER) AS day, CAST(? AS TIMESTAMP) AS start_at, CAST(? AS TIMESTAMP) AS end_at"
		}
		rows = append(rows, row)
		args = append(args, i, b.StartUTC, b.EndUTC)
	}
	return "WITH days AS (" + strings.Join(rows, " UNION ALL ") + ") ", args
}
