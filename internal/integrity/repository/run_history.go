package repository

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"
)

type RunFilters struct {
	TargetID                                            int64
	Query, Status, Package, Model, ChannelID, RiskLevel string
	From, To                                            *time.Time
}

func (f RunFilters) Valid() bool {
	if f.TargetID < 0 || !slices.Contains([]string{"", "DRAFT", "PRECHECKING", "QUEUED", "RUNNING", "ANALYZING", "COMPLETED", "PARTIAL", "FAILED", "REVIEW_REQUIRED", "CANCELLING", "CANCELLED"}, f.Status) || !slices.Contains([]string{"", "quick", "standard", "deep", "custom"}, f.Package) || !slices.Contains([]string{"", "low", "attention", "medium", "high", "severe_black_box_statistical_judgment", "insufficient"}, f.RiskLevel) {
		return false
	}
	for _, s := range []string{f.Query, f.Model, f.ChannelID} {
		if len(s) > 128 || !utf8.ValidString(s) || strings.ContainsAny(s, "\x00\r\n") {
			return false
		}
	}
	return f.From == nil || f.To == nil || !f.From.After(*f.To)
}

// RunHistoryRecord is an explicit non-S2 SELECT projection. CurrentTarget*
// fields are live descriptive metadata, never the historical request snapshot.
type RunHistoryRecord struct {
	ID, OrganizationID, TargetID, CreatedBy, Version                                 int64
	Package, Status, ManifestHash                                                    string
	RuleBundleVersion, TemplateBundleVersion, ScoringVersion, TokenizerBundleVersion string
	RequestCount, TokenCount, EstimatedCostMicros                                    int64
	CostKnown                                                                        bool
	ValidSampleCount, PlannedSamples, CompletedSamples                               int
	CreatedAt                                                                        time.Time
	StartedAt, FinishedAt, ExecutionClosedAt                                         *time.Time
	CurrentTargetName, CurrentModel, CurrentChannelID                                *string
	AnalysisRevision                                                                 *int
	OverallRisk, Confidence                                                          *float64
	RiskLevel, EvidenceGrade, Completeness                                           *string
}

const historyRunColumns = `r.id,r.organization_id,r.target_id,r.created_by,r.version,
r.request_count,r.token_count,r.estimated_cost_micros,r.cost_known,r.valid_sample_count,r.created_at,r.started_at,r.finished_at,r.execution_closed_at,
(SELECT COUNT(*) FROM integrity_logical_samples s WHERE s.organization_id=r.organization_id AND s.run_id=r.id) AS planned_samples,
(SELECT COUNT(*) FROM integrity_logical_samples s WHERE s.organization_id=r.organization_id AND s.run_id=r.id AND s.completed_at IS NOT NULL) AS completed_samples,
rr.analysis_revision,rr.overall_risk,rr.confidence`

// Only fixed repository column literals reach this helper. Bound encoded bytes
// in SQL, before database/sql allocates strings. NULL remains NULL; overlong
// scalar fields become an invalid newline rejected by DTO validation; oversized
// documents become empty, never partial JSON.
func readBoundedText(tx *gorm.DB, column, alias string, limit int) string {
	length := "length(CAST(" + column + " AS BLOB))"
	if tx.Name() == "postgres" {
		length = "octet_length(" + column + ")"
	}
	invalid := "\n"
	if limit > 256 {
		invalid = ""
	}
	return "CASE WHEN " + length + "<=" + strconv.Itoa(limit) + " OR " + column + " IS NULL THEN " + column + " ELSE '" + invalid + "' END AS " + alias
}

func historyQuery(tx *gorm.DB, orgID int64) *gorm.DB {
	columns := historyRunColumns
	for _, field := range []struct {
		column, alias string
		limit         int
	}{
		{"r.package", "package", 16}, {"r.status", "status", 32}, {"r.manifest_hash", "manifest_hash", 64},
		{"r.rule_bundle_version", "rule_bundle_version", 128}, {"r.template_bundle_version", "template_bundle_version", 128},
		{"r.scoring_version", "scoring_version", 128}, {"r.tokenizer_bundle_version", "tokenizer_bundle_version", 128},
		{"t.name", "current_target_name", 256}, {"t.model", "current_model", 256}, {"t.channel_id", "current_channel_id", 256},
		{"rr.risk_level", "risk_level", 64}, {"rr.evidence_grade", "evidence_grade", 1}, {"rr.completeness", "completeness", 16},
	} {
		columns += "," + readBoundedText(tx, field.column, field.alias, field.limit)
	}
	return tx.Table("integrity_runs r").Select(columns).
		Joins("LEFT JOIN integrity_targets t ON t.organization_id=r.organization_id AND t.id=r.target_id AND t.deleted_at IS NULL").
		Joins("LEFT JOIN integrity_run_results rr ON rr.organization_id=r.organization_id AND rr.run_id=r.id AND rr.analysis_revision=1 AND rr.is_published=?", true).
		Where("r.organization_id=?", orgID)
}

// A read never needs an audit append or outbound capability. Every method fixes
// its required permission and re-reads persisted session/grants before SELECT.
func (t *Tenant) resultReadTransaction(evidence bool, fn func(*gorm.DB) error) error {
	if err := t.store.RequireControlAuthority(t.ctx, t.orgID); err != nil {
		return err
	}
	auth := t.ctx.Value(controlAuthorityKey{}).(controlAuthority).identity
	read := func(tx *gorm.DB) error {
		// The same snapshot authenticates the reader and supplies every row.
		// Password/session hashes are deliberately not loaded by this path.
		var user User
		if err := tx.Select("id,must_change_password,password_changed_at,"+readBoundedText(tx, "status", "status", 16)).Where("id=?", auth.UserID).Take(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrManagementSession
			}
			return err
		}
		var session Session
		if err := tx.Select("id,created_at,expires_at,revoked_at").Where("id=? AND user_id=?", auth.SessionID, auth.UserID).Take(&session).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrManagementSession
			}
			return err
		}
		if user.Status != "active" || session.RevokedAt != nil || !session.ExpiresAt.After(time.Now()) || session.CreatedAt.Before(user.PasswordChangedAt) {
			return ErrManagementSession
		}
		if user.MustChangePassword {
			return ErrPasswordChangeRequired
		}
		// Only these two closed codes can be transferred, even if unrelated
		// permission metadata is damaged. No arbitrary grant strings are read.
		var grants []string
		err := tx.Raw(`SELECT permission_code FROM (
			SELECT rp.permission_code FROM role_permissions rp
			JOIN member_roles mr ON mr.organization_id=rp.organization_id AND mr.role_id=rp.role_id
			JOIN organization_members om ON om.organization_id=mr.organization_id AND om.id=mr.member_id
			JOIN organizations o ON o.id=om.organization_id
			WHERE om.organization_id=? AND om.user_id=? AND om.status='active' AND o.status='active' AND rp.permission_code IN ('run.read','evidence.read')
			UNION
			SELECT mp.permission_code FROM member_permissions mp
			JOIN organization_members om ON om.organization_id=mp.organization_id AND om.id=mp.member_id
			JOIN organizations o ON o.id=om.organization_id
			WHERE om.organization_id=? AND om.user_id=? AND om.status='active' AND o.status='active' AND mp.permission_code IN ('run.read','evidence.read')
		) reader_permissions`, t.orgID, auth.UserID, t.orgID, auth.UserID).Scan(&grants).Error
		if err != nil {
			return err
		}
		if !slices.Contains(grants, "run.read") || evidence && !slices.Contains(grants, "evidence.read") {
			return ErrManagementPermission
		}
		return fn(tx)
	}
	var err error
	if t.store.driver == "postgres" {
		err = t.store.db.WithContext(t.ctx).Transaction(read, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	} else {
		// The SQLite writer DSN uses _txlock=immediate. A pinned connection and
		// explicit DEFERRED transaction override that default for WAL readers.
		err = t.store.db.WithContext(t.ctx).Connection(func(conn *gorm.DB) error {
			// Connection supplies a clone-zero statement; give each operation an
			// independent builder while retaining its pinned ConnPool.
			conn = conn.Session(&gorm.Session{NewDB: true})
			if err := conn.Exec("BEGIN DEFERRED").Error; err != nil {
				return err
			}
			committed := false
			defer func() {
				if !committed {
					cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.ctx), 2*time.Second)
					defer cancel()
					_ = conn.WithContext(cleanup).Exec("ROLLBACK").Error
				}
			}()
			if err := read(conn); err != nil {
				return err
			}
			if err := conn.Exec("COMMIT").Error; err != nil {
				return err
			}
			committed = true
			return nil
		})
	}
	for _, known := range []error{ErrResultDocument, ErrConfiguration} {
		if errors.Is(err, known) {
			return known
		}
	}
	return managementError(err)
}

func (t *Tenant) ListRunHistory(page ListOptions, filters RunFilters) ([]RunHistoryRecord, error) {
	if page.AfterID < 0 || page.Limit < 1 || page.Limit > 100 || !filters.Valid() {
		return nil, ErrConfiguration
	}
	rows := []RunHistoryRecord{}
	err := t.resultReadTransaction(false, func(tx *gorm.DB) error {
		q, err := historyPageQuery(tx, t.orgID, page.AfterID, filters)
		if err != nil {
			return err
		}
		return q.Limit(page.Limit).Scan(&rows).Error
	})
	return rows, err
}

// Shared ordering/filter construction only; callers retain their own fixed
// page bounds and snapshot authorization requirements.
func historyPageQuery(tx *gorm.DB, orgID, afterID int64, filters RunFilters) (*gorm.DB, error) {
	q := historyQuery(tx, orgID)
	if filters.TargetID > 0 {
		q = q.Where("r.target_id=?", filters.TargetID)
	}
	for _, v := range []struct{ column, value string }{{"r.status", filters.Status}, {"r.package", filters.Package}, {"t.model", filters.Model}, {"t.channel_id", filters.ChannelID}, {"rr.risk_level", filters.RiskLevel}} {
		if v.value != "" {
			q = q.Where(v.column+"=?", v.value)
		}
	}
	if filters.Query != "" {
		pattern := "%" + strings.ToLower(strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(filters.Query)) + "%"
		q = q.Where("(LOWER(t.name) LIKE ? ESCAPE '!' OR LOWER(t.model) LIKE ? ESCAPE '!')", pattern, pattern)
	}
	if filters.From != nil {
		q = q.Where("r.created_at>=?", *filters.From)
	}
	if filters.To != nil {
		q = q.Where("r.created_at<=?", *filters.To)
	}
	if afterID > 0 {
		var anchor struct{ CreatedAt time.Time }
		// The HTTP cursor binds reader/org/filters. Its immutable ordering
		// anchor must survive ordinary status/current-target metadata changes.
		if err := tx.Table("integrity_runs").Select("created_at").Where("organization_id=? AND id=?", orgID, afterID).Take(&anchor).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, ErrConfiguration
			}
			return nil, err
		}
		q = q.Where("(r.created_at < ? OR (r.created_at = ? AND r.id < ?))", anchor.CreatedAt, anchor.CreatedAt, afterID)
	}
	return q.Order("r.created_at DESC, r.id DESC"), nil
}
