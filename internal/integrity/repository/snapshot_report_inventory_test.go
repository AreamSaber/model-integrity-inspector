package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/report"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func snapshotReportTestFixture(t *testing.T, store *Store) (*Tenant, *JobQueue, RunRecord) {
	t.Helper()
	tenant, _, plan, policy := executionFixture(t, store, 2)
	// Set real compiled versions before the run is created. The general
	// repository fixture's opaque "1" versions are not valid report inputs.
	plan.Versions.Rule, plan.Versions.Scoring = scoring.Version, scoring.Version
	plan.Versions.Template, plan.Versions.Tokenizer = templates.BuiltinVersion, tokenizer.BuiltinVersion
	run, q, samples := executionStart(t, tenant, plan, policy)
	for _, sample := range samples {
		lease := mustClaim(t, q)
		attempt := reserveTestAttempt(t, tenant, q, lease, sample)
		body := responseFixtureBody(t, tenant, q, lease, sample, attempt)
		if err := q.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error {
			return tx.FinishLegacyAttemptWithCapture(sample.ID, attempt.ID, successOutcome(), 0, body)
		}); err != nil {
			t.Fatal("complete actual sample", err)
		}
	}
	lease := mustClaim(t, q)
	source, err := q.LoadRunAnalysis(t.Context(), lease)
	if err != nil {
		t.Fatal("load actual analysis", err)
	}
	publication := analysisPublicationFixture(t, run, samples)
	if err := q.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error {
		return tx.PublishRunAnalysis(source, publication)
	}); err != nil {
		t.Fatal("publish actual analysis", err)
	}
	readPermissions(t, tenant)
	var role int64
	if err := store.db.Table("roles").Select("id").Where("organization_id=? AND name=?", tenant.orgID, "administrator").Scan(&role).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.db.Exec("INSERT INTO permissions (code) VALUES ('report.export') ON CONFLICT (code) DO NOTHING").Error; err != nil {
		t.Fatal(err)
	}
	if err := store.db.Exec("INSERT INTO role_permissions (organization_id,role_id,permission_code) VALUES (?,?,?)", tenant.orgID, role, "report.export").Error; err != nil {
		t.Fatal(err)
	}
	return tenant, q, run
}

// This fixture exercises real create/claim/freeze/generate/publish/complete
// transactions, never hand-inserts a normal ready row. Its S1 projection is a
// typed development-kernel fixture bound to actual run/sample/attempt rows,
// not run.BuildReportSnapshot or a claim of a complete Worker/analysis E2E.
func snapshotReportTestPublish(t *testing.T, tenant *Tenant, q *JobQueue, run RunRecord, format string, index int) ReportRecord {
	t.Helper()
	row, err := tenant.CreateReport(ReportInput{RunID: run.ID, AnalysisRevision: 1, Format: format, IdempotencyKey: fmt.Sprintf("snapshot-report-%s-%d", format, index)})
	if err != nil {
		t.Fatal("create report fixture", err)
	}
	lease := mustClaim(t, q)
	if lease.Job.ObjectID != row.ID {
		t.Fatal("wrong report lease")
	}
	source, err := q.LoadReportSource(t.Context(), lease)
	if err != nil {
		t.Fatal("load report fixture", err)
	}
	var frozen snapshotReportSource
	if err := source.Use(func(data PublishedRead, prior []byte) error {
		if len(prior) != 0 || data.Run.FinishedAt == nil {
			return ErrReportInvalid
		}
		versions := report.Versions{Rule: data.Run.RuleBundleVersion, Template: data.Run.TemplateBundleVersion, Scoring: data.Run.ScoringVersion, Tokenizer: data.Run.TokenizerBundleVersion}
		id := strconv.FormatInt(run.ID, 10)
		input := report.Input{Run: report.Run{ID: id, TargetID: strconv.FormatInt(data.Run.TargetID, 10), Package: data.Run.Package, CreatedAt: data.Run.CreatedAt, StartedAt: data.Run.StartedAt, FinishedAt: *data.Run.FinishedAt, RequestCount: data.Run.RequestCount, TokenCount: data.Run.TokenCount}, Result: report.Result{RunID: id, AnalysisRevision: 1, Versions: versions, ExpectedSamples: len(data.Samples), ValidSamples: len(data.Samples), OverallRisk: data.Result.OverallRisk, PromptRisk: data.Result.PromptRisk, Confidence: 50, EvidenceGrade: "C", RiskLevel: "medium", Completeness: "partial", Limitations: []string{"MI_DEVELOPMENT_RULES_UNCALIBRATED"}}}
		for _, s := range data.Samples {
			sample := report.Sample{ID: strconv.FormatInt(s.ID, 10), RunID: id, ProbeInstanceID: strconv.FormatInt(s.ProbeInstanceID, 10), Ordinal: s.Ordinal, Family: "sequence", Language: "en-US", Validity: s.Validity, Included: true, RequestedMaxTokens: 256, TokenizerQuality: "unavailable", FinalAttemptID: nil}
			for _, a := range data.Attempts {
				if a.LogicalSampleID == s.ID {
					attempt := report.Attempt{ID: strconv.FormatInt(a.ID, 10), AttemptNo: a.AttemptNo, Validity: a.Validity, HTTPStatus: a.HTTPStatus, PromptTokens: a.PromptTokens, CompletionTokens: a.CompletionTokens, TotalTokens: a.TotalTokens, DurationMS: a.DurationMS, StartedAt: a.StartedAt, FinishedAt: a.FinishedAt}
					sample.Attempts = append(sample.Attempts, attempt)
					if s.FinalAttemptID != nil && *s.FinalAttemptID == a.ID {
						sample.FinalAttemptID = &attempt.ID
					}
				}
			}
			input.Samples = append(input.Samples, sample)
		}
		frozen = snapshotReportSource{versions, input}
		return nil
	}); err != nil {
		t.Fatal("project fixture source", err)
	}
	encoded, err := json.Marshal(frozen)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := report.NewDevelopmentSnapshot(report.Scope{ReportID: strconv.FormatInt(row.ID, 10), OrganizationID: strconv.FormatInt(row.OrganizationID, 10), RunID: strconv.FormatInt(run.ID, 10), AnalysisRevision: 1, GeneratedAt: row.CreatedAt, Versions: frozen.Versions}, frozen.Input)
	if err != nil {
		t.Fatal("validate actual frozen fixture", err)
	}
	var content, file string
	var body []byte
	// Independent selection from the actual renderer; do not use the helper
	// under test as the expected publication/hash oracle.
	if format == "csv" {
		a, e := report.GenerateCSV(snapshot)
		if e != nil {
			t.Fatal(e)
		}
		content, file, body = a.ContentHash(), a.FileHash(), a.Bytes()
	} else {
		a, e := report.Generate(snapshot)
		if e != nil {
			t.Fatal(e)
		}
		content = a.ContentHash()
		if format == "json" {
			file, body = a.JSONFileHash(), a.JSON()
		} else {
			file, body = a.HTMLFileHash(), a.HTML()
		}
	}
	if reportDigest(body) != strings.TrimPrefix(file, "sha256:") {
		t.Fatal("actual generated bytes hash")
	}
	if err := q.FreezeReportSource(t.Context(), lease, source, encoded); err != nil {
		t.Fatal("freeze real report", err)
	}
	if err := q.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error {
		return tx.PublishReport(source, reportDigest(encoded), ReportPublication{ContentHash: content, FileHash: strings.TrimPrefix(file, "sha256:"), FileSize: int64(len(body))})
	}); err != nil {
		t.Fatal("publish real report", err)
	}
	return csvRepositoryStored(t, tenant.store, tenant.orgID, row.ID)
}

func snapshotReportTestFailure(t *testing.T, s *Store, cfg Config, want error) {
	t.Helper()
	ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
	defer closeView()
	got, err := s.snapshotReportInventory(ctx, tx)
	if !errors.Is(err, want) || got.entries != nil {
		t.Fatalf("inventory must return fixed failure and zero results: %v", err)
	}
}

func TestSnapshotReportInventory101RowsSameViewOwnedAndFormats(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, q, run := snapshotReportTestFixture(t, s)
		original := make([]ReportRecord, 0, 101)
		for i := 0; i < 101; i++ {
			original = append(original, snapshotReportTestPublish(t, tenant, q, run, []string{"json", "html", "csv"}[i%3], i))
		}
		slices.SortFunc(original, func(a, b ReportRecord) int {
			if a.ID < b.ID {
				return -1
			}
			if a.ID > b.ID {
				return 1
			}
			return 0
		})
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		pages := []int{}
		if err := tx.Callback().Query().After("gorm:query").Register("snapshot_report_pages", func(q *gorm.DB) {
			if p, ok := q.Statement.Dest.(*[]snapshotReportRow); ok && q.Error == nil {
				pages = append(pages, len(*p))
			}
		}); err != nil {
			t.Fatal(err)
		}
		poolless := &Store{driver: cfg.Driver}
		got, err := poolless.snapshotReportInventory(ctx, tx.Where("1=0").Select("id").Limit(1).Order("r.id DESC"))
		if err != nil || len(got.entries) != 101 || !reflect.DeepEqual(pages, []int{100, 1}) {
			t.Fatalf("real cross-page inventory: %v pages=%v", err, pages)
		}
		for i, e := range got.entries {
			r := original[i]
			if e.id != r.ID || e.organizationID != r.OrganizationID || e.runID != r.RunID || e.analysisRevision != r.AnalysisRevision || e.revision != r.Revision || e.format != r.FormatName || e.schema != r.SchemaVersion || e.contentHash != *r.ContentHash || e.sourceHash != *r.SourceHash || e.fileHash != *r.FileHash || e.fileSize != *r.FileSize || e.objectName != *r.StoragePath || e.sourceSize != int64(len(*r.SourceJSON)) {
				t.Fatal("inventory lost exact original metadata")
			}
		}
		owned := slices.Clone(got.entries)
		got.entries[0].objectName = "owned-canary"
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		// A real publication on another connection, committed after the read
		// snapshot: old view stays 101 and a new view sees 102. Also disable the
		// organization after publication; inventory must retain its history.
		user, err := other.GetUser(t.Context(), run.CreatedBy)
		if err != nil {
			t.Fatal("read existing report creator", err)
		}
		authority := managementSession(t, other, user)
		otherContext := bindTargetTestSession(t, other, testActorContext(t, user.ID), authority.SessionID, tenant.orgID)
		otherTenant, err := other.WithOrganization(otherContext, tenant.orgID)
		if err != nil {
			t.Fatal(err)
		}
		if err := q.Close(t.Context()); err != nil {
			t.Fatal("release original real consumer", err)
		}
		otherQueue, err := other.OpenJobQueue(otherContext)
		if err != nil {
			t.Fatal("acquire new consumer on another connection", err)
		}
		defer func() { _ = otherQueue.Close(t.Context()) }()
		newRow := snapshotReportTestPublish(t, otherTenant, otherQueue, run, "csv", 102)
		if err := other.db.Table("organizations").Where("id=?", tenant.orgID).Update("status", "disabled").Error; err != nil {
			t.Fatal("disable historical organization", err)
		}
		again, err := poolless.snapshotReportInventory(ctx, tx)
		if err != nil || !reflect.DeepEqual(again.entries, owned) {
			t.Fatal("old snapshot changed or result aliased", err)
		}
		var one int
		if err := tx.Raw("SELECT 1").Scan(&one).Error; err != nil || one != 1 {
			t.Fatal("caller transaction ended")
		}
		closeView()
		ctx, tx, closeNew := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeNew()
		latest, err := poolless.snapshotReportInventory(ctx, tx)
		if err != nil || len(latest.entries) != 102 {
			t.Fatal("new view omitted disabled-org report", err)
		}
		found := false
		for _, e := range latest.entries {
			found = found || e.id == newRow.ID
		}
		if !found {
			t.Fatal("newly committed ready report absent")
		}
		for _, r := range original {
			if current := csvRepositoryStored(t, s, r.OrganizationID, r.ID); !reflect.DeepEqual(current, r) {
				t.Fatal("inventory altered existing JSON/HTML/CSV row")
			}
		}
		closeNew()
		// Damage the LAST of 102 ready rows. A complete first page and 101
		// verified source bodies must not turn into a returned partial backup.
		snapshotReportTestCorruptible(t, s)
		last := latest.entries[len(latest.entries)-1].id
		if err := s.db.Exec("UPDATE integrity_reports SET file_hash='damaged' WHERE id=?", last).Error; err != nil {
			t.Fatal("damage last isolated row")
		}
		ctx, tx, closeDamaged := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeDamaged()
		pages, bodies := []int{}, 0
		if err := tx.Callback().Query().After("gorm:query").Register("snapshot_report_late_corruption", func(query *gorm.DB) {
			switch value := query.Statement.Dest.(type) {
			case *[]snapshotReportRow:
				pages = append(pages, len(*value))
			case *snapshotReportSourceRow:
				bodies++
			}
		}); err != nil {
			t.Fatal(err)
		}
		if partial, err := s.snapshotReportInventory(ctx, tx); !errors.Is(err, errSnapshotReportInvalid) || partial.entries != nil || bodies != 101 || !reflect.DeepEqual(pages, []int{100, 2}) {
			t.Fatalf("late corruption escaped or was not reached: %v pages=%v sources=%d", err, pages, bodies)
		}
	})
}

// Corruption tests first prove normal ready-row immutability, then replace ONLY
// the isolated fixture's table with an unconstrained copy. This models offline
// damage; it is not a supported publication path or a production migration.
func snapshotReportTestCorruptible(t *testing.T, s *Store) {
	t.Helper()
	if err := s.db.Exec("UPDATE integrity_reports SET file_hash='wrong' WHERE status='ready'").Error; err == nil {
		t.Fatal("normal ready rows mutable")
	}
	for _, statement := range []string{"ALTER TABLE integrity_reports RENAME TO snapshot_report_original", "CREATE TABLE integrity_reports AS SELECT * FROM snapshot_report_original"} {
		if err := s.db.Exec(statement).Error; err != nil {
			t.Fatal("prepare isolated report corruption fixture", err)
		}
	}
	if s.driver == "postgres" {
		// CTAS retains PostgreSQL scalar types: widen ONLY the isolated copy
		// so offline malformed timestamps/out-of-range revisions can be tested.
		for _, statement := range []string{
			"ALTER TABLE integrity_reports ALTER COLUMN revision TYPE BIGINT",
			"ALTER TABLE integrity_reports ALTER COLUMN created_at TYPE TEXT USING CAST(created_at AS TEXT)",
			"ALTER TABLE integrity_reports ALTER COLUMN completed_at TYPE TEXT USING CAST(completed_at AS TEXT)",
			"ALTER TABLE integrity_reports ALTER COLUMN frozen_at TYPE TEXT USING CAST(frozen_at AS TEXT)",
		} {
			if err := s.db.Exec(statement).Error; err != nil {
				t.Fatal("widen isolated corruption fixture")
			}
		}
	}
	t.Cleanup(func() {
		for _, statement := range []string{"DROP TABLE integrity_reports", "ALTER TABLE snapshot_report_original RENAME TO integrity_reports"} {
			if err := s.db.Exec(statement).Error; err != nil {
				t.Error("restore isolated report table")
			}
		}
	})
}
func snapshotReportTestReset(t *testing.T, s *Store) {
	t.Helper()
	for _, statement := range []string{"DELETE FROM integrity_reports", "INSERT INTO integrity_reports SELECT * FROM snapshot_report_original"} {
		if err := s.db.Exec(statement).Error; err != nil {
			t.Fatal("restore isolated report rows")
		}
	}
}

func TestSnapshotReportInventoryMalformedRowsFailClosed(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, q, run := snapshotReportTestFixture(t, s)
		row := snapshotReportTestPublish(t, tenant, q, run, "json", 1)
		snapshotReportTestCorruptible(t, s)
		for _, tc := range []struct {
			name, column string
			value        any
			unsupported  bool
		}{
			{"id_null", "id", nil, false}, {"id_zero", "id", 0, false}, {"id_negative", "id", -1, false}, {"org_null", "organization_id", nil, false}, {"org_orphan", "organization_id", 1, false}, {"run_orphan", "run_id", 1, false}, {"revision_zero", "revision", 0, false}, {"revision_high", "revision", int64(2147483648), false}, {"analysis_revision", "analysis_revision", 2, false},
			{"format_null", "format", nil, false}, {"format_pdf", "format", "pdf", false}, {"format_alias", "format", "CSV", false}, {"schema_csv_profile", "schema_version", "mii.report.csv.v1", false}, {"source_hash", "source_hash", strings.Repeat("f", 64), false}, {"content_hash", "content_hash", "sha256:" + strings.Repeat("f", 64), false}, {"file_hash", "file_hash", strings.Repeat("f", 64), false}, {"file_size_changed", "file_size", *row.FileSize + 1, false}, {"file_size_zero", "file_size", 0, false}, {"file_size_limit", "file_size", reportFileLimit + 1, false}, {"filename", "storage_path", "../outside.json", false}, {"created_at", "created_at", row.CreatedAt.Add(time.Second), false}, {"completed_before_freeze", "completed_at", row.CreatedAt.Add(-time.Second), false}, {"frozen_at_invalid", "frozen_at", "invalid", false}, {"error_code", "error_code", "MI_REPORT_GENERATION_FAILED", false}, {"job_foreign", "job_id", *row.JobID + 1, false}, {"creator_orphan", "created_by", 1, false},
			{"legacy_created_by", "created_by", nil, true}, {"legacy_job", "job_id", nil, true}, {"legacy_source", "source_json", nil, true}, {"legacy_source_hash", "source_hash", nil, true}, {"legacy_file_hash", "file_hash", nil, true}, {"legacy_file_size", "file_size", nil, true}, {"legacy_frozen", "frozen_at", nil, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				value := tc.value
				if stamp, ok := value.(time.Time); ok {
					value = stamp.Format(time.RFC3339Nano)
				}
				if err := s.db.Table("integrity_reports").Where("id=?", row.ID).Update(tc.column, value).Error; err != nil {
					t.Fatal("write isolated damaged field", err)
				}
				want := errSnapshotReportInvalid
				if tc.unsupported {
					want = errSnapshotReportUnsupported
				}
				snapshotReportTestFailure(t, s, cfg, want)
				snapshotReportTestReset(t, s)
			})
		}
		if err := s.db.Exec("INSERT INTO integrity_reports SELECT * FROM snapshot_report_original").Error; err != nil {
			t.Fatal(err)
		}
		snapshotReportTestFailure(t, s, cfg, errSnapshotReportInvalid)
		snapshotReportTestReset(t, s)
		if cfg.Driver == "sqlite" {
			for _, tc := range []struct {
				column string
				value  any
			}{{"id", 1.5}, {"organization_id", []byte("1")}, {"format", []byte("json")}, {"source_json", []byte(*row.SourceJSON)}, {"created_at", []byte(row.CreatedAt.Format(time.RFC3339Nano))}} {
				if err := s.db.Exec("UPDATE integrity_reports SET "+tc.column+"=?", tc.value).Error; err != nil {
					t.Fatal("write isolated wrong SQLite type")
				}
				snapshotReportTestFailure(t, s, cfg, errSnapshotReportInvalid)
				snapshotReportTestReset(t, s)
			}
		}
	})
}

func TestSnapshotReportInventorySourceAndSQLBounds(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, q, run := snapshotReportTestFixture(t, s)
		row := snapshotReportTestPublish(t, tenant, q, run, "csv", 1)
		snapshotReportTestCorruptible(t, s)
		for _, field := range []string{"format", "schema_version", "source_hash", "content_hash", "file_hash", "storage_path", "created_at", "completed_at", "frozen_at"} {
			t.Run("sql_"+field, func(t *testing.T) {
				if err := s.db.Exec("UPDATE integrity_reports SET "+field+"=?", strings.Repeat("界", 350000)).Error; err != nil {
					t.Fatal("write actual oversize scalar")
				}
				ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
				defer closeView()
				var projected []snapshotReportRow
				if err := tx.Table("integrity_reports r").Select(snapshotReportColumns(tx)).Find(&projected).Error; err != nil || len(projected) != 1 {
					t.Fatal("read bounded SQL scalar", err)
				}
				values := reflect.ValueOf(projected[0])
				for i := 0; i < values.NumField(); i++ {
					if values.Field(i).Kind() == reflect.String && len(values.Field(i).String()) > 128 {
						t.Fatal("oversized SQL scalar crossed boundary")
					}
				}
				if got, err := s.snapshotReportInventory(ctx, tx); !errors.Is(err, errSnapshotReportInvalid) || got.entries != nil {
					t.Fatal("oversize scalar accepted", err)
				}
				closeView()
				snapshotReportTestReset(t, s)
			})
		}
		for _, raw := range []string{strings.Repeat(" ", reportInputLimit+1), "{}", *row.SourceJSON + " ", strings.Replace(*row.SourceJSON, `"versions":`, `"Versions":`, 1), strings.Replace(*row.SourceJSON, `"versions":`, `"versions":{},"versions":`, 1), strings.Replace(*row.SourceJSON, `"run_id":"`+strconv.FormatInt(run.ID, 10)+`"`, `"run_id":"1"`, 1), strings.Repeat("[", 65) + strings.Repeat("]", 65)} {
			if err := s.db.Exec("UPDATE integrity_reports SET source_json=?,source_hash=?", raw, reportDigest([]byte(raw))).Error; err != nil {
				t.Fatal(err)
			}
			snapshotReportTestFailure(t, s, cfg, errSnapshotReportInvalid)
			snapshotReportTestReset(t, s)
		}
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		if got, err := s.snapshotReportInventoryLimited(ctx, tx, 1); err != nil || len(got.entries) != 1 {
			t.Fatal("exact report cap", err)
		}
		closeView()
		// Actual two rows; SQL COUNT limit detects the overrun before any body.
		if err := s.db.Exec("INSERT INTO integrity_reports SELECT * FROM snapshot_report_original").Error; err != nil {
			t.Fatal(err)
		}
		ctx, tx, closeNext := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeNext()
		if got, err := s.snapshotReportInventoryLimited(ctx, tx, 1); !errors.Is(err, errSnapshotReportLimit) || got.entries != nil {
			t.Fatal("tight resource limit silently truncated", err)
		}
	})
}

func TestSnapshotReportInventoryCancellationAndGuards(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, q, run := snapshotReportTestFixture(t, s)
		snapshotReportTestPublish(t, tenant, q, run, "html", 1)
		snapshotReportTestPublish(t, tenant, q, run, "csv", 2)
		for _, cause := range []string{"cancel", "query_error"} {
			t.Run(cause, func(t *testing.T) {
				ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
				defer closeView()
				work, cancel := context.WithCancel(ctx)
				defer cancel()
				observed := 0
				if err := tx.Callback().Query().After("gorm:query").Register("snapshot_report_terminal_failure", func(q *gorm.DB) {
					if _, ok := q.Statement.Dest.(*snapshotReportSourceRow); ok && q.Error == nil {
						observed++
						if observed != 2 {
							return
						}
						if cause == "cancel" {
							cancel()
						} else {
							_ = q.AddError(errors.New("private-database-error-canary"))
						}
					}
				}); err != nil {
					t.Fatal(err)
				}
				got, err := s.snapshotReportInventory(work, tx)
				if !errors.Is(err, ErrUnavailable) || got.entries != nil || observed != 2 || err.Error() != ErrUnavailable.Error() {
					t.Fatal("post-query failure/cancel disclosed partial result", err)
				}
			})
		}
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		for _, invalid := range []*gorm.DB{nil, {}, s.db} {
			if got, err := s.snapshotReportInventory(ctx, invalid); !errors.Is(err, ErrConfiguration) || got.entries != nil {
				t.Fatal("invalid transaction accepted")
			}
		}
		for _, invalid := range []context.Context{nil, context.Background()} {
			if got, err := s.snapshotReportInventory(invalid, tx); !errors.Is(err, ErrConfiguration) || got.entries != nil {
				t.Fatal("unbounded context accepted")
			}
		}
		for _, limit := range []int{-1, 0, snapshotReportMaxEntries + 1} {
			if got, err := s.snapshotReportInventoryLimited(ctx, tx, limit); !errors.Is(err, ErrConfiguration) || got.entries != nil {
				t.Fatal("production report cap expanded")
			}
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if got, err := s.snapshotReportInventory(canceled, tx); !errors.Is(err, ErrUnavailable) || got.entries != nil {
			t.Fatal("cancelled accepted")
		}
		if err := tx.Statement.ConnPool.(*sql.Tx).Rollback(); err != nil {
			t.Fatal(err)
		}
		if got, err := s.snapshotReportInventory(ctx, tx); !errors.Is(err, ErrUnavailable) || got.entries != nil {
			t.Fatal("closed transaction accepted")
		}
		closeView()
		options := &sql.TxOptions{Isolation: sql.LevelReadCommitted, ReadOnly: true}
		if cfg.Driver == "sqlite" {
			options = &sql.TxOptions{ReadOnly: true}
		}
		ctx, tx, closeWeak := auditSnapshotTestTransaction(t, cfg, options, false)
		defer closeWeak()
		if got, err := s.snapshotReportInventory(ctx, tx); !errors.Is(err, ErrConfiguration) || got.entries != nil {
			t.Fatal("insufficient snapshot isolation accepted")
		}
		if got, err := (&Store{driver: "unsupported"}).snapshotReportInventory(ctx, tx); !errors.Is(err, ErrConfiguration) || got.entries != nil {
			t.Fatal("cross-dialect transaction accepted")
		}
	})
}

func TestSnapshotReportInventoryRepresentation(t *testing.T) {
	entry := snapshotReportEntry{id: 1234, objectName: "private-canary"}
	inventory := snapshotReportInventory{entries: []snapshotReportEntry{entry}}
	for _, v := range []any{entry, &entry, inventory, &inventory} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if out := fmt.Sprintf(format, v); strings.Contains(out, "canary") || strings.Contains(out, "1234") || !strings.Contains(out, "private snapshot report") {
				t.Fatal("fmt leaked inventory")
			}
		}
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("JSON accepted private state")
		}
		if _, err := yaml.Marshal(v); err == nil {
			t.Fatal("YAML accepted private state")
		}
		out := snapshotInventoryLogText(t, v)
		if strings.Contains(out, "canary") || strings.Contains(out, "1234") || !strings.HasPrefix(out, "[private snapshot report ") {
			t.Fatal("slog leaked inventory")
		}
	}
}

func TestSnapshotReportDecodeAcceptsKernelMaximumCollections(t *testing.T) {
	for _, tc := range []struct {
		name                                  string
		samples, attempts, findings, patterns int
	}{
		{"samples_and_retry_chains", report.MaxSamples, 3, 0, 0},
		{"findings", 1, 1, report.MaxFindings, 0},
		{"behavior_patterns", 1, 1, 0, 2048},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scope, source := snapshotReportMaximumSource(tc.samples, tc.attempts, tc.findings, tc.patterns)
			if _, err := report.NewDevelopmentSnapshot(scope, source.Input); err != nil {
				t.Fatal("fixture must first be accepted by the real kernel", err)
			}
			raw, err := json.Marshal(source)
			if err != nil || len(raw) > reportInputLimit {
				t.Fatal("fixture outside real freeze limit")
			}
			var restored snapshotReportSource
			if !snapshotReportDecode(string(raw), &restored) || !reflect.DeepEqual(restored, source) {
				t.Fatal("inventory imposed a narrower limit than the report kernel")
			}
		})
	}
}

func snapshotReportMaximumSource(samples, attempts, findings, patterns int) (report.Scope, snapshotReportSource) {
	stamp := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	versions := report.Versions{Rule: scoring.Version, Scoring: scoring.Version, Template: templates.BuiltinVersion, Tokenizer: tokenizer.BuiltinVersion}
	scope := report.Scope{ReportID: "1", OrganizationID: "2", RunID: "3", AnalysisRevision: 1, GeneratedAt: stamp, Versions: versions}
	risk := float64(50)
	source := snapshotReportSource{Versions: versions, Input: report.Input{
		Run:    report.Run{ID: "3", TargetID: "4", Package: "custom", CreatedAt: stamp, FinishedAt: stamp, RequestCount: int64(samples * attempts)},
		Result: report.Result{RunID: "3", AnalysisRevision: 1, Versions: versions, ExpectedSamples: samples, ValidSamples: samples, OverallRisk: &risk, PromptRisk: &risk, Confidence: 50, EvidenceGrade: "C", RiskLevel: "medium", Completeness: "full"},
	}}
	for i := range samples {
		sample := report.Sample{ID: strconv.Itoa(1000 + i), RunID: "3", ProbeInstanceID: strconv.Itoa(2000 + i), Ordinal: i, Family: "sequence", Language: "en-US", Validity: "VALID", Included: true, RequestedMaxTokens: 256, TokenizerQuality: "unavailable"}
		for j := range attempts {
			sample.Attempts = append(sample.Attempts, report.Attempt{ID: strconv.Itoa(10000 + i*3 + j), AttemptNo: j + 1, Validity: "VALID", StartedAt: &stamp, FinishedAt: &stamp})
		}
		if attempts > 0 {
			sample.FinalAttemptID = &sample.Attempts[attempts-1].ID
		}
		source.Input.Samples = append(source.Input.Samples, sample)
	}
	for i := range findings {
		source.Input.Findings = append(source.Input.Findings, report.Finding{ID: strconv.Itoa(20000 + i), RunID: "3", AnalysisRevision: 1, Category: "prompt", RuleID: "development.aggregate.prompt", RuleVersion: scoring.Version, Severity: "medium", RiskScore: risk, Confidence: 50, EvidenceGrade: "C", SampleRefs: []string{"1000"}})
	}
	if patterns > 0 {
		behavior := &report.BehaviorStatistics{AnalyzedSamples: samples}
		for i := range patterns {
			behavior.Patterns = append(behavior.Patterns, report.Pattern{Kind: "extra_prefix", Fingerprint: fmt.Sprintf("%064x", i+1), State: "insufficient_coverage", FamilyCount: 1, TemplateCount: 1, LanguageCount: 1, SampleRefs: []string{"1000"}})
		}
		source.Input.Result.Behavior = behavior
	}
	return scope, source
}

func TestSnapshotReportStampAndDecodeClosedProtocol(t *testing.T) {
	stamp := time.Date(2026, 9, 10, 1, 2, 3, 123456789, time.UTC)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05.999999999 -0700 MST"} {
		if got, ok := snapshotReportStamp(stamp.Format(layout)); !ok || !got.Equal(stamp) {
			t.Fatal("supported actual database timestamp rejected")
		}
	}
	for _, raw := range []string{"", "1999-12-31T23:59:59Z", "10000-01-01T00:00:00Z", "2026-09-10 arbitrary"} {
		if _, ok := snapshotReportStamp(raw); ok {
			t.Fatal("invalid timestamp accepted")
		}
	}
	_, source := snapshotReportMaximumSource(1, 1, 0, 0)
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		string(encoded) + "{}", string(encoded) + " ", string(encoded[:len(encoded)-1]),
		strings.Replace(string(encoded), `"versions":`, `"Versions":`, 1),
		strings.Replace(string(encoded), `"versions":`, `"versions":{},"versions":`, 1),
		strings.Replace(string(encoded), `"input":`, `"unknown":0,"input":`, 1),
		strings.Replace(string(encoded), `"samples":[`, `"samples":[`+strings.Repeat("null,", 2048), 1),
		strings.Repeat("[", 65) + strings.Repeat("]", 65),
		`{"` + strings.Repeat("k", 129) + `":0}`, `{"input":"` + strings.Repeat("x", 4097) + `"}`,
		string([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}),
	} {
		var decoded snapshotReportSource
		if snapshotReportDecode(raw, &decoded) {
			t.Fatal("noncanonical or unbounded source protocol accepted")
		}
	}
}
