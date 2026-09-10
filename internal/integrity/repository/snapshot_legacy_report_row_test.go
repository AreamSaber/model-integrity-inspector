package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
)

// Backing Run/result and tenant are real fixture lifecycle rows. The report is
// deliberately inserted with ONLY foundation's thirteen columns, not modern
// CreateReport/Freeze publication: this models retained historical metadata.
func snapshotLegacyReportFixture(t *testing.T, s *Store) (map[string]any, RunRecord) {
	t.Helper()
	_, _, run := snapshotReportTestFixture(t, s)
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	stamp := "2026-09-10 12:34:56.123456789+08:00"
	if s.driver == "postgres" {
		stamp = "2000-01-01 00:00:00.000001"
	}
	row := map[string]any{"id": id, "organization_id": run.OrganizationID, "run_id": run.ID, "analysis_revision": int64(1),
		"format": "historical-format", "schema_version": "original-schema", "revision": int64(1),
		"content_hash": nil, "storage_path": "private-locator-canary", "status": "ready", "error_code": nil,
		"created_at": stamp, "completed_at": nil}
	if err := s.db.Table("integrity_reports").Create(snapshotLegacyReportClone(row)).Error; err != nil {
		t.Fatal("insert original thirteen-column historical report", err)
	}
	return row, run
}

func snapshotLegacyReportReplace(t *testing.T, s *Store, original, row map[string]any) {
	t.Helper()
	if err := s.db.Exec("DELETE FROM integrity_reports WHERE id=?", original["id"]).Error; err != nil {
		t.Fatal("remove only isolated historical row", err)
	}
	if err := s.db.Table("integrity_reports").Create(snapshotLegacyReportClone(row)).Error; err != nil {
		t.Fatal("reinsert isolated original-shape report", err)
	}
}

func snapshotLegacyReportClone(row map[string]any) map[string]any {
	copy := make(map[string]any, len(row))
	for k, v := range row {
		copy[k] = v
	}
	return copy
}

func snapshotLegacyReportExpected(t *testing.T, driver string, values map[string]any) string {
	t.Helper()
	integer := func(name string) backupmanifest.LegacyReportRowInteger {
		if value, ok := values[name]; ok && value != nil {
			return backupmanifest.LegacyReportRowInteger{Present: true, Value: value.(int64)}
		}
		return backupmanifest.LegacyReportRowInteger{}
	}
	text := func(name string) backupmanifest.LegacyReportRowText {
		if value, ok := values[name]; ok && value != nil {
			data := value.(string)
			return backupmanifest.LegacyReportRowText{Present: true, Bytes: int64(len(data)), Reader: strings.NewReader(data)}
		}
		return backupmanifest.LegacyReportRowText{}
	}
	stamp := func(name string) backupmanifest.LegacyReportRowTime {
		v := text(name)
		if !v.Present || driver == "sqlite" {
			return backupmanifest.LegacyReportRowTime(v)
		}
		// Independently specified PostgreSQL timestamp binary vectors, never
		// timestamp_send/adapter metadata or driver time.Time round trips.
		var raw []byte
		switch values[name] {
		case "2000-01-01 00:00:00.000001":
			raw = []byte{0, 0, 0, 0, 0, 0, 0, 1}
		case "1999-12-31 23:59:59.999999":
			raw = bytes.Repeat([]byte{255}, 8)
		case "infinity":
			raw = []byte{127, 255, 255, 255, 255, 255, 255, 255}
		default:
			t.Fatal("fixture lacks an independent binary timestamp oracle")
		}
		return backupmanifest.LegacyReportRowTime{Present: true, Bytes: 8, Reader: bytes.NewReader(raw)}
	}
	r := backupmanifest.LegacyReportRow{DatabaseDriver: driver,
		ID: integer("id").Value, OrganizationID: integer("organization_id").Value, RunID: integer("run_id").Value, AnalysisRevision: integer("analysis_revision").Value,
		ReportFormat: text("format"), SchemaVersion: text("schema_version"), Revision: integer("revision").Value,
		ContentHash: text("content_hash"), StoragePath: text("storage_path"), Status: text("status"), ErrorCode: text("error_code"),
		CreatedAt: stamp("created_at"), CompletedAt: stamp("completed_at"), CreatedBy: integer("created_by"), JobID: integer("job_id"),
		SourceJSON: text("source_json"), SourceHash: text("source_hash"), FileHash: text("file_hash"), FileSize: integer("file_size"), FrozenAt: stamp("frozen_at")}
	sum, err := backupmanifest.DigestLegacyReportRow(t.Context(), r, backupmanifest.LegacyReportRowLimits{MaxBytes: backupmanifest.MaxFileBytes, Timeout: time.Second})
	if err != nil {
		t.Fatal("independent original-value hasher failed", err)
	}
	return sum
}

func snapshotLegacyReportRead(t *testing.T, s *Store, cfg Config, id int64) (snapshotLegacyReportDescriptor, error) {
	t.Helper()
	ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
	defer closeView()
	return s.snapshotLegacyReportRow(ctx, tx, id, backupmanifest.MaxFileBytes)
}

func TestSnapshotLegacyReportRowOriginalThirteenAndPartialValues(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		original, run := snapshotLegacyReportFixture(t, s)
		id := original["id"].(int64)
		got, err := snapshotLegacyReportRead(t, s, cfg, id)
		if err != nil || got.id != id || got.organizationID != run.OrganizationID || got.runID != run.ID || got.rowVersion != backupmanifest.LegacyReportRowVersion || got.rowSHA256 != snapshotLegacyReportExpected(t, cfg.Driver, original) {
			t.Fatal("original nullable historical row changed", err)
		}
		var optionalCount int
		if err := s.db.Raw("SELECT CASE WHEN created_by IS NULL AND job_id IS NULL AND source_json IS NULL AND source_hash IS NULL AND file_hash IS NULL AND file_size IS NULL AND frozen_at IS NULL THEN 7 ELSE 0 END FROM integrity_reports WHERE id=?", id).Scan(&optionalCount).Error; err != nil || optionalCount != 7 {
			t.Fatal("fixture did not preserve migration14 nulls")
		}
		partial := snapshotLegacyReportClone(original)
		partial["source_json"], partial["source_hash"], partial["file_size"] = "{ \"opaque\": 1 }\n", "not-a-modern-hash", int64(-1)
		partial["created_by"], partial["frozen_at"] = run.CreatedBy, nil
		snapshotLegacyReportReplace(t, s, original, partial)
		next, err := snapshotLegacyReportRead(t, s, cfg, id)
		if err != nil || next.rowSHA256 == got.rowSHA256 || next.rowSHA256 != snapshotLegacyReportExpected(t, cfg.Driver, partial) {
			t.Fatal("partial legacy columns normalized or promoted", err)
		}
		for _, value := range []any{next, &snapshotLegacyReportReader{}} {
			if strings.Contains(fmt.Sprintf("%#v", value), "private-locator-canary") {
				t.Fatal("private descriptor leaked locator")
			}
			if data, err := json.Marshal(value); err == nil || data != nil {
				t.Fatal("private descriptor serialized")
			}
			var log bytes.Buffer
			slog.New(slog.NewJSONHandler(&log, nil)).Info("test", "value", value)
			if strings.Contains(log.String(), "private-locator-canary") {
				t.Fatal("private reader logged locator")
			}
		}
	})
}

func TestSnapshotLegacyReportRowEachSourceColumnAndNullVersusEmpty(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		original, run := snapshotLegacyReportFixture(t, s)
		id := original["id"].(int64)
		base := snapshotLegacyReportExpected(t, cfg.Driver, original)
		var jobID int64
		if err := s.db.Table("integrity_jobs").Select("id").Where("organization_id=?", run.OrganizationID).Order("id").Limit(1).Scan(&jobID).Error; err != nil || jobID <= 0 {
			t.Fatal("find real same-organization job")
		}
		stamp := "2026-09-10 12:34:56.123456789+07:00"
		if cfg.Driver == "postgres" {
			stamp = "1999-12-31 23:59:59.999999"
		}
		mutations := []struct {
			name  string
			value any
		}{
			{"id", id + 100}, {"format", "historical-format "}, {"schema_version", "original-schema-v2"}, {"revision", int64(2)},
			{"content_hash", ""}, {"storage_path", ""}, {"status", "unknown-historical-state"}, {"error_code", ""},
			{"created_at", stamp}, {"completed_at", stamp}, {"created_by", run.CreatedBy}, {"job_id", jobID},
			{"source_json", ""}, {"source_hash", ""}, {"file_hash", ""}, {"file_size", int64(0)}, {"frozen_at", stamp},
		}
		for _, mutation := range mutations {
			t.Run(mutation.name, func(t *testing.T) {
				row := snapshotLegacyReportClone(original)
				row[mutation.name] = mutation.value
				snapshotLegacyReportReplace(t, s, original, row)
				got, err := snapshotLegacyReportRead(t, s, cfg, row["id"].(int64))
				if err != nil || got.rowSHA256 == base || got.rowSHA256 != snapshotLegacyReportExpected(t, cfg.Driver, row) {
					t.Fatal("original column absent from commitment", err)
				}
				snapshotLegacyReportReplace(t, s, row, original)
			})
		}
		// Changed declared parent identities must not be accepted with hashes
		// of another organization's history; corruption cases cover all three.
		for _, field := range []string{"organization_id", "run_id", "analysis_revision"} {
			if err := s.db.Exec("UPDATE integrity_reports SET "+field+"=? WHERE id=?", int64(999999), id).Error; err == nil {
				t.Fatal("real historical FK/immutability guard accepted mismatched parent")
			}
		}
		// Explicit NULL and empty values are different even for a locator that
		// was already present in the original thirteen columns.
		row := snapshotLegacyReportClone(original)
		row["storage_path"] = nil
		snapshotLegacyReportReplace(t, s, original, row)
		null, err := snapshotLegacyReportRead(t, s, cfg, id)
		if err != nil {
			t.Fatal(err)
		}
		row["storage_path"] = ""
		snapshotLegacyReportReplace(t, s, row, row)
		empty, err := snapshotLegacyReportRead(t, s, cfg, id)
		if err != nil || null.rowSHA256 == empty.rowSHA256 {
			t.Fatal("NULL locator became empty locator", err)
		}
	})
}

func TestSnapshotLegacyReportRowSameROViewAndPoollessStore(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		row, _ := snapshotLegacyReportFixture(t, s)
		id := row["id"].(int64)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		poolless := &Store{driver: s.driver}
		first, err := poolless.snapshotLegacyReportRow(ctx, tx.Where("1=0").Limit(1), id, backupmanifest.MaxFileBytes)
		if err != nil {
			t.Fatal("actual transaction escaped to Store pool", err)
		}
		changed := snapshotLegacyReportClone(row)
		changed["storage_path"] = "independently-committed-locator"
		snapshotLegacyReportReplace(t, s, row, changed)
		again, err := poolless.snapshotLegacyReportRow(ctx, tx, id, backupmanifest.MaxFileBytes)
		if err != nil || first != again {
			t.Fatal("snapshot drifted to independently committed row", err)
		}
		closeView()
		fresh, err := snapshotLegacyReportRead(t, s, cfg, id)
		if err != nil || fresh.rowSHA256 == first.rowSHA256 || fresh.rowSHA256 != snapshotLegacyReportExpected(t, cfg.Driver, changed) {
			t.Fatal("new view did not observe committed raw row", err)
		}
		if got, err := s.snapshotLegacyReportRow(ctx, tx, id, backupmanifest.MaxFileBytes); err == nil || got != (snapshotLegacyReportDescriptor{}) {
			t.Fatal("closed caller transaction returned descriptor")
		}
		_, tx, closeView = auditSnapshotTestTransaction(t, cfg, nil, true)
		if err := tx.Exec("UPDATE integrity_reports SET status=status WHERE id=?", id).Error; err == nil {
			t.Fatal("actual RO transaction accepted write")
		}
		closeView()
	})
}

func TestSnapshotLegacyReportRowLargeOpaqueSourceUsesSQLSlices(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		row, _ := snapshotLegacyReportFixture(t, s)
		id := row["id"].(int64)
		row["source_json"] = strings.Repeat("opaque\x00invalid-json\xff", (5<<20)/20+3)
		if cfg.Driver == "postgres" {
			row["source_json"] = strings.Repeat("opaque invalid-json ", (5<<20)/20+3)
		}
		snapshotLegacyReportReplace(t, s, row, row)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		var largest, slices int
		if err := tx.Callback().Row().After("gorm:row").Register("legacy_row_observe_slices", func(q *gorm.DB) {
			if strings.Contains(q.Statement.SQL.String(), " AS data FROM integrity_reports") {
				slices++
			}
		}); err != nil {
			t.Fatal(err)
		}
		got, err := s.snapshotLegacyReportRow(ctx, tx, id, backupmanifest.MaxFileBytes)
		if err != nil || got.rowSHA256 != snapshotLegacyReportExpected(t, cfg.Driver, row) || slices < 80 {
			t.Fatal("large opaque source was truncated/decoded or not sliced", err, slices)
		}
		// A fresh borrowed reader is inspected directly in this same real tx;
		// its bounded SQL interface is independent of the hasher's buffer size.
		r := &snapshotLegacyReportReader{ctx: ctx, tx: tx, descriptor: got, column: snapshotLegacyReportColumns[15], size: int64(len(row["source_json"].(string)))}
		buffer := make([]byte, 2<<20)
		for {
			n, err := r.Read(buffer)
			largest = max(largest, n)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					t.Fatal(err)
				}
				break
			}
		}
		if largest > 64<<10 || r.offset != r.size {
			t.Fatal("oversized consumer bypassed fixed SQL slice limit")
		}
	})
}

// Only this isolated fixture's report table is replaced; original constraints
// are first shown to reject mutation. All copy/table operations remain inside
// the test schema/file. Actual PostgreSQL scalar types are preserved by CTAS.
func snapshotLegacyReportCorruptible(t *testing.T, s *Store, id int64) {
	t.Helper()
	if err := s.db.Exec("UPDATE integrity_reports SET status=status WHERE id=?", id).Error; err == nil {
		t.Fatal("ready report lacked immutable guard")
	}
	for _, query := range []string{"ALTER TABLE integrity_reports RENAME TO legacy_row_original", "CREATE TABLE integrity_reports AS SELECT * FROM legacy_row_original"} {
		if err := s.db.Exec(query).Error; err != nil {
			t.Fatal("prepare isolated offline-corruption copy", err)
		}
	}
	t.Cleanup(func() {
		for _, query := range []string{"DROP TABLE integrity_reports", "ALTER TABLE legacy_row_original RENAME TO integrity_reports"} {
			if err := s.db.Exec(query).Error; err != nil {
				t.Error("restore isolated report source table", err)
			}
		}
	})
}

func snapshotLegacyReportResetCopy(t *testing.T, s *Store) {
	t.Helper()
	for _, query := range []string{"DROP TABLE integrity_reports", "CREATE TABLE integrity_reports AS SELECT * FROM legacy_row_original"} {
		if err := s.db.Exec(query).Error; err != nil {
			t.Fatal("reset only isolated corruptible table", err)
		}
	}
}

func TestSnapshotLegacyReportRowOriginalTypesAndForeignBindings(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		row, run := snapshotLegacyReportFixture(t, s)
		id := row["id"].(int64)
		snapshotLegacyReportCorruptible(t, s, id)
		var organization Organization
		if err := s.db.Where("id=?", run.OrganizationID).Take(&organization).Error; err != nil {
			t.Fatal(err)
		}
		organization.ID, _ = NewID()
		organization.Status = "disabled"
		if err := s.db.Create(&organization).Error; err != nil {
			t.Fatal(err)
		}
		foreignJob, _ := NewID()
		stamp := time.Now().UTC().Truncate(time.Microsecond)
		if err := s.db.Table("integrity_jobs").Create(map[string]any{"id": foreignJob, "organization_id": organization.ID, "type": "historical.job", "object_id": id, "idempotency_key": "legacy-foreign-job", "status": "failed", "available_at": stamp, "created_at": stamp, "updated_at": stamp}).Error; err != nil {
			t.Fatal("create actual other-organization retained job", err)
		}
		cases := []struct {
			name, column string
			value        any
			want         error
		}{
			{"organization_id", "organization_id", organization.ID, errSnapshotLegacyReportInvalid},
			{"run_id", "run_id", run.ID + 9999, errSnapshotLegacyReportInvalid},
			{"analysis_revision", "analysis_revision", int64(2), errSnapshotLegacyReportInvalid},
			{"created_by", "created_by", int64(999999), errSnapshotLegacyReportInvalid},
			{"job_foreign_organization", "job_id", foreignJob, errSnapshotLegacyReportInvalid},
			{"required_null", "format", nil, errSnapshotLegacyReportInvalid},
		}
		if cfg.Driver == "sqlite" {
			cases = append(cases,
				struct {
					name, column string
					value        any
					want         error
				}{"integer_blob", "organization_id", bytes.Repeat([]byte{1}, 1<<20), errSnapshotLegacyReportInvalid},
				struct {
					name, column string
					value        any
					want         error
				}{"integer_real", "revision", 1.5, errSnapshotLegacyReportInvalid},
				struct {
					name, column string
					value        any
					want         error
				}{"text_blob", "source_json", []byte("original-text-must-not-be-blob"), errSnapshotLegacyReportInvalid},
				struct {
					name, column string
					value        any
					want         error
				}{"timestamp_blob", "created_at", []byte("2026-09-10"), errSnapshotLegacyReportUnsupported},
				struct {
					name, column string
					value        any
					want         error
				}{"timestamp_integer", "completed_at", int64(123), errSnapshotLegacyReportUnsupported})
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				snapshotLegacyReportResetCopy(t, s)
				if err := s.db.Exec("UPDATE integrity_reports SET "+tc.column+"=? WHERE id=?", tc.value, id).Error; err != nil {
					t.Fatal("install actual isolated row damage", err)
				}
				ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
				defer closeView()
				chunks := 0
				if err := tx.Callback().Row().Before("gorm:row").Register("legacy_no_body_before_shape", func(q *gorm.DB) {
					if strings.Contains(q.Statement.SQL.String(), " AS data FROM integrity_reports") {
						chunks++
					}
				}); err != nil {
					t.Fatal(err)
				}
				got, err := s.snapshotLegacyReportRow(ctx, tx, id, backupmanifest.MaxFileBytes)
				if !errors.Is(err, tc.want) || got != (snapshotLegacyReportDescriptor{}) || chunks != 0 {
					t.Fatal("bad original type/binding crossed into body reads or returned identity", err, chunks)
				}
			})
		}
		snapshotLegacyReportResetCopy(t, s)
		if err := s.db.Exec("INSERT INTO integrity_reports SELECT * FROM legacy_row_original").Error; err != nil {
			t.Fatal(err)
		}
		if got, err := snapshotLegacyReportRead(t, s, cfg, id); err == nil || got != (snapshotLegacyReportDescriptor{}) {
			t.Fatal("duplicate original identity returned a descriptor")
		}
	})
}

func TestSnapshotLegacyReportRowLateSQLFailureCancellationAndRollback(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		row, _ := snapshotLegacyReportFixture(t, s)
		id := row["id"].(int64)
		row["source_json"] = strings.Repeat("late-source-body-", 15000)
		row["frozen_at"] = row["created_at"]
		snapshotLegacyReportReplace(t, s, row, row)
		for _, mode := range []string{"sql_error", "cancel", "rollback_last_time", "truncate", "extra", "missing_chunk_row"} {
			t.Run(mode, func(t *testing.T) {
				ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
				defer closeView()
				child, cancel := context.WithCancel(ctx)
				defer cancel()
				var sourceSlices int
				reached := false
				if err := tx.Callback().Row().Before("gorm:row").Register("legacy_late_actual_sql_fault", func(q *gorm.DB) {
					query := q.Statement.SQL.String()
					if !strings.Contains(query, " AS data FROM integrity_reports") {
						return
					}
					if strings.Contains(query, "r.source_json") {
						sourceSlices++
					}
					lastTime := strings.Contains(query, "r.frozen_at")
					if reached || mode == "rollback_last_time" && !lastTime || mode != "rollback_last_time" && sourceSlices != 2 {
						return
					}
					reached = true
					switch mode {
					case "cancel":
						cancel()
					case "rollback_last_time":
						if err := tx.Statement.ConnPool.(*sql.Tx).Rollback(); err != nil {
							t.Error("actual caller rollback", err)
						}
					case "sql_error":
						q.Statement.SQL.Reset()
						q.Statement.SQL.WriteString("SELECT missing_private_row_canary_column FROM integrity_reports")
						q.Statement.Vars = nil
					case "truncate":
						q.Statement.SQL.Reset()
						if cfg.Driver == "sqlite" {
							q.Statement.SQL.WriteString("SELECT CAST('' AS BLOB) AS data FROM integrity_reports LIMIT 1")
						} else {
							q.Statement.SQL.WriteString("SELECT ''::bytea AS data FROM integrity_reports LIMIT 1")
						}
						q.Statement.Vars = nil
					case "extra":
						q.Statement.Vars[1] = snapshotLegacyReportChunkBytes + 1
					case "missing_chunk_row":
						q.Statement.SQL.Reset()
						if cfg.Driver == "sqlite" {
							q.Statement.SQL.WriteString("SELECT CAST('' AS BLOB) AS data FROM integrity_reports WHERE 1=0")
						} else {
							q.Statement.SQL.WriteString("SELECT ''::bytea AS data FROM integrity_reports WHERE FALSE")
						}
						q.Statement.Vars = nil
					}
				}); err != nil {
					t.Fatal(err)
				}
				got, err := s.snapshotLegacyReportRow(child, tx, id, backupmanifest.MaxFileBytes)
				if err == nil || got != (snapshotLegacyReportDescriptor{}) || !reached || sourceSlices < 2 {
					t.Fatal("late real SQL failure was not reached or exposed partial result", err, reached, sourceSlices)
				}
				if strings.Contains(err.Error(), "private_row_canary") {
					t.Fatal("SQL error text leaked")
				}
			})
		}
	})
}

func TestSnapshotLegacyReportRowPostgresRejectsImplicitTimestampConversion(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		if cfg.Driver != "postgres" {
			t.Skip("PostgreSQL native type guard")
		}
		row, _ := snapshotLegacyReportFixture(t, s)
		id := row["id"].(int64)
		snapshotLegacyReportCorruptible(t, s, id)
		for _, kind := range []string{"text", "date", "timestamp with time zone"} {
			t.Run(kind, func(t *testing.T) {
				snapshotLegacyReportResetCopy(t, s)
				if err := s.db.Exec("ALTER TABLE integrity_reports ALTER COLUMN created_at TYPE " + kind + " USING CAST(created_at AS " + kind + ")").Error; err != nil {
					t.Fatal(err)
				}
				got, err := snapshotLegacyReportRead(t, s, cfg, id)
				if !errors.Is(err, errSnapshotLegacyReportUnsupported) || got != (snapshotLegacyReportDescriptor{}) {
					t.Fatal("timestamp_send could implicitly reinterpret another original SQL type", err)
				}
			})
		}
	})
}

func TestSnapshotLegacyReportRowGuardsReturnNoDescriptor(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		row, _ := snapshotLegacyReportFixture(t, s)
		id := row["id"].(int64)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		for _, tc := range []struct {
			ctx       context.Context
			tx        *gorm.DB
			id, limit int64
		}{
			{nil, tx, id, 1}, {context.Background(), tx, id, 1}, {ctx, nil, id, 1}, {ctx, s.db, id, 1},
			{ctx, tx, 0, 1}, {ctx, tx, id, 0}, {ctx, tx, id, backupmanifest.MaxFileBytes + 1},
		} {
			if got, err := s.snapshotLegacyReportRow(tc.ctx, tc.tx, tc.id, tc.limit); !errors.Is(err, ErrConfiguration) || got != (snapshotLegacyReportDescriptor{}) {
				t.Fatal("guard returned usable descriptor", err)
			}
		}
		for _, candidate := range []int64{id + 999999, id} {
			got, err := s.snapshotLegacyReportRow(ctx, tx, candidate, 1)
			if err == nil || got != (snapshotLegacyReportDescriptor{}) {
				t.Fatal("missing row or insufficient framing budget passed")
			}
		}
		typedNil := tx.Session(&gorm.Session{NewDB: true, Initialized: true})
		typedNil.Statement.ConnPool = (*sql.Tx)(nil)
		if got, err := s.snapshotLegacyReportRow(ctx, typedNil, id, backupmanifest.MaxFileBytes); !errors.Is(err, ErrConfiguration) || got != (snapshotLegacyReportDescriptor{}) {
			t.Fatal("typed nil transaction passed")
		}
		if !reflect.DeepEqual(row["storage_path"], "private-locator-canary") {
			t.Fatal("fixture unexpectedly changed")
		}
	})
}

func TestSnapshotLegacyReportRowPostgresTimestampSendOracle(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		if cfg.Driver != "postgres" {
			t.Skip("native PostgreSQL binary protocol case")
		}
		row, _ := snapshotLegacyReportFixture(t, s)
		id := row["id"].(int64)
		for _, value := range []string{"2000-01-01 00:00:00.000001", "1999-12-31 23:59:59.999999", "infinity"} {
			row["created_at"], row["completed_at"], row["frozen_at"] = value, value, value
			snapshotLegacyReportReplace(t, s, row, row)
			got, err := snapshotLegacyReportRead(t, s, cfg, id)
			if err != nil || got.rowSHA256 != snapshotLegacyReportExpected(t, cfg.Driver, row) {
				t.Fatal("native timestamp bytes differ from independent epoch/infinity oracle", err)
			}
			var raw struct{ Data []byte }
			if err := s.db.Raw("SELECT pg_catalog.timestamp_send(created_at) AS data FROM integrity_reports WHERE id=?", id).Scan(&raw).Error; err != nil || len(raw.Data) != 8 {
				t.Fatal("actual timestamp binary not eight bytes")
			}
			t.Logf("timestamp fixture binary=%s", hex.EncodeToString(raw.Data))
		}
	})
}

func TestSnapshotLegacyReportRowSQLiteTimestampOriginalBytes(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		if cfg.Driver != "sqlite" {
			t.Skip("SQLite original TEXT storage case")
		}
		row, _ := snapshotLegacyReportFixture(t, s)
		id := row["id"].(int64)
		seen := map[string]bool{}
		for _, stamp := range []string{"2026-09-10 12:34:56.123456789+08:00", "2026-09-10 12:34:56.123456789+07:00", "2026-09-10 12:34:56.123456788+08:00", "2026-09-10T12:34:56.123456789+08:00", "", "unchanged\x00timestamp\xff"} {
			row["created_at"], row["completed_at"], row["frozen_at"] = stamp, stamp, stamp
			snapshotLegacyReportReplace(t, s, row, row)
			got, err := snapshotLegacyReportRead(t, s, cfg, id)
			if err != nil || seen[got.rowSHA256] || got.rowSHA256 != snapshotLegacyReportExpected(t, cfg.Driver, row) {
				t.Fatal("time parser or TEXT encoding changed original bytes", err)
			}
			seen[got.rowSHA256] = true
		}
	})
}
