package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
)

// Seed only original foundation columns, not a fake modern publication. These
// rows model retained unverified history and do not claim any existing file.
func snapshotCompleteTestLegacy(t *testing.T, s *Store, run RunRecord, id int64) map[string]any {
	t.Helper()
	stamp := "2026-09-10 12:34:56.123456789+08:00"
	if s.driver == "postgres" {
		stamp = "2000-01-01 00:00:00.000001"
	}
	return map[string]any{"id": id, "organization_id": run.OrganizationID, "run_id": run.ID, "analysis_revision": int64(1),
		"format": "opaque-historical-format", "schema_version": "original-schema", "revision": id,
		"content_hash": nil, "storage_path": "private-complete-locator-canary", "status": "ready", "error_code": nil,
		"created_at": stamp, "completed_at": nil}
}

func snapshotCompleteTestInsert(t *testing.T, s *Store, row map[string]any) {
	t.Helper()
	if err := s.db.Table("integrity_reports").Create(snapshotLegacyReportClone(row)).Error; err != nil {
		t.Fatal("insert retained original report", err)
	}
}

func snapshotCompleteTestObserve(t *testing.T, s *Store, cfg Config, want error) snapshotCompleteReportInventory {
	t.Helper()
	ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
	defer closeView()
	got, err := s.snapshotCompleteReportInventory(ctx, tx)
	if !errors.Is(err, want) || want != nil && (err.Error() != want.Error() || !reflect.DeepEqual(got, snapshotCompleteReportInventory{})) {
		t.Fatal("complete inventory error/zero-result contract", err)
	}
	return got
}

func TestSnapshotCompleteReportInventoryMixed101OriginalAndSameView(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, q, run := snapshotReportTestFixture(t, s)
		modern := make([]ReportRecord, 0, 3)
		for i, format := range []string{"json", "html", "csv"} {
			modern = append(modern, snapshotReportTestPublish(t, tenant, q, run, format, i))
		}
		expected := make(map[int64]string, 98)
		for id := int64(1); id <= 98; id++ {
			row := snapshotCompleteTestLegacy(t, s, run, id)
			if id == 98 {
				row["source_json"] = strings.Repeat("opaque not-json \r\n", 320000)
				row["source_hash"], row["file_size"], row["created_by"] = "original-declared-not-sha", int64(-1), run.CreatedBy
			}
			snapshotCompleteTestInsert(t, s, row)
			expected[id] = snapshotLegacyReportExpected(t, cfg.Driver, row)
		}
		queued := snapshotCompleteTestLegacy(t, s, run, 1000)
		queued["status"] = "queued"
		snapshotCompleteTestInsert(t, s, queued)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		pages := []int{}
		if err := tx.Callback().Query().After("gorm:query").Register("complete_mixed_pages", func(query *gorm.DB) {
			if p, ok := query.Statement.Dest.(*[]snapshotReportRow); ok {
				pages = append(pages, len(*p))
			}
		}); err != nil {
			t.Fatal(err)
		}
		poolless := &Store{driver: cfg.Driver}
		got, err := poolless.snapshotCompleteReportInventory(ctx, tx.Where("1=0").Select("id").Limit(1).Order("r.id DESC"))
		if err != nil || len(got.modern) != 3 || len(got.legacy) != 98 || !reflect.DeepEqual(pages, []int{100, 1}) {
			t.Fatal("mixed ready pages incomplete", err, pages)
		}
		for _, entry := range got.legacy {
			if entry.row.rowSHA256 != expected[entry.row.id] || entry.row.rowVersion != backupmanifest.LegacyReportRowVersion || entry.row.organizationID != run.OrganizationID || entry.row.runID != run.ID || entry.verification != backupmanifest.LegacyReportUnverified || entry.fileState != backupmanifest.LegacyReportFileUnmapped {
				t.Fatal("legacy raw bytes/identity/classification changed")
			}
		}
		for _, original := range modern {
			index := slices.IndexFunc(got.modern, func(e snapshotReportEntry) bool { return e.id == original.ID })
			if index < 0 || got.modern[index].fileHash != *original.FileHash || got.modern[index].contentHash != *original.ContentHash || got.modern[index].fileSize != *original.FileSize || got.modern[index].sourceHash != *original.SourceHash || got.modern[index].format != original.FormatName {
				t.Fatal("modern original byte evidence changed")
			}
		}
		owned := snapshotCompleteReportInventory{slices.Clone(got.modern), slices.Clone(got.legacy)}
		got.modern[0].fileHash, got.legacy[0].row.rowSHA256 = "caller-change", "caller-change"
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		snapshotCompleteTestInsert(t, other, snapshotCompleteTestLegacy(t, other, run, 99))
		if err := other.db.Table("organizations").Where("id=?", tenant.orgID).Update("status", "disabled").Error; err != nil {
			t.Fatal(err)
		}
		again, err := poolless.snapshotCompleteReportInventory(ctx, tx)
		if err != nil || !reflect.DeepEqual(again, owned) {
			t.Fatal("other connection changed old read view or result ownership", err)
		}
		var one int
		if err := tx.Raw("SELECT 1").Scan(&one).Error; err != nil || one != 1 {
			t.Fatal("inventory ended caller transaction")
		}
		closeView()
		latest := snapshotCompleteTestObserve(t, poolless, cfg, nil)
		if len(latest.modern) != 3 || len(latest.legacy) != 99 {
			t.Fatal("new view omitted disabled tenant history")
		}
		// Existing strict API still rejects history; its semantics were not changed.
		snapshotReportTestFailure(t, s, cfg, errSnapshotReportUnsupported)
		for _, original := range modern {
			if current := csvRepositoryStored(t, s, original.OrganizationID, original.ID); !reflect.DeepEqual(original, current) {
				t.Fatal("observer rewrote publication")
			}
		}
	})
}

func TestSnapshotCompleteReportInventoryNullableClassificationNoDowngrade(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, q, run := snapshotReportTestFixture(t, s)
		modern := snapshotReportTestPublish(t, tenant, q, run, "json", 1)
		snapshotLegacyReportCorruptible(t, s, modern.ID)
		for _, column := range []string{"created_by", "job_id", "source_json", "source_hash", "file_hash", "file_size", "frozen_at"} {
			t.Run("null_"+column, func(t *testing.T) {
				snapshotLegacyReportResetCopy(t, s)
				if err := s.db.Exec("UPDATE integrity_reports SET "+column+"=NULL WHERE id=?", modern.ID).Error; err != nil {
					t.Fatal(err)
				}
				got := snapshotCompleteTestObserve(t, s, cfg, nil)
				if len(got.modern) != 0 || len(got.legacy) != 1 || got.legacy[0].verification != backupmanifest.LegacyReportUnverified || got.legacy[0].fileState != backupmanifest.LegacyReportFileUnmapped {
					t.Fatal("partial metadata promoted or lost")
				}
				ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
				defer closeView()
				direct, err := s.snapshotLegacyReportRow(ctx, tx, modern.ID, backupmanifest.MaxFileBytes)
				if err != nil || direct != got.legacy[0].row {
					t.Fatal("classification changed complete original row commitment", err)
				}
			})
		}
		for _, mutation := range []struct {
			column string
			value  any
		}{{"file_hash", "bad"}, {"source_json", "{}"}, {"schema_version", "future-report-schema"}, {"format", "pdf"}, {"file_size", int64(0)}, {"created_by", int64(0)}} {
			t.Run("complete_invalid_"+mutation.column, func(t *testing.T) {
				snapshotLegacyReportResetCopy(t, s)
				snapshotCompleteTestInsert(t, s, snapshotCompleteTestLegacy(t, s, run, 1))
				if err := s.db.Exec("UPDATE integrity_reports SET "+mutation.column+"=? WHERE id=?", mutation.value, modern.ID).Error; err != nil {
					t.Fatal(err)
				}
				snapshotCompleteTestObserve(t, s, cfg, errSnapshotReportInvalid)
			})
		}
	})
}

func TestSnapshotCompleteReportInventoryEmptyTransactionAndLimits(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		if got, err := s.snapshotCompleteReportInventory(ctx, tx); err != nil || len(got.modern)+len(got.legacy) != 0 {
			t.Fatal("empty complete inventory", err)
		}
		typedNil := tx.Session(&gorm.Session{NewDB: true, Initialized: true})
		typedNil.Statement.ConnPool = (*sql.Tx)(nil)
		for _, tc := range []struct {
			ctx   context.Context
			tx    *gorm.DB
			limit int
			bytes int64
		}{
			{nil, tx, 1, 100}, {context.Background(), tx, 1, 100}, {ctx, nil, 1, 100}, {ctx, typedNil, 1, 100}, {ctx, s.db, 1, 100},
			{ctx, tx, 0, 100}, {ctx, tx, snapshotReportMaxEntries + 1, 100}, {ctx, tx, 1, 0}, {ctx, tx, 1, backupmanifest.MaxFileBytes + 1},
		} {
			got, err := s.snapshotCompleteReportInventoryLimited(tc.ctx, tc.tx, tc.limit, tc.bytes)
			if !errors.Is(err, ErrConfiguration) || !reflect.DeepEqual(got, snapshotCompleteReportInventory{}) {
				t.Fatal("invalid configuration accepted", err)
			}
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if got, err := s.snapshotCompleteReportInventory(canceled, tx); !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, snapshotCompleteReportInventory{}) {
			t.Fatal("canceled empty view produced candidate")
		}
		closeView()
		if got, err := s.snapshotCompleteReportInventory(ctx, tx); err == nil || !reflect.DeepEqual(got, snapshotCompleteReportInventory{}) {
			t.Fatal("closed transaction produced candidate")
		}
	})
}

func TestSnapshotCompleteReportInventoryFormatting(t *testing.T) {
	entry := snapshotCompleteLegacyReportEntry{row: snapshotLegacyReportDescriptor{rowSHA256: "private-complete-canary"}}
	inventory := snapshotCompleteReportInventory{modern: []snapshotReportEntry{{objectName: "private-complete-canary"}}, legacy: []snapshotCompleteLegacyReportEntry{entry}}
	for _, item := range []any{entry, &entry, inventory, &inventory} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if strings.Contains(fmt.Sprintf(format, item), "canary") {
				t.Fatal("private candidate formatted")
			}
		}
		if _, err := json.Marshal(item); err == nil {
			t.Fatal("private candidate JSON serialized")
		}
		if _, err := yaml.Marshal(item); err == nil {
			t.Fatal("private candidate YAML serialized")
		}
		var log bytes.Buffer
		slog.New(slog.NewJSONHandler(&log, nil)).Info("candidate", "candidate", item)
		if strings.Contains(log.String(), "canary") {
			t.Fatal("private candidate logged")
		}
	}
}
