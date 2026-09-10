package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
	"model-integrity-inspector.local/mii/migrations"
)

func snapshotMigrationTestFailure(t *testing.T, s *Store, cfg Config, want error) {
	t.Helper()
	// This existing fixture verifies native SQLite IsReadOnly before BeginTx;
	// both dialects then own an actual dedicated database/sql read transaction.
	ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
	defer closeView()
	got, err := s.snapshotMigrationInventory(ctx, tx)
	if !errors.Is(err, want) || got.entries != nil {
		t.Fatalf("migration inventory failure classification/zero result: %v", err)
	}
}

func TestSnapshotMigrationInventoryExactOwnedAndSameView(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		// No initialization or audit signer is required for this narrow history
		// projection. Neither fact can be inferred from its successful result.
		expected, err := migrations.ForDialect(cfg.Driver)
		if err != nil || len(expected) == 0 {
			t.Fatal("load compiled dialect history")
		}
		var original []SchemaVersion
		if err := s.db.Table("schema_migrations").Order("version").Find(&original).Error; err != nil {
			t.Fatal("read independent original test history")
		}
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		poolless := &Store{driver: cfg.Driver}
		got, err := poolless.snapshotMigrationInventory(ctx, tx.Where("1=0").Limit(1).Order("version DESC").Select("version"))
		if err != nil || len(got.entries) != len(expected) {
			t.Fatalf("complete history without any usable Store pool: %v", err)
		}
		for i, row := range got.entries {
			if row.version != expected[i].Version || row.name != expected[i].Name || row.checksum != expected[i].Checksum {
				t.Fatal("migration identity/order does not equal compiled dialect chain")
			}
		}
		owned := slices.Clone(got.entries)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal("open independent migration writer")
		}
		defer func() { _ = other.Close() }()
		changed := other.db.Table("schema_migrations").Where("version=?", expected[len(expected)-1].Version).Update("checksum", strings.Repeat("f", 64))
		if changed.Error != nil || changed.RowsAffected != 1 {
			t.Fatal("commit independent migration-history change")
		}
		got.entries[0].name = "owned-result-canary"
		again, err := poolless.snapshotMigrationInventory(ctx, tx)
		if err != nil || !reflect.DeepEqual(again.entries, owned) {
			t.Fatal("history used newer live state or aliased earlier owned result")
		}
		var one int
		if err := tx.Raw("SELECT 1").Scan(&one).Error; err != nil || one != 1 {
			t.Fatal("inventory ended its caller-owned transaction")
		}
		closeView()
		snapshotMigrationTestFailure(t, s, cfg, ErrSchemaMismatch)
		if err := other.db.Table("schema_migrations").Where("version=?", expected[len(expected)-1].Version).Update("checksum", expected[len(expected)-1].Checksum).Error; err != nil {
			t.Fatal("restore independently changed test history")
		}
		var after []SchemaVersion
		if err := s.db.Table("schema_migrations").Order("version").Find(&after).Error; err != nil || !reflect.DeepEqual(after, original) {
			t.Fatal("read-only inventory changed migration rows or applied timestamps")
		}
	})
}

// Replace ONLY this eachDatabase fixture's ledger after proving its real
// constraints reject the malformed writes. The original immutable migration
// source files are never changed; the retained table restores the exact rows.
func snapshotMigrationTestCorruptible(t *testing.T, s *Store) {
	t.Helper()
	for _, statement := range []string{
		"UPDATE schema_migrations SET version=NULL WHERE version=1",
		"UPDATE schema_migrations SET version=0 WHERE version=1",
		"UPDATE schema_migrations SET version=-1 WHERE version=1",
		"UPDATE schema_migrations SET version=2 WHERE version=1",
		"UPDATE schema_migrations SET name=NULL WHERE version=1",
		"UPDATE schema_migrations SET checksum=NULL WHERE version=1",
		"UPDATE schema_migrations SET status=NULL WHERE version=1",
		"UPDATE schema_migrations SET status='failed' WHERE version=1",
		"UPDATE schema_migrations SET applied_at=NULL WHERE version=1",
	} {
		if err := s.db.Exec(statement).Error; err == nil {
			t.Fatal("normal test ledger did not reject malformed write")
		}
	}
	for _, statement := range []string{
		"ALTER TABLE schema_migrations RENAME TO snapshot_migration_original",
		"CREATE TABLE schema_migrations (version BIGINT, name TEXT, checksum TEXT, status TEXT, applied_at TIMESTAMP)",
		"INSERT INTO schema_migrations SELECT * FROM snapshot_migration_original",
	} {
		if err := s.db.Exec(statement).Error; err != nil {
			t.Fatal("prepare isolated unconstrained migration-history corruption fixture")
		}
	}
	t.Cleanup(func() {
		for _, statement := range []string{"DROP TABLE schema_migrations", "ALTER TABLE snapshot_migration_original RENAME TO schema_migrations"} {
			if err := s.db.Exec(statement).Error; err != nil {
				t.Error("restore original constrained migration history in isolated fixture")
			}
		}
	})
}

func snapshotMigrationTestResetRows(t *testing.T, s *Store) {
	t.Helper()
	for _, statement := range []string{"DELETE FROM schema_migrations", "INSERT INTO schema_migrations SELECT * FROM snapshot_migration_original"} {
		if err := s.db.Exec(statement).Error; err != nil {
			t.Fatal("restore isolated corruption fixture rows")
		}
	}
}

func TestSnapshotMigrationInventoryRejectsActualMalformedHistory(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		snapshotMigrationTestCorruptible(t, s)
		for _, tc := range []struct{ name, statement string }{
			{"empty", "DELETE FROM schema_migrations"},
			{"missing_first", "DELETE FROM schema_migrations WHERE version=1"},
			{"missing_middle", "DELETE FROM schema_migrations WHERE version=2"},
			{"missing_last", "DELETE FROM schema_migrations WHERE version=(SELECT MAX(version) FROM schema_migrations)"},
			{"extra", "INSERT INTO schema_migrations SELECT version+1000,name,checksum,status,applied_at FROM schema_migrations WHERE version=1"},
			{"duplicate", "INSERT INTO schema_migrations SELECT * FROM schema_migrations WHERE version=1"},
			{"name", "UPDATE schema_migrations SET name='wrong_name' WHERE version=2"},
			{"checksum", "UPDATE schema_migrations SET checksum='wrong_checksum' WHERE version=2"},
			{"status", "UPDATE schema_migrations SET status='failed' WHERE version=2"},
			{"null_version", "UPDATE schema_migrations SET version=NULL WHERE version=2"},
			{"null_name", "UPDATE schema_migrations SET name=NULL WHERE version=2"},
			{"null_checksum", "UPDATE schema_migrations SET checksum=NULL WHERE version=2"},
			{"null_status", "UPDATE schema_migrations SET status=NULL WHERE version=2"},
			{"null_applied_at", "UPDATE schema_migrations SET applied_at=NULL WHERE version=2"},
			{"zero_version", "UPDATE schema_migrations SET version=0 WHERE version=2"},
			{"negative_version", "UPDATE schema_migrations SET version=-1 WHERE version=2"},
			{"huge_version", "UPDATE schema_migrations SET version=9223372036854775807 WHERE version=2"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := s.db.Exec(tc.statement).Error; err != nil {
					t.Fatal("write actual malformed migration row into isolated fixture")
				}
				snapshotMigrationTestFailure(t, s, cfg, ErrSchemaMismatch)
				snapshotMigrationTestResetRows(t, s)
			})
		}
		if cfg.Driver == "sqlite" {
			for _, statement := range []string{
				"UPDATE schema_migrations SET version=1.5 WHERE version=2",
				"UPDATE schema_migrations SET version=X'32' WHERE version=2",
				"UPDATE schema_migrations SET name=CAST(name AS BLOB) WHERE version=2",
				"UPDATE schema_migrations SET checksum=CAST(checksum AS BLOB) WHERE version=2",
				"UPDATE schema_migrations SET status=CAST(status AS BLOB) WHERE version=2",
			} {
				if err := s.db.Exec(statement).Error; err != nil {
					t.Fatal("write actual SQLite dynamic-type corruption")
				}
				snapshotMigrationTestFailure(t, s, cfg, ErrSchemaMismatch)
				snapshotMigrationTestResetRows(t, s)
			}
		}
	})
}

func TestSnapshotMigrationInventorySQLTextAndCountBounds(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		snapshotMigrationTestCorruptible(t, s)
		for _, field := range []struct {
			name, statement string
			limit           int
		}{
			{"name", "UPDATE schema_migrations SET name=? WHERE version=1", 64},
			{"checksum", "UPDATE schema_migrations SET checksum=? WHERE version=1", 64},
			{"status", "UPDATE schema_migrations SET status=? WHERE version=1", 7},
		} {
			for _, size := range []int{field.limit, field.limit + 1} {
				data := strings.Repeat("x", size)
				if err := s.db.Exec(field.statement, data).Error; err != nil {
					t.Fatal("write exact scalar SQL boundary fixture")
				}
				_, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
				var rows []snapshotMigrationRow
				err := tx.Table("schema_migrations").Select(snapshotMigrationColumns(tx)).Where("version=1").Limit(1).Find(&rows).Error
				closeView()
				if err != nil || len(rows) != 1 {
					t.Fatal("read scalar SQL boundary projection")
				}
				value := rows[0].Name
				switch field.name {
				case "checksum":
					value = rows[0].Checksum
				case "status":
					value = rows[0].Status
				}
				want := data
				if size > field.limit {
					want = "\n"
				}
				if value != want {
					t.Fatal("SQL scalar boundary accepted overflow or truncated valid-length bytes")
				}
				snapshotMigrationTestResetRows(t, s)
			}
		}
		for _, tc := range []struct {
			name, statement string
			data            string
		}{
			{"name", "UPDATE schema_migrations SET name=? WHERE version=1", strings.Repeat("x", 1<<20)},
			{"checksum", "UPDATE schema_migrations SET checksum=? WHERE version=1", strings.Repeat("x", 1<<20)},
			{"status", "UPDATE schema_migrations SET status=? WHERE version=1", strings.Repeat("x", 1<<20)},
			{"name_utf8_bytes", "UPDATE schema_migrations SET name=? WHERE version=1", strings.Repeat("界", 22)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := s.db.Exec(tc.statement, tc.data).Error; err != nil {
					t.Fatal("write real overlong scalar to isolated ledger")
				}
				ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
				defer closeView()
				var projected []snapshotMigrationRow
				if err := tx.Table("schema_migrations").Select(snapshotMigrationColumns(tx)).Where("version=1").Limit(1).Find(&projected).Error; err != nil || len(projected) != 1 {
					t.Fatal("read real bounded SQL projection")
				}
				row := projected[0]
				value := row.Name
				switch tc.name {
				case "checksum":
					value = row.Checksum
				case "status":
					value = row.Status
				}
				if value != "\n" {
					t.Fatal("oversized scalar entered Go instead of exact SQL-side invalid sentinel")
				}
				if got, err := s.snapshotMigrationInventory(ctx, tx); !errors.Is(err, ErrSchemaMismatch) || got.entries != nil {
					t.Fatal("bounded invalid scalar yielded accepted/partial history")
				}
				closeView()
				snapshotMigrationTestResetRows(t, s)
			})
		}
		expected, err := migrations.ForDialect(cfg.Driver)
		if err != nil {
			t.Fatal("read compiled chain for SQL count boundary")
		}
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		for _, limit := range []int{1, len(expected) - 1, len(expected)} {
			got, err := s.snapshotMigrationInventoryLimited(ctx, tx, limit)
			if limit == len(expected) {
				if err != nil || len(got.entries) != len(expected) {
					t.Fatal("exact real row cap failed")
				}
			} else if !errors.Is(err, errSnapshotMigrationLimit) || got.entries != nil {
				t.Fatal("actual row count beyond strict cap was truncated/accepted")
			}
		}
		for _, limit := range []int{0, -1, backupmanifest.MaxMigrations + 1} {
			if got, err := s.snapshotMigrationInventoryLimited(ctx, tx, limit); !errors.Is(err, ErrConfiguration) || got.entries != nil {
				t.Fatal("private cap expanded or bypassed production hard policy")
			}
		}
		closeView()
		// 4,097 actual excess rows, but only compiled-count+1 may cross into Go.
		if err := s.db.Exec(`WITH RECURSIVE extra(v) AS (SELECT 1000 UNION ALL SELECT v+1 FROM extra WHERE v<5096)
INSERT INTO schema_migrations SELECT v,'future','invalid','applied',CURRENT_TIMESTAMP FROM extra`).Error; err != nil {
			t.Fatal("insert actual excess migration rows")
		}
		ctx, tx, closeView = auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		observed := 0
		if err := tx.Callback().Query().After("gorm:query").Register("snapshot_migration_row_bound", func(q *gorm.DB) {
			if rows, ok := q.Statement.Dest.(*[]snapshotMigrationRow); ok && q.Error == nil {
				observed += len(*rows)
			}
		}); err != nil {
			t.Fatal("observe real bounded query result")
		}
		if got, err := s.snapshotMigrationInventory(ctx, tx); !errors.Is(err, ErrSchemaMismatch) || got.entries != nil || observed != len(expected)+1 {
			t.Fatal("unknown longer history was accepted or materialized without compiled count bound")
		}
	})
}

func TestSnapshotMigrationInventoryCancellationAndQueryFailure(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		for _, cause := range []string{"cancel_after_rows", "query_error_after_rows"} {
			t.Run(cause, func(t *testing.T) {
				ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
				defer closeView()
				work, cancel := context.WithCancel(ctx)
				defer cancel()
				observed := 0
				if err := tx.Callback().Query().After("gorm:query").Register("snapshot_migration_terminal_failure", func(q *gorm.DB) {
					if rows, ok := q.Statement.Dest.(*[]snapshotMigrationRow); ok && q.Error == nil {
						observed += len(*rows)
						if cause == "cancel_after_rows" {
							cancel()
						} else {
							_ = q.AddError(errors.New("private-database-error-canary"))
						}
					}
				}); err != nil {
					t.Fatal("install post-real-query fault observation")
				}
				got, err := s.snapshotMigrationInventory(work, tx)
				if !errors.Is(err, ErrUnavailable) || got.entries != nil || observed == 0 || err.Error() != ErrUnavailable.Error() {
					t.Fatal("post-read cancel/query failure leaked partial history or raw diagnostic")
				}
			})
		}
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if got, err := s.snapshotMigrationInventory(canceled, tx); !errors.Is(err, ErrUnavailable) || got.entries != nil {
			t.Fatal("already canceled inventory accepted")
		}
		actual := tx.Statement.ConnPool.(*sql.Tx)
		if err := actual.Rollback(); err != nil {
			t.Fatal("close actual read transaction for failure test")
		}
		if got, err := s.snapshotMigrationInventory(ctx, tx); !errors.Is(err, ErrUnavailable) || got.entries != nil {
			t.Fatal("closed actual transaction accepted")
		}
	})
}

func TestSnapshotMigrationInventoryRequestAndRepresentationGuards(t *testing.T) {
	value := snapshotMigrationInventory{entries: []snapshotMigrationEntry{{1234, "private-migration-canary", "hash-canary"}}}
	for _, input := range []any{value, &value} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if fmt.Sprintf(format, input) != "[private snapshot migration inventory]" {
				t.Fatal("ordinary formatting disclosed private inventory")
			}
		}
		if _, err := json.Marshal(input); err == nil {
			t.Fatal("ordinary JSON serialized private inventory")
		}
		if _, err := yaml.Marshal(input); err == nil {
			t.Fatal("ordinary YAML serialized private inventory")
		}
		out := snapshotInventoryLogText(t, input)
		if out != "[private snapshot migration inventory]" {
			t.Fatal("structured logging disclosed private inventory")
		}
	}
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		typedNil := tx.Session(&gorm.Session{NewDB: true, Initialized: true})
		typedNil.Statement.ConnPool = (*sql.Tx)(nil)
		wrongDriver := &Store{driver: "unsupported"}
		for _, store := range []*Store{nil, wrongDriver} {
			if got, err := store.snapshotMigrationInventory(ctx, tx); !errors.Is(err, ErrConfiguration) || got.entries != nil {
				t.Fatal("missing Store or incompatible dialect accepted")
			}
		}
		for _, invalid := range []*gorm.DB{nil, {}, {Config: &gorm.Config{}}, s.db, typedNil} {
			if got, err := s.snapshotMigrationInventory(ctx, invalid); !errors.Is(err, ErrConfiguration) || got.entries != nil {
				t.Fatal("missing/malformed transaction or naked pool accepted")
			}
		}
		for _, missing := range []context.Context{nil, context.Background()} {
			if got, err := s.snapshotMigrationInventory(missing, tx); !errors.Is(err, ErrConfiguration) || got.entries != nil {
				t.Fatal("missing context or deadline accepted")
			}
		}
		conn, err := s.sql.Conn(ctx)
		if err != nil {
			t.Fatal("acquire bare test connection")
		}
		bare := tx.Session(&gorm.Session{NewDB: true, Initialized: true})
		bare.Statement.ConnPool = conn
		got, err := s.snapshotMigrationInventory(ctx, bare)
		if closeErr := conn.Close(); closeErr != nil {
			t.Fatal("release bare test connection")
		}
		if !errors.Is(err, ErrConfiguration) || got.entries != nil {
			t.Fatal("bare connection accepted as read-only transaction")
		}
		closeView()
		if cfg.Driver == "sqlite" {
			ctx, weak, closeWeak := auditSnapshotTestTransaction(t, cfg, nil, false)
			defer closeWeak()
			if got, err := s.snapshotMigrationInventory(ctx, weak); !errors.Is(err, ErrConfiguration) || got.entries != nil {
				t.Fatal("SQLite missing supplemental query_only accepted")
			}
		} else {
			for _, options := range []sql.TxOptions{{ReadOnly: true, Isolation: sql.LevelReadCommitted}, {ReadOnly: false, Isolation: sql.LevelRepeatableRead}} {
				ctx, weak, closeWeak := auditSnapshotTestTransaction(t, cfg, &options, true)
				got, err := s.snapshotMigrationInventory(ctx, weak)
				closeWeak()
				if !errors.Is(err, ErrConfiguration) || got.entries != nil {
					t.Fatal("PG weak/writable transaction accepted")
				}
			}
		}
	})
}

func TestSnapshotMigrationInventoryMissingLedgerDoesNotCreateIt(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		// Open has created the SQLite file, but no migration has been performed.
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		got, err := s.snapshotMigrationInventory(ctx, tx)
		closeView()
		if !errors.Is(err, ErrUnavailable) || got.entries != nil {
			t.Fatal("missing ledger returned success or partial history")
		}
		check, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		var count int64
		query := "SELECT COUNT(*) FROM sqlite_schema WHERE name='schema_migrations'"
		if cfg.Driver == "postgres" {
			query = "SELECT COUNT(*) FROM pg_catalog.pg_tables WHERE schemaname=current_schema() AND tablename='schema_migrations'"
		}
		if err := s.db.WithContext(check).Raw(query).Scan(&count).Error; err != nil || count != 0 {
			t.Fatal("inventory unexpectedly created a migration table")
		}
	})
}
