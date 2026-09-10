package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
	"model-integrity-inspector.local/mii/migrations"
)

var errSnapshotMigrationLimit = errors.New("SNAPSHOT_MIGRATION_LIMIT")

type snapshotMigrationEntry struct {
	version        int
	name, checksum string
}

// This owned projection certifies only the compiled migration HISTORY within
// one supplied snapshot. It is not physical schema/constraint certification,
// initialization, complete backup inventory, authorization or restore approval.
type snapshotMigrationInventory struct{ entries []snapshotMigrationEntry }

func (snapshotMigrationInventory) String() string { return "[private snapshot migration inventory]" }
func (v snapshotMigrationInventory) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, v.String())
}
func (v snapshotMigrationInventory) LogValue() slog.Value { return slog.StringValue(v.String()) }
func (snapshotMigrationInventory) MarshalJSON() ([]byte, error) {
	return nil, ErrConfiguration
}
func (snapshotMigrationInventory) MarshalYAML() (any, error) { return nil, ErrConfiguration }

// The trusted caller continuously owns the actual read-only transaction and
// connection. SQLite native physical RO MUST be checked with Conn.Raw BEFORE
// this transaction is begun, as for verifyAuditSnapshot; query_only below is
// only supplemental. No pool query, migration, lock or transaction end occurs.
func (s *Store) snapshotMigrationInventory(ctx context.Context, tx *gorm.DB) (snapshotMigrationInventory, error) {
	return s.snapshotMigrationInventoryLimited(ctx, tx, backupmanifest.MaxMigrations)
}

// A private tighter cap exercises real SQL resource refusal; it cannot raise
// the production policy. Unknown extra migrations fail exact-history checking,
// even when their count is below that resource cap. No partial result escapes.
func (s *Store) snapshotMigrationInventoryLimited(ctx context.Context, tx *gorm.DB, limit int) (snapshotMigrationInventory, error) {
	if ctx == nil || s == nil || tx == nil || tx.Config == nil || tx.Error != nil || tx.Statement == nil ||
		tx.Dialector == nil || tx.Name() != s.driver || limit < 1 || limit > backupmanifest.MaxMigrations {
		return snapshotMigrationInventory{}, ErrConfiguration
	}
	if ctx.Err() != nil {
		return snapshotMigrationInventory{}, ErrUnavailable
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return snapshotMigrationInventory{}, ErrConfiguration
	}
	if actual, ok := tx.Statement.ConnPool.(*sql.Tx); !ok || actual == nil {
		return snapshotMigrationInventory{}, ErrConfiguration
	}
	read := tx.Session(&gorm.Session{NewDB: true, Context: ctx})
	if err := auditSnapshotTransaction(read, s.driver); err != nil {
		return snapshotMigrationInventory{}, err
	}
	expected, err := migrations.ForDialect(s.driver)
	if err != nil || len(expected) == 0 {
		return snapshotMigrationInventory{}, ErrSchemaMismatch
	}
	if len(expected) > backupmanifest.MaxMigrations {
		return snapshotMigrationInventory{}, errSnapshotMigrationLimit
	}
	// At most compiled-count+1 bounded rows cross into Go. The extra row proves
	// a newer/longer chain instead of silently accepting a truncated prefix.
	var rows []snapshotMigrationRow
	if err := read.Table("schema_migrations").Select(snapshotMigrationColumns(read)).
		Order("schema_migrations.version").Limit(min(limit, len(expected)) + 1).Find(&rows).Error; err != nil {
		return snapshotMigrationInventory{}, ErrUnavailable
	}
	if ctx.Err() != nil {
		return snapshotMigrationInventory{}, ErrUnavailable
	}
	if len(rows) > limit {
		return snapshotMigrationInventory{}, errSnapshotMigrationLimit
	}
	applied := make([]SchemaVersion, len(rows))
	for i, row := range rows {
		if row.AppliedPresent != 1 {
			return snapshotMigrationInventory{}, ErrSchemaMismatch
		}
		applied[i] = SchemaVersion{Version: row.Version, Name: row.Name, Checksum: row.Checksum, Status: row.Status}
	}
	if err := verifyHistory(expected, applied, true); err != nil {
		// Do not propagate the helper's wrapper or any database value in errors.
		return snapshotMigrationInventory{}, ErrSchemaMismatch
	}
	result := snapshotMigrationInventory{entries: make([]snapshotMigrationEntry, len(applied))}
	for i, row := range applied {
		result.entries[i] = snapshotMigrationEntry{row.Version, row.Name, row.Checksum}
	}
	if ctx.Err() != nil {
		return snapshotMigrationInventory{}, ErrUnavailable
	}
	return result, nil
}

// Only bounded scalar metadata crosses the SQL boundary. applied_at is not a
// manifest field: check its mandatory presence without reading/allocating a
// potentially corrupted SQLite timestamp string or attesting its chronology.
type snapshotMigrationRow struct {
	Version                int
	Name, Checksum, Status string
	AppliedPresent         int
}

func snapshotMigrationColumns(tx *gorm.DB) string {
	condition := "version BETWEEN 1 AND " + strconv.Itoa(backupmanifest.MaxMigrations)
	if tx.Name() == "sqlite" {
		// SQLite affinity is not a type guarantee after offline corruption. A
		// BLOB/TEXT/REAL version must not be converted into a plausible integer.
		condition = "typeof(version)='integer' AND " + condition
	}
	columns := "CASE WHEN " + condition + " THEN version ELSE 0 END AS version," +
		"CASE WHEN applied_at IS NULL THEN 0 ELSE 1 END AS applied_present"
	for _, field := range []struct {
		name  string
		limit int
	}{{"name", 64}, {"checksum", 64}, {"status", 7}} {
		length := "octet_length(" + field.name + ")"
		condition := field.name + " IS NOT NULL"
		if tx.Name() == "sqlite" {
			// Do not let database/sql coerce a SQLite BLOB to valid text. Count
			// encoded bytes rather than Unicode characters before allocation.
			condition = "typeof(" + field.name + ")='text'"
			length = "length(CAST(" + field.name + " AS BLOB))"
		}
		columns += ",CASE WHEN " + condition + " AND " + length + "<=" + strconv.Itoa(field.limit) +
			" THEN " + field.name + " ELSE '\n' END AS " + field.name
	}
	return columns
}
