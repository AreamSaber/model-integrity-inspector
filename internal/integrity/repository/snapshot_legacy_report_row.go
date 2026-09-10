package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
)

var (
	errSnapshotLegacyReportInvalid     = errors.New("SNAPSHOT_LEGACY_REPORT_ROW_INVALID")
	errSnapshotLegacyReportUnsupported = errors.New("SNAPSHOT_LEGACY_REPORT_ROW_UNSUPPORTED")
	errSnapshotLegacyReportLimit       = errors.New("SNAPSHOT_LEGACY_REPORT_ROW_LIMIT")
)

// The result owns only identity and a commitment to one original row. It does
// not classify modern/legacy publication, expose a locator/body, open any file,
// establish report provenance, authorize restore, or certify a whole inventory.
type snapshotLegacyReportDescriptor struct {
	id, organizationID, runID, analysisRevision, revision int64
	rowVersion, rowSHA256                                 string
}

func (snapshotLegacyReportDescriptor) String() string { return "[private snapshot legacy report row]" }
func (v snapshotLegacyReportDescriptor) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, v.String())
}
func (v snapshotLegacyReportDescriptor) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (snapshotLegacyReportDescriptor) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (snapshotLegacyReportDescriptor) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

type snapshotLegacyReportColumn struct {
	name, kind, pgType string
	nullable           bool
}

// Exact foundation thirteen columns followed by migration fourteen's seven.
// SQL identifiers/types below are exclusively these source-code constants.
var snapshotLegacyReportColumns = [20]snapshotLegacyReportColumn{
	{"id", "integer", "int8", false}, {"organization_id", "integer", "int8", false},
	{"run_id", "integer", "int8", false}, {"analysis_revision", "integer", "int4", false},
	{"format", "text", "text", false}, {"schema_version", "text", "text", false},
	{"revision", "integer", "int4", false}, {"content_hash", "text", "text", true},
	{"storage_path", "text", "text", true}, {"status", "text", "text", false},
	{"error_code", "text", "text", true}, {"created_at", "time", "timestamp", false},
	{"completed_at", "time", "timestamp", true}, {"created_by", "integer", "int8", true},
	{"job_id", "integer", "int8", true}, {"source_json", "text", "text", true},
	{"source_hash", "text", "text", true}, {"file_hash", "text", "text", true},
	{"file_size", "integer", "int8", true}, {"frozen_at", "time", "timestamp", true},
}

type snapshotLegacyReportMetadata struct {
	Ordinal, State int
	Scalar, Bytes  int64
}

// The caller continuously owns this real RO transaction/connection. SQLite
// native physical RO must be checked with Conn.Raw BEFORE BeginTx; query_only
// here is supplemental, not proof of open mode. PostgreSQL must be genuinely
// READ ONLY with repeatable-read/serializable isolation. Never use the Store
// pool, begin/end a transaction, filter active tenants, or read a filesystem.
func (s *Store) snapshotLegacyReportRow(ctx context.Context, tx *gorm.DB, id, byteLimit int64) (snapshotLegacyReportDescriptor, error) {
	if ctx == nil || s == nil || tx == nil || tx.Config == nil || tx.Statement == nil || tx.Error != nil || tx.Dialector == nil || tx.Name() != s.driver || id <= 0 || byteLimit < 1 || byteLimit > backupmanifest.MaxFileBytes {
		return snapshotLegacyReportDescriptor{}, ErrConfiguration
	}
	if ctx.Err() != nil {
		return snapshotLegacyReportDescriptor{}, ErrUnavailable
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return snapshotLegacyReportDescriptor{}, ErrConfiguration
	}
	if actual, ok := tx.Statement.ConnPool.(*sql.Tx); !ok || actual == nil {
		return snapshotLegacyReportDescriptor{}, ErrConfiguration
	}
	timeout := min(time.Until(deadline), backupmanifest.MaxStreamTimeout)
	if timeout <= 0 {
		return snapshotLegacyReportDescriptor{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	read := tx.Session(&gorm.Session{NewDB: true, Context: ctx})
	if err := auditSnapshotTransaction(read, s.driver); err != nil {
		return snapshotLegacyReportDescriptor{}, err
	}
	if err := snapshotLegacyReportSchema(read); err != nil {
		return snapshotLegacyReportDescriptor{}, err
	}
	metadata, err := snapshotLegacyReportMetadataRead(read, id)
	if err != nil {
		return snapshotLegacyReportDescriptor{}, err
	}
	if ctx.Err() != nil {
		return snapshotLegacyReportDescriptor{}, ErrUnavailable
	}
	descriptor := snapshotLegacyReportDescriptor{metadata[0].Scalar, metadata[1].Scalar, metadata[2].Scalar, metadata[3].Scalar, metadata[6].Scalar, backupmanifest.LegacyReportRowVersion, ""}
	if descriptor.id != id {
		return snapshotLegacyReportDescriptor{}, errSnapshotLegacyReportInvalid
	}
	if err := snapshotLegacyReportBindings(read, descriptor); err != nil {
		return snapshotLegacyReportDescriptor{}, err
	}
	var readers []*snapshotLegacyReportReader
	defer func() {
		for _, reader := range readers {
			reader.closed, reader.tx, reader.ctx = true, nil, nil
		}
	}()
	text := func(index int) backupmanifest.LegacyReportRowText {
		m := metadata[index]
		if m.State == 0 {
			return backupmanifest.LegacyReportRowText{}
		}
		reader := &snapshotLegacyReportReader{ctx: ctx, tx: read, descriptor: descriptor, column: snapshotLegacyReportColumns[index], size: m.Bytes}
		readers = append(readers, reader)
		return backupmanifest.LegacyReportRowText{Present: true, Bytes: m.Bytes, Reader: reader}
	}
	integer := func(index int) backupmanifest.LegacyReportRowInteger {
		return backupmanifest.LegacyReportRowInteger{Present: metadata[index].State == 1, Value: metadata[index].Scalar}
	}
	row := backupmanifest.LegacyReportRow{
		DatabaseDriver: s.driver, ID: descriptor.id, OrganizationID: descriptor.organizationID, RunID: descriptor.runID,
		AnalysisRevision: descriptor.analysisRevision, ReportFormat: text(4), SchemaVersion: text(5), Revision: descriptor.revision,
		ContentHash: text(7), StoragePath: text(8), Status: text(9), ErrorCode: text(10),
		CreatedAt: backupmanifest.LegacyReportRowTime(text(11)), CompletedAt: backupmanifest.LegacyReportRowTime(text(12)),
		CreatedBy: integer(13), JobID: integer(14), SourceJSON: text(15), SourceHash: text(16), FileHash: text(17),
		FileSize: integer(18), FrozenAt: backupmanifest.LegacyReportRowTime(text(19)),
	}
	sum, err := backupmanifest.DigestLegacyReportRow(ctx, row, backupmanifest.LegacyReportRowLimits{MaxBytes: byteLimit, Timeout: timeout})
	if err != nil {
		if errors.Is(err, backupmanifest.ErrLimit) {
			return snapshotLegacyReportDescriptor{}, errSnapshotLegacyReportLimit
		}
		if errors.Is(err, backupmanifest.ErrInvalid) || errors.Is(err, backupmanifest.ErrMismatch) {
			return snapshotLegacyReportDescriptor{}, errSnapshotLegacyReportInvalid
		}
		return snapshotLegacyReportDescriptor{}, ErrUnavailable
	}
	// No success after a late caller rollback or failed final stream read. This
	// is still not ownership of caller transaction completion/publication.
	if err := snapshotLegacyReportBindings(read, descriptor); err != nil {
		return snapshotLegacyReportDescriptor{}, err
	}
	if ctx.Err() != nil {
		return snapshotLegacyReportDescriptor{}, ErrUnavailable
	}
	descriptor.rowSHA256 = sum
	return descriptor, nil
}

func snapshotLegacyReportSchema(tx *gorm.DB) error {
	var valid bool
	if tx.Name() == "sqlite" {
		// Only a scalar crosses SQL; arbitrary schema names/types are not read.
		if err := tx.Raw("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='integrity_reports') AND (SELECT COUNT(*) FROM pragma_table_info('integrity_reports'))=20").Scan(&valid).Error; err != nil {
			return ErrUnavailable
		}
	} else {
		values := make([]string, 0, len(snapshotLegacyReportColumns))
		for _, c := range snapshotLegacyReportColumns {
			values = append(values, "('"+c.name+"','"+c.pgType+"')")
		}
		query := `SELECT pg_catalog.current_setting('server_encoding')='UTF8'
 AND EXISTS (SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=pg_catalog.to_regclass('integrity_reports') AND c.relkind='r')
 AND (SELECT COUNT(*) FROM pg_catalog.pg_attribute a WHERE a.attrelid=pg_catalog.to_regclass('integrity_reports') AND a.attnum>0 AND NOT a.attisdropped)=20
 AND NOT EXISTS (SELECT 1 FROM (VALUES ` + strings.Join(values, ",") + `) e(name,kind)
 LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=pg_catalog.to_regclass('integrity_reports') AND a.attname=e.name AND a.attnum>0 AND NOT a.attisdropped
 LEFT JOIN pg_catalog.pg_type t ON t.oid=a.atttypid
 LEFT JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
 WHERE a.attnum IS NULL OR t.typname<>e.kind OR n.nspname<>'pg_catalog')`
		if err := tx.Raw(query).Scan(&valid).Error; err != nil {
			return ErrUnavailable
		}
	}
	if !valid {
		return errSnapshotLegacyReportUnsupported
	}
	return nil
}

func snapshotLegacyReportColumnSQL(tx *gorm.DB, c snapshotLegacyReportColumn) (valid, bytes string) {
	name := "r." + c.name
	valid = name + " IS NOT NULL"
	if tx.Name() == "sqlite" {
		kind := c.kind
		if kind == "time" {
			kind = "text"
		}
		valid = "typeof(" + name + ")='" + kind + "'"
		return valid, "CAST(" + name + " AS BLOB)"
	}
	if c.kind == "time" {
		return valid, "pg_catalog.timestamp_send(" + name + ")"
	}
	// The schema gate requires server_encoding=UTF8, so this bytea projection
	// does not transcode original stored TEXT. Non-UTF8 databases are explicitly
	// unsupported by this row protocol adapter, never silently normalized.
	return valid, "pg_catalog.convert_to(" + name + ",'UTF8')"
}

func snapshotLegacyReportMetadataRead(tx *gorm.DB, id int64) ([20]snapshotLegacyReportMetadata, error) {
	var result [20]snapshotLegacyReportMetadata
	queries := make([]string, 0, 20)
	args := make([]any, 0, 20)
	for i, c := range snapshotLegacyReportColumns {
		name := "r." + c.name
		valid, data := snapshotLegacyReportColumnSQL(tx, c)
		scalar, size := "0", "0"
		if c.kind == "integer" {
			scalar = "CASE WHEN " + valid + " THEN " + name + " ELSE 0 END"
		} else {
			length := "length(" + data + ")"
			if tx.Name() == "postgres" {
				length = "octet_length(" + data + ")"
			}
			size = "CASE WHEN " + valid + " THEN " + length + " ELSE 0 END"
		}
		state := "CASE WHEN " + name + " IS NULL THEN 0 WHEN " + valid + " THEN 1 ELSE 2 END"
		queries = append(queries, "SELECT "+strconv.Itoa(i+1)+" AS ordinal,"+state+" AS state,"+scalar+" AS scalar,"+size+" AS bytes FROM integrity_reports r WHERE r.id=?")
		args = append(args, id)
	}
	var rows []snapshotLegacyReportMetadata
	if err := tx.Raw("SELECT * FROM ("+strings.Join(queries, " UNION ALL ")+") legacy_row_metadata ORDER BY ordinal LIMIT 21", args...).Scan(&rows).Error; err != nil {
		return result, ErrUnavailable
	}
	if len(rows) != 20 {
		return result, errSnapshotLegacyReportInvalid
	}
	for i, row := range rows {
		c := snapshotLegacyReportColumns[i]
		if row.Ordinal != i+1 || row.State < 0 || row.State > 2 || !c.nullable && row.State == 0 {
			return [20]snapshotLegacyReportMetadata{}, errSnapshotLegacyReportInvalid
		}
		if row.State == 2 {
			if c.kind == "time" && tx.Name() == "sqlite" {
				return [20]snapshotLegacyReportMetadata{}, errSnapshotLegacyReportUnsupported
			}
			return [20]snapshotLegacyReportMetadata{}, errSnapshotLegacyReportInvalid
		}
		if row.Bytes < 0 || row.Bytes > backupmanifest.MaxFileBytes {
			return [20]snapshotLegacyReportMetadata{}, errSnapshotLegacyReportLimit
		}
		result[i] = row
	}
	return result, nil
}

func snapshotLegacyReportBindings(tx *gorm.DB, d snapshotLegacyReportDescriptor) error {
	var rows []int
	query := `SELECT CASE WHEN EXISTS (SELECT 1 FROM organizations o WHERE o.id=r.organization_id)
 AND EXISTS (SELECT 1 FROM integrity_runs u WHERE u.organization_id=r.organization_id AND u.id=r.run_id)
 AND EXISTS (SELECT 1 FROM integrity_run_results a WHERE a.organization_id=r.organization_id AND a.run_id=r.run_id AND a.analysis_revision=r.analysis_revision)
 AND (r.created_by IS NULL OR EXISTS (SELECT 1 FROM users u WHERE u.id=r.created_by))
 AND (r.job_id IS NULL OR EXISTS (SELECT 1 FROM integrity_jobs j WHERE j.organization_id=r.organization_id AND j.id=r.job_id))
 THEN 1 ELSE 0 END FROM integrity_reports r WHERE r.id=? AND r.organization_id=? AND r.run_id=? AND r.analysis_revision=? AND r.revision=? LIMIT 2`
	if err := tx.Raw(query, d.id, d.organizationID, d.runID, d.analysisRevision, d.revision).Scan(&rows).Error; err != nil {
		return ErrUnavailable
	}
	if len(rows) != 1 || rows[0] != 1 {
		return errSnapshotLegacyReportInvalid
	}
	return nil
}
