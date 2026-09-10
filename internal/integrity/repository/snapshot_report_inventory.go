package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
	"model-integrity-inspector.local/mii/internal/integrity/report"
)

var (
	errSnapshotReportInvalid = errors.New("SNAPSHOT_REPORT_INVALID")
	errSnapshotReportLimit   = errors.New("SNAPSHOT_REPORT_LIMIT")
	// Older ready rows without the immutable-source publication protocol must
	// not disappear from a backup or be silently rewritten using today's data.
	errSnapshotReportUnsupported = errors.New("SNAPSHOT_REPORT_UNSUPPORTED")
)

const snapshotReportMaxEntries = backupmanifest.MaxEntries - 3
const snapshotReportPageSize = 100

type snapshotReportEntry struct {
	id, organizationID, runID                                     int64
	analysisRevision, revision                                    int
	format, schema, sourceHash, contentHash, fileHash, objectName string
	sourceSize, fileSize                                          int64
}

func (snapshotReportEntry) String() string               { return "[private snapshot report entry]" }
func (v snapshotReportEntry) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (v snapshotReportEntry) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (snapshotReportEntry) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (snapshotReportEntry) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

// References and byte-consistency evidence ONLY. This neither opens report
// files nor authenticates provenance, checks all backup inventory or restores
// data. No source body or generated artifact is retained in this owned result.
type snapshotReportInventory struct{ entries []snapshotReportEntry }

func (snapshotReportInventory) String() string               { return "[private snapshot report inventory]" }
func (v snapshotReportInventory) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (v snapshotReportInventory) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (snapshotReportInventory) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (snapshotReportInventory) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

// The trusted caller owns this actual transaction, including its termination.
// SQLite physical RO must be established with native Conn.Raw before BeginTx;
// query_only is only supplemental, not proof of a physically read-only open.
// Neither live authorization nor an active-organization filter belongs here.
func (s *Store) snapshotReportInventory(ctx context.Context, tx *gorm.DB) (snapshotReportInventory, error) {
	return s.snapshotReportInventoryLimited(ctx, tx, snapshotReportMaxEntries)
}

func (s *Store) snapshotReportInventoryLimited(ctx context.Context, tx *gorm.DB, limit int) (snapshotReportInventory, error) {
	if ctx == nil || s == nil || tx == nil || tx.Config == nil || tx.Error != nil || tx.Statement == nil || tx.Dialector == nil || tx.Name() != s.driver || limit < 1 || limit > snapshotReportMaxEntries {
		return snapshotReportInventory{}, ErrConfiguration
	}
	if ctx.Err() != nil {
		return snapshotReportInventory{}, ErrUnavailable
	}
	if _, ok := ctx.Deadline(); !ok {
		return snapshotReportInventory{}, ErrConfiguration
	}
	if actual, ok := tx.Statement.ConnPool.(*sql.Tx); !ok || actual == nil {
		return snapshotReportInventory{}, ErrConfiguration
	}
	read := tx.Session(&gorm.Session{NewDB: true, Context: ctx})
	if err := auditSnapshotTransaction(read, s.driver); err != nil {
		return snapshotReportInventory{}, err
	}
	// A capped SQL count refuses excess rows before allocating entries. A final
	// count equality also detects duplicate/nonpositive IDs skipped by keyset
	// pagination in a damaged table; no apparently valid prefix can escape.
	var total int64
	if err := read.Raw("SELECT COUNT(*) FROM (SELECT 1 FROM integrity_reports WHERE status='ready' LIMIT ?) inventory_reports", limit+1).Scan(&total).Error; err != nil {
		return snapshotReportInventory{}, ErrUnavailable
	}
	if total > int64(limit) {
		return snapshotReportInventory{}, errSnapshotReportLimit
	}
	result := snapshotReportInventory{entries: make([]snapshotReportEntry, 0, int(total))}
	var cursor int64
	for {
		var page []snapshotReportRow
		if err := read.Table("integrity_reports r").Select(snapshotReportColumns(read)).Where("r.status='ready' AND r.id>?", cursor).Order("r.id").Limit(snapshotReportPageSize).Find(&page).Error; err != nil {
			return snapshotReportInventory{}, ErrUnavailable
		}
		if ctx.Err() != nil {
			return snapshotReportInventory{}, ErrUnavailable
		}
		for _, row := range page {
			if row.ID <= cursor || len(result.entries) >= limit {
				return snapshotReportInventory{}, errSnapshotReportInvalid
			}
			entry, err := snapshotReportVerifyRow(ctx, read, row)
			if err != nil {
				return snapshotReportInventory{}, err
			}
			result.entries = append(result.entries, entry)
			cursor = row.ID
		}
		if len(page) < snapshotReportPageSize {
			break
		}
	}
	if ctx.Err() != nil {
		return snapshotReportInventory{}, ErrUnavailable
	}
	if int64(len(result.entries)) != total {
		return snapshotReportInventory{}, errSnapshotReportInvalid
	}
	return result, nil
}

type snapshotReportRow struct {
	ID, OrganizationID, RunID, CreatedBy, JobID, FileSize, TargetID                                         int64
	AnalysisRevision, Revision, Bound, Modern                                                               int
	Format, SchemaVersion, ContentHash, StoragePath, SourceHash, FileHash, CreatedAt, CompletedAt, FrozenAt string
	Rule, Template, Scoring, Tokenizer                                                                      string
}

type snapshotReportSourceRow struct{ SourceJSON string }

// All identifiers passed to these helpers are closed source-code literals.
// CASE prevents large or incorrectly typed SQLite values crossing into Go.
func snapshotReportInteger(tx *gorm.DB, column, alias string, maxValue int64) string {
	condition := column + " BETWEEN 1 AND " + strconv.FormatInt(maxValue, 10)
	if tx.Name() == "sqlite" {
		condition = "typeof(" + column + ")='integer' AND " + condition
	}
	return "CASE WHEN " + condition + " THEN " + column + " ELSE 0 END AS " + alias
}
func snapshotReportText(tx *gorm.DB, column, alias string, limit int, timestamp bool) string {
	expression, condition := column, column+" IS NOT NULL"
	if timestamp {
		expression = "CAST(" + column + " AS TEXT)"
	}
	length := "octet_length(" + expression + ")"
	if tx.Name() == "sqlite" {
		condition = "typeof(" + column + ")='text'"
		length = "length(CAST(" + column + " AS BLOB))"
	}
	return "CASE WHEN " + condition + " AND " + length + "<=" + strconv.Itoa(limit) + " THEN " + expression + " ELSE '' END AS " + alias
}
func snapshotReportColumns(tx *gorm.DB) string {
	columns := []string{}
	for _, field := range []string{"id", "organization_id", "run_id", "created_by", "job_id", "file_size", "analysis_revision", "revision"} {
		maximum := int64(9223372036854775807)
		switch field {
		case "file_size":
			maximum = reportFileLimit
		case "analysis_revision":
			maximum = 1
		case "revision":
			maximum = 2147483647
		}
		columns = append(columns, snapshotReportInteger(tx, "r."+field, field, maximum))
	}
	for _, field := range []struct {
		name  string
		limit int
	}{{"format", 8}, {"schema_version", 32}, {"content_hash", 71}, {"storage_path", 128}, {"source_hash", 64}, {"file_hash", 64}, {"created_at", 64}, {"completed_at", 64}, {"frozen_at", 64}} {
		columns = append(columns, snapshotReportText(tx, "r."+field.name, field.name, field.limit, strings.HasSuffix(field.name, "_at")))
	}
	// These are same-snapshot relational bindings, not current permissions or
	// authenticity claims. Disabled users/orgs and revoked grants remain valid
	// historical references. Completed report Jobs must retain exact identity.
	columns = append(columns, `CASE WHEN EXISTS (SELECT 1 FROM organizations o WHERE o.id=r.organization_id)
 AND EXISTS (SELECT 1 FROM users u WHERE u.id=r.created_by)
 AND EXISTS (SELECT 1 FROM integrity_runs u WHERE u.organization_id=r.organization_id AND u.id=r.run_id)
 AND EXISTS (SELECT 1 FROM integrity_run_results a WHERE a.organization_id=r.organization_id AND a.run_id=r.run_id AND a.analysis_revision=r.analysis_revision AND a.is_published=TRUE)
 AND EXISTS (SELECT 1 FROM integrity_jobs j WHERE j.organization_id=r.organization_id AND j.id=r.job_id AND j.object_id=r.id AND j.type='integrity.report.generate' AND j.status='completed' AND j.idempotency_key=('report:' || CAST(r.id AS TEXT)))
 AND r.error_code IS NULL THEN 1 ELSE 0 END AS bound`,
		`CASE WHEN r.created_by IS NOT NULL AND r.job_id IS NOT NULL AND r.source_json IS NOT NULL AND r.source_hash IS NOT NULL AND r.file_hash IS NOT NULL AND r.file_size IS NOT NULL AND r.frozen_at IS NOT NULL THEN 1 ELSE 0 END AS modern`)
	columns = append(columns, "(SELECT "+snapshotReportInteger(tx, "u.target_id", "target_id", 9223372036854775807)+" FROM integrity_runs u WHERE u.organization_id=r.organization_id AND u.id=r.run_id) AS target_id")
	for _, field := range []struct{ column, alias string }{{"rule_bundle_version", "rule"}, {"template_bundle_version", "template"}, {"scoring_version", "scoring"}, {"tokenizer_bundle_version", "tokenizer"}} {
		columns = append(columns, "(SELECT "+snapshotReportText(tx, "u."+field.column, field.alias, 128, false)+" FROM integrity_runs u WHERE u.organization_id=r.organization_id AND u.id=r.run_id) AS "+field.alias)
	}
	return strings.Join(columns, ",")
}

func snapshotReportStamp(raw string) (time.Time, bool) {
	// PostgreSQL TIMESTAMP text and the pinned SQLite driver's stored times.
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05.999999999-07", "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05.999999999 -0700 MST"} {
		v, err := time.Parse(layout, raw)
		if err == nil && v.Year() >= 2000 && v.Year() <= 9999 {
			return v.UTC(), true
		}
	}
	return time.Time{}, false
}

// Exact private wire protocol emitted by run.BuildReportSnapshot. Importing
// run here would create a cycle; use the existing report kernel for semantics,
// canonicalization and all three renderers, never a copied hash algorithm.
type snapshotReportSource struct {
	Versions report.Versions `json:"versions"`
	Input    report.Input    `json:"input"`
}

func snapshotReportVerifyRow(ctx context.Context, tx *gorm.DB, row snapshotReportRow) (snapshotReportEntry, error) {
	if row.Modern != 1 {
		return snapshotReportEntry{}, errSnapshotReportUnsupported
	}
	created, cok := snapshotReportStamp(row.CreatedAt)
	completed, pok := snapshotReportStamp(row.CompletedAt)
	frozen, fok := snapshotReportStamp(row.FrozenAt)
	if row.Bound != 1 || row.ID <= 0 || row.OrganizationID <= 0 || row.RunID <= 0 || row.CreatedBy <= 0 || row.JobID <= 0 || row.TargetID <= 0 || row.AnalysisRevision != 1 || row.Revision < 1 || !validReportFormat(row.Format) || row.SchemaVersion != reportSchema || !cok || !pok || !fok || frozen.Before(created) || completed.Before(frozen) || len(row.ContentHash) != 71 || !strings.HasPrefix(row.ContentHash, "sha256:") || !executionHash.MatchString(strings.TrimPrefix(row.ContentHash, "sha256:")) || !executionHash.MatchString(row.SourceHash) || !executionHash.MatchString(row.FileHash) || row.FileSize < 1 || row.StoragePath != ReportObjectName(row.OrganizationID, row.FileHash, row.Format) {
		return snapshotReportEntry{}, errSnapshotReportInvalid
	}
	// Never include source_json in the metadata page: at most one <=4 MiB
	// document crosses SQL at once. No source is returned or accumulated.
	var source snapshotReportSourceRow
	if err := tx.Table("integrity_reports").Select(snapshotReportText(tx, "source_json", "source_json", reportInputLimit, false)).Where("id=? AND organization_id=? AND status='ready'", row.ID, row.OrganizationID).Take(&source).Error; err != nil {
		return snapshotReportEntry{}, ErrUnavailable
	}
	if ctx.Err() != nil {
		return snapshotReportEntry{}, ErrUnavailable
	}
	if len(source.SourceJSON) < 2 || reportDigest([]byte(source.SourceJSON)) != row.SourceHash {
		return snapshotReportEntry{}, errSnapshotReportInvalid
	}
	var decoded snapshotReportSource
	if !snapshotReportDecode(source.SourceJSON, &decoded) || decoded.Versions != (report.Versions{Rule: row.Rule, Template: row.Template, Scoring: row.Scoring, Tokenizer: row.Tokenizer}) || decoded.Input.Run.TargetID != strconv.FormatInt(row.TargetID, 10) {
		return snapshotReportEntry{}, errSnapshotReportInvalid
	}
	snapshot, err := report.NewDevelopmentSnapshot(report.Scope{ReportID: strconv.FormatInt(row.ID, 10), OrganizationID: strconv.FormatInt(row.OrganizationID, 10), RunID: strconv.FormatInt(row.RunID, 10), AnalysisRevision: row.AnalysisRevision, GeneratedAt: created, Versions: decoded.Versions}, decoded.Input)
	if err != nil {
		return snapshotReportEntry{}, errSnapshotReportInvalid
	}
	content, file, size, err := snapshotReportRendered(snapshot, row.Format)
	if ctx.Err() != nil {
		return snapshotReportEntry{}, ErrUnavailable
	}
	if err != nil || content != row.ContentHash || file != "sha256:"+row.FileHash || size != row.FileSize {
		return snapshotReportEntry{}, errSnapshotReportInvalid
	}
	return snapshotReportEntry{row.ID, row.OrganizationID, row.RunID, row.AnalysisRevision, row.Revision, row.Format, row.SchemaVersion, row.SourceHash, row.ContentHash, row.FileHash, row.StoragePath, int64(len(source.SourceJSON)), row.FileSize}, nil
}

func snapshotReportRendered(snapshot *report.Snapshot, format string) (string, string, int64, error) {
	if format == "csv" {
		a, err := report.GenerateCSV(snapshot)
		if err != nil {
			return "", "", 0, errSnapshotReportInvalid
		}
		return a.ContentHash(), a.FileHash(), int64(len(a.Bytes())), nil
	}
	a, err := report.Generate(snapshot)
	if err != nil {
		return "", "", 0, errSnapshotReportInvalid
	}
	if format == "json" {
		return a.ContentHash(), a.JSONFileHash(), int64(len(a.JSON())), nil
	}
	if format == "html" {
		return a.ContentHash(), a.HTMLFileHash(), int64(len(a.HTML())), nil
	}
	return "", "", 0, errSnapshotReportInvalid
}

func snapshotReportDecode(raw string, out *snapshotReportSource) bool {
	if len(raw) < 2 || len(raw) > reportInputLimit || !utf8.ValidString(raw) {
		return false
	}
	// Production freezes json.Marshal of this explicit wire type. Requiring
	// those exact bytes rejects duplicate/case-aliased/unknown/missing fields,
	// noncanonical escapes and trailing documents before accepting a source.
	// The token pass first bounds nesting, strings and collections, preventing
	// pathological typed allocations before the report kernel's own preflight.
	d := json.NewDecoder(strings.NewReader(raw))
	d.UseNumber()
	var walk func(int) bool
	walk = func(depth int) bool {
		// The 4 MiB raw-document bound already bounds total token count by
		// bytes; do not impose an unrelated, narrower token-count ceiling.
		if depth > 64 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		switch v := token.(type) {
		case string:
			return len(v) <= 4096
		case json.Delim:
			if v != '{' && v != '[' {
				return false
			}
			count := 0
			for d.More() {
				count++
				if count > 2048 {
					return false
				}
				if v == '{' {
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok || len(name) > 128 {
						return false
					}
				}
				if !walk(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && (v == '{' && end == json.Delim('}') || v == '[' && end == json.Delim(']'))
		}
		return true
	}
	if !walk(0) {
		return false
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return false
	}
	d = json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return false
	}
	encoded, err := json.Marshal(out)
	return err == nil && bytes.Equal(encoded, []byte(raw))
}
