package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
)

var (
	errSnapshotArtifactInvalid     = errors.New("SNAPSHOT_ARTIFACT_INVALID")
	errSnapshotArtifactLimit       = errors.New("SNAPSHOT_ARTIFACT_LIMIT")
	errSnapshotArtifactUnsupported = errors.New("SNAPSHOT_ARTIFACT_UNSUPPORTED")
	errSnapshotArtifactCallback    = errors.New("SNAPSHOT_ARTIFACT_CALLBACK")
	errSnapshotArtifactIncomplete  = errors.New("SNAPSHOT_ARTIFACT_INCOMPLETE")
	errSnapshotArtifactConsumed    = errors.New("SNAPSHOT_ARTIFACT_CONSUMED")
	errSnapshotArtifactClosed      = errors.New("SNAPSHOT_ARTIFACT_CLOSED")
)

const snapshotArtifactMaxEntries = backupmanifest.MaxEntries - 3
const snapshotArtifactPageSize = 100

// Closed identity/byte evidence, not executable admission or provenance. Status,
// sensitivity and replay data remain unmodified in the database snapshot; no
// current-version, status, sensitivity, or active-organization filter is used.
type snapshotArtifactDescriptor struct {
	category, version, sha256 string
	organizationID, id, bytes int64
}

func (snapshotArtifactDescriptor) String() string               { return "[private snapshot artifact descriptor]" }
func (v snapshotArtifactDescriptor) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (v snapshotArtifactDescriptor) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (snapshotArtifactDescriptor) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (snapshotArtifactDescriptor) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

type snapshotArtifactInventory struct{ entries []snapshotArtifactDescriptor }

func (snapshotArtifactInventory) String() string               { return "[private snapshot artifact inventory]" }
func (v snapshotArtifactInventory) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (v snapshotArtifactInventory) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (snapshotArtifactInventory) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (snapshotArtifactInventory) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

func (s *Store) snapshotArtifactInventory(ctx context.Context, tx *gorm.DB, sink snapshotArtifactSink) (snapshotArtifactInventory, error) {
	return s.snapshotArtifactInventoryLimited(ctx, tx, sink, snapshotArtifactMaxEntries, backupmanifest.MaxFileBytes)
}

// Limits are private and can only tighten production bounds. Other inventory
// categories and archive framing must be charged by the final coordinator.
func (s *Store) snapshotArtifactInventoryLimited(ctx context.Context, tx *gorm.DB, sink snapshotArtifactSink, limit int, byteLimit int64) (snapshotArtifactInventory, error) {
	if ctx == nil || s == nil || tx == nil || tx.Config == nil || tx.Error != nil || tx.Statement == nil || tx.Dialector == nil || tx.Name() != s.driver || sink == nil || limit < 1 || limit > snapshotArtifactMaxEntries || byteLimit < 1 || byteLimit > backupmanifest.MaxFileBytes {
		return snapshotArtifactInventory{}, ErrConfiguration
	}
	if ctx.Err() != nil {
		return snapshotArtifactInventory{}, ErrUnavailable
	}
	if _, ok := ctx.Deadline(); !ok {
		return snapshotArtifactInventory{}, ErrConfiguration
	}
	if actual, ok := tx.Statement.ConnPool.(*sql.Tx); !ok || actual == nil {
		return snapshotArtifactInventory{}, ErrConfiguration
	}
	read := tx.Session(&gorm.Session{NewDB: true, Context: ctx})
	if err := auditSnapshotTransaction(read, s.driver); err != nil {
		return snapshotArtifactInventory{}, err
	}
	categories := []struct{ category, table string }{{"rule", "integrity_rule_bundles"}, {"template", "integrity_template_bundles"}}
	counts := make([]int64, len(categories))
	var total int64
	for index, source := range categories {
		if err := read.Raw("SELECT COUNT(*) FROM (SELECT 1 FROM "+source.table+" LIMIT ?) inventory_artifacts", limit+1).Scan(&counts[index]).Error; err != nil {
			return snapshotArtifactInventory{}, ErrUnavailable
		}
		total += counts[index]
		if total > int64(limit) {
			return snapshotArtifactInventory{}, errSnapshotArtifactLimit
		}
	}
	result := snapshotArtifactInventory{entries: make([]snapshotArtifactDescriptor, 0, int(total))}
	type versionIdentity struct {
		category       string
		organizationID int64
		version        string
	}
	versions := make(map[versionIdentity]struct{}, int(total))
	var consumed int64
	for index, source := range categories {
		var cursor, seen int64
		for {
			var page []snapshotArtifactRow
			if err := read.Table(source.table+" a").Select(snapshotArtifactColumns(read, source.category)).Where("a.id>?", cursor).Order("a.id").Limit(snapshotArtifactPageSize).Find(&page).Error; err != nil {
				return snapshotArtifactInventory{}, ErrUnavailable
			}
			for _, row := range page {
				if ctx.Err() != nil {
					return snapshotArtifactInventory{}, ErrUnavailable
				}
				if row.ID <= cursor || row.OrganizationID <= 0 || row.Bound != 1 || row.BodyValid != 1 || row.VersionValid != 1 || !executionHash.MatchString(row.ContentHash) || len(result.entries) >= limit {
					return snapshotArtifactInventory{}, errSnapshotArtifactInvalid
				}
				// Foundation permits opaque bodies and labels that v2 cannot carry.
				// Do not mutate, normalize, omit, or invent their identity. Extending
				// the archive schema remains a required future compatibility unit.
				if !executionLabel.MatchString(row.Version) || row.Bytes == 0 {
					return snapshotArtifactInventory{}, errSnapshotArtifactUnsupported
				}
				if row.Bytes < 0 || row.Bytes > byteLimit-consumed {
					return snapshotArtifactInventory{}, errSnapshotArtifactLimit
				}
				key := versionIdentity{source.category, row.OrganizationID, row.Version}
				if _, exists := versions[key]; exists {
					return snapshotArtifactInventory{}, errSnapshotArtifactInvalid
				}
				versions[key] = struct{}{}
				descriptor := snapshotArtifactDescriptor{source.category, row.Version, row.ContentHash, row.OrganizationID, row.ID, row.Bytes}
				fetch := snapshotArtifactSQLFetch(read, source.table, row.ID)
				if err := snapshotArtifactConsume(ctx, descriptor, fetch, sink); err != nil {
					return snapshotArtifactInventory{}, err
				}
				result.entries = append(result.entries, descriptor)
				consumed += row.Bytes
				cursor, seen = row.ID, seen+1
			}
			if len(page) < snapshotArtifactPageSize {
				break
			}
		}
		if seen != counts[index] {
			return snapshotArtifactInventory{}, errSnapshotArtifactInvalid
		}
	}
	if ctx.Err() != nil {
		return snapshotArtifactInventory{}, ErrUnavailable
	}
	return result, nil
}

type snapshotArtifactRow struct {
	ID, OrganizationID, Bytes      int64
	Bound, BodyValid, VersionValid int
	Version, ContentHash           string
}

func snapshotArtifactColumns(tx *gorm.DB, category string) string {
	columns := []string{
		snapshotReportInteger(tx, "a.id", "id", 9223372036854775807),
		snapshotReportInteger(tx, "a.organization_id", "organization_id", 9223372036854775807),
		snapshotReportText(tx, "a.version", "version", 128, false),
		snapshotReportText(tx, "a.content_hash", "content_hash", 64, false),
	}
	valid, size := "a.content_json IS NOT NULL", "octet_length(convert_to(a.content_json,'UTF8'))"
	versionValid := "a.version IS NOT NULL"
	if tx.Name() == "sqlite" {
		valid, size = "typeof(a.content_json)='text'", "length(CAST(a.content_json AS BLOB))"
		versionValid = "typeof(a.version)='text'"
	}
	columns = append(columns, "CASE WHEN "+valid+" THEN 1 ELSE 0 END AS body_valid", "CASE WHEN "+valid+" THEN "+size+" ELSE -1 END AS bytes", "CASE WHEN "+versionValid+" THEN 1 ELSE 0 END AS version_valid")
	bound := "EXISTS (SELECT 1 FROM organizations o WHERE o.id=a.organization_id)"
	if category == "rule" {
		bound += " AND EXISTS (SELECT 1 FROM organization_members m WHERE m.organization_id=a.organization_id AND m.user_id=a.created_by)"
	}
	columns = append(columns, "CASE WHEN "+bound+" THEN 1 ELSE 0 END AS bound")
	return strings.Join(columns, ",")
}

// Tables originate ONLY from closed literals above; IDs/offsets are parameters.
// SQL sends at most 64 KiB per fetch into Go, including opaque multi-megabyte
// historical bodies. PostgreSQL may still detoast/materialize text server-side.
func snapshotArtifactSQLFetch(tx *gorm.DB, table string, id int64) snapshotArtifactFetch {
	return func(ctx context.Context, offset, size int64) ([]byte, error) {
		if ctx.Err() != nil || offset < 0 || offset > backupmanifest.MaxFileBytes || size < 1 || size > snapshotArtifactChunkBytes {
			return nil, ErrUnavailable
		}
		expression := "substr(CAST(content_json AS BLOB), ?, ?)"
		if tx.Name() == "postgres" {
			// PostgreSQL TEXT cannot reach this position; avoid an implicit int4
			// overflow if a corrupt metadata provider claims an impossible size.
			if offset >= 2147483647 {
				return nil, errSnapshotArtifactLimit
			}
			expression = "substring(convert_to(content_json,'UTF8') FROM ? FOR ?)"
		}
		var chunk struct{ Data []byte }
		read := tx.Session(&gorm.Session{NewDB: true, Context: ctx})
		query := "SELECT " + expression + " AS data FROM " + table + " WHERE id=?"
		result := read.Raw(query, offset+1, size, id).Scan(&chunk)
		if result.Error != nil || result.RowsAffected != 1 {
			clear(chunk.Data)
			return nil, ErrUnavailable
		}
		return chunk.Data, nil
	}
}

// A deterministic archive entry identifier is intentionally NOT generated here:
// the final coordinator owns the global namespace, framing, and byte budget.
