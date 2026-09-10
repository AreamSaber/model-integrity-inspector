package repository

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
)

// The row digest commits to all twenty original nullable columns. Neither a
// missing publication field nor this classification proves historical origin.
// No locator/file has been inspected: unmapped is mandatory unfinished work for
// the file coordinator, never an observed/missing file or authority to activate.
type snapshotCompleteLegacyReportEntry struct {
	row                     snapshotLegacyReportDescriptor
	verification, fileState string
}

func (snapshotCompleteLegacyReportEntry) String() string {
	return "[private complete legacy report entry]"
}
func (v snapshotCompleteLegacyReportEntry) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, v.String())
}
func (v snapshotCompleteLegacyReportEntry) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (snapshotCompleteLegacyReportEntry) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (snapshotCompleteLegacyReportEntry) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

// Complete refers ONLY to the same-view ready-row inventory. Modern entries
// have the existing publication/source/render byte checks, not file existence
// or provenance authentication. Legacy entries never enter that trusted path.
// No source body, original locator, transaction or file capability escapes.
type snapshotCompleteReportInventory struct {
	modern []snapshotReportEntry
	legacy []snapshotCompleteLegacyReportEntry
}

func (snapshotCompleteReportInventory) String() string { return "[private complete report inventory]" }
func (v snapshotCompleteReportInventory) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, v.String())
}
func (v snapshotCompleteReportInventory) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (snapshotCompleteReportInventory) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (snapshotCompleteReportInventory) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

func (s *Store) snapshotCompleteReportInventory(ctx context.Context, tx *gorm.DB) (snapshotCompleteReportInventory, error) {
	return s.snapshotCompleteReportInventoryLimited(ctx, tx, snapshotReportMaxEntries, backupmanifest.MaxFileBytes)
}

// entryLimit applies to modern + legacy together. legacyRowByteLimit is a
// PER-ROW framing-and-content budget, not a whole-archive budget. The coordinator
// must additionally bound all other entries, files, manifest and archive bytes.
// The caller continuously owns this actual RO transaction. SQLite native RO
// must be established before BeginTx; query_only is only supplemental. No Store
// pool fallback, live authorization/tenant filter, transaction end or file read.
func (s *Store) snapshotCompleteReportInventoryLimited(ctx context.Context, tx *gorm.DB, entryLimit int, legacyRowByteLimit int64) (snapshotCompleteReportInventory, error) {
	if ctx == nil || s == nil || tx == nil || tx.Config == nil || tx.Error != nil || tx.Statement == nil || tx.Dialector == nil || tx.Name() != s.driver || entryLimit < 1 || entryLimit > snapshotReportMaxEntries || legacyRowByteLimit < 1 || legacyRowByteLimit > backupmanifest.MaxFileBytes {
		return snapshotCompleteReportInventory{}, ErrConfiguration
	}
	if ctx.Err() != nil {
		return snapshotCompleteReportInventory{}, ErrUnavailable
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return snapshotCompleteReportInventory{}, ErrConfiguration
	}
	if actual, ok := tx.Statement.ConnPool.(*sql.Tx); !ok || actual == nil {
		return snapshotCompleteReportInventory{}, ErrConfiguration
	}
	read := tx.Session(&gorm.Session{NewDB: true, Context: ctx})
	if err := auditSnapshotTransaction(read, s.driver); err != nil {
		return snapshotCompleteReportInventory{}, err
	}
	// The fixed legacy row protocol must not silently omit future columns, even
	// on an empty or all-modern table. Keep the existing modern-only API intact.
	if err := snapshotLegacyReportSchema(read); err != nil {
		return snapshotCompleteReportInventory{}, err
	}
	count := func() (int64, error) {
		var total int64
		if err := read.Raw("SELECT COUNT(*) FROM (SELECT 1 FROM integrity_reports WHERE status='ready' LIMIT ?) complete_inventory_reports", entryLimit+1).Scan(&total).Error; err != nil || ctx.Err() != nil {
			return 0, ErrUnavailable
		}
		if total > int64(entryLimit) {
			return 0, errSnapshotReportLimit
		}
		return total, nil
	}
	total, err := count()
	if err != nil {
		return snapshotCompleteReportInventory{}, err
	}
	result := snapshotCompleteReportInventory{modern: []snapshotReportEntry{}, legacy: []snapshotCompleteLegacyReportEntry{}}
	var cursor, seen int64
	for {
		var page []snapshotReportRow
		if err := read.Table("integrity_reports r").Select(snapshotReportColumns(read)).Where("r.status='ready' AND r.id>?", cursor).Order("r.id").Limit(snapshotReportPageSize).Find(&page).Error; err != nil || ctx.Err() != nil {
			return snapshotCompleteReportInventory{}, ErrUnavailable
		}
		for _, row := range page {
			if row.ID <= cursor || seen >= total {
				return snapshotCompleteReportInventory{}, errSnapshotReportInvalid
			}
			switch row.Modern {
			case 1:
				entry, err := snapshotReportVerifyRow(ctx, read, row)
				if err != nil { // Never downgrade a failed modern row to legacy.
					return snapshotCompleteReportInventory{}, err
				}
				result.modern = append(result.modern, entry)
			case 0:
				descriptor, err := s.snapshotLegacyReportRow(ctx, read, row.ID, legacyRowByteLimit)
				if err != nil {
					return snapshotCompleteReportInventory{}, err
				}
				result.legacy = append(result.legacy, snapshotCompleteLegacyReportEntry{descriptor, backupmanifest.LegacyReportUnverified, backupmanifest.LegacyReportFileUnmapped})
			default:
				return snapshotCompleteReportInventory{}, errSnapshotReportInvalid
			}
			cursor, seen = row.ID, seen+1
		}
		if len(page) < snapshotReportPageSize {
			break
		}
	}
	// This final real query detects late rollback/failure even after the last
	// modern renderer, and closes NULL/nonpositive/duplicate cursor gaps. It is
	// still not ownership of the caller's later commit or archive publication.
	final, err := count()
	if err != nil {
		return snapshotCompleteReportInventory{}, err
	}
	if seen != total || final != total {
		return snapshotCompleteReportInventory{}, errSnapshotReportInvalid
	}
	return result, nil
}
