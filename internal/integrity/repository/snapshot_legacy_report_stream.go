package repository

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"gorm.io/gorm"
)

const snapshotLegacyReportChunkBytes = 64 << 10

// Entirely private, synchronously borrowed by the pure fixed-row hasher. It
// returns no synthetic EOF at the declared length: one final SQL slice proves
// both the row's continued presence and the actual end of its byte value.
type snapshotLegacyReportReader struct {
	ctx          context.Context
	tx           *gorm.DB
	descriptor   snapshotLegacyReportDescriptor
	column       snapshotLegacyReportColumn
	size, offset int64
	closed       bool
}

func (*snapshotLegacyReportReader) String() string { return "[private snapshot legacy report reader]" }
func (v *snapshotLegacyReportReader) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, v.String())
}
func (v *snapshotLegacyReportReader) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (*snapshotLegacyReportReader) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (*snapshotLegacyReportReader) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

func (r *snapshotLegacyReportReader) Read(dst []byte) (int, error) {
	if r == nil || r.closed || r.ctx == nil || r.tx == nil || r.ctx.Err() != nil {
		return 0, ErrUnavailable
	}
	if len(dst) == 0 {
		return 0, nil
	}
	size := min(len(dst), snapshotLegacyReportChunkBytes)
	valid, data := snapshotLegacyReportColumnSQL(r.tx, r.column)
	length, chunk := "length("+data+")", "substr("+data+", ?, ?)"
	if r.tx.Name() == "postgres" {
		if r.offset >= 2147483647 {
			return 0, errSnapshotLegacyReportLimit
		}
		length, chunk = "octet_length("+data+")", "substring("+data+" FROM ? FOR ?)"
	}
	var row struct{ Data []byte }
	d := r.descriptor
	query := "SELECT " + chunk + " AS data FROM integrity_reports r WHERE r.id=? AND r.organization_id=? AND r.run_id=? AND r.analysis_revision=? AND r.revision=? AND " + valid + " AND " + length + "=?"
	read := r.tx.Session(&gorm.Session{NewDB: true, Context: r.ctx}).Raw(query, r.offset+1, size, d.id, d.organizationID, d.runID, d.analysisRevision, d.revision, r.size).Scan(&row)
	defer clear(row.Data)
	if read.Error != nil || read.RowsAffected != 1 || r.ctx.Err() != nil {
		return 0, ErrUnavailable
	}
	if len(row.Data) > size || int64(len(row.Data)) > r.size-r.offset {
		return 0, errSnapshotLegacyReportInvalid
	}
	if len(row.Data) == 0 {
		if r.offset != r.size {
			return 0, errSnapshotLegacyReportInvalid
		}
		return 0, io.EOF
	}
	n := copy(dst, row.Data)
	r.offset += int64(n)
	return n, nil
}
