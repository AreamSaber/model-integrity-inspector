package backupmanifest

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	hashpkg "hash"
	"io"
	"log/slog"
	"time"
)

// LegacyReportRowText borrows the exact bytes of one SQL TEXT value. Bytes is
// its encoded byte count, not a character count. Present empty values still
// require a reader that produces real EOF; NULL requires zero Bytes/nil Reader.
// Readers are synchronous, must honor the caller's lifetime/deadline, and must
// not retain work. No JSON, UTF-8, whitespace, hash or locator normalization is
// performed. The future snapshot adapter must supply the original bytes.
type LegacyReportRowText struct {
	Present bool
	Bytes   int64
	Reader  io.Reader
}

type LegacyReportRowInteger struct {
	Present bool
	Value   int64
}

// LegacyReportRowTime borrows the exact driver-specific timestamp representation.
// SQLite uses the original SQL TEXT storage bytes (checked as TEXT, read as BLOB),
// never an already parsed time.Time or reformatted string. Offsets, nanoseconds,
// spelling and empty TEXT are preserved. Non-TEXT SQLite timestamps require a
// different explicit protocol, not an implicit cast/normalization. PostgreSQL
// uses the native eight-byte TIMESTAMP WITHOUT TIME ZONE binary representation:
// signed big-endian microseconds since 2000-01-01, including its infinity values.
// No DateStyle, host timezone, parsing, rounding or reconstruction is involved.
// The same null/length/reader rules as LegacyReportRowText apply. This component
// cannot prove that a future snapshot adapter obtained the stipulated bytes.
type LegacyReportRowTime struct {
	Present bool
	Bytes   int64
	Reader  io.Reader
}

// LegacyReportRow is the fixed 20-column integrity_reports logical row after
// migration 14. It is not a Report, a publication proof or restore authority.
// Nullable values are explicit; even unknown legacy TEXT/hash/locator contents
// remain exact. The current identity bounds match the manifest's identities.
type LegacyReportRow struct {
	DatabaseDriver                              string
	ID, OrganizationID, RunID, AnalysisRevision int64
	ReportFormat, SchemaVersion                 LegacyReportRowText
	Revision                                    int64
	ContentHash, StoragePath, Status, ErrorCode LegacyReportRowText
	CreatedAt, CompletedAt                      LegacyReportRowTime
	CreatedBy, JobID                            LegacyReportRowInteger
	SourceJSON, SourceHash, FileHash            LegacyReportRowText
	FileSize                                    LegacyReportRowInteger
	FrozenAt                                    LegacyReportRowTime
}

// MaxBytes includes the domain, all framing/scalars and every TEXT byte. It may
// only tighten the archive's fixed 1 TiB ceiling; no row is buffered in memory.
type LegacyReportRowLimits struct {
	MaxBytes int64
	Timeout  time.Duration
}

func (LegacyReportRowText) String() string                  { return "[private legacy report text]" }
func (v LegacyReportRowText) Format(s fmt.State, _ rune)    { _, _ = io.WriteString(s, v.String()) }
func (v LegacyReportRowText) LogValue() slog.Value          { return slog.StringValue(v.String()) }
func (LegacyReportRowText) MarshalJSON() ([]byte, error)    { return nil, ErrInvalid }
func (LegacyReportRowText) MarshalYAML() (any, error)       { return nil, ErrInvalid }
func (LegacyReportRowInteger) String() string               { return "[private legacy report integer]" }
func (v LegacyReportRowInteger) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (v LegacyReportRowInteger) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (LegacyReportRowInteger) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (LegacyReportRowInteger) MarshalYAML() (any, error)    { return nil, ErrInvalid }
func (LegacyReportRowTime) String() string                  { return "[private legacy report time]" }
func (v LegacyReportRowTime) Format(s fmt.State, _ rune)    { _, _ = io.WriteString(s, v.String()) }
func (v LegacyReportRowTime) LogValue() slog.Value          { return slog.StringValue(v.String()) }
func (LegacyReportRowTime) MarshalJSON() ([]byte, error)    { return nil, ErrInvalid }
func (LegacyReportRowTime) MarshalYAML() (any, error)       { return nil, ErrInvalid }
func (LegacyReportRow) String() string                      { return "[private legacy report row]" }
func (v LegacyReportRow) Format(s fmt.State, _ rune)        { _, _ = io.WriteString(s, v.String()) }
func (v LegacyReportRow) LogValue() slog.Value              { return slog.StringValue(v.String()) }
func (LegacyReportRow) MarshalJSON() ([]byte, error)        { return nil, ErrInvalid }
func (LegacyReportRow) MarshalYAML() (any, error)           { return nil, ErrInvalid }

const legacyReportRowDomain = "mii/legacy-report-row/v1\x00"
const (
	legacyRowInteger  = byte(1)
	legacyRowTypeText = byte(2)
	legacyRowTime     = byte(3)
)

type legacyReportRowColumn struct {
	kind     byte
	required bool
	integer  LegacyReportRowInteger
	text     LegacyReportRowText
	stamp    LegacyReportRowTime
}

// Column order is part of LegacyReportRowVersion, not Go struct reflection:
// 1 id; 2 organization_id; 3 run_id; 4 analysis_revision; 5 format;
// 6 schema_version; 7 revision; 8 content_hash; 9 storage_path; 10 status;
// 11 error_code; 12 created_at; 13 completed_at; 14 created_by; 15 job_id;
// 16 source_json; 17 source_hash; 18 file_hash; 19 file_size; 20 frozen_at.
// A future column addition needs a separately defined row protocol, not silent
// inclusion/omission under this version.
func legacyReportRowColumns(r LegacyReportRow) [20]legacyReportRowColumn {
	integer := func(v int64) legacyReportRowColumn {
		return legacyReportRowColumn{kind: legacyRowInteger, required: true, integer: LegacyReportRowInteger{true, v}}
	}
	optionalInteger := func(v LegacyReportRowInteger) legacyReportRowColumn {
		return legacyReportRowColumn{kind: legacyRowInteger, integer: v}
	}
	text := func(v LegacyReportRowText, required bool) legacyReportRowColumn {
		return legacyReportRowColumn{kind: legacyRowTypeText, required: required, text: v}
	}
	stamp := func(v LegacyReportRowTime, required bool) legacyReportRowColumn {
		return legacyReportRowColumn{kind: legacyRowTime, required: required, stamp: v}
	}
	return [20]legacyReportRowColumn{
		integer(r.ID), integer(r.OrganizationID), integer(r.RunID), integer(r.AnalysisRevision),
		text(r.ReportFormat, true), text(r.SchemaVersion, true), integer(r.Revision),
		text(r.ContentHash, false), text(r.StoragePath, false), text(r.Status, true), text(r.ErrorCode, false),
		stamp(r.CreatedAt, true), stamp(r.CompletedAt, false), optionalInteger(r.CreatedBy), optionalInteger(r.JobID),
		text(r.SourceJSON, false), text(r.SourceHash, false), text(r.FileHash, false), optionalInteger(r.FileSize), stamp(r.FrozenAt, false),
	}
}

func legacyReportRowColumnShape(c legacyReportRowColumn) (bool, int64, bool) {
	switch c.kind {
	case legacyRowInteger:
		return c.integer.Present, 8, c.integer.Present || c.integer.Value == 0
	case legacyRowTypeText:
		return c.text.Present, c.text.Bytes + 8, c.text.Bytes >= 0 && c.text.Bytes <= MaxFileBytes && (c.text.Present && c.text.Reader != nil || !c.text.Present && c.text.Bytes == 0 && c.text.Reader == nil)
	case legacyRowTime:
		return legacyReportRowColumnShape(legacyReportRowColumn{kind: legacyRowTypeText, text: LegacyReportRowText(c.stamp)})
	default:
		return false, 0, false
	}
}

// DigestLegacyReportRow implements LegacyReportRowVersion. The preimage is the
// ASCII domain above, driver:u8 (SQLite=1,PostgreSQL=2), column-count:u8 (20),
// then twenty fixed frames:
// ordinal:u8, type:u8 (integer=1,text=2,time=3), presence:u8 (NULL=0,value=1).
// NULL has no payload. Integers are signed 64-bit two's-complement big-endian.
// TEXT is length:u64 big-endian followed by exactly that many unchanged bytes.
// Time is length:u64 followed by the exact driver-specific timestamp bytes
// defined above. The output is lowercase SHA-256, never a MAC/signature or evidence
// of row acquisition. Every TEXT must finish with exact io.EOF; real errors,
// late errors/cancellation and excess bytes cannot produce a usable hash.
func DigestLegacyReportRow(ctx context.Context, row LegacyReportRow, limits LegacyReportRowLimits) (sum string, result error) {
	defer func() {
		if recover() != nil {
			sum, result = "", ErrRead
		}
	}()
	if ctx == nil || ctx.Err() != nil {
		return "", ErrCanceled
	}
	if limits.MaxBytes < 1 || limits.MaxBytes > MaxFileBytes || limits.Timeout <= 0 || limits.Timeout > MaxStreamTimeout {
		return "", ErrLimit
	}
	if row.ID <= 0 || row.OrganizationID <= 0 || row.RunID <= 0 || row.AnalysisRevision < 1 || row.AnalysisRevision > 2147483647 || row.Revision < 1 || row.Revision > 2147483647 {
		return "", ErrInvalid
	}
	var driver byte
	switch row.DatabaseDriver {
	case "sqlite":
		driver = 1
	case "postgres":
		driver = 2
	default:
		return "", ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()
	columns := legacyReportRowColumns(row)
	total := int64(len(legacyReportRowDomain) + 2)
	for _, column := range columns {
		present, payload, valid := legacyReportRowColumnShape(column)
		if !valid || column.required && !present {
			return "", ErrInvalid
		}
		if driver == 2 && column.kind == legacyRowTime && present && column.stamp.Bytes != 8 {
			return "", ErrInvalid
		}
		size := int64(3)
		if present {
			size += payload
		}
		if total > limits.MaxBytes-size {
			return "", ErrLimit
		}
		total += size
	}
	buffer := make([]byte, 64<<10)
	defer clear(buffer)
	h := sha256.New()
	_, _ = h.Write([]byte(legacyReportRowDomain))
	_, _ = h.Write([]byte{driver, 20})
	for i, column := range columns {
		if ctx.Err() != nil {
			return "", ErrCanceled
		}
		present, _, _ := legacyReportRowColumnShape(column)
		// #nosec G115 -- Fixed twenty-column array; ordinals are 1..20.
		frame := [3]byte{byte(i + 1), column.kind, 0}
		if present {
			frame[2] = 1
		}
		_, _ = h.Write(frame[:])
		if !present {
			continue
		}
		switch column.kind {
		case legacyRowInteger:
			var encoded [8]byte
			// #nosec G115 -- Deliberate signed two's-complement protocol encoding.
			binary.BigEndian.PutUint64(encoded[:], uint64(column.integer.Value))
			_, _ = h.Write(encoded[:])
		case legacyRowTypeText, legacyRowTime:
			value := column.text
			if column.kind == legacyRowTime {
				value = LegacyReportRowText(column.stamp)
			}
			var encoded [8]byte
			// #nosec G115 -- Shape validation bounds length to 0..1 TiB.
			binary.BigEndian.PutUint64(encoded[:], uint64(value.Bytes))
			_, _ = h.Write(encoded[:])
			if err := digestLegacyReportRowText(ctx, h, buffer, value); err != nil {
				return "", err
			}
		}
	}
	if ctx.Err() != nil {
		return "", ErrCanceled
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func digestLegacyReportRowText(ctx context.Context, h hashpkg.Hash, buffer []byte, value LegacyReportRowText) error {
	var read int64
	for {
		if ctx.Err() != nil {
			return ErrCanceled
		}
		requested := min(int64(len(buffer)), value.Bytes-read+1)
		n, err := value.Reader.Read(buffer[:requested])
		if n < 0 || int64(n) > requested {
			return ErrRead
		}
		if ctx.Err() != nil {
			return ErrCanceled
		}
		if int64(n) > value.Bytes-read {
			return ErrMismatch
		}
		if n > 0 {
			_, _ = h.Write(buffer[:n])
			clear(buffer[:n])
			read += int64(n)
		}
		if err == io.EOF { //nolint:errorlint // Only exact Reader EOF is successful; joined read failures must not pass.
			if read != value.Bytes {
				return ErrMismatch
			}
			return nil
		}
		if err != nil || n == 0 {
			return ErrRead
		}
	}
}
