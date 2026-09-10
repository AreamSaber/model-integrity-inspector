package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"model-integrity-inspector.local/mii/internal/integrity/reportstorage"
)

const backupReportFileChunkBytes = 64 << 10

var errBackupReportFileCopy = errors.New("MI_BACKUP_REPORT_FILE_COPY_FAILED")

// This private receipt proves only that Store.Read verified a modern file and
// a trusted synchronous writer accepted all its bytes. It is NOT database
// authorization, a publication/restore capability, or a whole-archive receipt.
type backupReportFileReceipt struct {
	organizationID int64
	hash           string
	format         string
	size           int64
}

func (backupReportFileReceipt) String() string { return "[private backup report file receipt]" }
func (v backupReportFileReceipt) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, v.String())
}
func (v backupReportFileReceipt) LogValue() slog.Value { return slog.StringValue(v.String()) }
func (backupReportFileReceipt) MarshalJSON() ([]byte, error) {
	return nil, errBackupReportFileCopy
}
func (backupReportFileReceipt) MarshalYAML() (any, error) {
	return nil, errBackupReportFileCopy
}

// The future coordinator must obtain ref from its complete, same-transaction
// authorized inventory; an arbitrary valid Reference does not establish that
// provenance. Legacy storage_path and unknown layouts are deliberately absent.
//
// Read owns ONE complete source body (at most reportstorage.MaxBytes, 16 MiB),
// using the existing native no-follow/ACL/identity/size/hash checks. Only output
// is chunked: this is not a 64 KiB source-memory/streaming implementation. The
// owned body is cleared before returning, including cancellation and panic.
//
// sink must obey io.Writer (no retaining/modifying p) and cooperate with the
// deadline: a synchronous blocked Write cannot be forcibly interrupted here.
// There is no retry, sink rollback, Close, Sync or publish. On any failure the
// receipt is zero, but sink may contain a prefix or even all plaintext. Keep it
// private/unpublished until the WHOLE authenticated archive and atomic output
// lifecycle succeed; callers must not swallow this function's failure.
func copyBackupReportFile(ctx context.Context, store *reportstorage.Store, ref reportstorage.Reference, sink io.Writer) (receipt backupReportFileReceipt, err error) {
	var data []byte
	defer func() {
		clear(data)
		// Includes a typed-nil writer and an unexpected writer panic. Do not
		// stringify, wrap or log caller-controlled error/panic values.
		if recover() != nil {
			receipt, err = backupReportFileReceipt{}, errBackupReportFileCopy
		}
	}()
	if ctx == nil || store == nil || sink == nil {
		return backupReportFileReceipt{}, ErrConfig
	}
	if _, ok := ctx.Deadline(); !ok {
		return backupReportFileReceipt{}, ErrConfig
	}
	if ctx.Err() != nil {
		return backupReportFileReceipt{}, errBackupReportFileCopy
	}
	data, err = store.Read(ctx, ref)
	if err != nil {
		// Keep only the storage component's fixed, public error identities.
		for _, known := range []error{reportstorage.ErrUnsafe, reportstorage.ErrUnavailable, reportstorage.ErrIntegrity} {
			if errors.Is(err, known) {
				return backupReportFileReceipt{}, known
			}
		}
		return backupReportFileReceipt{}, errBackupReportFileCopy
	}
	for offset := 0; offset < len(data); {
		if ctx.Err() != nil {
			return backupReportFileReceipt{}, errBackupReportFileCopy
		}
		end := min(offset+backupReportFileChunkBytes, len(data))
		// Full slice bounds stop a writer from reslicing into a later chunk.
		n, writeErr := sink.Write(data[offset:end:end])
		if writeErr != nil || n != end-offset || ctx.Err() != nil {
			return backupReportFileReceipt{}, errBackupReportFileCopy
		}
		offset = end
	}
	if ctx.Err() != nil {
		return backupReportFileReceipt{}, errBackupReportFileCopy
	}
	return backupReportFileReceipt{ref.OrganizationID, ref.Hash, ref.Format, ref.Size}, nil
}
