package app

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/reportstorage"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

// Real file and AEAD composition, with a synthetic backup scope (not a DB
// manifest, coordinator, filesystem publication, or restore authorization).
func TestBackupReportFileActualArchiveRequiresWholeCompletion(t *testing.T) {
	store, _ := backupReportFileTestStore(t)
	original := backupReportFileTestArtifacts(t)["csv"]
	ref := backupReportFileTestPut(t, store, "csv", original)
	ring, err := secret.NewKeyRing("v3", map[string][]byte{"v3": bytes.Repeat([]byte{0x37}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	seal, open, err := ring.NewBackupCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	scope := secret.BackupScope{BackupID: 31, ManifestHash: ref.Hash}
	limits := secret.BackupLimits{MaxBytes: 1 << 20, MaxEntries: 4, Timeout: 5 * time.Second}
	for _, mode := range []string{"valid", "copy_failed", "entry_failure_swallowed", "late_producer_failure", "truncated_tail", "extra_tail"} {
		t.Run(mode, func(t *testing.T) {
			var staging bytes.Buffer
			var tentativeCopy backupReportFileReceipt
			var entryFailure error
			sealed, err := seal.Seal(t.Context(), scope, limits, &staging, func(_ context.Context, archive *secret.BackupArchiveWriter) error {
				entryFailure = archive.WriteEntry(secret.BackupEntry{Kind: "report", ID: "report-31-csv"}, func(ctx context.Context, out io.Writer) error {
					if mode == "copy_failed" || mode == "entry_failure_swallowed" {
						realOut := out
						out = backupReportFileWriterFunc(func(p []byte) (int, error) {
							n, err := realOut.Write(p)
							if err != nil {
								return n, err
							}
							return n, backupReportFilePrivateError{}
						})
					}
					var copyErr error
					tentativeCopy, copyErr = copyBackupReportFile(ctx, store, ref, out)
					return copyErr
				})
				if mode == "late_producer_failure" {
					return errBackupReportFileCopy
				}
				if mode == "entry_failure_swallowed" {
					return nil // Real archive's sticky entry error must still win.
				}
				return entryFailure
			})
			var publishedArchive []byte
			if err == nil {
				publishedArchive = bytes.Clone(staging.Bytes())
			}
			if mode == "copy_failed" || mode == "entry_failure_swallowed" || mode == "late_producer_failure" {
				if err == nil || sealed != (secret.BackupReceipt{}) || publishedArchive != nil || staging.Len() == 0 {
					t.Fatal("partial archive gained a completion receipt/publication")
				}
				if mode == "late_producer_failure" {
					if tentativeCopy.size != ref.Size || entryFailure != nil {
						t.Fatal("late failure did not exercise an already-copied complete entry")
					}
				} else if tentativeCopy != (backupReportFileReceipt{}) || entryFailure == nil {
					t.Fatal("copy failure was not propagated to the real archive")
				}
				return
			}
			if err != nil || sealed.Entries != 1 || tentativeCopy.size != ref.Size || publishedArchive == nil {
				t.Fatal("actual file/archive production failed", err)
			}
			switch mode {
			case "truncated_tail":
				publishedArchive = publishedArchive[:len(publishedArchive)-1]
			case "extra_tail":
				publishedArchive = append(publishedArchive, 1)
			}
			var tentativePlain []byte
			opened, err := open.Open(t.Context(), scope, limits, bytes.NewReader(publishedArchive), func(_ context.Context, entry secret.BackupEntry, reader io.Reader) error {
				if tentativePlain != nil || entry.Kind != "report" || entry.ID != "report-31-csv" {
					return ErrConfig
				}
				var readErr error
				tentativePlain, readErr = io.ReadAll(io.LimitReader(reader, reportstorage.MaxBytes+1))
				if readErr != nil || !bytes.Equal(tentativePlain, original) {
					return errBackupReportFileCopy
				}
				return nil
			})
			var publishedPlain []byte
			if err == nil {
				publishedPlain = tentativePlain
			}
			if mode == "valid" {
				if err != nil || opened.Entries != 1 || !bytes.Equal(publishedPlain, original) {
					t.Fatal("real encrypted archive changed report bytes", err)
				}
			} else if err == nil || opened != (secret.BackupReceipt{}) || publishedPlain != nil || !bytes.Equal(tentativePlain, original) {
				t.Fatal("tail failure did not withhold a fully consumed report entry")
			}
		})
	}
}
