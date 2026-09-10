package app

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
	"model-integrity-inspector.local/mii/internal/integrity/privatefile"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

var errBackupArchiveReadback = errors.New("MI_BACKUP_ARCHIVE_READBACK_FAILED")

// finishBackupArchive is the final coordinator stage, not an HTTP entry point.
// All inputs originate in its owned snapshot/publication operation. directory is
// a configured trusted private destination, objectID is generated internally,
// and expected is the original successful Seal receipt. A prior WriteNew error,
// even with Published=true, must never call this method as a successful write.
//
// It validates the WHOLE real file against the original manifest and ciphertext
// receipts before the short DB completion transaction. It neither acquires the
// snapshot nor substitutes for resource closure, key-purpose verification or
// process cleanup. Failures leave the private file intact and never call Abort.
func finishBackupArchive(ctx context.Context, lease *repository.MaintenanceLease, directory, objectID string, manifest backupmanifest.Manifest, opener *secret.BackupOpener, limits secret.BackupLimits, expected secret.BackupReceipt, written privatefile.Receipt) (repository.BackupCompletionReceipt, error) {
	if ctx == nil || ctx.Err() != nil || lease == nil || opener == nil || len(objectID) != 64 || strings.Trim(objectID, "0123456789abcdef") != "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || limits.Timeout <= 0 || limits.Timeout > secret.BackupMaxTimeout {
		return repository.BackupCompletionReceipt{}, errBackupArchiveReadback
	}
	ctx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()
	id, started := lease.BackupIdentity()
	if id != manifest.BackupID || started != manifest.StartedAtMicros || expected.Version != secret.BackupFormatVersion || !written.Published || written.Size != expected.ArchiveBytes || written.SHA256 != expected.ArchiveSHA256 || written.Size < 1 || written.Size > privatefile.MaxBytes || !slices.Contains(manifest.KeyVersions, expected.KeyVersion) {
		return repository.BackupCompletionReceipt{}, errBackupArchiveReadback
	}
	// Canonical encoding and independent decoding also make owned list copies;
	// subsequent callbacks cannot change the verification plan through aliases.
	data, sum, err := backupmanifest.Encode(manifest)
	if err != nil {
		return repository.BackupCompletionReceipt{}, errBackupArchiveReadback
	}
	owned, err := backupmanifest.Decode(data, id, sum)
	clear(data)
	if err != nil {
		return repository.BackupCompletionReceipt{}, errBackupArchiveReadback
	}
	if _, err := lease.Observe(ctx); err != nil {
		return repository.BackupCompletionReceipt{}, err
	}
	var opened secret.BackupReceipt
	file, err := privatefile.Read(ctx, filepath.Join(directory, objectID+".mii-backup"), privatefile.Limits{MaxBytes: written.Size, Timeout: limits.Timeout}, func(ctx context.Context, in io.Reader) error {
		return backupmanifest.VerifyStream(ctx, owned, limits.Timeout, func(ctx context.Context, accept func(string, string, io.Reader) error) error {
			var openErr error
			opened, openErr = opener.Open(ctx, secret.BackupScope{BackupID: id, ManifestHash: sum}, limits, in, func(_ context.Context, entry secret.BackupEntry, reader io.Reader) error {
				return accept(entry.Kind, entry.ID, reader)
			})
			return openErr
		})
	})
	if err != nil || opened != expected || file.Size != written.Size || file.SHA256 != written.SHA256 || ctx.Err() != nil {
		return repository.BackupCompletionReceipt{}, errBackupArchiveReadback
	}
	return lease.CompleteBackup(ctx, repository.BackupPublication{BackupID: id, SnapshotAtMicros: owned.SnapshotAtMicros, ManifestVersion: owned.SchemaVersion, ManifestSHA256: sum, DatabaseSHA256: owned.Database.File.SHA256, ArchiveSHA256: opened.ArchiveSHA256, ArchiveBytes: opened.ArchiveBytes, PlaintextBytes: opened.PlaintextBytes, Entries: opened.Entries, WrappingKeyVersion: opened.KeyVersion, ObjectID: objectID})
}
