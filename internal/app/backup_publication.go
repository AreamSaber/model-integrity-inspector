package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
	"model-integrity-inspector.local/mii/internal/integrity/privatefile"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

var errBackupPublication = errors.New("MI_BACKUP_PUBLICATION_FAILED")

// Separate logical budgets: workspace counts each owned object once; archive
// plaintext counts every entry, including repeated use of the same object and
// the generated manifest. Ciphertext has its own framing-inclusive file budget.
// Concurrent workspace+ciphertext logical storage is bounded by their sum, NOT
// physical filesystem allocation/free-space reservation or measured capacity.
type backupPublicationLimits struct {
	MaxWorkspaceBytes int64
	MaxPlaintextBytes int64
	MaxArchiveBytes   int64
	MaxEntries        int
	Timeout           time.Duration
}

// The synchronous trusted capture transfers ownership of these values and MUST
// NOT retain/mutate them or start detached work. This is not an HTTP DTO, a SQL
// API, evidence of a genuine full snapshot, or a way to supply archive paths.
// Objects contains precisely the non-manifest entry IDs from the supplied
// manifest. The coordinator creates canonical backup-manifest itself.
type backupPublicationCapture struct {
	manifest backupmanifest.Manifest
	objects  map[string]privatefile.BackupObject
}

func (backupPublicationCapture) String() string               { return "[private backup capture]" }
func (v backupPublicationCapture) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (v backupPublicationCapture) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (backupPublicationCapture) MarshalJSON() ([]byte, error) { return nil, errBackupPublication }
func (backupPublicationCapture) MarshalYAML() (any, error)    { return nil, errBackupPublication }

type backupPublicationCaptureFunc func(context.Context, *privatefile.BackupWorkspace) (backupPublicationCapture, error)

// Dependencies are immutable per invocation, never package-global hooks. Only
// tests wrap real successful calls to test propagation of controlled late
// failures; production always supplies the actual native implementations.
type backupPublicationDependencies struct {
	workspace func(context.Context, string, privatefile.BackupWorkspaceLimits, func(context.Context, *privatefile.BackupWorkspace) error) (privatefile.BackupWorkspaceReceipt, error)
	write     func(context.Context, string, privatefile.Limits, func(context.Context, io.Writer) error) (privatefile.Receipt, error)
}

// publishBackupArchive owns archive construction through authenticated durable
// completion. Capture must close its independent DB/source staging scopes and
// establish actual same-snapshot closure; this function cannot infer those facts
// from a claimed manifest. Only final payloads belong in this workspace.
//
// There is no automatic Abort, retry, overwrite or cleanup of published files.
// Any failed call returns zero completion. If native publication succeeded but
// its final close, readback or database completion failed, the private archive
// remains for explicit authorized reconciliation, not as a downloadable backup.
func publishBackupArchive(ctx context.Context, lease *repository.MaintenanceLease, directory string, sealer *secret.BackupSealer, opener *secret.BackupOpener, limits backupPublicationLimits, capture backupPublicationCaptureFunc) (repository.BackupCompletionReceipt, error) {
	return publishBackupArchiveWithDependencies(ctx, lease, directory, sealer, opener, limits, capture, backupPublicationDependencies{workspace: privatefile.WithBackupWorkspace, write: privatefile.WriteNew})
}

func publishBackupArchiveWithDependencies(ctx context.Context, lease *repository.MaintenanceLease, directory string, sealer *secret.BackupSealer, opener *secret.BackupOpener, limits backupPublicationLimits, capture backupPublicationCaptureFunc, deps backupPublicationDependencies) (receipt repository.BackupCompletionReceipt, finalErr error) {
	returned := false
	defer func() {
		if !returned {
			_ = recover()
			finalErr = errBackupPublication
		}
		if finalErr != nil {
			receipt = repository.BackupCompletionReceipt{}
		}
	}()
	receipt, finalErr = runBackupPublication(ctx, lease, directory, sealer, opener, limits, capture, deps)
	returned = true
	return receipt, finalErr
}

type backupPublicationPlan struct {
	manifest                       backupmanifest.Manifest
	sum                            string
	entries                        []backupmanifest.Entry
	objects                        map[string]privatefile.BackupObject
	workspaceBytes, plaintextBytes int64
	workspaceObjects               int
}

func runBackupPublication(ctx context.Context, lease *repository.MaintenanceLease, directory string, sealer *secret.BackupSealer, opener *secret.BackupOpener, limits backupPublicationLimits, capture backupPublicationCaptureFunc, deps backupPublicationDependencies) (repository.BackupCompletionReceipt, error) {
	zero := repository.BackupCompletionReceipt{}
	if ctx == nil || ctx.Err() != nil || lease == nil || sealer == nil || opener == nil || capture == nil || deps.workspace == nil || deps.write == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return zero, errBackupPublication
	}
	if limits.MaxWorkspaceBytes < 1 || limits.MaxWorkspaceBytes > privatefile.MaxBytes || limits.MaxPlaintextBytes < 1 || limits.MaxPlaintextBytes > secret.BackupMaxBytes || limits.MaxArchiveBytes < 1 || limits.MaxArchiveBytes > privatefile.MaxBytes || limits.MaxEntries < 3 || limits.MaxEntries > backupmanifest.MaxEntries || limits.Timeout <= 0 || limits.Timeout > privatefile.MaxTimeout {
		return zero, errBackupPublication
	}
	ctx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()
	backupID, started := lease.BackupIdentity()
	if backupID <= 0 || started <= 0 {
		return zero, errBackupPublication
	}
	if _, err := lease.Observe(ctx); err != nil {
		return zero, err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return zero, errBackupPublication
	}
	objectID := hex.EncodeToString(nonce[:])
	cryptoLimits := secret.BackupLimits{MaxBytes: limits.MaxPlaintextBytes, MaxEntries: limits.MaxEntries, Timeout: limits.Timeout}
	var plan backupPublicationPlan
	var sealed secret.BackupReceipt
	written, err := deps.write(ctx, filepath.Join(directory, objectID+".mii-backup"), privatefile.Limits{MaxBytes: limits.MaxArchiveBytes, Timeout: limits.Timeout}, func(ctx context.Context, dst io.Writer) error {
		staged, err := deps.workspace(ctx, directory, privatefile.BackupWorkspaceLimits{MaxBytes: limits.MaxWorkspaceBytes, MaxEntries: limits.MaxEntries, Timeout: limits.Timeout}, func(ctx context.Context, w *privatefile.BackupWorkspace) error {
			captured, err := capture(ctx, w)
			if err != nil {
				return errBackupPublication
			}
			plan, err = prepareBackupPublicationPlan(ctx, w, captured, backupID, started, limits)
			if err != nil {
				return errBackupPublication
			}
			buffer := make([]byte, 64<<10)
			defer clear(buffer)
			sealed, err = sealer.Seal(ctx, secret.BackupScope{BackupID: backupID, ManifestHash: plan.sum}, cryptoLimits, dst, func(_ context.Context, a *secret.BackupArchiveWriter) error {
				for _, entry := range plan.entries {
					if ctx.Err() != nil {
						return errBackupPublication
					}
					if err := a.WriteEntry(secret.BackupEntry{Kind: entry.Kind, ID: entry.File.EntryID}, func(_ context.Context, out io.Writer) error {
						info, err := w.Read(plan.objects[entry.File.EntryID], func(_ context.Context, r io.Reader) error { _, err := io.CopyBuffer(out, r, buffer); return err })
						if err != nil || info.Size != entry.File.Bytes || info.SHA256 != entry.File.SHA256 {
							return errBackupPublication
						}
						return nil
					}); err != nil {
						return errBackupPublication
					}
				}
				return nil
			})
			if err != nil || sealed.Version != secret.BackupFormatVersion || sealed.Entries != len(plan.entries) || sealed.PlaintextBytes != plan.plaintextBytes || !slices.Contains(plan.manifest.KeyVersions, sealed.KeyVersion) || ctx.Err() != nil {
				return errBackupPublication
			}
			return nil
		})
		// This runs only AFTER workspace final inspection, invalidation, close
		// and cleanup. Extra unmapped scratch (including empty objects) fails
		// before WriteNew may publish, even if AEAD already emitted its trailer.
		if err != nil || staged.Objects != plan.workspaceObjects || staged.Bytes != plan.workspaceBytes || ctx.Err() != nil {
			return errBackupPublication
		}
		return nil
	})
	if err != nil || !written.Published || written.Size != sealed.ArchiveBytes || written.SHA256 != sealed.ArchiveSHA256 || written.Size < 1 || written.Size > limits.MaxArchiveBytes || ctx.Err() != nil {
		return zero, errBackupPublication
	}
	// No subsequent cleanup, publication action or fallible work follows a
	// successful DB completion. The completion receipt is the commit outcome.
	return finishBackupArchive(ctx, lease, directory, objectID, plan.manifest, opener, cryptoLimits, sealed, written)
}

func prepareBackupPublicationPlan(ctx context.Context, w *privatefile.BackupWorkspace, captured backupPublicationCapture, backupID, started int64, limits backupPublicationLimits) (backupPublicationPlan, error) {
	zero := backupPublicationPlan{}
	if ctx.Err() != nil || captured.manifest.BackupID != backupID || captured.manifest.StartedAtMicros != started || len(captured.objects) > limits.MaxEntries-1 {
		return zero, errBackupPublication
	}
	encoded, sum, err := backupmanifest.Encode(captured.manifest)
	if err != nil {
		return zero, errBackupPublication
	}
	defer clear(encoded)
	owned, err := backupmanifest.Decode(encoded, backupID, sum)
	if err != nil {
		return zero, errBackupPublication
	}
	entries, err := backupmanifest.Entries(owned)
	if err != nil || len(entries) > limits.MaxEntries || len(captured.objects) != len(entries)-1 {
		return zero, errBackupPublication
	}
	plan := backupPublicationPlan{manifest: owned, sum: sum, entries: entries, objects: make(map[string]privatefile.BackupObject, len(entries)), workspaceBytes: int64(len(encoded)), plaintextBytes: int64(len(encoded)), workspaceObjects: 1}
	if plan.workspaceBytes > limits.MaxWorkspaceBytes || plan.plaintextBytes > limits.MaxPlaintextBytes {
		return zero, errBackupPublication
	}
	unique := make(map[privatefile.BackupObject]bool, len(captured.objects))
	for _, entry := range entries[1:] {
		if ctx.Err() != nil {
			return zero, errBackupPublication
		}
		object, present := captured.objects[entry.File.EntryID]
		if !present {
			return zero, errBackupPublication
		}
		info, err := object.Info()
		if err != nil || info.Size != entry.File.Bytes || info.SHA256 != entry.File.SHA256 || info.Size > limits.MaxPlaintextBytes-plan.plaintextBytes {
			return zero, errBackupPublication
		}
		plan.plaintextBytes += info.Size
		if !unique[object] {
			if info.Size > limits.MaxWorkspaceBytes-plan.workspaceBytes {
				return zero, errBackupPublication
			}
			unique[object] = true
			plan.workspaceBytes += info.Size
			plan.workspaceObjects++
		}
		plan.objects[entry.File.EntryID] = object
	}
	manifestObject, err := w.Put(privatefile.BackupObjectLimits{MaxBytes: int64(len(encoded))}, func(_ context.Context, dst io.Writer) error { _, err := dst.Write(encoded); return err })
	if err != nil {
		return zero, errBackupPublication
	}
	info, err := manifestObject.Info()
	if err != nil || info.Size != int64(len(encoded)) || info.SHA256 != sum || entries[0].Kind != "manifest" || entries[0].File.EntryID != "backup-manifest" || entries[0].File.SHA256 != sum || ctx.Err() != nil {
		return zero, errBackupPublication
	}
	plan.objects["backup-manifest"] = manifestObject
	return plan, nil
}
