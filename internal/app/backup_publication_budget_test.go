package app

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
	"model-integrity-inspector.local/mii/internal/integrity/privatefile"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

// Distinct legitimate entry IDs may share one exact byte object. The manifest
// remains explicit; this fixture deduplicates only its owned immutable payloads.
func backupPublicationDeduplicatedCapture(t *testing.T, f *backupCompletionFixture, w *privatefile.BackupWorkspace) backupPublicationCapture {
	t.Helper()
	entries, err := backupmanifest.Entries(f.manifest)
	if err != nil {
		t.Fatal("alias entry fixture")
	}
	result := backupPublicationCapture{manifest: f.manifest, objects: make(map[string]privatefile.BackupObject)}
	byBody := make(map[string]privatefile.BackupObject)
	for _, entry := range entries[1:] {
		body := f.body[entry.File.EntryID]
		object, exists := byBody[string(body)]
		if !exists {
			object, err = w.Put(privatefile.BackupObjectLimits{MaxBytes: int64(len(body)), AllowEmpty: len(body) == 0}, func(_ context.Context, dst io.Writer) error { _, err := dst.Write(body); return err })
			if err != nil {
				t.Fatal("alias real put", err)
			}
			byBody[string(body)] = object
		}
		result.objects[entry.File.EntryID] = object
	}
	return result
}

func TestBackupPublicationSharedObjectSeparateCumulativeBudgets(t *testing.T) {
	for _, mode := range []string{"exact", "workspace_one_short", "plaintext_unique_only", "entries_one_short"} {
		t.Run(mode, func(t *testing.T) {
			f := newBackupPublicationFixture(t, "sqlite")
			shared := f.body[f.manifest.Artifacts[0].File.EntryID]
			f.body["config-template"] = shared
			f.manifest.ConfigTemplate.Bytes = int64(len(shared))
			f.manifest.ConfigTemplate.SHA256 = backupCompletionDigest(shared)
			// Actual archive output crosses several 64 KiB data frames.
			large := bytes.Repeat([]byte("synthetic-database-payload"), 6000)
			f.body["database-snapshot"] = large
			f.manifest.Database.File.Bytes = int64(len(large))
			f.manifest.Database.File.SHA256 = backupCompletionDigest(large)
			encoded, sum, err := backupmanifest.Encode(f.manifest)
			if err != nil {
				t.Fatal("alias canonical manifest")
			}
			entries, err := backupmanifest.Entries(f.manifest)
			if err != nil {
				t.Fatal("alias canonical plan")
			}
			limits := backupPublicationTestLimits()
			limits.MaxWorkspaceBytes, limits.MaxPlaintextBytes = int64(len(encoded)), int64(len(encoded))
			unique := make(map[string]bool)
			for _, entry := range entries[1:] {
				body := f.body[entry.File.EntryID]
				limits.MaxPlaintextBytes += int64(len(body))
				if !unique[string(body)] {
					limits.MaxWorkspaceBytes += int64(len(body))
					unique[string(body)] = true
				}
			}
			limits.MaxEntries = len(entries)
			wantPlaintext := limits.MaxPlaintextBytes
			if limits.MaxWorkspaceBytes >= wantPlaintext || len(unique)+1 != len(entries)-1 {
				t.Fatal("fixture did not actually share an object")
			}
			switch mode {
			case "workspace_one_short":
				limits.MaxWorkspaceBytes--
			case "plaintext_unique_only":
				limits.MaxPlaintextBytes = limits.MaxWorkspaceBytes
			case "entries_one_short":
				limits.MaxEntries--
			}
			got, err := publishBackupArchive(f.ctx, f.lease, f.directory, f.sealer, f.opener, limits, func(_ context.Context, w *privatefile.BackupWorkspace) (backupPublicationCapture, error) {
				return backupPublicationDeduplicatedCapture(t, f, w), nil
			})
			if mode != "exact" {
				if err == nil || got != (repository.BackupCompletionReceipt{}) || len(backupPublicationFiles(t, f.directory)) != 0 {
					t.Fatal("incorrect shared-object budget accepted", err)
				}
				f.assertNotReady(t)
				return
			}
			if err != nil || got.Entries != len(entries) || got.ManifestSHA256 != sum {
				t.Fatal("legal shared object rejected", err)
			}
			// Independently open the actual private file and compare every byte,
			// including both aliased entry payloads and the regenerated manifest.
			f.body["backup-manifest"] = encoded
			files := backupPublicationFiles(t, f.directory)
			if len(files) != 1 {
				t.Fatal("alias archive count")
			}
			var opened secret.BackupReceipt
			_, err = privatefile.Read(f.ctx, filepath.Join(f.directory, files[0]), privatefile.Limits{MaxBytes: limits.MaxArchiveBytes, Timeout: limits.Timeout}, func(ctx context.Context, r io.Reader) error {
				var err error
				opened, err = f.opener.Open(ctx, secret.BackupScope{BackupID: f.manifest.BackupID, ManifestHash: sum}, secret.BackupLimits{MaxBytes: limits.MaxPlaintextBytes, MaxEntries: limits.MaxEntries, Timeout: limits.Timeout}, r, func(_ context.Context, entry secret.BackupEntry, r io.Reader) error {
					body, err := io.ReadAll(r)
					if err != nil || !bytes.Equal(body, f.body[entry.ID]) {
						return errBackupPublication
					}
					return nil
				})
				return err
			})
			if err != nil || opened.PlaintextBytes != wantPlaintext {
				t.Fatal("alias bytes not actually repeated", err)
			}
		})
	}
}

func TestBackupPublicationActualCiphertextTrailerBudget(t *testing.T) {
	f := newBackupPublicationFixture(t, "sqlite")
	entries, err := backupmanifest.Entries(f.manifest)
	if err != nil {
		t.Fatal("trailer fixture entries")
	}
	// Actual successful Seal determines exact framing-inclusive size without
	// publishing a file. Nonce values change bytes, never this framing length.
	sized, err := f.sealer.Seal(f.ctx, f.scope, f.limits, io.Discard, func(_ context.Context, a *secret.BackupArchiveWriter) error {
		for _, entry := range entries {
			if err := a.WriteEntry(secret.BackupEntry{Kind: entry.Kind, ID: entry.File.EntryID}, func(_ context.Context, w io.Writer) error { _, err := w.Write(f.body[entry.File.EntryID]); return err }); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil || sized.ArchiveBytes < 2 {
		t.Fatal("actual trailer size fixture", err)
	}
	limits := backupPublicationTestLimits()
	limits.MaxArchiveBytes = sized.ArchiveBytes - 1
	got, err := publishBackupArchive(f.ctx, f.lease, f.directory, f.sealer, f.opener, limits, func(_ context.Context, w *privatefile.BackupWorkspace) (backupPublicationCapture, error) {
		return backupPublicationFixtureCapture(t, f, w), nil
	})
	if err == nil || got != (repository.BackupCompletionReceipt{}) || len(backupPublicationFiles(t, f.directory)) != 0 {
		t.Fatal("final ciphertext frame budget failure was published", err)
	}
	f.assertNotReady(t)
}

func TestBackupPublicationObservedEmptyLegacyAlias(t *testing.T) {
	f := newBackupPublicationFixture(t, "sqlite")
	f.manifest.SchemaVersion = backupmanifest.VersionV3
	org := f.manifest.AuditAnchors[0].OrganizationID
	for i := range f.manifest.Artifacts {
		a := &f.manifest.Artifacts[i]
		if a.Category == "rule" || a.Category == "template" {
			a.Scope, a.OrganizationID, a.ID = backupmanifest.ArtifactScopeOrganization, org, int64(i+1)
		} else {
			a.Scope = backupmanifest.ArtifactScopeInstalled
		}
	}
	for i, entryID := range []string{"legacy-empty-one", "legacy-empty-two"} {
		f.manifest.LegacyReports = append(f.manifest.LegacyReports, backupmanifest.LegacyReport{
			ID: int64(i + 1), OrganizationID: org, RunID: 1, AnalysisRevision: 1, Revision: 1,
			RowVersion: backupmanifest.LegacyReportRowVersion, RowSHA256: backupCompletionDigest([]byte("synthetic preserved empty legacy row " + entryID)),
			Verification: backupmanifest.LegacyReportUnverified, FileState: backupmanifest.LegacyReportFileObserved,
			ObservedFile: &backupmanifest.File{EntryID: entryID, SHA256: backupCompletionDigest(nil)},
		})
		f.body[entryID] = nil
	}
	encoded, sum, err := backupmanifest.Encode(f.manifest)
	if err != nil {
		t.Fatal("empty legacy manifest fixture", err)
	}
	f.body["backup-manifest"] = encoded
	f.scope = secret.BackupScope{BackupID: f.manifest.BackupID, ManifestHash: sum}
	got, err := publishBackupArchive(f.ctx, f.lease, f.directory, f.sealer, f.opener, backupPublicationTestLimits(), func(_ context.Context, w *privatefile.BackupWorkspace) (backupPublicationCapture, error) {
		captured := backupPublicationDeduplicatedCapture(t, f, w)
		if captured.objects["legacy-empty-one"] != captured.objects["legacy-empty-two"] {
			return captured, errBackupPublication
		}
		return captured, nil
	})
	if err != nil || got.Entries != 9 || got.ManifestVersion != backupmanifest.VersionV3 {
		t.Fatal("actual observed-empty alias rejected", err)
	}
	files := backupPublicationFiles(t, f.directory)
	if len(files) != 1 {
		t.Fatal("empty legacy archive count")
	}
	opened, _ := backupPublicationAuthenticate(t, f, filepath.Join(f.directory, files[0]))
	if opened.Entries != 9 {
		t.Fatal("empty observed entries were skipped")
	}
}

func TestBackupPublicationRejectsLimitsBeforeCapture(t *testing.T) {
	for _, mode := range []string{"workspace_zero", "workspace_large", "plaintext_zero", "plaintext_large", "cipher_zero", "cipher_large", "entries_low", "entries_high", "timeout_zero", "timeout_large", "timeout_elapsed", "nil_context", "canceled_context", "nil_lease", "nil_sealer", "nil_opener", "nil_capture", "relative_directory"} {
		t.Run(mode, func(t *testing.T) {
			f := newBackupPublicationFixture(t, "sqlite")
			limits := backupPublicationTestLimits()
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			lease, sealer, opener, directory := f.lease, f.sealer, f.opener, f.directory
			called := false
			capture := backupPublicationCaptureFunc(func(context.Context, *privatefile.BackupWorkspace) (backupPublicationCapture, error) {
				called = true
				return backupPublicationCapture{}, nil
			})
			switch mode {
			case "workspace_zero":
				limits.MaxWorkspaceBytes = 0
			case "workspace_large":
				limits.MaxWorkspaceBytes = privatefile.MaxBytes + 1
			case "plaintext_zero":
				limits.MaxPlaintextBytes = 0
			case "plaintext_large":
				limits.MaxPlaintextBytes = secret.BackupMaxBytes + 1
			case "cipher_zero":
				limits.MaxArchiveBytes = 0
			case "cipher_large":
				limits.MaxArchiveBytes = privatefile.MaxBytes + 1
			case "entries_low":
				limits.MaxEntries = 2
			case "entries_high":
				limits.MaxEntries = backupmanifest.MaxEntries + 1
			case "timeout_zero":
				limits.Timeout = 0
			case "timeout_large":
				limits.Timeout = privatefile.MaxTimeout + 1
			case "timeout_elapsed":
				limits.Timeout = time.Nanosecond
			case "nil_context":
				ctx = nil
			case "canceled_context":
				cancel()
			case "nil_lease":
				lease = nil
			case "nil_sealer":
				sealer = nil
			case "nil_opener":
				opener = nil
			case "nil_capture":
				capture = nil
			case "relative_directory":
				directory = "relative"
			}
			got, err := publishBackupArchive(ctx, lease, directory, sealer, opener, limits, capture)
			if called || err == nil || got != (repository.BackupCompletionReceipt{}) || len(backupPublicationFiles(t, f.directory)) != 0 {
				t.Fatal("invalid preflight reached capture or publication", err)
			}
			f.assertNotReady(t)
		})
	}
}
