package app

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
	"model-integrity-inspector.local/mii/internal/integrity/privatefile"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

// Source bodies/inventory are explicitly synthetic. These tests exercise real
// owned publication, physical file authentication, authority and both database
// commit/rollback paths; they do not claim a full database snapshot or restore.
func TestBackupPublicationDualDatabaseCommit(t *testing.T) {
	for _, driver := range []string{"sqlite", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			f := newBackupPublicationFixture(t, driver)
			got, err := publishBackupArchive(f.ctx, f.lease, f.directory, f.sealer, f.opener, backupPublicationTestLimits(), func(_ context.Context, w *privatefile.BackupWorkspace) (backupPublicationCapture, error) {
				return backupPublicationFixtureCapture(t, f, w), nil
			})
			if err != nil || got.BackupID != f.manifest.BackupID || got.DatabaseSHA256 != f.manifest.Database.File.SHA256 || got.Entries != 7 {
				t.Fatal("real dual database publication", err)
			}
			files := backupPublicationFiles(t, f.directory)
			if len(files) != 1 || files[0] != got.ObjectID+".mii-backup" || got.ObjectID == f.objectID {
				t.Fatal("publication identity/residue differs")
			}
			opened, file := backupPublicationAuthenticate(t, f, filepath.Join(f.directory, files[0]))
			if opened.ArchiveSHA256 != got.ArchiveSHA256 || file.Size != got.ArchiveBytes || opened.PlaintextBytes != got.PlaintextBytes {
				t.Fatal("durable completion differs from independently authenticated original")
			}
			read, err := f.app.store.ReadBackupCompletion(f.ctx, f.auth, got.BackupID)
			if err != nil || read != got {
				t.Fatal("publication receipt not durably authenticated", err)
			}
			if err := f.app.store.VerifyAllAudit(f.ctx, true); err != nil {
				t.Fatal("publication audit chain")
			}
		})
	}
}

func backupPublicationAuthenticate(t *testing.T, f *backupCompletionFixture, path string) (secret.BackupReceipt, privatefile.Receipt) {
	t.Helper()
	var opened secret.BackupReceipt
	file, err := privatefile.Read(f.ctx, path, privatefile.Limits{MaxBytes: 3 << 20, Timeout: 10 * time.Second}, func(ctx context.Context, r io.Reader) error {
		return backupmanifest.VerifyStream(ctx, f.manifest, 10*time.Second, func(ctx context.Context, accept func(string, string, io.Reader) error) error {
			var err error
			opened, err = f.opener.Open(ctx, f.scope, f.limits, r, func(_ context.Context, entry secret.BackupEntry, r io.Reader) error {
				return accept(entry.Kind, entry.ID, r)
			})
			return err
		})
	})
	if err != nil || opened.ArchiveSHA256 != file.SHA256 || opened.ArchiveBytes != file.Size {
		t.Fatal("independent complete original file authentication", err)
	}
	return opened, file
}

func TestBackupPublicationAuthorityChangesAcrossCapture(t *testing.T) {
	for _, stage := range []string{"before_capture", "during_capture", "after_publication"} {
		t.Run(stage, func(t *testing.T) {
			for _, driver := range []string{"sqlite", "postgres"} {
				t.Run(driver, func(t *testing.T) {
					f := newBackupPublicationFixture(t, driver)
					revoke := func() {
						if err := f.app.store.RevokeSession(f.ctx, f.auth.UserID, f.session.SessionHash, time.Now().UTC()); err != nil {
							t.Fatal("revoke actual current principal", err)
						}
					}
					if stage == "before_capture" {
						revoke()
					}
					deps := backupPublicationDependencies{workspace: privatefile.WithBackupWorkspace, write: privatefile.WriteNew}
					var written privatefile.Receipt
					if stage == "after_publication" {
						// Controlled scheduling boundary AFTER real final WriteNew success,
						// not an injected native fault or a claimed post-read SQL barrier.
						deps.write = func(ctx context.Context, path string, limits privatefile.Limits, produce func(context.Context, io.Writer) error) (privatefile.Receipt, error) {
							receipt, err := privatefile.WriteNew(ctx, path, limits, produce)
							if err == nil {
								written = receipt
								f.assertNotReady(t)
								revoke()
							}
							return receipt, err
						}
					}
					captured := false
					got, err := publishBackupArchiveWithDependencies(f.ctx, f.lease, f.directory, f.sealer, f.opener, backupPublicationTestLimits(), func(_ context.Context, w *privatefile.BackupWorkspace) (backupPublicationCapture, error) {
						captured = true
						result := backupPublicationFixtureCapture(t, f, w)
						if stage == "during_capture" {
							revoke()
						}
						return result, nil
					}, deps)
					if !errors.Is(err, repository.ErrManagementSession) || got != (repository.BackupCompletionReceipt{}) || captured != (stage != "before_capture") {
						t.Fatal("authority change admitted capture/completion", err)
					}
					f.assertNotReady(t)
					files := backupPublicationFiles(t, f.directory)
					if stage == "before_capture" {
						if len(files) != 0 {
							t.Fatal("unauthorized capture published ciphertext")
						}
						return
					}
					if len(files) != 1 {
						t.Fatal("authority failure removed private published orphan")
					}
					_, file := backupPublicationAuthenticate(t, f, filepath.Join(f.directory, files[0]))
					if stage == "after_publication" && (!written.Published || file.Size != written.Size || file.SHA256 != written.SHA256) {
						t.Fatal("revocation changed authentic original publication")
					}
				})
			}
		})
	}
}

func TestBackupPublicationFinalDatabaseFailure(t *testing.T) {
	for _, driver := range []string{"sqlite", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			f := newBackupPublicationFixture(t, driver)
			statements := []string{"CREATE TRIGGER publication_fixture_fail AFTER UPDATE ON system_maintenance WHEN NEW.mode='normal' BEGIN SELECT RAISE(ABORT,'publication private canary'); END"}
			if driver == "postgres" {
				statements = []string{"CREATE FUNCTION publication_fixture_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'publication private canary'; END $$", "CREATE TRIGGER publication_fixture_fail AFTER UPDATE ON system_maintenance FOR EACH ROW WHEN (NEW.mode='normal') EXECUTE FUNCTION publication_fixture_reject()"}
			}
			for _, statement := range statements {
				if _, err := f.db.ExecContext(t.Context(), statement); err != nil {
					t.Fatal("install exact final publication SQL rejection")
				}
			}
			var original privatefile.Receipt
			var path string
			deps := backupPublicationDependencies{workspace: privatefile.WithBackupWorkspace, write: func(ctx context.Context, target string, limits privatefile.Limits, produce func(context.Context, io.Writer) error) (privatefile.Receipt, error) {
				receipt, err := privatefile.WriteNew(ctx, target, limits, produce)
				if err == nil {
					original, path = receipt, target
				}
				return receipt, err
			}}
			got, err := publishBackupArchiveWithDependencies(f.ctx, f.lease, f.directory, f.sealer, f.opener, backupPublicationTestLimits(), func(_ context.Context, w *privatefile.BackupWorkspace) (backupPublicationCapture, error) {
				return backupPublicationFixtureCapture(t, f, w), nil
			}, deps)
			want := repository.ErrUnavailable
			if driver == "sqlite" {
				want = repository.ErrConflict
			}
			if !errors.Is(err, want) || got != (repository.BackupCompletionReceipt{}) || strings.Contains(err.Error(), "canary") || !original.Published {
				t.Fatal("final SQL fault did not rollback publication readiness", err)
			}
			f.assertNotReady(t)
			if err := f.app.store.VerifyAllAudit(f.ctx, true); err != nil {
				t.Fatal("publication rollback changed preexisting audit chain")
			}
			files := backupPublicationFiles(t, f.directory)
			if len(files) != 1 || files[0] != filepath.Base(path) {
				t.Fatal("SQL failure changed publication identity")
			}
			opened, file := backupPublicationAuthenticate(t, f, path)
			if original.Size != file.Size || original.SHA256 != file.SHA256 {
				t.Fatal("SQL failure changed original private ciphertext")
			}
			drop := "DROP TRIGGER publication_fixture_fail"
			if driver == "postgres" {
				drop += " ON system_maintenance"
			}
			if _, err := f.db.ExecContext(t.Context(), drop); err != nil {
				t.Fatal("remove only controlled publication rejection")
			}
			if driver == "postgres" {
				if _, err := f.db.ExecContext(t.Context(), "DROP FUNCTION publication_fixture_reject()"); err != nil {
					t.Fatal("remove only fixture trigger function")
				}
			}
			// Deliberate test recovery on the SAME file, not a new publication or
			// production auto-retry. Removing only the fault proves its causality.
			objectID := strings.TrimSuffix(filepath.Base(path), ".mii-backup")
			completed, err := finishBackupArchive(f.ctx, f.lease, f.directory, objectID, f.manifest, f.opener, f.limits, opened, original)
			if err != nil || completed.ArchiveSHA256 != original.SHA256 || completed.ObjectID != objectID {
				t.Fatal("same authentic archive cannot complete after exact fault removal", err)
			}
			read, err := f.app.store.ReadBackupCompletion(f.ctx, f.auth, f.manifest.BackupID)
			if err != nil || read != completed {
				t.Fatal("recovered publication completion not durably verified")
			}
		})
	}
}
