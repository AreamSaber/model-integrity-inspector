package app

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/privatefile"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func TestBackupPublicationRejectsSwallowedBorrowFailures(t *testing.T) {
	for _, mode := range []string{"short_read", "late_reader", "late_writer", "swallowed_write_limit", "reentrant_read"} {
		t.Run(mode, func(t *testing.T) {
			f := newBackupPublicationFixture(t, "sqlite")
			var fault error
			got, err := publishBackupArchive(f.ctx, f.lease, f.directory, f.sealer, f.opener, backupPublicationTestLimits(), func(_ context.Context, w *privatefile.BackupWorkspace) (backupPublicationCapture, error) {
				captured := backupPublicationFixtureCapture(t, f, w)
				switch mode {
				case "short_read":
					_, fault = w.Read(captured.objects["config-template"], func(context.Context, io.Reader) error { return nil })
				case "late_reader":
					var reader io.Reader
					_, err := w.Read(captured.objects["config-template"], func(_ context.Context, r io.Reader) error { reader = r; _, err := io.Copy(io.Discard, r); return err })
					if err != nil {
						return captured, err
					}
					_, fault = reader.Read(make([]byte, 1))
				case "late_writer":
					var writer io.Writer
					_, err := w.Put(privatefile.BackupObjectLimits{MaxBytes: 1}, func(_ context.Context, dst io.Writer) error {
						writer = dst
						_, err := dst.Write([]byte("x"))
						return err
					})
					if err != nil {
						return captured, err
					}
					_, fault = writer.Write([]byte("y"))
				case "swallowed_write_limit":
					_, _ = w.Put(privatefile.BackupObjectLimits{MaxBytes: 1}, func(_ context.Context, dst io.Writer) error { _, fault = dst.Write([]byte("xx")); return nil })
				case "reentrant_read":
					_, _ = w.Read(captured.objects["config-template"], func(_ context.Context, _ io.Reader) error {
						_, fault = w.Read(captured.objects["database-snapshot"], func(_ context.Context, r io.Reader) error { _, err := io.Copy(io.Discard, r); return err })
						return nil
					})
				}
				// Deliberately swallow the genuine owned-capability failure.
				return captured, nil
			})
			if fault == nil || err == nil || got != (repository.BackupCompletionReceipt{}) || len(backupPublicationFiles(t, f.directory)) != 0 {
				t.Fatal("swallowed genuine borrow failure published", err)
			}
			f.assertNotReady(t)
		})
	}
}

func TestBackupPublicationActiveCaptureOperationCanceledAndJoined(t *testing.T) {
	for _, mode := range []string{"read", "put"} {
		t.Run(mode, func(t *testing.T) {
			f := newBackupPublicationFixture(t, "sqlite")
			ctx, cancel := context.WithCancel(f.ctx)
			started, done := make(chan struct{}), make(chan struct{})
			result := make(chan error, 1)
			launched := false
			defer func() {
				cancel()
				if launched {
					<-done
				} // Also join every early-return/fatal path.
			}()
			got, err := publishBackupArchive(ctx, f.lease, f.directory, f.sealer, f.opener, backupPublicationTestLimits(), func(_ context.Context, w *privatefile.BackupWorkspace) (backupPublicationCapture, error) {
				captured := backupPublicationFixtureCapture(t, f, w)
				launched = true
				go func() {
					defer close(done)
					if mode == "read" {
						_, err := w.Read(captured.objects["config-template"], func(ctx context.Context, _ io.Reader) error { close(started); <-ctx.Done(); return ctx.Err() })
						result <- err
					} else {
						_, err := w.Put(privatefile.BackupObjectLimits{MaxBytes: 1}, func(ctx context.Context, dst io.Writer) error {
							if _, err := dst.Write([]byte("x")); err != nil {
								return err
							}
							close(started)
							<-ctx.Done()
							return ctx.Err()
						})
						result <- err
					}
				}()
				select {
				case <-started:
				case <-done:
					return captured, errors.New("borrow fixture did not reach barrier")
				case <-time.After(2 * time.Second):
					cancel()
					return captured, errors.New("borrow fixture barrier timeout")
				}
				return captured, nil // Forbidden detached active operation.
			})
			if !launched || err == nil || got != (repository.BackupCompletionReceipt{}) || len(backupPublicationFiles(t, f.directory)) != 0 {
				t.Fatal("live capture operation survived publication", err)
			}
			select {
			case <-started:
			default:
				t.Fatal("active IO barrier was not actually reached")
			}
			// The public operation must already have joined its owned file use.
			// done closes immediately after Read/Put returns; receive the result
			// rather than racing a scheduler-dependent done-channel observation.
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("active borrowed operation returned success")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("active borrowed operation not canceled")
			}
			f.assertNotReady(t)
		})
	}
}

func TestBackupPublicationRejectsLiveForeignObject(t *testing.T) {
	f := newBackupPublicationFixture(t, "sqlite")
	var publicationErr error
	var got repository.BackupCompletionReceipt
	foreignParent := backupPublicationPrivateDirectory(t)
	_, err := privatefile.WithBackupWorkspace(f.ctx, foreignParent, privatefile.BackupWorkspaceLimits{MaxBytes: 1024, MaxEntries: 1, Timeout: 10 * time.Second}, func(_ context.Context, other *privatefile.BackupWorkspace) error {
		body := f.body["config-template"]
		foreign, err := other.Put(privatefile.BackupObjectLimits{MaxBytes: int64(len(body))}, func(_ context.Context, dst io.Writer) error { _, err := dst.Write(body); return err })
		if err != nil {
			return err
		}
		got, publicationErr = publishBackupArchive(f.ctx, f.lease, f.directory, f.sealer, f.opener, backupPublicationTestLimits(), func(_ context.Context, w *privatefile.BackupWorkspace) (backupPublicationCapture, error) {
			captured := backupPublicationFixtureCapture(t, f, w)
			info, err := foreign.Info()
			if err != nil || info.Size != captured.manifest.ConfigTemplate.Bytes || info.SHA256 != captured.manifest.ConfigTemplate.SHA256 {
				return captured, errBackupPublication
			}
			captured.objects["config-template"] = foreign
			return captured, nil
		})
		// Foreign ownership remains live, readable and unchanged after rejection.
		_, err = other.Read(foreign, func(_ context.Context, r io.Reader) error { _, err := io.Copy(io.Discard, r); return err })
		return err
	})
	if err != nil || publicationErr == nil || got != (repository.BackupCompletionReceipt{}) || len(backupPublicationFiles(t, f.directory)) != 0 {
		t.Fatal("live foreign object was accepted or invalidated", err)
	}
	f.assertNotReady(t)
}
