package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
	"model-integrity-inspector.local/mii/internal/integrity/privatefile"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

func backupPublicationTestLimits() backupPublicationLimits {
	return backupPublicationLimits{MaxWorkspaceBytes: 2 << 20, MaxPlaintextBytes: 2 << 20, MaxArchiveBytes: 3 << 20, MaxEntries: 16, Timeout: 10 * time.Second}
}

func newBackupPublicationFixture(t *testing.T, driver string) *backupCompletionFixture {
	t.Helper()
	f := newBackupCompletionFixture(t, driver)
	f.directory = backupPublicationPrivateDirectory(t)
	return f
}

func backupPublicationFixtureCapture(t *testing.T, f *backupCompletionFixture, w *privatefile.BackupWorkspace) backupPublicationCapture {
	t.Helper()
	entries, err := backupmanifest.Entries(f.manifest)
	if err != nil {
		t.Fatal("publication fixture entry plan")
	}
	result := backupPublicationCapture{manifest: f.manifest, objects: make(map[string]privatefile.BackupObject)}
	for _, entry := range entries[1:] {
		body := f.body[entry.File.EntryID]
		object, err := w.Put(privatefile.BackupObjectLimits{MaxBytes: int64(len(body)), AllowEmpty: entry.File.Bytes == 0}, func(_ context.Context, dst io.Writer) error { _, err := dst.Write(body); return err })
		if err != nil {
			t.Fatal("publication fixture actual object put", err)
		}
		result.objects[entry.File.EntryID] = object
	}
	return result
}

func backupPublicationFiles(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal("inspect exact private test directory")
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || len(name) != 64+len(".mii-backup") || !strings.HasSuffix(name, ".mii-backup") || strings.Trim(name[:64], "0123456789abcdef") != "" {
			t.Fatal("unexpected private test directory residue")
		}
		names = append(names, name)
	}
	return names
}

func TestBackupPublicationActualOwnedFlow(t *testing.T) {
	f := newBackupPublicationFixture(t, "sqlite")
	if _, err := privatefile.WithBackupWorkspace(f.ctx, f.directory, privatefile.BackupWorkspaceLimits{MaxBytes: 1, MaxEntries: 1, Timeout: time.Second}, func(context.Context, *privatefile.BackupWorkspace) error { return nil }); err != nil {
		t.Fatal("publication fixture native workspace preflight", err)
	}
	var retained privatefile.BackupObject
	var workspace *privatefile.BackupWorkspace
	got, err := publishBackupArchive(f.ctx, f.lease, f.directory, f.sealer, f.opener, backupPublicationTestLimits(), func(_ context.Context, w *privatefile.BackupWorkspace) (backupPublicationCapture, error) {
		workspace = w
		captured := backupPublicationFixtureCapture(t, f, w)
		retained = captured.objects["database-snapshot"]
		f.assertNotReady(t)
		return captured, nil
	})
	if err != nil {
		t.Fatal("actual publication failed", err)
	}
	if _, err := retained.Info(); !errors.Is(err, privatefile.ErrClosed) {
		t.Fatal("object survived successful publication")
	}
	if _, err := workspace.Read(retained, func(context.Context, io.Reader) error { return nil }); !errors.Is(err, privatefile.ErrClosed) {
		t.Fatal("workspace survived completion")
	}
	files := backupPublicationFiles(t, f.directory)
	if len(files) != 1 || files[0] != got.ObjectID+".mii-backup" || got.ObjectID == f.objectID || got.Entries != 7 {
		t.Fatal("publication did not choose its own random opaque identity")
	}
	read, err := f.app.store.ReadBackupCompletion(f.ctx, f.auth, f.manifest.BackupID)
	if err != nil || read != got {
		t.Fatal("publication completion not durably authenticated")
	}
	if err := f.app.store.VerifyAllAudit(f.ctx, true); err != nil {
		t.Fatal("publication full audit chain")
	}
}

func TestBackupPublicationRejectsCaptureBeforePublishing(t *testing.T) {
	for _, mode := range []string{"missing_entry", "unknown_entry", "supplied_manifest", "wrong_hash", "wrong_size", "wrong_backup", "wrong_started", "zero_object", "extra_scratch", "extra_empty_scratch", "capture_error", "capture_panic", "capture_panic_nil", "canceled", "foreign_object"} {
		t.Run(mode, func(t *testing.T) {
			f := newBackupPublicationFixture(t, "sqlite")
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			var escaped privatefile.BackupObject
			if mode == "foreign_object" {
				_, err := privatefile.WithBackupWorkspace(f.ctx, f.directory, privatefile.BackupWorkspaceLimits{MaxBytes: 1, MaxEntries: 1, Timeout: time.Second}, func(_ context.Context, w *privatefile.BackupWorkspace) error {
					var err error
					escaped, err = w.Put(privatefile.BackupObjectLimits{MaxBytes: 1}, func(_ context.Context, dst io.Writer) error { _, err := dst.Write([]byte("x")); return err })
					return err
				})
				if err != nil {
					t.Fatal("foreign workspace fixture", err)
				}
			}
			got, err := publishBackupArchive(ctx, f.lease, f.directory, f.sealer, f.opener, backupPublicationTestLimits(), func(_ context.Context, w *privatefile.BackupWorkspace) (backupPublicationCapture, error) {
				captured := backupPublicationFixtureCapture(t, f, w)
				switch mode {
				case "missing_entry":
					delete(captured.objects, "config-template")
				case "unknown_entry":
					captured.objects["unknown"] = captured.objects["config-template"]
					delete(captured.objects, "config-template")
				case "supplied_manifest":
					captured.objects["backup-manifest"] = captured.objects["config-template"]
				case "wrong_hash":
					captured.manifest.ConfigTemplate.SHA256 = strings.Repeat("a", 64)
				case "wrong_size":
					captured.manifest.ConfigTemplate.Bytes++
				case "wrong_backup":
					captured.manifest.BackupID++
				case "wrong_started":
					captured.manifest.StartedAtMicros--
				case "zero_object":
					captured.objects["config-template"] = privatefile.BackupObject{}
				case "foreign_object":
					captured.objects["config-template"] = escaped
				case "extra_scratch", "extra_empty_scratch":
					body := []byte("unmapped intermediate source")
					if mode == "extra_empty_scratch" {
						body = nil
					}
					if _, err := w.Put(privatefile.BackupObjectLimits{MaxBytes: int64(len(body)), AllowEmpty: len(body) == 0}, func(_ context.Context, dst io.Writer) error { _, err := dst.Write(body); return err }); err != nil {
						t.Fatal("extra scratch fixture")
					}
				case "capture_error":
					return captured, errors.New("private capture canary")
				case "capture_panic":
					panic("private capture canary")
				case "capture_panic_nil":
					panic(nil)
				case "canceled":
					cancel()
				}
				return captured, nil
			})
			if err == nil || got != (repository.BackupCompletionReceipt{}) || strings.Contains(err.Error(), "canary") {
				t.Fatal("bad capture was published", err)
			}
			f.assertNotReady(t)
			if len(backupPublicationFiles(t, f.directory)) != 0 {
				t.Fatal("bad capture left published archive")
			}
		})
	}
}

// Real successful native calls followed by controlled dependency errors test
// propagation only. They do NOT pretend that the native close/cleanup actually
// failed; those native fault paths are independently tested in privatefile.
func TestBackupPublicationLateNativeResultPropagation(t *testing.T) {
	for _, mode := range []string{"workspace_error", "workspace_cancel", "workspace_count", "workspace_bytes", "write_error", "write_cancel", "write_panic_nil", "write_unpublished", "write_hash"} {
		t.Run(mode, func(t *testing.T) {
			f := newBackupPublicationFixture(t, "sqlite")
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			deps := backupPublicationDependencies{workspace: privatefile.WithBackupWorkspace, write: privatefile.WriteNew}
			completedNative, completeCallback := false, false
			var published privatefile.Receipt
			var publishedPath string
			if strings.HasPrefix(mode, "workspace_") {
				deps.workspace = func(ctx context.Context, parent string, limits privatefile.BackupWorkspaceLimits, use func(context.Context, *privatefile.BackupWorkspace) error) (privatefile.BackupWorkspaceReceipt, error) {
					receipt, err := privatefile.WithBackupWorkspace(ctx, parent, limits, func(ctx context.Context, w *privatefile.BackupWorkspace) error {
						err := use(ctx, w)
						completeCallback = err == nil
						return err
					})
					if err != nil {
						return receipt, err
					}
					completedNative = true
					switch mode {
					case "workspace_error":
						return receipt, errors.New("private cleanup canary")
					case "workspace_cancel":
						cancel()
					case "workspace_count":
						receipt.Objects--
					case "workspace_bytes":
						receipt.Bytes--
					}
					return receipt, nil
				}
			} else {
				deps.write = func(ctx context.Context, path string, limits privatefile.Limits, produce func(context.Context, io.Writer) error) (privatefile.Receipt, error) {
					receipt, err := privatefile.WriteNew(ctx, path, limits, produce)
					if err != nil {
						return receipt, err
					}
					completedNative = true
					published = receipt
					publishedPath = path
					f.assertNotReady(t)
					switch mode {
					case "write_error":
						return receipt, errors.New("private final close canary")
					case "write_cancel":
						cancel()
					case "write_panic_nil":
						panic(nil)
					case "write_unpublished":
						receipt.Published = false
					case "write_hash":
						receipt.SHA256 = strings.Repeat("e", 64)
					}
					return receipt, nil
				}
			}
			got, err := publishBackupArchiveWithDependencies(ctx, f.lease, f.directory, f.sealer, f.opener, backupPublicationTestLimits(), func(_ context.Context, w *privatefile.BackupWorkspace) (backupPublicationCapture, error) {
				return backupPublicationFixtureCapture(t, f, w), nil
			}, deps)
			if !completedNative || err == nil || got != (repository.BackupCompletionReceipt{}) || strings.Contains(err.Error(), "canary") {
				t.Fatal("late native result escaped", err)
			}
			f.assertNotReady(t)
			files := backupPublicationFiles(t, f.directory)
			if strings.HasPrefix(mode, "workspace_") {
				if !completeCallback || len(files) != 0 {
					t.Fatal("workspace late error did not prevent ciphertext publication")
				}
			} else {
				if !published.Published || len(files) != 1 {
					t.Fatal("real already-published archive was removed")
				}
				// #nosec G304 -- exact private path returned only by the real test dependency's WriteNew call.
				body, err := os.ReadFile(publishedPath)
				if err != nil || backupCompletionDigest(body) != published.SHA256 || int64(len(body)) != published.Size {
					t.Fatal("retained published archive differs from original receipt")
				}
			}
		})
	}
}

func TestBackupPublicationReadbackFailurePreservesPublishedFile(t *testing.T) {
	f := newBackupPublicationFixture(t, "sqlite")
	key, err := secret.NewKeyRing(f.cfg.MasterKeyVersion, map[string][]byte{f.cfg.MasterKeyVersion: bytes.Repeat([]byte{0x29}, 32)})
	if err != nil {
		t.Fatal("wrong readback key fixture")
	}
	_, wrong, err := key.NewBackupCapabilities()
	if err != nil {
		t.Fatal("wrong readback opener fixture")
	}
	got, err := publishBackupArchive(f.ctx, f.lease, f.directory, f.sealer, wrong, backupPublicationTestLimits(), func(_ context.Context, w *privatefile.BackupWorkspace) (backupPublicationCapture, error) {
		return backupPublicationFixtureCapture(t, f, w), nil
	})
	if !errors.Is(err, errBackupArchiveReadback) || got != (repository.BackupCompletionReceipt{}) {
		t.Fatal("failed readback finalized publication", err)
	}
	f.assertNotReady(t)
	files := backupPublicationFiles(t, f.directory)
	if len(files) != 1 {
		t.Fatal("uncompleted private ciphertext was not retained")
	}
	path := filepath.Join(f.directory, files[0])
	_, err = privatefile.Read(f.ctx, path, privatefile.Limits{MaxBytes: 3 << 20, Timeout: 10 * time.Second}, func(ctx context.Context, r io.Reader) error {
		_, err := f.opener.Open(ctx, f.scope, f.limits, r, func(_ context.Context, _ secret.BackupEntry, r io.Reader) error {
			_, err := io.Copy(io.Discard, r)
			return err
		})
		return err
	})
	if err != nil {
		t.Fatal("retained original cannot authenticate with original correct key")
	}
}

func TestBackupPublicationCaptureSerializationClosed(t *testing.T) {
	value := backupPublicationCapture{manifest: backupmanifest.Manifest{SourceCommit: "private-canary"}, objects: map[string]privatefile.BackupObject{"private-object-canary": {}}}
	for _, v := range []any{value, &value} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if got := fmt.Sprintf(format, v); got != "[private backup capture]" {
				t.Fatal("capture formatting exposed owned data")
			}
		}
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("capture JSON accepted")
		}
		if _, err := yaml.Marshal(v); err == nil {
			t.Fatal("capture YAML accepted")
		}
	}
}
