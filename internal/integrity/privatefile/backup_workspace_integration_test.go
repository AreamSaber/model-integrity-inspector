//go:build windows || linux

package privatefile_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/privatefile"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

func workspaceIntegrationLimits() privatefile.BackupWorkspaceLimits {
	return privatefile.BackupWorkspaceLimits{MaxBytes: 2 << 20, MaxEntries: 4, Timeout: 10 * time.Second}
}

// This descriptor proves the sequencing constraint with actual observed bytes.
// It is NOT the product manifest schema or a claim of full database inventory,
// snapshot acquisition, restore SQL validation or application activation.
type workspaceIntegrationDescriptor struct {
	DatabaseBytes  int64  `json:"database_bytes"`
	DatabaseSHA256 string `json:"database_sha256"`
	EmptySHA256    string `json:"empty_sha256"`
}

func TestBackupWorkspaceActualSQLiteThenAEADAndIsolatedReRead(t *testing.T) {
	for _, tailDamage := range []bool{false, true} {
		name := "complete"
		if tailDamage {
			name = "authenticated_tail_failure"
		}
		t.Run(name, func(t *testing.T) {
			parent := privatefile.BackupWorkspaceTestDirectory(t)
			cipherPath := filepath.Join(parent, "encrypted.backup")
			sealer, opener := integrationBackupKeys(t, 0x61)
			cryptoLimits := secret.BackupLimits{MaxBytes: 2 << 20, MaxEntries: 3, Timeout: 10 * time.Second}
			var scope secret.BackupScope
			var staged privatefile.BackupWorkspaceReceipt
			var sealed secret.BackupReceipt
			var original privatefile.BackupObjectInfo
			file, err := privatefile.WriteNew(t.Context(), cipherPath, privatefile.Limits{MaxBytes: 3 << 20, Timeout: 10 * time.Second}, func(ctx context.Context, dst io.Writer) error {
				var err error
				staged, err = privatefile.WithBackupWorkspace(ctx, parent, workspaceIntegrationLimits(), func(ctx context.Context, w *privatefile.BackupWorkspace) error {
					var database privatefile.BackupObject
					source, err := privatefile.WithSQLiteStaging(ctx, parent, privatefile.BackupWorkspaceTestSQLiteLimits(), privatefile.BackupWorkspaceTestBuildSQLite, func(_ context.Context, r io.Reader) error {
						var err error
						database, err = w.Put(privatefile.BackupObjectLimits{MaxBytes: 1 << 20}, func(_ context.Context, dst io.Writer) error { _, err := io.Copy(dst, r); return err })
						return err
					})
					if err != nil {
						return err
					}
					original, err = database.Info()
					if err != nil {
						return err
					}
					if source.Size != original.Size || source.SHA256 != original.SHA256 {
						return privatefile.ErrUnsafe
					}
					empty, err := w.Put(privatefile.BackupObjectLimits{AllowEmpty: true}, func(context.Context, io.Writer) error { return nil })
					if err != nil {
						return err
					}
					emptyInfo, err := empty.Info()
					if err != nil {
						return err
					}
					manifestBytes, err := json.Marshal(workspaceIntegrationDescriptor{original.Size, original.SHA256, emptyInfo.SHA256})
					if err != nil {
						return err
					}
					defer clear(manifestBytes)
					manifestHash := sha256.Sum256(manifestBytes)
					scope = secret.BackupScope{BackupID: 91, ManifestHash: hex.EncodeToString(manifestHash[:])}
					manifest, err := w.Put(privatefile.BackupObjectLimits{MaxBytes: int64(len(manifestBytes))}, func(_ context.Context, dst io.Writer) error { _, err := dst.Write(manifestBytes); return err })
					if err != nil {
						return err
					}
					// The final independently retained descriptor hash now exists;
					// the one-shot SQLite stream has already ended and cleaned up.
					sealed, err = sealer.Seal(ctx, scope, cryptoLimits, dst, func(_ context.Context, archive *secret.BackupArchiveWriter) error {
						for _, item := range []struct {
							entry  secret.BackupEntry
							object privatefile.BackupObject
						}{{secret.BackupEntry{Kind: "manifest", ID: "manifest"}, manifest}, {secret.BackupEntry{Kind: "database", ID: "database-snapshot"}, database}, {secret.BackupEntry{Kind: "report", ID: "legacy-empty"}, empty}} {
							if err := archive.WriteEntry(item.entry, func(_ context.Context, out io.Writer) error {
								_, err := w.Read(item.object, func(_ context.Context, r io.Reader) error { _, err := io.Copy(out, r); return err })
								return err
							}); err != nil {
								return err
							}
						}
						return nil
					})
					return err
				})
				return err // Including the workspace's final close and cleanup.
			})
			if err != nil || !file.Published || staged.Objects != 3 || sealed.Entries != 3 {
				t.Fatalf("staging/AEAD/publication: %v", err)
			}
			if file.Size != sealed.ArchiveBytes || file.SHA256 != sealed.ArchiveSHA256 {
				t.Fatal("native ciphertext differs from seal")
			}
			var ciphertext bytes.Buffer
			_, err = privatefile.Read(t.Context(), cipherPath, privatefile.Limits{MaxBytes: 3 << 20, Timeout: 10 * time.Second}, func(_ context.Context, r io.Reader) error { _, err := io.Copy(&ciphertext, r); return err })
			if err != nil {
				t.Fatal("ciphertext checked read failed")
			}
			if tailDamage {
				ciphertext.Bytes()[ciphertext.Len()-1] ^= 1
			}
			consumed, rechecked := 0, 0
			var opened secret.BackupReceipt
			restored, err := privatefile.WithBackupWorkspace(t.Context(), parent, workspaceIntegrationLimits(), func(ctx context.Context, w *privatefile.BackupWorkspace) error {
				objects := make(map[string]privatefile.BackupObject)
				var err error
				opened, err = opener.Open(ctx, scope, cryptoLimits, bytes.NewReader(ciphertext.Bytes()), func(_ context.Context, entry secret.BackupEntry, r io.Reader) error {
					object, err := w.Put(privatefile.BackupObjectLimits{MaxBytes: 1 << 20, AllowEmpty: entry.ID == "legacy-empty"}, func(_ context.Context, dst io.Writer) error { _, err := io.Copy(dst, r); return err })
					if err != nil {
						return err
					}
					objects[entry.ID] = object
					consumed++
					return nil
				})
				if err != nil {
					return err
				} // Tail auth failure must invalidate every staged object.
				for id, object := range objects {
					info, err := w.Read(object, func(_ context.Context, r io.Reader) error { _, err := io.Copy(io.Discard, r); return err })
					if err != nil {
						return err
					}
					if id == "database-snapshot" && info != original {
						return privatefile.ErrUnsafe
					}
					if id == "legacy-empty" && info.Size != 0 {
						return privatefile.ErrUnsafe
					}
					rechecked++
				}
				return nil
			})
			if consumed != 3 {
				t.Fatalf("tail case did not finish all plaintext callbacks: %d", consumed)
			}
			if tailDamage {
				if err == nil || restored != (privatefile.BackupWorkspaceReceipt{}) || opened != (secret.BackupReceipt{}) || rechecked != 0 {
					t.Fatal("tail failure escaped isolated staging boundary")
				}
			} else if err != nil || restored.Objects != 3 || rechecked != 3 || opened.Entries != 3 {
				t.Fatalf("isolated authenticated reread: %v", err)
			}
			privatefile.BackupIntegrationTestEntries(t, parent, 1)
		})
	}
}

func TestBackupWorkspaceLateCancellationPreventsCiphertextPublication(t *testing.T) {
	parent := privatefile.BackupWorkspaceTestDirectory(t)
	path := filepath.Join(parent, "must-not-publish.backup")
	sealer, _ := integrationBackupKeys(t, 0x52)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var staged privatefile.BackupWorkspaceReceipt
	var sealed secret.BackupReceipt
	file, err := privatefile.WriteNew(ctx, path, privatefile.Limits{MaxBytes: 1 << 20, Timeout: 10 * time.Second}, func(ctx context.Context, dst io.Writer) error {
		var err error
		staged, err = privatefile.WithBackupWorkspace(ctx, parent, workspaceIntegrationLimits(), func(ctx context.Context, w *privatefile.BackupWorkspace) error {
			object, err := w.Put(privatefile.BackupObjectLimits{MaxBytes: 7}, func(_ context.Context, dst io.Writer) error { _, err := dst.Write([]byte("content")); return err })
			if err != nil {
				return err
			}
			sealed, err = sealer.Seal(ctx, integrationBackupScope(), integrationCryptoLimits(7), dst, func(_ context.Context, a *secret.BackupArchiveWriter) error {
				return a.WriteEntry(secret.BackupEntry{Kind: "database", ID: "fixture"}, func(_ context.Context, dst io.Writer) error {
					_, err := w.Read(object, func(_ context.Context, r io.Reader) error { _, err := io.Copy(dst, r); return err })
					return err
				})
			})
			if err != nil {
				return err
			}
			cancel() // Ciphertext trailer complete; enclosing workspace is not.
			return nil
		})
		return err
	})
	if sealed.Entries != 1 {
		t.Fatal("fault did not occur after successful AEAD completion")
	}
	if err == nil || staged != (privatefile.BackupWorkspaceReceipt{}) || file != (privatefile.Receipt{}) {
		t.Fatal("late workspace failure published ciphertext")
	}
	integrationMissing(t, path)
	privatefile.BackupIntegrationTestEntries(t, parent, 0)
}

func TestBackupWorkspaceLargeStreamingBudgetAndRepeat(t *testing.T) {
	parent := privatefile.BackupWorkspaceTestDirectory(t)
	const size = int64(25<<20) + 17
	limits := privatefile.BackupWorkspaceLimits{MaxBytes: size, MaxEntries: 1, Timeout: time.Minute}
	want := sha256.New()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	receipt, err := privatefile.WithBackupWorkspace(t.Context(), parent, limits, func(_ context.Context, w *privatefile.BackupWorkspace) error {
		object, err := w.Put(privatefile.BackupObjectLimits{MaxBytes: size}, func(_ context.Context, dst io.Writer) error {
			_, err := io.Copy(io.MultiWriter(dst, want), &integrationPatternReader{remaining: size})
			return err
		})
		if err != nil {
			return err
		}
		for range 2 {
			actual := sha256.New()
			info, err := w.Read(object, func(_ context.Context, r io.Reader) error { _, err := io.Copy(actual, r); return err })
			if err != nil {
				return err
			}
			if info.Size != size || info.SHA256 != hex.EncodeToString(want.Sum(nil)) || !bytes.Equal(actual.Sum(nil), want.Sum(nil)) {
				return privatefile.ErrUnsafe
			}
		}
		return nil
	})
	runtime.ReadMemStats(&after)
	if err != nil || receipt.Bytes != size || receipt.Objects != 1 {
		t.Fatalf("large bounded spool: %v", err)
	}
	if after.TotalAlloc-before.TotalAlloc > 12<<20 {
		t.Fatal("workspace accumulated a large object body")
	}
	privatefile.BackupIntegrationTestEntries(t, parent, 0)
}
