//go:build windows || linux

package privatefile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func backupWorkspaceTestLimits() BackupWorkspaceLimits {
	return BackupWorkspaceLimits{MaxBytes: 2 << 20, MaxEntries: 10, Timeout: 10 * time.Second}
}
func backupWorkspaceProduce(body []byte) func(context.Context, io.Writer) error {
	return func(_ context.Context, w io.Writer) error { _, err := w.Write(body); return err }
}
func backupWorkspaceConsume(_ context.Context, r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}
func backupWorkspaceRequireZero(t *testing.T, receipt BackupWorkspaceReceipt, err error) {
	t.Helper()
	if err == nil || receipt != (BackupWorkspaceReceipt{}) || strings.Contains(err.Error(), "canary") {
		t.Fatalf("failure not closed: %v / %v", receipt, err)
	}
}

func TestBackupWorkspaceRealRepeatAndEmpty(t *testing.T) {
	parent := newSQLiteTestDirectory(t)
	body := bytes.Repeat([]byte("private-canary"), 10000)
	want := sha256.Sum256(body)
	var retained *BackupWorkspace
	var object BackupObject
	var borrowedWriter io.Writer
	var borrowedReader io.Reader
	receipt, err := WithBackupWorkspace(t.Context(), parent, backupWorkspaceTestLimits(), func(ctx context.Context, w *BackupWorkspace) error {
		retained = w
		var err error
		object, err = w.Put(BackupObjectLimits{MaxBytes: int64(len(body))}, func(ctx context.Context, dst io.Writer) error {
			borrowedWriter = dst
			return backupWorkspaceProduce(body)(ctx, dst)
		})
		if err != nil {
			return err
		}
		info, err := object.Info()
		if err != nil || info.Size != int64(len(body)) || info.SHA256 != hex.EncodeToString(want[:]) {
			return ErrUnsafe
		}
		for range 3 {
			var actual bytes.Buffer
			observed, err := w.Read(object, func(_ context.Context, r io.Reader) error {
				borrowedReader = r
				_, err := io.Copy(&actual, r)
				return err
			})
			if err != nil {
				return err
			}
			if !bytes.Equal(actual.Bytes(), body) || observed != info {
				return ErrUnsafe
			}
		}
		empty, err := w.Put(BackupObjectLimits{AllowEmpty: true}, backupWorkspaceProduce(nil))
		if err != nil {
			return err
		}
		info, err = w.Read(empty, backupWorkspaceConsume)
		emptyHash := sha256.Sum256(nil)
		if err != nil || info.Size != 0 || info.SHA256 != hex.EncodeToString(emptyHash[:]) {
			return ErrUnsafe
		}
		return nil
	})
	if err != nil || receipt.Objects != 2 || receipt.Bytes != int64(len(body)) {
		t.Fatalf("real spool: %v / %v", receipt, err)
	}
	if _, err := object.Info(); !errors.Is(err, ErrClosed) {
		t.Fatal("object outlived workspace")
	}
	if _, err := retained.Read(object, backupWorkspaceConsume); !errors.Is(err, ErrClosed) {
		t.Fatal("workspace outlived callback")
	}
	if _, err := borrowedWriter.Write([]byte("late")); !errors.Is(err, ErrClosed) {
		t.Fatal("writer outlived callback")
	}
	if _, err := borrowedReader.Read(make([]byte, 1)); !errors.Is(err, ErrClosed) {
		t.Fatal("reader outlived callback")
	}
	assertSQLiteParentEmpty(t, parent)
}

func TestBackupWorkspaceFailureClosure(t *testing.T) {
	for _, name := range []string{"write_limit_swallowed", "write_io_swallowed", "empty_forbidden", "producer_error", "producer_panic", "producer_panic_nil", "producer_nil", "read_partial", "read_error", "read_panic", "read_panic_nil", "read_io_swallowed", "read_nil", "read_cancel_swallowed", "last_chunk_cancel", "callback_error", "callback_panic", "callback_panic_nil", "late_writer", "late_reader", "reentry_put", "reentry_read", "foreign_object", "object_limit", "entry_limit", "workspace_limit"} {
		t.Run(name, func(t *testing.T) {
			parent := newSQLiteTestDirectory(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			limits := backupWorkspaceTestLimits()
			if name == "entry_limit" {
				limits.MaxEntries = 1
			}
			if name == "workspace_limit" {
				limits.MaxBytes = 7
			}
			receipt, err := WithBackupWorkspace(ctx, parent, limits, func(_ context.Context, w *BackupWorkspace) error {
				var writer io.Writer
				produce := func(_ context.Context, dst io.Writer) error {
					writer = dst
					switch name {
					case "empty_forbidden":
						return nil
					case "producer_error":
						return errors.New("private canary")
					case "producer_panic":
						panic("private canary")
					case "producer_panic_nil":
						panic(nil)
					case "write_io_swallowed":
						if err := dst.(backupWorkspaceWriter).b.stream.file.Close(); err != nil {
							t.Fatal("write IO fault setup")
						}
						_, _ = dst.Write([]byte("x"))
						return nil
					case "write_limit_swallowed":
						_, _ = dst.Write([]byte("123456789"))
						return nil
					case "reentry_put":
						_, _ = w.Put(BackupObjectLimits{MaxBytes: 1}, backupWorkspaceProduce([]byte("x")))
					}
					_, err := dst.Write([]byte("1234567"))
					if name == "last_chunk_cancel" {
						cancel()
					}
					return err
				}
				if name == "producer_nil" {
					produce = nil
				}
				object, putErr := w.Put(BackupObjectLimits{MaxBytes: 7}, produce)
				if putErr != nil {
					if object != (BackupObject{}) {
						t.Error("failed Put returned object")
					}
					return nil
				}
				switch name {
				case "callback_error":
					return errors.New("private canary")
				case "callback_panic":
					panic("private canary")
				case "callback_panic_nil":
					panic(nil)
				case "late_writer":
					_, _ = writer.Write([]byte("late"))
					return nil
				case "foreign_object":
					_, _ = w.Read(BackupObject{}, backupWorkspaceConsume)
					return nil
				case "object_limit":
					_, _ = w.Put(BackupObjectLimits{MaxBytes: MaxBytes + 1}, backupWorkspaceProduce(nil))
					return nil
				case "entry_limit", "workspace_limit":
					_, _ = w.Put(BackupObjectLimits{MaxBytes: 1}, backupWorkspaceProduce([]byte("x")))
					return nil
				}
				var retained io.Reader
				consume := func(_ context.Context, r io.Reader) error {
					retained = r
					switch name {
					case "read_partial":
						_, _ = r.Read(make([]byte, 1))
						return nil
					case "read_error":
						return errors.New("private canary")
					case "read_panic":
						panic("private canary")
					case "read_panic_nil":
						panic(nil)
					case "read_io_swallowed":
						if err := r.(backupWorkspaceReader).b.stream.file.Close(); err != nil {
							t.Fatal("read IO fault setup")
						}
						_, _ = r.Read(make([]byte, 1))
						return nil
					case "reentry_read":
						_, _ = w.Read(object, backupWorkspaceConsume)
					case "read_cancel_swallowed":
						cancel()
						_, _ = r.Read(make([]byte, 1))
						return nil
					}
					_, err := io.Copy(io.Discard, r)
					return err
				}
				if name == "read_nil" {
					consume = nil
				}
				observed, readErr := w.Read(object, consume)
				if readErr != nil && observed != (BackupObjectInfo{}) {
					t.Error("failed Read returned observation")
				}
				if name == "late_reader" {
					_, _ = retained.Read(make([]byte, 1))
				}
				return nil // Deliberately swallow operation errors.
			})
			backupWorkspaceRequireZero(t, receipt, err)
			assertSQLiteParentEmpty(t, parent)
		})
	}
}

func TestBackupWorkspaceFinalCloseAndCancellation(t *testing.T) {
	for _, name := range []string{"put_close", "read_close", "final_cancel"} {
		t.Run(name, func(t *testing.T) {
			parent := newSQLiteTestDirectory(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			closes := 0
			hooks := &backupWorkspaceHooks{beforeObjectClose: func(f *os.File) {
				closes++
				if name == "put_close" || name == "read_close" && closes == 2 {
					_ = f.Close()
				}
			}, beforeCleanup: func(backupWorkspaceNative) {
				if name == "final_cancel" {
					cancel()
				}
			}}
			receipt, err := withBackupWorkspace(ctx, parent, backupWorkspaceTestLimits(), func(_ context.Context, w *BackupWorkspace) error {
				object, err := w.Put(BackupObjectLimits{MaxBytes: 7}, backupWorkspaceProduce([]byte("content")))
				if err != nil {
					return nil
				}
				_, _ = w.Read(object, backupWorkspaceConsume)
				return nil
			}, hooks)
			backupWorkspaceRequireZero(t, receipt, err)
			assertSQLiteParentEmpty(t, parent)
		})
	}
}

func TestBackupWorkspaceDetachedOperationCanceledAndJoined(t *testing.T) {
	parent := newSQLiteTestDirectory(t)
	started := make(chan struct{})
	done := make(chan struct{})
	var operationErr error
	receipt, err := WithBackupWorkspace(t.Context(), parent, backupWorkspaceTestLimits(), func(_ context.Context, w *BackupWorkspace) error {
		go func() {
			defer close(done)
			_, operationErr = w.Put(BackupObjectLimits{MaxBytes: 1}, func(ctx context.Context, _ io.Writer) error { close(started); <-ctx.Done(); return ctx.Err() })
		}()
		select {
		case <-started:
			return nil
		case <-time.After(5 * time.Second):
			return ErrIncomplete
		}
	})
	<-done // With has canceled and joined the native operation before cleanup.
	backupWorkspaceRequireZero(t, receipt, err)
	if operationErr == nil {
		t.Fatal("detached operation succeeded")
	}
	assertSQLiteParentEmpty(t, parent)
}

func TestBackupWorkspaceSerializationIsClosed(t *testing.T) {
	parent := newSQLiteTestDirectory(t)
	receipt, err := WithBackupWorkspace(t.Context(), parent, backupWorkspaceTestLimits(), func(_ context.Context, w *BackupWorkspace) error {
		var output io.Writer
		object, err := w.Put(BackupObjectLimits{MaxBytes: 7}, func(ctx context.Context, dst io.Writer) error {
			output = dst
			return backupWorkspaceProduce([]byte("content"))(ctx, dst)
		})
		if err != nil {
			return err
		}
		info, err := object.Info()
		if err != nil {
			return err
		}
		for _, value := range []any{w, *w, object, &object, info, &info, output, BackupWorkspaceReceipt{Objects: 7, Bytes: 999}} {
			for _, format := range []string{"%v", "%+v", "%#v"} {
				if got := fmt.Sprintf(format, value); !strings.HasPrefix(got, "[private backup ") || strings.Contains(got, parent) {
					return ErrUnsafe
				}
			}
			if _, err := json.Marshal(value); err == nil {
				return ErrUnsafe
			}
			if _, err := yaml.Marshal(value); err == nil {
				return ErrUnsafe
			}
			var log bytes.Buffer
			slog.New(slog.NewJSONHandler(&log, nil)).Info("observation", "value", value)
			if strings.Contains(log.String(), parent) || strings.Contains(log.String(), info.SHA256) {
				return ErrUnsafe
			}
		}
		return nil
	})
	if err != nil || receipt.Objects != 1 {
		t.Fatalf("closed format: %v", err)
	}
	assertSQLiteParentEmpty(t, parent)
}

func TestBackupWorkspaceActualSQLiteReReadable(t *testing.T) {
	parent := newSQLiteTestDirectory(t)
	receipt, err := WithBackupWorkspace(t.Context(), parent, backupWorkspaceTestLimits(), func(ctx context.Context, w *BackupWorkspace) error {
		var object BackupObject
		source, err := WithSQLiteStaging(ctx, parent, sqliteTestLimits(), buildSQLiteTestDatabase, func(_ context.Context, r io.Reader) error {
			var err error
			object, err = w.Put(BackupObjectLimits{MaxBytes: 1 << 20}, func(_ context.Context, dst io.Writer) error { _, err := io.Copy(dst, r); return err })
			return err
		})
		if err != nil {
			return err
		} // Including final SQLite cleanup; never just consume completion.
		for range 2 {
			var header [16]byte
			info, err := w.Read(object, func(_ context.Context, r io.Reader) error {
				if _, err := io.ReadFull(r, header[:]); err != nil {
					return err
				}
				_, err := io.Copy(io.Discard, r)
				return err
			})
			if err != nil {
				return err
			}
			if string(header[:]) != "SQLite format 3\x00" || info.SHA256 != source.SHA256 || info.Size != source.Size {
				return ErrUnsafe
			}
		}
		return nil
	})
	if err != nil || receipt.Objects != 1 || receipt.Bytes == 0 {
		t.Fatalf("actual SQLite spool: %v", err)
	}
	assertSQLiteParentEmpty(t, parent)
}

func TestBackupWorkspaceNativeHashMutation(t *testing.T) {
	parent := newSQLiteTestDirectory(t)
	consumed := false
	receipt, err := WithBackupWorkspace(t.Context(), parent, backupWorkspaceTestLimits(), func(_ context.Context, w *BackupWorkspace) error {
		object, err := w.Put(BackupObjectLimits{MaxBytes: 7}, backupWorkspaceProduce([]byte("content")))
		if err != nil {
			return err
		}
		path := filepath.Join(backupWorkspaceNativeTestPath(w.state.native), object.entry.name)
		// #nosec G304 -- package-local fault injection into this test's opaque owned object only.
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal("mutation open setup")
		}
		n, writeErr := f.WriteAt([]byte("changed"), 0)
		closeErr := f.Close()
		if n != 7 || writeErr != nil || closeErr != nil {
			t.Fatal("mutation write setup")
		}
		stamp := object.entry.id.ModTime()
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal("mutation timestamp setup")
		}
		info, err := w.Read(object, func(_ context.Context, r io.Reader) error {
			body, err := io.ReadAll(r)
			consumed = bytes.Equal(body, []byte("changed"))
			return err
		})
		if err == nil || info != (BackupObjectInfo{}) {
			t.Error("same size/identity/timestamp hash mutation accepted")
		}
		return nil
	})
	backupWorkspaceRequireZero(t, receipt, err)
	if !consumed {
		t.Fatal("hash counterexample did not reach streamed hash check")
	}
	assertSQLiteParentEmpty(t, parent)
}

func TestBackupWorkspaceNativeUnknownReplacementAndCleanup(t *testing.T) {
	for _, name := range []string{"unknown", "replacement", "missing", "hardlink", "cleanup_close"} {
		t.Run(name, func(t *testing.T) {
			parent := newSQLiteTestDirectory(t)
			var retainedPath string
			var originalPath string
			hooks := &backupWorkspaceHooks{}
			if name == "cleanup_close" {
				hooks.beforeCleanup = func(n backupWorkspaceNative) { backupWorkspaceNativeTestBreakClose(t, n) }
			}
			receipt, err := withBackupWorkspace(t.Context(), parent, backupWorkspaceTestLimits(), func(_ context.Context, w *BackupWorkspace) error {
				object, err := w.Put(BackupObjectLimits{MaxBytes: 7}, backupWorkspaceProduce([]byte("content")))
				if err != nil {
					return err
				}
				dir := backupWorkspaceNativeTestPath(w.state.native)
				originalPath = filepath.Join(dir, object.entry.name)
				switch name {
				case "unknown":
					retainedPath = filepath.Join(dir, "unknown-canary")
					if err := os.WriteFile(retainedPath, []byte("do-not-delete"), 0o600); err != nil {
						t.Fatal("unknown file setup")
					}
				case "replacement":
					// Preserve the original generation outside the workspace before
					// replacing its name. Windows ancestor deny-delete pins also
					// reject os.Rename's parent open, so use actual link+unlink here.
					if err := os.Link(originalPath, filepath.Join(parent, "old-generation")); err != nil {
						t.Fatal("replacement preserve setup")
					}
					if err := os.Remove(originalPath); err != nil {
						t.Fatal("replacement remove setup")
					}
					retainedPath = originalPath
					if err := os.WriteFile(retainedPath, []byte("do-not-delete"), 0o600); err != nil {
						t.Fatal("replacement setup")
					}
				case "missing":
					if err := os.Remove(originalPath); err != nil {
						t.Fatal("missing setup")
					}
				case "hardlink":
					retainedPath = filepath.Join(parent, "hardlink-canary")
					if err := os.Link(originalPath, retainedPath); err != nil {
						t.Fatal("hardlink setup")
					}
				case "cleanup_close":
					retainedPath = originalPath
				}
				if name != "cleanup_close" {
					info, err := w.Read(object, backupWorkspaceConsume)
					if err == nil || info != (BackupObjectInfo{}) {
						t.Error("unsafe native generation returned observation")
					}
				}
				return nil
			}, hooks)
			backupWorkspaceRequireZero(t, receipt, err)
			if retainedPath != "" {
				// #nosec G304 -- exact fault fixture path inside this test's private random root.
				body, readErr := os.ReadFile(retainedPath)
				want := "do-not-delete"
				if name == "cleanup_close" || name == "hardlink" {
					want = "content"
				}
				if readErr != nil || string(body) != want {
					t.Fatal("unknown/replacement/orphan was removed or modified")
				}
			}
			if name == "unknown" {
				if _, err := os.Lstat(originalPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("verified own file not precisely removed")
				}
			}
			// Fixture Cleanup owns and identity-validates this random test root;
			// production intentionally leaves unsafe/unknown private orphans.
		})
	}
}

func TestBackupWorkspaceGlobalExactZeroAndInvalidBounds(t *testing.T) {
	parent := newSQLiteTestDirectory(t)
	limits := backupWorkspaceTestLimits()
	limits.MaxBytes = 0
	limits.MaxEntries = 1
	receipt, err := WithBackupWorkspace(t.Context(), parent, limits, func(_ context.Context, w *BackupWorkspace) error {
		object, err := w.Put(BackupObjectLimits{AllowEmpty: true}, backupWorkspaceProduce(nil))
		if err != nil {
			return err
		}
		_, err = w.Read(object, backupWorkspaceConsume)
		return err
	})
	if err != nil || receipt != (BackupWorkspaceReceipt{Objects: 1}) {
		t.Fatalf("zero-byte budget: %v", err)
	}
	for _, bad := range []BackupWorkspaceLimits{{}, {MaxBytes: -1, MaxEntries: 1, Timeout: time.Second}, {MaxBytes: MaxBytes + 1, MaxEntries: 1, Timeout: time.Second}, {MaxBytes: 1, MaxEntries: MaxBackupWorkspaceEntries + 1, Timeout: time.Second}, {MaxBytes: 1, MaxEntries: 1, Timeout: MaxTimeout + 1}} {
		called := false
		receipt, err := WithBackupWorkspace(t.Context(), parent, bad, func(context.Context, *BackupWorkspace) error { called = true; return nil })
		backupWorkspaceRequireZero(t, receipt, err)
		if called {
			t.Fatal("invalid limit entered callback")
		}
	}
	assertSQLiteParentEmpty(t, parent)
}

func TestBackupWorkspaceInFlightBorrowCannotEscape(t *testing.T) {
	for _, mode := range []string{"writer", "reader"} {
		t.Run(mode, func(t *testing.T) {
			parent := newSQLiteTestDirectory(t)
			var finished chan struct{}
			var ioErr error
			start := func(ctx context.Context, b *backupWorkspaceBorrow, invoke func() error) error {
				b.stream.mu.Lock()
				finished = make(chan struct{})
				go func() { defer close(finished); ioErr = invoke() }()
				deadline := time.Now().Add(5 * time.Second)
				for {
					b.mu.Lock()
					active := b.active != nil
					b.mu.Unlock()
					if active {
						break
					}
					if time.Now().After(deadline) {
						b.stream.mu.Unlock()
						<-finished
						return ErrIncomplete
					}
					runtime.Gosched()
				}
				go func() { <-ctx.Done(); b.stream.mu.Unlock() }()
				return nil // A borrowed syscall is active when the callback ends.
			}
			receipt, err := WithBackupWorkspace(t.Context(), parent, backupWorkspaceTestLimits(), func(_ context.Context, w *BackupWorkspace) error {
				if mode == "writer" {
					_, _ = w.Put(BackupObjectLimits{MaxBytes: 1}, func(ctx context.Context, dst io.Writer) error {
						return start(ctx, dst.(backupWorkspaceWriter).b, func() error { _, err := dst.Write([]byte("x")); return err })
					})
				} else {
					object, err := w.Put(BackupObjectLimits{MaxBytes: 1}, backupWorkspaceProduce([]byte("x")))
					if err != nil {
						return err
					}
					_, _ = w.Read(object, func(ctx context.Context, src io.Reader) error {
						return start(ctx, src.(backupWorkspaceReader).b, func() error { _, err := src.Read(make([]byte, 1)); return err })
					})
				}
				return nil
			})
			if finished == nil {
				t.Fatal("borrow barrier was not reached")
			}
			<-finished
			backupWorkspaceRequireZero(t, receipt, err)
			if ioErr == nil {
				t.Fatal("in-flight escaped callback IO succeeded")
			}
			assertSQLiteParentEmpty(t, parent)
		})
	}
}

func TestBackupWorkspaceLateUnknownAndEmptyCancellation(t *testing.T) {
	parent := newSQLiteTestDirectory(t)
	var unknown string
	receipt, err := withBackupWorkspace(t.Context(), parent, backupWorkspaceTestLimits(), func(context.Context, *BackupWorkspace) error { return nil }, &backupWorkspaceHooks{beforeCleanup: func(n backupWorkspaceNative) {
		unknown = filepath.Join(backupWorkspaceNativeTestPath(n), "unknown-final-entry")
		if err := os.WriteFile(unknown, []byte("must-remain"), 0o600); err != nil {
			t.Fatal("late unknown setup")
		}
	}})
	backupWorkspaceRequireZero(t, receipt, err)
	// #nosec G304 -- exact unknown-entry fixture created above inside the owned test root.
	if body, err := os.ReadFile(unknown); err != nil || string(body) != "must-remain" {
		t.Fatal("late unknown entry was removed")
	}
	ctx, cancel := context.WithCancel(t.Context())
	receipt, err = WithBackupWorkspace(ctx, parent, backupWorkspaceTestLimits(), func(context.Context, *BackupWorkspace) error { cancel(); return nil })
	backupWorkspaceRequireZero(t, receipt, err)
	if !errors.Is(err, ErrCanceled) {
		t.Fatal("empty canceled workspace reported wrong error")
	}
}
