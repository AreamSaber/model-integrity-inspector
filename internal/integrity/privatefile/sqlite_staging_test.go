package privatefile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func sqliteTestLimits() SQLiteLimits {
	return SQLiteLimits{MaxDatabaseBytes: 1 << 20, MaxWorkspaceBytes: 2 << 20, Timeout: 10 * time.Second}
}

// This is real SQLite SQL, including a closed writer followed by an OS read-only
// connection. It is not an online snapshot/coordinator or a restore proof.
func buildSQLiteTestDatabase(ctx context.Context, target *SQLiteTarget) error {
	uri, err := target.URI()
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	_, writeErr := db.ExecContext(ctx, "CREATE TABLE specimen (id INTEGER PRIMARY KEY, content TEXT NOT NULL); INSERT INTO specimen VALUES (1, 'SQLite staging test content')")
	closeErr := db.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	uri, err = target.ROURI()
	if err != nil {
		return err
	}
	ro, err := sql.Open("sqlite", uri)
	if err != nil {
		return err
	}
	defer func() { _ = ro.Close() }()
	var check, value string
	if err := ro.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&check); err != nil || check != "ok" {
		return ErrIncomplete
	}
	if err := ro.QueryRowContext(ctx, "SELECT content FROM specimen WHERE id=1").Scan(&value); err != nil || value != "SQLite staging test content" {
		return ErrIncomplete
	}
	rows, err := ro.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	bad := rows.Next()
	rowErr := rows.Err()
	rowCloseErr := rows.Close()
	if bad || rowErr != nil || rowCloseErr != nil {
		return ErrIncomplete
	}
	if _, err := ro.ExecContext(ctx, "INSERT INTO specimen VALUES (2,'forbidden')"); err == nil {
		return ErrUnsafe
	}
	if err := ro.Close(); err != nil {
		return err
	}
	return target.Check()
}

func TestSQLiteStagingRealDatabaseLifecycle(t *testing.T) {
	parent := newSQLiteTestDirectory(t)
	var saved SQLiteTarget
	var borrowed io.Reader
	var actual bytes.Buffer
	receipt, err := WithSQLiteStaging(context.Background(), parent, sqliteTestLimits(), func(ctx context.Context, target *SQLiteTarget) error {
		saved = *target
		return buildSQLiteTestDatabase(ctx, target)
	}, func(_ context.Context, r io.Reader) error {
		borrowed = r
		if err := saved.Check(); !errors.Is(err, ErrClosed) {
			return ErrUnsafe
		}
		_, err := io.Copy(&actual, r)
		return err
	})
	if err != nil {
		t.Fatalf("staging failed: %v", err)
	}
	if !bytes.HasPrefix(actual.Bytes(), []byte("SQLite format 3\x00")) || receipt.Size != int64(actual.Len()) || receipt.Published {
		t.Fatal("not a complete unpublished SQLite main file")
	}
	want := sha256.Sum256(actual.Bytes())
	if receipt.SHA256 != hex.EncodeToString(want[:]) {
		t.Fatal("receipt hash differs from consumed bytes")
	}
	if _, err := saved.URI(); !errors.Is(err, ErrClosed) {
		t.Fatal("copied target remained usable")
	}
	if _, err := borrowed.Read(make([]byte, 1)); !errors.Is(err, ErrClosed) {
		t.Fatal("borrowed reader remained usable")
	}
	assertSQLiteParentEmpty(t, parent)
}

func TestSQLiteStagingCallbackFailures(t *testing.T) {
	for _, name := range []string{"build_error", "build_panic", "consume_error", "consume_panic", "partial", "cancel_after_eof", "mutate_after_eof"} {
		t.Run(name, func(t *testing.T) {
			parent := newSQLiteTestDirectory(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var targetPath string
			receipt, err := WithSQLiteStaging(ctx, parent, sqliteTestLimits(), func(ctx context.Context, target *SQLiteTarget) error {
				targetPath = target.state.native.databasePath()
				if err := buildSQLiteTestDatabase(ctx, target); err != nil {
					return err
				}
				if name == "build_error" {
					return errors.New("private callback canary")
				}
				if name == "build_panic" {
					panic("private panic canary")
				}
				return nil
			}, func(_ context.Context, r io.Reader) error {
				if name == "partial" {
					_, _ = r.Read(make([]byte, 1))
					return nil
				}
				if _, err := io.Copy(io.Discard, r); err != nil {
					return err
				}
				switch name {
				case "consume_error":
					return errors.New("private callback canary")
				case "consume_panic":
					panic("private panic canary")
				case "cancel_after_eof":
					cancel()
				case "mutate_after_eof":
					stamp := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
					if err := os.Chtimes(targetPath, stamp, stamp); err != nil {
						t.Fatal("native attribute change setup failed")
					}
				}
				return nil
			})
			if err == nil || receipt != (Receipt{}) || strings.Contains(err.Error(), "canary") {
				t.Fatalf("failed operation disclosed a receipt or callback error: %v", err)
			}
			want := ErrCallback
			switch name {
			case "partial":
				want = ErrIncomplete
			case "cancel_after_eof":
				want = ErrCanceled
			case "mutate_after_eof":
				want = ErrUnsafe
			}
			if !errors.Is(err, want) {
				t.Fatalf("wrong closed error: %v", err)
			}
			assertSQLiteParentEmpty(t, parent)
		})
	}
}

func TestSQLiteStagingSwallowedCheckFailure(t *testing.T) {
	parent := newSQLiteTestDirectory(t)
	limits := sqliteTestLimits()
	limits.MaxDatabaseBytes = 4096
	consumed := false
	receipt, err := WithSQLiteStaging(context.Background(), parent, limits, func(ctx context.Context, target *SQLiteTarget) error {
		uri, err := target.URI()
		if err != nil {
			return err
		}
		db, err := sql.Open("sqlite", uri)
		if err != nil {
			return err
		}
		_, writeErr := db.ExecContext(ctx, "CREATE TABLE specimen(x BLOB); INSERT INTO specimen VALUES(zeroblob(16384))")
		closeErr := db.Close()
		if writeErr != nil || closeErr != nil {
			return ErrCallback
		}
		if err := target.Check(); !errors.Is(err, ErrLimit) {
			t.Fatal("real SQLite file did not exceed main budget")
		}
		// Remove the immediate cause after observing it. The previous Check
		// failure must remain sticky and prevent consumer execution.
		if err := os.Truncate(target.state.native.databasePath(), 0); err != nil {
			t.Fatal("test-owned shrink setup failed")
		}
		return nil
	}, func(context.Context, io.Reader) error { consumed = true; return nil })
	if !errors.Is(err, ErrLimit) || receipt != (Receipt{}) || consumed {
		t.Fatal("swallowed check failure was accepted")
	}
	assertSQLiteParentEmpty(t, parent)
}

func TestSQLiteStagingProtectionAndInputBounds(t *testing.T) {
	var zero SQLiteTarget
	if !errors.Is(zero.Check(), ErrClosed) {
		t.Fatal("zero target not closed")
	}
	if _, err := zero.URI(); !errors.Is(err, ErrClosed) {
		t.Fatal("zero URI not closed")
	}
	parent := newSQLiteTestDirectory(t)
	_, err := WithSQLiteStaging(context.Background(), parent, sqliteTestLimits(), func(ctx context.Context, target *SQLiteTarget) error {
		var logs bytes.Buffer
		slog.New(slog.NewTextHandler(&logs, nil)).Info("target", "target", *target)
		for _, text := range []string{fmt.Sprintf("%+v %#v", *target, target), logs.String()} {
			if strings.Contains(text, parent) || strings.Contains(text, ".mii-sqlite-") || strings.Contains(text, "file:") {
				t.Fatal("target logging exposed a path")
			}
		}
		if _, err := json.Marshal(*target); err == nil {
			t.Fatal("value serialization accepted")
		}
		return buildSQLiteTestDatabase(ctx, target)
	}, func(_ context.Context, r io.Reader) error { _, err := io.Copy(io.Discard, r); return err })
	if err != nil {
		t.Fatal(err)
	}
	for _, limits := range []SQLiteLimits{
		{},
		{MaxDatabaseBytes: MaxBytes + 1, MaxWorkspaceBytes: MaxSQLiteWorkspaceBytes, Timeout: time.Second},
		{MaxDatabaseBytes: 100, MaxWorkspaceBytes: 99, Timeout: time.Second},
		{MaxDatabaseBytes: 1, MaxWorkspaceBytes: MaxSQLiteWorkspaceBytes + 1, Timeout: time.Second},
		{MaxDatabaseBytes: 1, MaxWorkspaceBytes: 1, Timeout: MaxTimeout + 1},
	} {
		called := false
		receipt, err := WithSQLiteStaging(context.Background(), parent, limits, func(context.Context, *SQLiteTarget) error { called = true; return nil }, func(context.Context, io.Reader) error { called = true; return nil })
		if !errors.Is(err, ErrLimit) || receipt != (Receipt{}) || called {
			t.Fatal("invalid limits accepted")
		}
	}
	assertSQLiteParentEmpty(t, parent)
}

func assertSQLiteParentEmpty(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("unexpected staging orphan after successful cleanup")
	}
}

func TestSQLiteStagingCompoundFailurePreservesUnknown(t *testing.T) {
	parent := newSQLiteTestDirectory(t)
	var unknown string
	receipt, err := WithSQLiteStaging(context.Background(), parent, sqliteTestLimits(), func(ctx context.Context, target *SQLiteTarget) error {
		if err := buildSQLiteTestDatabase(ctx, target); err != nil {
			return err
		}
		unknown = filepath.Join(filepath.Dir(target.state.native.databasePath()), "not-owned-by-staging")
		if err := os.WriteFile(unknown, []byte("unknown-entry-must-survive"), 0o600); err != nil {
			t.Fatal("test-owned unknown setup failed")
		}
		panic("callback canary plus unsafe workspace")
	}, func(context.Context, io.Reader) error { t.Fatal("consumer reached unsafe workspace"); return nil })
	if err == nil || receipt != (Receipt{}) {
		t.Fatal("compound failure accepted")
	}
	// #nosec G304 -- This test created the fixed canary in its own native private fixture.
	content, readErr := os.ReadFile(unknown)
	if readErr != nil || string(content) != "unknown-entry-must-survive" {
		t.Fatal("cleanup removed or modified unknown entry")
	}
}

func TestSQLiteStagingActualWALWorkspaceAndClosedSidecars(t *testing.T) {
	for _, name := range []string{"wal_consolidated", "workspace_limit", "persistent_journal"} {
		t.Run(name, func(t *testing.T) {
			parent := newSQLiteTestDirectory(t)
			limits := sqliteTestLimits()
			if name == "workspace_limit" {
				limits.MaxDatabaseBytes, limits.MaxWorkspaceBytes = 64<<10, 64<<10
			}
			consumed := false
			receipt, err := WithSQLiteStaging(context.Background(), parent, limits, func(ctx context.Context, target *SQLiteTarget) error {
				uri, err := target.URI()
				if err != nil {
					return err
				}
				db, err := sql.Open("sqlite", uri)
				if err != nil {
					return err
				}
				defer func() { _ = db.Close() }()
				db.SetMaxOpenConns(1)
				mode := "WAL"
				if name == "persistent_journal" {
					mode = "PERSIST"
				}
				var observed string
				// Test-owned fixed enum, never request-provided SQL.
				if err := db.QueryRowContext(ctx, "PRAGMA journal_mode="+mode).Scan(&observed); err != nil || !strings.EqualFold(observed, mode) {
					return ErrCallback
				}
				if _, err := db.ExecContext(ctx, "CREATE TABLE specimen(x BLOB); INSERT INTO specimen VALUES (zeroblob(32768))"); err != nil {
					return err
				}
				path := target.state.native.databasePath()
				if name != "persistent_journal" {
					for _, suffix := range []string{"-wal", "-shm"} {
						info, err := os.Stat(path + suffix)
						if err != nil || info.Size() <= 0 {
							t.Fatal("actual SQLite WAL/SHM was not created")
						}
					}
				}
				checkErr := target.Check()
				if name == "workspace_limit" {
					mainInfo, statErr := os.Stat(path)
					if statErr != nil || mainInfo.Size() >= limits.MaxDatabaseBytes || !errors.Is(checkErr, ErrLimit) {
						t.Fatal("workspace-only overage was not detected while main remained below budget")
					}
					// SQLite closes and consolidates below the main-file budget.
					// A previously observed workspace overage is still sticky.
					return db.Close()
				}
				if checkErr != nil {
					return checkErr
				}
				if name == "wal_consolidated" {
					if err := db.QueryRowContext(ctx, "PRAGMA journal_mode=DELETE").Scan(&observed); err != nil || observed != "delete" {
						return ErrIncomplete
					}
				}
				if err := db.Close(); err != nil {
					return err
				}
				if name == "persistent_journal" {
					if _, err := os.Stat(path + "-journal"); err != nil {
						t.Fatal("closed PERSIST sidecar setup failed")
					}
					return nil
				}
				roURI, err := target.ROURI()
				if err != nil {
					return err
				}
				ro, err := sql.Open("sqlite", roURI)
				if err != nil {
					return err
				}
				var check string
				queryErr := ro.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&check)
				closeErr := ro.Close()
				if queryErr != nil || closeErr != nil || check != "ok" {
					return ErrIncomplete
				}
				return nil
			}, func(_ context.Context, r io.Reader) error {
				consumed = true
				_, err := io.Copy(io.Discard, r)
				return err
			})
			switch name {
			case "wal_consolidated":
				if err != nil || !consumed || receipt.Size <= 0 || receipt.Published {
					t.Fatalf("closed main did not succeed: %v", err)
				}
			case "workspace_limit":
				if !errors.Is(err, ErrLimit) || consumed || receipt != (Receipt{}) {
					t.Fatal("workspace limit was swallowed")
				}
			case "persistent_journal":
				if !errors.Is(err, ErrIncomplete) || consumed || receipt != (Receipt{}) {
					t.Fatalf("persistent sidecar was silently omitted: %v", err)
				}
			}
			assertSQLiteParentEmpty(t, parent)
		})
	}
}

func TestSQLiteStagingURIExistingOnly(t *testing.T) {
	parent := newSQLiteTestDirectory(t)
	_, err := WithSQLiteStaging(context.Background(), parent, sqliteTestLimits(), func(ctx context.Context, target *SQLiteTarget) error {
		uri, err := target.URI()
		if err != nil {
			return err
		}
		parsed, err := url.Parse(uri)
		if err != nil || parsed.Query().Get("mode") != "rw" {
			t.Fatal("write URI does not require existing file")
		}
		parsed.Path += "-never-created"
		db, err := sql.Open("sqlite", parsed.String())
		if err != nil {
			return err
		}
		pingErr := db.PingContext(ctx)
		closeErr := db.Close()
		if pingErr == nil || closeErr != nil {
			t.Fatal("mode=rw did not refuse nonexistent target")
		}
		if _, err := os.Stat(target.state.native.databasePath() + "-never-created"); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("SQLite created a missing file")
		}
		return buildSQLiteTestDatabase(ctx, target)
	}, func(_ context.Context, r io.Reader) error { _, err := io.Copy(io.Discard, r); return err })
	if err != nil {
		t.Fatal(err)
	}
	assertSQLiteParentEmpty(t, parent)
}

func TestSQLiteStagingJournalGenerations(t *testing.T) {
	parent := newSQLiteTestDirectory(t)
	pin := filepath.Join(parent, ".test-retained-journal")
	var pinned bool
	var pinID [3]uint64
	t.Cleanup(func() {
		if pinned {
			if sqliteTestFileID(t, pin) == pinID {
				_ = os.Remove(pin)
			}
		}
	})
	_, err := WithSQLiteStaging(context.Background(), parent, sqliteTestLimits(), func(ctx context.Context, target *SQLiteTarget) error {
		uri, err := target.URI()
		if err != nil {
			return err
		}
		db, err := sql.Open("sqlite", uri)
		if err != nil {
			return err
		}
		defer func() { _ = db.Close() }()
		db.SetMaxOpenConns(1)
		if _, err := db.ExecContext(ctx, "CREATE TABLE specimen(x BLOB); BEGIN; INSERT INTO specimen VALUES(zeroblob(4096))"); err != nil {
			return err
		}
		journal := target.state.native.databasePath() + "-journal"
		if _, err := os.Stat(journal); err != nil {
			t.Fatal("first transaction did not create real journal")
		}
		first := sqliteTestSidecarID(t, target, "snapshot.db-journal")
		pinID = first
		if err := target.Check(); err != nil {
			return err
		}
		// Pin the OLD object outside the SQLite workspace only after its valid
		// single-link Check. COMMIT removes the real journal name; the next Check
		// observes absence. This avoids allocator-dependent inode reuse without
		// closing a SQLite inode fd or creating an unknown workspace entry.
		if err := os.Link(journal, pin); err != nil {
			t.Fatal("native test-owned journal pin failed")
		}
		pinned = true
		if _, err := db.ExecContext(ctx, "COMMIT"); err != nil {
			return err
		}
		if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("SQLite did not delete first journal")
		}
		if err := target.Check(); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, "BEGIN; INSERT INTO specimen VALUES(zeroblob(4096))"); err != nil {
			return err
		}
		if _, err := os.Stat(journal); err != nil {
			t.Fatal("second transaction did not create real journal")
		}
		second := sqliteTestSidecarID(t, target, "snapshot.db-journal")
		if first == second {
			t.Fatal("test requires a genuinely new journal identity")
		}
		if err := target.Check(); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, "COMMIT"); err != nil {
			return err
		}
		if err := db.Close(); err != nil {
			return err
		}
		return target.Check()
	}, func(_ context.Context, r io.Reader) error { _, err := io.Copy(io.Discard, r); return err })
	if pinned {
		if sqliteTestFileID(t, pin) != pinID {
			t.Fatal("test-owned journal pin identity changed; not deleted")
		}
		if err := os.Remove(pin); err != nil {
			t.Fatal("test-owned journal pin cleanup failed")
		}
		pinned = false
	}
	if err != nil {
		t.Fatalf("legitimate observed journal generations rejected: %v", err)
	}
	assertSQLiteParentEmpty(t, parent)
}
