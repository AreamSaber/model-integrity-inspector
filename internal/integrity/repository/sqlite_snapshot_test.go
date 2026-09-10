package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/privatefile"
)

const snapshotTestLargeBytes = 25<<20 + 17

func snapshotTestOptions() sqliteSnapshotOptions {
	return sqliteSnapshotOptions{StepPages: 64, MaxSteps: 1 << 16, BusyRetries: 2, BusyDelay: 5 * time.Millisecond}
}

func snapshotTestLimits() privatefile.SQLiteLimits {
	return privatefile.SQLiteLimits{MaxDatabaseBytes: 32 << 20, MaxWorkspaceBytes: 40 << 20, Timeout: 30 * time.Second}
}

func snapshotTestURI(path, mode string, pragmas ...string) string {
	path = filepath.ToSlash(path)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u := url.URL{Scheme: "file", Path: path}
	q := url.Values{"mode": {mode}}
	q["_pragma"] = pragmas
	u.RawQuery = q.Encode()
	return u.String()
}

type snapshotTestSource struct {
	dir, path string
	writer    *sql.DB
	pool      *sql.DB
	conn      *sql.Conn
}

// A fresh dedicated source is opened truly read-only. Keep the writer open so
// the committed post-checkpoint row remains in WAL, not just the main file.
func newSnapshotTestSource(t *testing.T, bytes int, journal string) *snapshotTestSource {
	t.Helper()
	f := &snapshotTestSource{dir: snapshotPrivateTestDir(t)}
	f.path = filepath.Join(f.dir, "source.db")
	var err error
	f.writer, err = sql.Open("sqlite", snapshotTestURI(f.path, "rwc", "busy_timeout(0)", "cache_size(-1024)", "journal_mode("+journal+")", "synchronous(FULL)"))
	if err != nil {
		t.Fatal("source writer open failed")
	}
	f.writer.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if f.conn != nil && f.conn.Close() != nil {
			t.Error("source connection close failed")
		}
		if f.pool != nil && f.pool.Close() != nil {
			t.Error("source pool close failed")
		}
		if f.writer.Close() != nil {
			t.Error("source writer close failed")
		}
	})
	snapshotTestExec(t, f.writer, "CREATE TABLE specimen(id INTEGER PRIMARY KEY, payload BLOB NOT NULL, label TEXT NOT NULL)")
	snapshotTestExec(t, f.writer, "INSERT INTO specimen VALUES(1,zeroblob(?),'checkpoint')", bytes)
	if journal == "WAL" {
		var busy, log, checkpoint int
		if err := f.writer.QueryRowContext(t.Context(), "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &checkpoint); err != nil || busy != 0 || log != 0 || checkpoint != 0 {
			t.Fatal("source initial WAL checkpoint failed")
		}
	}
	snapshotTestExec(t, f.writer, "INSERT INTO specimen VALUES(2,x'0123456789abcdef','committed-wal-marker')")
	f.pool, err = sql.Open("sqlite", snapshotTestURI(f.path, "ro", "busy_timeout(0)", "query_only(1)"))
	if err != nil {
		t.Fatal("source readonly pool failed")
	}
	f.pool.SetMaxOpenConns(1)
	f.conn, err = f.pool.Conn(t.Context())
	if err != nil {
		t.Fatal("source readonly connection failed")
	}
	return f
}

func snapshotTestExec(t *testing.T, db *sql.DB, statement string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(t.Context(), statement, args...); err != nil {
		t.Fatal("snapshot test SQL setup failed")
	}
}

func snapshotTestHash(t *testing.T, path string) string {
	t.Helper()
	// #nosec G304 -- only exact main/WAL paths from this test's private fixture.
	f, err := os.Open(path)
	if err != nil {
		t.Fatal("snapshot source hash open failed")
	}
	h := sha256.New()
	_, copyErr := io.Copy(h, f)
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal("snapshot source hash failed")
	}
	return hex.EncodeToString(h.Sum(nil))
}

func snapshotTestNoStaging(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal("snapshot staging inventory failed")
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".mii-sqlite-") {
			t.Error("snapshot left private staging after handled test case")
		}
	}
}

func snapshotTestReadCopy(ctx context.Context, target *privatefile.SQLiteTarget, bytes int) (finalErr error) {
	uri, err := target.ROURI()
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return ErrUnavailable
	}
	db.SetMaxOpenConns(1)
	defer func() {
		if err := db.Close(); err != nil {
			finalErr = ErrUnavailable
		}
	}()
	var count, size int
	var label, marker string
	if db.QueryRowContext(ctx, "SELECT count(*) FROM specimen").Scan(&count) != nil || count != 2 ||
		db.QueryRowContext(ctx, "SELECT length(payload),label FROM specimen WHERE id=1").Scan(&size, &label) != nil || size != bytes || label != "checkpoint" ||
		db.QueryRowContext(ctx, "SELECT hex(payload) FROM specimen WHERE id=2 AND label='committed-wal-marker'").Scan(&marker) != nil || marker != "0123456789ABCDEF" {
		return errSQLiteSnapshotIntegrity
	}
	// Actual readonly URI, not sql.TxOptions.ReadOnly or a mocked opener.
	if _, err := db.ExecContext(ctx, "DELETE FROM specimen"); err == nil {
		return errSQLiteSnapshotIntegrity
	}
	return nil
}

func TestSQLiteOnlineSnapshotActualWALLarge(t *testing.T) {
	f := newSnapshotTestSource(t, snapshotTestLargeBytes, "WAL")
	beforeMain, beforeWAL := snapshotTestHash(t, f.path), snapshotTestHash(t, f.path+"-wal")
	wal, err := os.Stat(f.path + "-wal")
	if err != nil || wal.Size() <= 32 {
		t.Fatal("source marker was not actually in WAL")
	}
	var stats sqliteSnapshotStats
	var helperErr error
	var streamed int64
	sum := sha256.New()
	receipt, err := privatefile.WithSQLiteStaging(t.Context(), f.dir, snapshotTestLimits(),
		func(ctx context.Context, target *privatefile.SQLiteTarget) error {
			stats, helperErr = sqliteOnlineSnapshot(ctx, f.conn, target, snapshotTestOptions())
			if helperErr != nil {
				return helperErr
			}
			return snapshotTestReadCopy(ctx, target, snapshotTestLargeBytes)
		}, func(_ context.Context, r io.Reader) error {
			var header [16]byte
			if _, err := io.ReadFull(r, header[:]); err != nil || string(header[:]) != "SQLite format 3\x00" {
				return errSQLiteSnapshotIntegrity
			}
			_, _ = sum.Write(header[:])
			n, err := io.Copy(sum, r)
			streamed = n + int64(len(header))
			return err
		})
	if err != nil || helperErr != nil || stats.Steps <= 1 || stats.PageCount <= 0 || receipt.Published ||
		receipt.Size != streamed || streamed <= 24<<20 || receipt.SHA256 != hex.EncodeToString(sum.Sum(nil)) {
		t.Fatalf("actual WAL snapshot failed: outer=%v helper=%v steps=%d pages=%d streamed=%d", err, helperErr, stats.Steps, stats.PageCount, streamed)
	}
	t.Logf("actual_online_backup steps=%d pages=%d database_bytes=%d streamed_hash_matches=true", stats.Steps, stats.PageCount, streamed)
	if snapshotTestHash(t, f.path) != beforeMain || snapshotTestHash(t, f.path+"-wal") != beforeWAL {
		t.Fatal("snapshot changed source main or WAL bytes")
	}
	var mode string
	if f.writer.QueryRowContext(t.Context(), "PRAGMA journal_mode").Scan(&mode) != nil || mode != "wal" {
		t.Fatal("snapshot modified source journal policy")
	}
	snapshotTestNoStaging(t, f.dir)
}

func TestSQLiteOnlineSnapshotSourceContract(t *testing.T) {
	for _, kind := range []string{"writable", "busy_timeout", "attached"} {
		t.Run(kind, func(t *testing.T) {
			f := newSnapshotTestSource(t, 4096, "WAL")
			source := f.conn
			switch kind {
			case "writable":
				var err error
				source, err = f.writer.Conn(t.Context())
				if err != nil {
					t.Fatal("writable source acquire failed")
				}
				defer func() {
					if source.Close() != nil {
						t.Error("writable source close failed")
					}
				}()
			case "busy_timeout":
				if _, err := source.ExecContext(t.Context(), "PRAGMA busy_timeout=7"); err != nil {
					t.Fatal("busy timeout setup failed")
				}
			case "attached":
				if _, err := source.ExecContext(t.Context(), "ATTACH DATABASE ? AS unapproved", snapshotTestURI(f.path, "ro")); err != nil {
					t.Fatal("attached database setup failed")
				}
			}
			var got error
			var stats sqliteSnapshotStats
			consumed := false
			receipt, err := privatefile.WithSQLiteStaging(t.Context(), f.dir, snapshotTestLimits(), func(ctx context.Context, target *privatefile.SQLiteTarget) error {
				stats, got = sqliteOnlineSnapshot(ctx, source, target, snapshotTestOptions())
				return got
			}, func(context.Context, io.Reader) error { consumed = true; return nil })
			if !errors.Is(got, ErrConfiguration) || err == nil || consumed || stats != (sqliteSnapshotStats{}) || receipt != (privatefile.Receipt{}) {
				t.Fatalf("unsafe source accepted: kind=%s helper=%v outer=%v", kind, got, err)
			}
			if kind == "busy_timeout" {
				var value int
				if source.QueryRowContext(t.Context(), "PRAGMA busy_timeout").Scan(&value) != nil || value != 7 {
					t.Fatal("source setting changed")
				}
			}
			snapshotTestNoStaging(t, f.dir)
		})
	}
}

func TestSQLiteOnlineSnapshotBoundsAndForeignKeys(t *testing.T) {
	for _, kind := range []string{"steps", "capacity", "foreign_key"} {
		t.Run(kind, func(t *testing.T) {
			f := newSnapshotTestSource(t, 2<<20, "WAL")
			options, limits := snapshotTestOptions(), snapshotTestLimits()
			want := privatefile.ErrLimit
			switch kind {
			case "steps":
				options.StepPages, options.MaxSteps = 1, 1
			case "capacity":
				limits.MaxDatabaseBytes, limits.MaxWorkspaceBytes = 64<<10, 3<<20
			case "foreign_key":
				snapshotTestExec(t, f.writer, "PRAGMA foreign_keys=OFF")
				snapshotTestExec(t, f.writer, "CREATE TABLE parent(id INTEGER PRIMARY KEY)")
				snapshotTestExec(t, f.writer, "CREATE TABLE child(parent_id INTEGER REFERENCES parent(id))")
				snapshotTestExec(t, f.writer, "INSERT INTO child VALUES(100)")
				want = errSQLiteSnapshotIntegrity
			}
			before := snapshotTestHash(t, f.path+"-wal")
			var got error
			var stats sqliteSnapshotStats
			consumed := false
			receipt, err := privatefile.WithSQLiteStaging(t.Context(), f.dir, limits, func(ctx context.Context, target *privatefile.SQLiteTarget) error {
				stats, got = sqliteOnlineSnapshot(ctx, f.conn, target, options)
				return got
			}, func(context.Context, io.Reader) error { consumed = true; return nil })
			if !errors.Is(got, want) || err == nil || consumed || stats != (sqliteSnapshotStats{}) || receipt != (privatefile.Receipt{}) {
				t.Fatalf("actual bound/validation not closed: kind=%s helper=%v outer=%v", kind, got, err)
			}
			if snapshotTestHash(t, f.path+"-wal") != before {
				t.Fatal("failed snapshot changed source WAL")
			}
			snapshotTestNoStaging(t, f.dir)
		})
	}
}

func TestSQLiteOnlineSnapshotRejectsCorruptedRealCopy(t *testing.T) {
	f := newSnapshotTestSource(t, 1<<20, "WAL")
	consumed, copied := false, false
	var validation error
	receipt, err := privatefile.WithSQLiteStaging(t.Context(), f.dir, snapshotTestLimits(), func(ctx context.Context, target *privatefile.SQLiteTarget) error {
		if _, err := sqliteOnlineSnapshot(ctx, f.conn, target, snapshotTestOptions()); err != nil {
			return err
		}
		copied = true
		uri, err := target.URI()
		if err != nil {
			return err
		}
		db, err := sql.Open("sqlite", uri)
		if err != nil {
			return ErrUnavailable
		}
		db.SetMaxOpenConns(1)
		_, first := db.ExecContext(ctx, "PRAGMA writable_schema=ON")
		_, second := db.ExecContext(ctx, "UPDATE sqlite_master SET rootpage=2147483647 WHERE name='specimen'")
		closeErr := db.Close()
		if first != nil || second != nil || closeErr != nil {
			return ErrUnavailable
		}
		validation = validateSQLiteSnapshot(ctx, target)
		return validation
	}, func(context.Context, io.Reader) error { consumed = true; return nil })
	if !copied || !errors.Is(validation, errSQLiteSnapshotIntegrity) || err == nil || consumed || receipt != (privatefile.Receipt{}) {
		t.Fatalf("corrupt actual backup accepted: copied=%t validation=%v outer=%v", copied, validation, err)
	}
	var count int
	if f.conn.QueryRowContext(t.Context(), "SELECT count(*) FROM specimen").Scan(&count) != nil || count != 2 {
		t.Fatal("source altered by copy corruption")
	}
	snapshotTestNoStaging(t, f.dir)
}

func TestSQLiteOnlineSnapshotActualBusy(t *testing.T) {
	f := newSnapshotTestSource(t, 4096, "DELETE")
	// Read once before the real competing connection takes an exclusive lock.
	var count int
	if f.conn.QueryRowContext(t.Context(), "SELECT count(*) FROM specimen").Scan(&count) != nil {
		t.Fatal("source initialization failed")
	}
	snapshotTestExec(t, f.writer, "BEGIN EXCLUSIVE")
	defer snapshotTestExec(t, f.writer, "ROLLBACK")
	var got error
	var stats sqliteSnapshotStats
	consumed := false
	started := time.Now()
	receipt, err := privatefile.WithSQLiteStaging(t.Context(), f.dir, snapshotTestLimits(), func(ctx context.Context, target *privatefile.SQLiteTarget) error {
		stats, got = sqliteOnlineSnapshot(ctx, f.conn, target, snapshotTestOptions())
		return got
	}, func(context.Context, io.Reader) error { consumed = true; return nil })
	if !errors.Is(got, errSQLiteSnapshotBusy) || err == nil || consumed || stats != (sqliteSnapshotStats{}) || receipt != (privatefile.Receipt{}) || time.Since(started) > 5*time.Second {
		t.Fatalf("actual SQLite BUSY not bounded: helper=%v outer=%v", got, err)
	}
	snapshotTestNoStaging(t, f.dir)
}

type snapshotCountingBackup struct {
	backup         sqliteSnapshotBackup
	steps, commits int
}

func (b *snapshotCountingBackup) Step(pages int32) (bool, error) {
	b.steps++
	return b.backup.Step(pages)
}
func (b *snapshotCountingBackup) PageCount() int               { return b.backup.PageCount() }
func (b *snapshotCountingBackup) Commit() (driver.Conn, error) { b.commits++; return b.backup.Commit() }

func TestSQLiteOnlineSnapshotActualStepBusy(t *testing.T) {
	f := newSnapshotTestSource(t, 4096, "DELETE")
	var got error
	var stats sqliteSnapshotStats
	var counted *snapshotCountingBackup
	consumed := false
	receipt, err := privatefile.WithSQLiteStaging(t.Context(), f.dir, snapshotTestLimits(), func(ctx context.Context, target *privatefile.SQLiteTarget) error {
		uri, err := target.URI()
		if err != nil {
			return err
		}
		return f.conn.Raw(func(raw any) (finalErr error) {
			conn, ok := raw.(sqliteSnapshotSource)
			if !ok {
				return ErrConfiguration
			}
			if err := checkSQLiteSnapshotSource(ctx, conn); err != nil {
				return err
			}
			// The real competing lock is acquired AFTER source preflight, so this
			// proves native Step BUSY rather than merely a preflight query failure.
			if _, err := f.writer.ExecContext(ctx, "BEGIN EXCLUSIVE"); err != nil {
				return ErrUnavailable
			}
			defer func() {
				if _, err := f.writer.ExecContext(ctx, "ROLLBACK"); err != nil {
					finalErr = ErrUnavailable
				}
			}()
			backup, err := conn.NewBackup(uri)
			if err != nil {
				return sqliteSnapshotError(ctx, err)
			}
			// A transparent counter around the actual native Backup; no fake
			// pages, errors, lock, connection, or finalization substitute.
			counted = &snapshotCountingBackup{backup: backup}
			stats, got = copySQLiteSnapshot(ctx, counted, target.Check, snapshotTestOptions())
			return got
		})
	}, func(context.Context, io.Reader) error { consumed = true; return nil })
	if counted == nil || counted.steps != 3 || counted.commits != 1 || !errors.Is(got, errSQLiteSnapshotBusy) || err == nil ||
		consumed || stats != (sqliteSnapshotStats{}) || receipt != (privatefile.Receipt{}) {
		t.Fatalf("native Step BUSY/finalize not bounded: helper=%v outer=%v native_started=%t", got, err, counted != nil)
	}
	snapshotTestNoStaging(t, f.dir)
}

func TestSQLiteOnlineSnapshotActualStepCancellation(t *testing.T) {
	f := newSnapshotTestSource(t, 4<<20, "WAL")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var got error
	var stats sqliteSnapshotStats
	consumed, observedJournal := false, false
	receipt, err := privatefile.WithSQLiteStaging(ctx, f.dir, snapshotTestLimits(), func(ctx context.Context, target *privatefile.SQLiteTarget) error {
		uri, err := target.URI()
		if err != nil {
			return err
		}
		u, err := url.Parse(uri)
		if err != nil {
			return ErrConfiguration
		}
		path := filepath.FromSlash(u.Path)
		if runtime.GOOS == "windows" {
			path = strings.TrimPrefix(path, `\`)
		}
		watchCtx, stop := context.WithCancel(ctx)
		done := make(chan bool, 1)
		go func() {
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			for {
				// A real DELETE journal appears only after native backup begins
				// its destination transaction, not on the precreated empty main.
				if st, err := os.Stat(path + "-journal"); err == nil && st.Size() > 0 {
					cancel()
					done <- true
					return
				}
				select {
				case <-watchCtx.Done():
					done <- false
					return
				case <-ticker.C:
				}
			}
		}()
		options := snapshotTestOptions()
		options.StepPages = 1
		stats, got = sqliteOnlineSnapshot(ctx, f.conn, target, options)
		stop()
		observedJournal = <-done // No detached callback or watcher outlives build.
		return got
	}, func(context.Context, io.Reader) error { consumed = true; return nil })
	if !observedJournal || !errors.Is(got, privatefile.ErrCanceled) || !errors.Is(err, privatefile.ErrCanceled) || consumed || stats != (sqliteSnapshotStats{}) || receipt != (privatefile.Receipt{}) {
		t.Fatalf("actual Step cancel failed: observed_journal=%t helper=%v outer=%v", observedJournal, got, err)
	}
	var count int
	if f.conn.QueryRowContext(t.Context(), "SELECT count(*) FROM specimen").Scan(&count) != nil || count != 2 {
		t.Fatal("canceled backup changed source")
	}
	snapshotTestNoStaging(t, f.dir)
}

func TestSQLiteOnlineSnapshotLongSchemaValidation(t *testing.T) {
	for _, kind := range []string{"integrity", "foreign_key"} {
		t.Run(kind, func(t *testing.T) {
			f := newSnapshotTestSource(t, 4096, "WAL")
			// This is actual SQLite schema text, not an injected driver error or
			// handcrafted backup file. Quotes and values are fixed test-owned ASCII.
			name := "snapshot-schema-canary-" + strings.Repeat("x", 1<<20)
			if kind == "integrity" {
				snapshotTestExec(t, f.writer, `CREATE TABLE "`+name+`"(value INTEGER CHECK(value=1))`)
				snapshotTestExec(t, f.writer, "PRAGMA ignore_check_constraints=ON")
				snapshotTestExec(t, f.writer, `INSERT INTO "`+name+`" VALUES(2)`)
				snapshotTestExec(t, f.writer, "PRAGMA ignore_check_constraints=OFF")
				var writerValid, readOnlyValid int
				query := "SELECT CASE WHEN integrity_check='ok' THEN 1 ELSE 0 END FROM pragma_integrity_check() LIMIT 1"
				if f.writer.QueryRowContext(t.Context(), query).Scan(&writerValid) != nil || writerValid != 0 ||
					f.conn.QueryRowContext(t.Context(), query).Scan(&readOnlyValid) != nil || readOnlyValid != 1 {
					t.Fatal("pinned readonly CHECK omission/real writer violation not reproduced")
				}
			} else {
				snapshotTestExec(t, f.writer, "PRAGMA foreign_keys=OFF")
				snapshotTestExec(t, f.writer, "CREATE TABLE parent(id INTEGER PRIMARY KEY)")
				snapshotTestExec(t, f.writer, `CREATE TABLE "`+name+`"(parent_id INTEGER REFERENCES parent(id))`)
				snapshotTestExec(t, f.writer, `INSERT INTO "`+name+`" VALUES(100)`)
			}
			var got error
			var stats sqliteSnapshotStats
			consumed := false
			receipt, err := privatefile.WithSQLiteStaging(t.Context(), f.dir, snapshotTestLimits(), func(ctx context.Context, target *privatefile.SQLiteTarget) error {
				stats, got = sqliteOnlineSnapshot(ctx, f.conn, target, snapshotTestOptions())
				return got
			}, func(context.Context, io.Reader) error { consumed = true; return nil })
			if !errors.Is(got, errSQLiteSnapshotIntegrity) || err == nil || got.Error() != errSQLiteSnapshotIntegrity.Error() ||
				consumed || stats != (sqliteSnapshotStats{}) || receipt != (privatefile.Receipt{}) {
				t.Fatalf("large schema validation not closed: kind=%s helper=%v outer=%v", kind, got, err)
			}
			snapshotTestNoStaging(t, f.dir)
		})
	}
}

func TestSQLiteSnapshotOptions(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	good := snapshotTestOptions()
	if err := validateSQLiteSnapshotOptions(ctx, good); err != nil {
		t.Fatal("valid options rejected")
	}
	for _, change := range []func(*sqliteSnapshotOptions){
		func(o *sqliteSnapshotOptions) { o.StepPages = 0 }, func(o *sqliteSnapshotOptions) { o.StepPages = 257 },
		func(o *sqliteSnapshotOptions) { o.MaxSteps = 0 }, func(o *sqliteSnapshotOptions) { o.MaxSteps = 1<<24 + 1 },
		func(o *sqliteSnapshotOptions) { o.BusyRetries = -1 }, func(o *sqliteSnapshotOptions) { o.BusyRetries = 129 },
		func(o *sqliteSnapshotOptions) { o.BusyDelay = -time.Nanosecond }, func(o *sqliteSnapshotOptions) { o.BusyDelay = 101 * time.Millisecond },
		func(o *sqliteSnapshotOptions) { o.BusyDelay = 0 },
	} {
		bad := good
		change(&bad)
		if !errors.Is(validateSQLiteSnapshotOptions(ctx, bad), ErrConfiguration) {
			t.Error("unbounded options accepted")
		}
	}
	if !errors.Is(validateSQLiteSnapshotOptions(context.Background(), good), ErrConfiguration) {
		t.Error("missing deadline accepted")
	}
	tooLong, stop := context.WithTimeout(t.Context(), privatefile.MaxTimeout+time.Hour)
	defer stop()
	if !errors.Is(validateSQLiteSnapshotOptions(tooLong, good), ErrConfiguration) {
		t.Error("excessive deadline accepted")
	}
	if !errors.Is(validateSQLiteSnapshotOptions(nil, good), privatefile.ErrCanceled) { //nolint:staticcheck // Deliberately verify nil context rejection.
		t.Error("nil context accepted")
	}
	cancel()
	if !errors.Is(validateSQLiteSnapshotOptions(ctx, good), privatefile.ErrCanceled) {
		t.Error("canceled context accepted")
	}
}

func TestSQLiteOnlineSnapshotPragmaShadowing(t *testing.T) {
	for _, kind := range []string{"foreign_key", "foreign_key_virtual", "database_list", "database_list_virtual"} {
		t.Run(kind, func(t *testing.T) {
			f := newSnapshotTestSource(t, 4096, "WAL")
			if strings.HasPrefix(kind, "foreign_key") {
				snapshotTestExec(t, f.writer, "PRAGMA foreign_keys=OFF")
				snapshotTestExec(t, f.writer, "CREATE TABLE parent(id INTEGER PRIMARY KEY)")
				snapshotTestExec(t, f.writer, "CREATE TABLE child(parent_id INTEGER REFERENCES parent(id))")
				snapshotTestExec(t, f.writer, "INSERT INTO child VALUES(100)")
				if strings.HasSuffix(kind, "virtual") {
					snapshotTestExec(t, f.writer, "CREATE VIRTUAL TABLE pragma_foreign_key_check USING fts5(x)")
				} else {
					snapshotTestExec(t, f.writer, "CREATE TABLE pragma_foreign_key_check(x)")
				}
			} else {
				if strings.HasSuffix(kind, "virtual") {
					snapshotTestExec(t, f.writer, "CREATE VIRTUAL TABLE pragma_database_list USING fts5(seq,name)")
				} else {
					snapshotTestExec(t, f.writer, "CREATE TABLE pragma_database_list(seq INTEGER,name TEXT)")
				}
				snapshotTestExec(t, f.writer, "INSERT INTO pragma_database_list VALUES(0,'main')")
				if _, err := f.conn.ExecContext(t.Context(), "ATTACH DATABASE ? AS unapproved", snapshotTestURI(f.path, "ro")); err != nil {
					t.Fatal("shadowing attached fixture failed")
				}
			}
			var got error
			var stats sqliteSnapshotStats
			consumed := false
			receipt, err := privatefile.WithSQLiteStaging(t.Context(), f.dir, snapshotTestLimits(), func(ctx context.Context, target *privatefile.SQLiteTarget) error {
				stats, got = sqliteOnlineSnapshot(ctx, f.conn, target, snapshotTestOptions())
				return got
			}, func(_ context.Context, r io.Reader) error {
				consumed = true
				_, err := io.Copy(io.Discard, r)
				return err
			})
			if got == nil || err == nil || consumed || stats != (sqliteSnapshotStats{}) || receipt != (privatefile.Receipt{}) {
				t.Fatalf("user table forged PRAGMA result: kind=%s helper=%v consumed=%t", kind, got, consumed)
			}
			t.Logf("shadow_rejected kind=%s helper=%v", kind, got)
			snapshotTestNoStaging(t, f.dir)
		})
	}
}

func TestSQLiteOnlineSnapshotIntegrityPragmaArgument(t *testing.T) {
	f := newSnapshotTestSource(t, 4096, "WAL")
	var valid int
	err := f.conn.QueryRowContext(t.Context(), "SELECT CASE WHEN integrity_check='ok' THEN 1 ELSE 0 END FROM pragma_integrity_check(1)").Scan(&valid)
	if err == nil || !strings.Contains(err.Error(), "no such table: 1") {
		t.Fatal("pinned numeric TVF argument behavior changed; recheck validator SQL")
	}
	// The eponymous pragma's hidden argument is TEXT. The pinned implementation
	// quotes 1 and interprets it as a table name, not the PRAGMA integer limit.
	// No-arg TVF performs full integrity verification; the first bad row suffices.
	if err := f.conn.QueryRowContext(t.Context(), "SELECT CASE WHEN integrity_check='ok' THEN 1 ELSE 0 END FROM pragma_integrity_check() LIMIT 2").Scan(&valid); err != nil || valid != 1 {
		t.Fatal("pinned no-argument integrity TVF did not verify valid database")
	}
}
