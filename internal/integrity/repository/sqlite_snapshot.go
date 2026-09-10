package repository

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net/url"
	"time"

	modernsqlite "modernc.org/sqlite"

	"model-integrity-inspector.local/mii/internal/integrity/privatefile"
)

var (
	errSQLiteSnapshotBusy       = errors.New("SQLITE_SNAPSHOT_BUSY")
	errSQLiteSnapshotIncomplete = errors.New("SQLITE_SNAPSHOT_INCOMPLETE")
	errSQLiteSnapshotIntegrity  = errors.New("SQLITE_SNAPSHOT_INTEGRITY_FAILED")
)

type sqliteSnapshotOptions struct {
	StepPages   int32
	MaxSteps    int
	BusyRetries int
	BusyDelay   time.Duration
}

type sqliteSnapshotStats struct {
	Steps     int
	PageCount int
}

type sqliteSnapshotSource interface {
	driver.QueryerContext
	IsReadOnly(string) (bool, error)
	NewBackup(string) (*modernsqlite.Backup, error)
}

type sqliteSnapshotBackup interface {
	Step(int32) (bool, error)
	PageCount() int
	Commit() (driver.Conn, error)
}

// sqliteOnlineSnapshot is infrastructure plumbing, NOT an authorized backup
// entry point. A future coordinator must acquire and keep maintenance authority,
// a fresh dedicated read-only source connection, and exclusive ownership of that
// connection throughout this call. The ordinary Store pool is deliberately not
// accepted: its source is writable and its busy_timeout is nonzero. No setting,
// transaction, migration, recovery, or business write is applied to the source.
//
// ctx must have a live bounded deadline (normally supplied by SQLite staging).
// An optional existing source read transaction belongs to the coordinator; this
// helper neither commits nor rolls it back. The actual source must be read-only,
// busy_timeout=0, and have no attached user database beyond main/temp. This helper
// does not implement same-snapshot inventory, audit admission, archives, or restore.
func sqliteOnlineSnapshot(ctx context.Context, source *sql.Conn, target *privatefile.SQLiteTarget,
	options sqliteSnapshotOptions,
) (stats sqliteSnapshotStats, finalErr error) {
	if err := validateSQLiteSnapshotOptions(ctx, options); err != nil {
		return sqliteSnapshotStats{}, err
	}
	if source == nil || target == nil {
		return sqliteSnapshotStats{}, ErrConfiguration
	}
	defer func() {
		if finalErr != nil {
			stats = sqliteSnapshotStats{}
		}
	}()
	uri, err := target.URI()
	if err != nil {
		return sqliteSnapshotStats{}, err
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "file" || u.Query().Get("mode") != "rw" {
		return sqliteSnapshotStats{}, ErrConfiguration
	}
	q := u.Query()
	// Only fixed internal pragmas are added to the capability's existing-file
	// URI. A small page cache limits scratch memory, not a hard kernel disk quota.
	q["_pragma"] = []string{"busy_timeout(0)", "cache_size(-1024)", "journal_mode(DELETE)", "synchronous(FULL)"}
	u.RawQuery = q.Encode()
	err = source.Raw(func(raw any) error {
		conn, ok := raw.(sqliteSnapshotSource)
		if !ok {
			return ErrConfiguration
		}
		if err := checkSQLiteSnapshotSource(ctx, conn); err != nil {
			return err
		}
		if err := checkSQLiteSnapshotStep(ctx, target.Check); err != nil {
			return err
		}
		backup, err := conn.NewBackup(u.String())
		if err != nil {
			return sqliteSnapshotError(ctx, err)
		}
		// Native backup and source are used only while the Raw callback owns them.
		stats, err = copySQLiteSnapshot(ctx, backup, target.Check, options)
		return err
	})
	if err != nil {
		return sqliteSnapshotStats{}, sqliteSnapshotError(ctx, err)
	}
	if err := validateSQLiteSnapshot(ctx, target); err != nil {
		return sqliteSnapshotStats{}, err
	}
	return stats, nil
}

func validateSQLiteSnapshotOptions(ctx context.Context, options sqliteSnapshotOptions) error {
	if ctx == nil || ctx.Err() != nil {
		return privatefile.ErrCanceled
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > privatefile.MaxTimeout {
		return ErrConfiguration
	}
	if options.StepPages < 1 || options.StepPages > 256 || options.MaxSteps < 1 || options.MaxSteps > 1<<24 ||
		options.BusyRetries < 0 || options.BusyRetries > 128 || options.BusyDelay < 0 || options.BusyDelay > 100*time.Millisecond ||
		options.BusyRetries > 0 && options.BusyDelay == 0 {
		return ErrConfiguration
	}
	return nil
}

func checkSQLiteSnapshotSource(ctx context.Context, conn sqliteSnapshotSource) error {
	readOnly, err := conn.IsReadOnly("main")
	if err != nil {
		return sqliteSnapshotError(ctx, err)
	}
	if !readOnly {
		return ErrConfiguration
	}
	value, err := sqliteSnapshotScalar(ctx, conn, "PRAGMA busy_timeout")
	if err != nil {
		return err
	}
	if timeout, ok := value.(int64); !ok || timeout != 0 {
		return ErrConfiguration
	}
	return sqliteSnapshotSchemas(ctx, conn)
}

func sqliteSnapshotSchemas(ctx context.Context, conn driver.QueryerContext) (finalErr error) {
	// Never transfer the source filename or an arbitrary attached schema label
	// into Go. Three projected rows suffice to reject anything beyond main/temp.
	rows, err := conn.QueryContext(ctx, `SELECT
CASE WHEN typeof(seq)='integer' AND seq=0 THEN 0 WHEN typeof(seq)='integer' AND seq=1 THEN 1 ELSE -1 END AS ordinal,
CASE WHEN EXISTS(SELECT 1 FROM main.sqlite_schema WHERE name COLLATE NOCASE='pragma_database_list') THEN 0
WHEN name='main' THEN 1 WHEN name='temp' THEN 2 ELSE 0 END AS kind
FROM main.pragma_database_list() LIMIT 3`, nil)
	if err != nil {
		return sqliteSnapshotError(ctx, err)
	}
	defer func() {
		if err := rows.Close(); err != nil && finalErr == nil {
			finalErr = sqliteSnapshotError(ctx, err)
		}
	}()
	if len(rows.Columns()) != 2 {
		return ErrConfiguration
	}
	var mainSeen, tempSeen bool
	for count := 0; ; count++ {
		values := make([]driver.Value, 2)
		err := rows.Next(values)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return sqliteSnapshotError(ctx, err)
		}
		if count >= 2 {
			return ErrConfiguration
		}
		seq, seqOK := values[0].(int64)
		kind, kindOK := values[1].(int64)
		if !seqOK || !kindOK {
			return ErrConfiguration
		}
		switch kind {
		case 1:
			if seq != 0 || mainSeen {
				return ErrConfiguration
			}
			mainSeen = true
		case 2:
			if seq != 1 || tempSeen {
				return ErrConfiguration
			}
			tempSeen = true
		default:
			return ErrConfiguration
		}
	}
	if !mainSeen {
		return ErrConfiguration
	}
	return nil
}

func sqliteSnapshotScalar(ctx context.Context, conn driver.QueryerContext, query string) (_ driver.Value, finalErr error) {
	rows, err := conn.QueryContext(ctx, query, nil)
	if err != nil {
		return nil, sqliteSnapshotError(ctx, err)
	}
	defer func() {
		if err := rows.Close(); err != nil && finalErr == nil {
			finalErr = sqliteSnapshotError(ctx, err)
		}
	}()
	if len(rows.Columns()) != 1 {
		return nil, errSQLiteSnapshotIncomplete
	}
	values := make([]driver.Value, 1)
	if err := rows.Next(values); err != nil {
		return nil, sqliteSnapshotError(ctx, err)
	}
	value := values[0]
	values[0] = nil
	if err := rows.Next(values); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, sqliteSnapshotError(ctx, err)
		}
		return nil, errSQLiteSnapshotIncomplete
	}
	return value, nil
}

// The small private interface permits fault tests of finalize/Close handling.
// Production always supplies the real modernc Backup returned by NewBackup.
func copySQLiteSnapshot(ctx context.Context, backup sqliteSnapshotBackup, check func() error,
	options sqliteSnapshotOptions,
) (stats sqliteSnapshotStats, finalErr error) {
	done := false
	defer func() {
		// Exactly one native sqlite3_backup_finish, even after cancellation or a
		// partial Step. Commit may return a connection after rolling back an
		// incomplete backup; that does not authorize successful output.
		destination, finishErr := backup.Commit()
		if finishErr != nil && finalErr == nil {
			finalErr = sqliteSnapshotError(ctx, finishErr)
		}
		if destination != nil {
			if finalErr == nil && done {
				finalErr = consolidateSQLiteSnapshot(ctx, destination)
			}
			if err := destination.Close(); err != nil && finalErr == nil {
				finalErr = sqliteSnapshotError(ctx, err)
			}
		} else if finalErr == nil {
			finalErr = errSQLiteSnapshotIncomplete
		}
		// On a Commit error modernc closes internally but discards its Close
		// error. No connection is returned to inspect. Fail and allow the private
		// staging cleanup to report/retain an orphan; do not promise full release.
		if !done && finalErr == nil {
			finalErr = errSQLiteSnapshotIncomplete
		}
		if ctx.Err() != nil {
			finalErr = privatefile.ErrCanceled
		}
		if finalErr != nil {
			stats = sqliteSnapshotStats{}
		}
	}()
	busyCount := 0
	for stats.Steps < options.MaxSteps {
		if err := checkSQLiteSnapshotStep(ctx, check); err != nil {
			return stats, err
		}
		more, stepErr := backup.Step(options.StepPages)
		stats.Steps++
		if err := checkSQLiteSnapshotStep(ctx, check); err != nil {
			return stats, err
		}
		if stepErr != nil {
			if !sqliteSnapshotBusy(stepErr) {
				return stats, sqliteSnapshotError(ctx, stepErr)
			}
			if busyCount >= options.BusyRetries {
				return stats, errSQLiteSnapshotBusy
			}
			busyCount++
			if err := waitSQLiteSnapshot(ctx, options.BusyDelay); err != nil {
				return stats, err
			}
			continue
		}
		if !more {
			done = true
			stats.PageCount = backup.PageCount()
			if stats.PageCount <= 0 {
				return stats, errSQLiteSnapshotIncomplete
			}
			return stats, nil
		}
	}
	return stats, privatefile.ErrLimit
}

func checkSQLiteSnapshotStep(ctx context.Context, check func() error) error {
	if ctx.Err() != nil {
		return privatefile.ErrCanceled
	}
	if err := check(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return privatefile.ErrCanceled
	}
	return nil
}

func waitSQLiteSnapshot(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return privatefile.ErrCanceled
	case <-timer.C:
		return nil
	}
}

func sqliteSnapshotBusy(err error) bool {
	var native *modernsqlite.Error
	return errors.As(err, &native) && (native.Code()&0xff == 5 || native.Code()&0xff == 6)
}

func consolidateSQLiteSnapshot(ctx context.Context, destination driver.Conn) error {
	query, ok := destination.(driver.QueryerContext)
	if !ok {
		return ErrConfiguration
	}
	value, err := sqliteSnapshotScalar(ctx, query, "PRAGMA journal_mode=DELETE")
	if err != nil {
		return err
	}
	if mode, ok := value.(string); !ok || mode != "delete" {
		return errSQLiteSnapshotIncomplete
	}
	// The pinned SQLite drops CHECK expressions when loading a read-only
	// schema. Verify the completed copy on this existing RW connection before
	// closing it, then still perform the independent read-only checks below.
	// This is a read-only validation statement, not a business/data mutation.
	return sqliteSnapshotIntegrity(ctx, query)
}

// validateSQLiteSnapshot opens only the capability's genuine mode=ro URI. It is
// intentionally separate so tests can corrupt a real completed copy and verify
// that the same production validator refuses it without executing recovery.
func validateSQLiteSnapshot(ctx context.Context, target *privatefile.SQLiteTarget) (finalErr error) {
	if err := checkSQLiteSnapshotStep(ctx, target.Check); err != nil {
		return err
	}
	uri, err := target.ROURI()
	if err != nil {
		return err
	}
	pool, err := sql.Open("sqlite", uri)
	if err != nil {
		return sqliteSnapshotError(ctx, err)
	}
	pool.SetMaxOpenConns(1)
	// Keep the returned connection idle until the checked DB.Close below.
	// MaxIdleConns(0) would close it inside Conn.Close/putConn, where database/sql
	// discards the driver's Close error, and leave DB.Close nothing to inspect.
	pool.SetMaxIdleConns(1)
	defer func() {
		if err := pool.Close(); err != nil && finalErr == nil {
			finalErr = sqliteSnapshotError(ctx, err)
		}
		if finalErr == nil {
			finalErr = checkSQLiteSnapshotStep(ctx, target.Check)
		}
	}()
	conn, err := pool.Conn(ctx)
	if err != nil {
		return sqliteSnapshotError(ctx, err)
	}
	defer func() {
		if err := conn.Close(); err != nil && finalErr == nil {
			finalErr = sqliteSnapshotError(ctx, err)
		}
	}()
	if err := conn.Raw(func(raw any) error {
		actual, ok := raw.(interface{ IsReadOnly(string) (bool, error) })
		if !ok {
			return ErrConfiguration
		}
		readOnly, err := actual.IsReadOnly("main")
		if err != nil {
			return sqliteSnapshotError(ctx, err)
		}
		if !readOnly {
			return ErrConfiguration
		}
		return nil
	}); err != nil {
		return sqliteSnapshotError(ctx, err)
	}
	var mode string
	var queryOnly int
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil || mode != "delete" {
		return sqliteSnapshotValidationError(ctx)
	}
	if err := conn.QueryRowContext(ctx, "PRAGMA query_only").Scan(&queryOnly); err != nil || queryOnly != 1 {
		return sqliteSnapshotValidationError(ctx)
	}
	if err := conn.Raw(func(raw any) error {
		query, ok := raw.(driver.QueryerContext)
		if !ok {
			return ErrConfiguration
		}
		return sqliteSnapshotIntegrity(ctx, query)
	}); err != nil {
		return err
	}
	return sqliteSnapshotForeignKeys(ctx, conn)
}

func sqliteSnapshotIntegrity(ctx context.Context, conn driver.QueryerContext) (finalErr error) {
	// An error can include an arbitrarily large schema label. Evaluate the sole
	// accepted outcome inside SQLite and return only a bounded integer to Go.
	// The pinned TVF quotes its TEXT argument: (1) becomes a table named "1",
	// not the numeric PRAGMA error limit. No argument checks the full database;
	// stop at the first bad row, with at most two small rows for exactness.
	rows, err := conn.QueryContext(ctx, `SELECT CASE
WHEN NOT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE name COLLATE NOCASE='pragma_integrity_check')
AND integrity_check='ok' THEN 1 ELSE 0 END AS valid
FROM main.pragma_integrity_check() LIMIT 2`, nil)
	if err != nil {
		return sqliteSnapshotValidationError(ctx)
	}
	defer func() {
		if err := rows.Close(); err != nil && finalErr == nil {
			finalErr = sqliteSnapshotValidationError(ctx)
		}
	}()
	if len(rows.Columns()) != 1 {
		return sqliteSnapshotValidationError(ctx)
	}
	values := make([]driver.Value, 1)
	if err := rows.Next(values); err != nil {
		return sqliteSnapshotValidationError(ctx)
	}
	if result, ok := values[0].(int64); !ok || result != 1 {
		return sqliteSnapshotValidationError(ctx)
	}
	if err := rows.Next(values); !errors.Is(err, io.EOF) {
		return sqliteSnapshotValidationError(ctx)
	}
	return nil
}

func sqliteSnapshotForeignKeys(ctx context.Context, conn *sql.Conn) (finalErr error) {
	// Rows.Next itself materializes result columns even without Scan. Project
	// one constant so neither child nor parent table names cross the boundary.
	rows, err := conn.QueryContext(ctx, `SELECT 1 FROM main.sqlite_schema WHERE name COLLATE NOCASE='pragma_foreign_key_check'
UNION ALL SELECT 1 FROM main.pragma_foreign_key_check() LIMIT 1`)
	if err != nil {
		return sqliteSnapshotValidationError(ctx)
	}
	defer func() {
		if err := rows.Close(); err != nil && finalErr == nil {
			finalErr = sqliteSnapshotValidationError(ctx)
		}
	}()
	// Zero rows is required. Do not load or expose offending table/key values.
	if rows.Next() || rows.Err() != nil {
		return sqliteSnapshotValidationError(ctx)
	}
	return nil
}

func sqliteSnapshotValidationError(ctx context.Context) error {
	if ctx.Err() != nil {
		return privatefile.ErrCanceled
	}
	return errSQLiteSnapshotIntegrity
}

func sqliteSnapshotError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return privatefile.ErrCanceled
	}
	// Preflight/schema opens can encounter the same native busy condition before
	// a Backup exists. Those paths fail immediately; only the Step loop retries.
	if sqliteSnapshotBusy(err) {
		return errSQLiteSnapshotBusy
	}
	for _, known := range []error{ErrConfiguration, ErrUnavailable, errSQLiteSnapshotBusy,
		errSQLiteSnapshotIncomplete, errSQLiteSnapshotIntegrity,
		privatefile.ErrLimit, privatefile.ErrCanceled, privatefile.ErrUnsafe, privatefile.ErrPermissions,
		privatefile.ErrClosed, privatefile.ErrUnavailable, privatefile.ErrFilesystem, privatefile.ErrIncomplete} {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrUnavailable
}
