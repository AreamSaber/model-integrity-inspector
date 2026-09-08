package repository

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/privatefile"
)

const sqliteSnapshotFaultCanary = "synthetic-snapshot-fault-canary-7f42"

const sqliteSnapshotFaultIntegrityQuery = `SELECT CASE
WHEN NOT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE name COLLATE NOCASE='pragma_integrity_check')
AND integrity_check='ok' THEN 1 ELSE 0 END AS valid
FROM main.pragma_integrity_check() LIMIT 2`

// These fakes exercise only the private finalize/control-flow contract. They
// do not open SQLite, copy pages, validate a database, or prove WAL behavior.
type sqliteSnapshotFaultStep struct {
	more bool
	err  error
}

type sqliteSnapshotFaultBackup struct {
	steps          []sqliteSnapshotFaultStep
	pageCount      int
	destination    driver.Conn
	commitErr      error
	stepCalls      int
	pageCountCalls int
	commitCalls    int
	stepPages      []int32
	events         *[]string
	onStep         func()
	onCommit       func()
}

func (b *sqliteSnapshotFaultBackup) Step(pages int32) (bool, error) {
	b.stepCalls++
	b.stepPages = append(b.stepPages, pages)
	*b.events = append(*b.events, "step")
	if b.onStep != nil {
		b.onStep()
	}
	if b.stepCalls > len(b.steps) {
		return false, errors.New("unexpected synthetic step")
	}
	step := b.steps[b.stepCalls-1]
	return step.more, step.err
}

func (b *sqliteSnapshotFaultBackup) PageCount() int {
	b.pageCountCalls++
	*b.events = append(*b.events, "page_count")
	return b.pageCount
}

func (b *sqliteSnapshotFaultBackup) Commit() (driver.Conn, error) {
	b.commitCalls++
	*b.events = append(*b.events, "commit")
	if b.onCommit != nil {
		b.onCommit()
	}
	return b.destination, b.commitErr
}

type sqliteSnapshotFaultConn struct {
	closeCalls int
	closeErr   error
	unexpected int
	events     *[]string
	onClose    func()
}

func (c *sqliteSnapshotFaultConn) Prepare(string) (driver.Stmt, error) {
	c.unexpected++
	return nil, errors.New(sqliteSnapshotFaultCanary)
}
func (c *sqliteSnapshotFaultConn) Begin() (driver.Tx, error) {
	c.unexpected++
	return nil, errors.New(sqliteSnapshotFaultCanary)
}
func (c *sqliteSnapshotFaultConn) Close() error {
	c.closeCalls++
	*c.events = append(*c.events, "connection_close")
	if c.onClose != nil {
		c.onClose()
	}
	return c.closeErr
}

type sqliteSnapshotFaultQueryConn struct {
	*sqliteSnapshotFaultConn
	rows       *sqliteSnapshotFaultRows
	integrity  *sqliteSnapshotFaultRows
	queryErr   error
	queryErrAt int
	queries    []string
	argumented bool
	onQuery    func(int)
}

func (c *sqliteSnapshotFaultQueryConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.queries = append(c.queries, query)
	c.argumented = c.argumented || len(args) != 0
	*c.events = append(*c.events, fmt.Sprintf("query_%d", len(c.queries)))
	if c.onQuery != nil {
		c.onQuery(len(c.queries))
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if c.queryErr != nil && len(c.queries) == c.queryErrAt {
		return nil, c.queryErr
	}
	switch len(c.queries) {
	case 1:
		return c.rows, nil
	case 2:
		return c.integrity, nil
	default:
		return nil, errors.New("unexpected synthetic destination query")
	}
}

type sqliteSnapshotFaultRows struct {
	columns    []string
	values     []driver.Value
	nextCalls  int
	closeCalls int
	closeErr   error
	nextErr    error
	nextErrAt  int
	events     *[]string
	stage      string
}

func (r *sqliteSnapshotFaultRows) Columns() []string { return r.columns }
func (r *sqliteSnapshotFaultRows) Close() error {
	r.closeCalls++
	*r.events = append(*r.events, r.stage+"_rows_close")
	return r.closeErr
}
func (r *sqliteSnapshotFaultRows) Next(dest []driver.Value) error {
	r.nextCalls++
	*r.events = append(*r.events, r.stage+"_next")
	if r.nextErr != nil && r.nextCalls == r.nextErrAt {
		return r.nextErr
	}
	if r.nextCalls > len(r.values) {
		return io.EOF
	}
	dest[0] = r.values[r.nextCalls-1]
	return nil
}

// An integer Code and SQLite-looking text must not impersonate the concrete
// modernc error type accepted by sqliteSnapshotBusy.
type sqliteSnapshotPretendBusy struct{}

func (sqliteSnapshotPretendBusy) Error() string {
	return sqliteSnapshotFaultCanary + ": SQLITE_BUSY (5)"
}
func (sqliteSnapshotPretendBusy) Code() int { return 5 }

type sqliteSnapshotFaultState struct {
	backup        *sqliteSnapshotFaultBackup
	connection    *sqliteSnapshotFaultConn
	query         *sqliteSnapshotFaultQueryConn
	rows          *sqliteSnapshotFaultRows
	integrity     *sqliteSnapshotFaultRows
	options       sqliteSnapshotOptions
	cancel        context.CancelFunc
	checkCalls    int
	checkErrorAt  int
	checkError    error
	cancelCheckAt int
	events        []string
}

func newSQLiteSnapshotFaultState(cancel context.CancelFunc) *sqliteSnapshotFaultState {
	s := &sqliteSnapshotFaultState{cancel: cancel,
		options: sqliteSnapshotOptions{StepPages: 8, MaxSteps: 4, BusyRetries: 3, BusyDelay: time.Microsecond}}
	s.connection = &sqliteSnapshotFaultConn{events: &s.events}
	s.rows = &sqliteSnapshotFaultRows{columns: []string{"journal_mode"}, values: []driver.Value{"delete"}, events: &s.events, stage: "journal"}
	s.integrity = &sqliteSnapshotFaultRows{columns: []string{"valid"}, values: []driver.Value{int64(1)}, events: &s.events, stage: "integrity"}
	s.query = &sqliteSnapshotFaultQueryConn{sqliteSnapshotFaultConn: s.connection, rows: s.rows, integrity: s.integrity, queryErrAt: 1}
	s.backup = &sqliteSnapshotFaultBackup{steps: []sqliteSnapshotFaultStep{{}}, pageCount: 11,
		destination: s.query, events: &s.events}
	return s
}

func (s *sqliteSnapshotFaultState) check() error {
	s.checkCalls++
	if s.checkCalls == s.cancelCheckAt {
		s.cancel()
	}
	if s.checkCalls == s.checkErrorAt {
		return s.checkError
	}
	return nil
}

func TestSQLiteSnapshotFinalizeFaults(t *testing.T) {
	canary := errors.New(sqliteSnapshotFaultCanary)
	for _, tc := range []struct {
		name                      string
		setup                     func(*sqliteSnapshotFaultState)
		wantErr                   error
		steps, pages, query, rows int
		integrityRows             int
		closes                    int
	}{
		{name: "success", steps: 1, pages: 1, query: 2, rows: 1, integrityRows: 1, closes: 1},
		{name: "step_error", setup: func(s *sqliteSnapshotFaultState) { s.backup.steps[0].err = canary },
			wantErr: ErrUnavailable, steps: 1, closes: 1},
		{name: "fake_busy_text", setup: func(s *sqliteSnapshotFaultState) {
			s.backup.steps[0].err = errors.New(sqliteSnapshotFaultCanary + ": database is locked (5) SQLITE_BUSY")
		}, wantErr: ErrUnavailable, steps: 1, closes: 1},
		{name: "fake_busy_code", setup: func(s *sqliteSnapshotFaultState) { s.backup.steps[0].err = sqliteSnapshotPretendBusy{} },
			wantErr: ErrUnavailable, steps: 1, closes: 1},
		{name: "wrapped_fake_busy_code", setup: func(s *sqliteSnapshotFaultState) {
			s.backup.steps[0].err = fmt.Errorf("%s: %w", sqliteSnapshotFaultCanary, sqliteSnapshotPretendBusy{})
		}, wantErr: ErrUnavailable, steps: 1, closes: 1},
		{name: "partial_commit_is_not_completion", setup: func(s *sqliteSnapshotFaultState) {
			s.options.MaxSteps = 2
			s.backup.steps = []sqliteSnapshotFaultStep{{more: true}, {more: true}}
		}, wantErr: privatefile.ErrLimit, steps: 2, closes: 1},
		{name: "commit_error_no_connection", setup: func(s *sqliteSnapshotFaultState) {
			s.backup.commitErr, s.backup.destination = canary, nil
		}, wantErr: ErrUnavailable, steps: 1, pages: 1},
		{name: "commit_error_with_connection", setup: func(s *sqliteSnapshotFaultState) { s.backup.commitErr = canary },
			wantErr: ErrUnavailable, steps: 1, pages: 1, closes: 1},
		{name: "commit_missing_connection", setup: func(s *sqliteSnapshotFaultState) { s.backup.destination = nil },
			wantErr: errSQLiteSnapshotIncomplete, steps: 1, pages: 1},
		{name: "close_error", setup: func(s *sqliteSnapshotFaultState) { s.connection.closeErr = canary },
			wantErr: ErrUnavailable, steps: 1, pages: 1, query: 2, rows: 1, integrityRows: 1, closes: 1},
		{name: "query_error", setup: func(s *sqliteSnapshotFaultState) { s.query.queryErr = canary },
			wantErr: ErrUnavailable, steps: 1, pages: 1, query: 1, closes: 1},
		{name: "query_interface_missing", setup: func(s *sqliteSnapshotFaultState) { s.backup.destination = s.connection },
			wantErr: ErrConfiguration, steps: 1, pages: 1, closes: 1},
		{name: "rows_close_error", setup: func(s *sqliteSnapshotFaultState) { s.rows.closeErr = canary },
			wantErr: ErrUnavailable, steps: 1, pages: 1, query: 1, rows: 1, closes: 1},
		{name: "rows_next_error", setup: func(s *sqliteSnapshotFaultState) { s.rows.nextErr, s.rows.nextErrAt = canary, 2 },
			wantErr: ErrUnavailable, steps: 1, pages: 1, query: 1, rows: 1, closes: 1},
		{name: "unconsolidated_mode", setup: func(s *sqliteSnapshotFaultState) { s.rows.values[0] = "wal" },
			wantErr: errSQLiteSnapshotIncomplete, steps: 1, pages: 1, query: 1, rows: 1, closes: 1},
		{name: "extra_scalar_row", setup: func(s *sqliteSnapshotFaultState) { s.rows.values = []driver.Value{"delete", "delete"} },
			wantErr: errSQLiteSnapshotIncomplete, steps: 1, pages: 1, query: 1, rows: 1, closes: 1},
		{name: "integrity_query_error", setup: func(s *sqliteSnapshotFaultState) { s.query.queryErr, s.query.queryErrAt = canary, 2 },
			wantErr: errSQLiteSnapshotIntegrity, steps: 1, pages: 1, query: 2, rows: 1, closes: 1},
		{name: "integrity_rows_close_error", setup: func(s *sqliteSnapshotFaultState) { s.integrity.closeErr = canary },
			wantErr: errSQLiteSnapshotIntegrity, steps: 1, pages: 1, query: 2, rows: 1, integrityRows: 1, closes: 1},
		{name: "integrity_first_next_error", setup: func(s *sqliteSnapshotFaultState) { s.integrity.nextErr, s.integrity.nextErrAt = canary, 1 },
			wantErr: errSQLiteSnapshotIntegrity, steps: 1, pages: 1, query: 2, rows: 1, integrityRows: 1, closes: 1},
		{name: "integrity_final_next_error", setup: func(s *sqliteSnapshotFaultState) { s.integrity.nextErr, s.integrity.nextErrAt = canary, 2 },
			wantErr: errSQLiteSnapshotIntegrity, steps: 1, pages: 1, query: 2, rows: 1, integrityRows: 1, closes: 1},
		{name: "integrity_missing_column", setup: func(s *sqliteSnapshotFaultState) { s.integrity.columns = nil },
			wantErr: errSQLiteSnapshotIntegrity, steps: 1, pages: 1, query: 2, rows: 1, integrityRows: 1, closes: 1},
		{name: "integrity_extra_column", setup: func(s *sqliteSnapshotFaultState) { s.integrity.columns = []string{"valid", "extra"} },
			wantErr: errSQLiteSnapshotIntegrity, steps: 1, pages: 1, query: 2, rows: 1, integrityRows: 1, closes: 1},
		{name: "integrity_missing_row", setup: func(s *sqliteSnapshotFaultState) { s.integrity.values = nil },
			wantErr: errSQLiteSnapshotIntegrity, steps: 1, pages: 1, query: 2, rows: 1, integrityRows: 1, closes: 1},
		{name: "integrity_extra_row", setup: func(s *sqliteSnapshotFaultState) { s.integrity.values = []driver.Value{int64(1), int64(1)} },
			wantErr: errSQLiteSnapshotIntegrity, steps: 1, pages: 1, query: 2, rows: 1, integrityRows: 1, closes: 1},
		{name: "integrity_bad_result", setup: func(s *sqliteSnapshotFaultState) { s.integrity.values[0] = int64(0) },
			wantErr: errSQLiteSnapshotIntegrity, steps: 1, pages: 1, query: 2, rows: 1, integrityRows: 1, closes: 1},
		{name: "integrity_text_result", setup: func(s *sqliteSnapshotFaultState) { s.integrity.values[0] = "1" },
			wantErr: errSQLiteSnapshotIntegrity, steps: 1, pages: 1, query: 2, rows: 1, integrityRows: 1, closes: 1},
		{name: "integrity_null_result", setup: func(s *sqliteSnapshotFaultState) { s.integrity.values[0] = nil },
			wantErr: errSQLiteSnapshotIntegrity, steps: 1, pages: 1, query: 2, rows: 1, integrityRows: 1, closes: 1},
		{name: "integrity_failure_survives_close_error", setup: func(s *sqliteSnapshotFaultState) {
			s.integrity.values[0], s.connection.closeErr = int64(0), canary
		}, wantErr: errSQLiteSnapshotIntegrity, steps: 1, pages: 1, query: 2, rows: 1, integrityRows: 1, closes: 1},
		{name: "zero_pages", setup: func(s *sqliteSnapshotFaultState) { s.backup.pageCount = 0 },
			wantErr: errSQLiteSnapshotIncomplete, steps: 1, pages: 1, closes: 1},
		{name: "check_before_step", setup: func(s *sqliteSnapshotFaultState) {
			s.checkErrorAt, s.checkError = 1, privatefile.ErrLimit
		}, wantErr: privatefile.ErrLimit, closes: 1},
		{name: "check_after_step", setup: func(s *sqliteSnapshotFaultState) {
			s.checkErrorAt, s.checkError = 2, privatefile.ErrUnsafe
		}, wantErr: privatefile.ErrUnsafe, steps: 1, closes: 1},
		{name: "first_failure_survives_finalize_failures", setup: func(s *sqliteSnapshotFaultState) {
			s.checkErrorAt, s.checkError = 1, privatefile.ErrLimit
			s.backup.commitErr, s.connection.closeErr = canary, canary
		}, wantErr: privatefile.ErrLimit, closes: 1},
		{name: "canceled_before_step", setup: func(s *sqliteSnapshotFaultState) { s.cancel() },
			wantErr: privatefile.ErrCanceled, closes: 1},
		{name: "canceled_during_check", setup: func(s *sqliteSnapshotFaultState) { s.cancelCheckAt = 1 },
			wantErr: privatefile.ErrCanceled, closes: 1},
		{name: "canceled_during_step", setup: func(s *sqliteSnapshotFaultState) { s.backup.onStep = s.cancel },
			wantErr: privatefile.ErrCanceled, steps: 1, closes: 1},
		{name: "canceled_during_commit", setup: func(s *sqliteSnapshotFaultState) { s.backup.onCommit = s.cancel },
			wantErr: privatefile.ErrCanceled, steps: 1, pages: 1, query: 1, closes: 1},
		{name: "canceled_during_close", setup: func(s *sqliteSnapshotFaultState) { s.connection.onClose = s.cancel },
			wantErr: privatefile.ErrCanceled, steps: 1, pages: 1, query: 2, rows: 1, integrityRows: 1, closes: 1},
		{name: "canceled_during_integrity_query", setup: func(s *sqliteSnapshotFaultState) {
			s.query.onQuery = func(n int) {
				if n == 2 {
					s.cancel()
				}
			}
		}, wantErr: privatefile.ErrCanceled, steps: 1, pages: 1, query: 2, rows: 1, closes: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			s := newSQLiteSnapshotFaultState(cancel)
			if tc.setup != nil {
				tc.setup(s)
			}
			stats, err := copySQLiteSnapshot(ctx, s.backup, s.check, s.options)
			//nolint:errorlint // Exact sentinel identity is the tested redaction contract; wrapped errors are not accepted.
			if err != tc.wantErr {
				t.Fatal("unexpected classified fault result")
			}
			if err != nil {
				if stats != (sqliteSnapshotStats{}) || strings.Contains(err.Error(), sqliteSnapshotFaultCanary) {
					t.Fatal("failure retained statistics or disclosed the synthetic canary")
				}
			} else if stats != (sqliteSnapshotStats{Steps: 1, PageCount: 11}) {
				t.Fatal("successful control flow returned incorrect statistics")
			}
			if s.backup.commitCalls != 1 || s.backup.stepCalls != tc.steps || s.backup.pageCountCalls != tc.pages ||
				s.connection.closeCalls != tc.closes || len(s.query.queries) != tc.query || s.rows.closeCalls != tc.rows || s.integrity.closeCalls != tc.integrityRows {
				t.Fatalf("lifecycle counts: commits=%d steps=%d page_queries=%d closes=%d queries=%d journal_closes=%d integrity_closes=%d",
					s.backup.commitCalls, s.backup.stepCalls, s.backup.pageCountCalls, s.connection.closeCalls, len(s.query.queries), s.rows.closeCalls, s.integrity.closeCalls)
			}
			if s.rows.nextCalls > 2 || s.integrity.nextCalls > 2 || tc.query < 2 && s.integrity.nextCalls != 0 {
				t.Fatal("destination scalar reads exceeded their phase or row bound")
			}
			if s.connection.unexpected != 0 || s.query.argumented {
				t.Fatal("unexpected generic statement/transaction capability used")
			}
			for _, pages := range s.backup.stepPages {
				if pages != s.options.StepPages || pages <= 0 || pages > 256 {
					t.Fatal("unbounded or modified page-step request")
				}
			}
			for i, query := range s.query.queries {
				allowed := []string{"PRAGMA journal_mode=DELETE", sqliteSnapshotFaultIntegrityQuery}
				if i >= len(allowed) || query != allowed[i] {
					t.Fatal("non-closed-set destination query")
				}
			}
			if tc.name == "success" && !slices.Equal(s.events,
				[]string{"step", "page_count", "commit", "query_1", "journal_next", "journal_next", "journal_rows_close",
					"query_2", "integrity_next", "integrity_next", "integrity_rows_close", "connection_close"}) {
				t.Fatal("successful finalize ordering changed")
			}
		})
	}
}

func TestSQLiteSnapshotFinalizeErrorRedaction(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for _, sentinel := range []error{ErrConfiguration, ErrUnavailable, errSQLiteSnapshotBusy,
		errSQLiteSnapshotIncomplete, errSQLiteSnapshotIntegrity, privatefile.ErrLimit,
		privatefile.ErrCanceled, privatefile.ErrUnsafe, privatefile.ErrPermissions, privatefile.ErrClosed,
		privatefile.ErrUnavailable, privatefile.ErrFilesystem, privatefile.ErrIncomplete} {
		wrapped := fmt.Errorf("%s: %w", sqliteSnapshotFaultCanary, sentinel)
		got := sqliteSnapshotError(ctx, wrapped)
		//nolint:errorlint // The boundary must remove the wrapper and return the exact public classification.
		if got != sentinel {
			t.Fatal("known sentinel wrapper was not redacted")
		}
	}
	for _, unknown := range []error{errors.New(sqliteSnapshotFaultCanary), sqliteSnapshotPretendBusy{},
		fmt.Errorf("%s: %w", sqliteSnapshotFaultCanary, sqliteSnapshotPretendBusy{})} {
		if sqliteSnapshotBusy(unknown) || !errors.Is(sqliteSnapshotError(ctx, unknown), ErrUnavailable) {
			t.Fatal("synthetic error impersonated a native retryable error")
		}
	}
	cancel()
	if !errors.Is(sqliteSnapshotError(ctx, errors.New(sqliteSnapshotFaultCanary)), privatefile.ErrCanceled) {
		t.Fatal("cancellation did not override an unclassified driver error")
	}
}

type sqliteSnapshotPoolConnector struct {
	connection driver.Conn
	connects   int
}

func (c *sqliteSnapshotPoolConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	c.connects++
	return c.connection, nil
}
func (*sqliteSnapshotPoolConnector) Driver() driver.Driver { return sqliteSnapshotPoolDriver{} }

type sqliteSnapshotPoolDriver struct{}

func (sqliteSnapshotPoolDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("unexpected synthetic legacy driver open")
}

// This uses the real database/sql pool with a synthetic driver connection. It
// proves where driver.Close errors are observable, not SQLite disk durability.
func TestSQLiteSnapshotFinalizePoolClosePropagation(t *testing.T) {
	for _, idle := range []int{0, 1} {
		t.Run(fmt.Sprintf("idle_%d", idle), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			canary := errors.New(sqliteSnapshotFaultCanary)
			var events []string
			native := &sqliteSnapshotFaultConn{closeErr: canary, events: &events}
			connector := &sqliteSnapshotPoolConnector{connection: native}
			pool := sql.OpenDB(connector)
			t.Cleanup(func() { _ = pool.Close() })
			pool.SetMaxOpenConns(1)
			pool.SetMaxIdleConns(idle)
			conn, err := pool.Conn(ctx)
			if err != nil {
				t.Fatal("synthetic pool acquisition failed")
			}
			if err := conn.Close(); err != nil {
				t.Fatal("sql.Conn.Close unexpectedly returned the native Close error")
			}
			if native.closeCalls != 1-idle {
				t.Fatal("driver close did not occur at the expected pool boundary")
			}
			closeErr := pool.Close()
			if idle == 0 && closeErr != nil || idle == 1 && !errors.Is(closeErr, canary) {
				t.Fatal("DB.Close error visibility differed from the pinned database/sql behavior")
			}
			if connector.connects != 1 || native.closeCalls != 1 || native.unexpected != 0 ||
				!slices.Equal(events, []string{"connection_close"}) {
				t.Fatal("pure pool-close fixture performed an unexpected operation")
			}
		})
	}
}
