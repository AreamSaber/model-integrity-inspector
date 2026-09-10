package app

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	modernsqlite "modernc.org/sqlite"
)

// This controlled diagnostic uses only a new temporary SQLite file. It does
// not reproduce the original CI scheduler timing or identify that run's opaque
// error. It proves the bare auxiliary connection's independent busy policy and
// its behavior under a known, synchronously acquired writer lock.
func TestPipelineAuxiliarySQLiteBareConnectionContendsWithWriter(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "auxiliary-connection.sqlite")
	production, err := repository.Open(ctx, repository.Config{Driver: "sqlite", DSN: path})
	if err != nil {
		t.Fatal("open temporary production-configured SQLite store")
	}
	t.Cleanup(func() { _ = production.Close() })
	// The actual production Open has established WAL. Reproduce the previous
	// pipeline helper: the independent sql.Open below receives just the path.
	auxiliary, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal("open temporary bare auxiliary SQLite pool")
	}
	t.Cleanup(func() { _ = auxiliary.Close() })
	writer, err := auxiliary.Conn(ctx)
	if err != nil {
		t.Fatal("pin temporary writer")
	}
	defer func() {
		if err := writer.Close(); err != nil {
			t.Error("close temporary writer connection")
		}
	}()
	reader, err := auxiliary.Conn(ctx)
	if err != nil {
		t.Fatal("pin independent auxiliary connection")
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Error("close temporary auxiliary connection")
		}
	}()
	for _, conn := range []*sql.Conn{writer, reader} {
		var busy, foreignKeys int
		var journal string
		if conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busy) != nil || conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys) != nil || conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal) != nil {
			t.Fatal("read bounded connection policy")
		}
		if busy != 0 || foreignKeys != 0 || journal != "wal" {
			t.Fatalf("bare auxiliary policy changed: busy_ms=%d foreign_keys=%d wal=%t", busy, foreignKeys, journal == "wal")
		}
	}
	if _, err := writer.ExecContext(ctx, "CREATE TABLE diagnostic_permission(organization_id INTEGER NOT NULL, permission_code TEXT NOT NULL, PRIMARY KEY(organization_id,permission_code))"); err != nil {
		t.Fatal("create temporary diagnostic table")
	}
	if _, err := writer.ExecContext(ctx, "INSERT INTO diagnostic_permission VALUES(1,'evidence.read')"); err != nil {
		t.Fatal("insert synthetic scoped permission")
	}
	if _, err := writer.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal("acquire real SQLite writer barrier")
	}
	locked := true
	defer func() {
		if locked {
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if _, err := writer.ExecContext(cleanup, "ROLLBACK"); err != nil {
				t.Error("release temporary writer barrier")
			}
		}
	}()
	// There is no timing guess or concurrent scheduling requirement here: the
	// writer barrier was acquired before this exact SQL statement is executed.
	_, err = reader.ExecContext(ctx, "DELETE FROM diagnostic_permission WHERE organization_id=$1 AND permission_code=$2", 1, "evidence.read")
	var sqliteErr *modernsqlite.Error
	if !errors.As(err, &sqliteErr) || sqliteErr.Code() != 5 || ctx.Err() != nil {
		t.Fatal("bare auxiliary statement did not fail with SQLITE_BUSY under the held writer barrier")
	}
	if pipelineSQLDiagnostic(ctx, err) != "class=sqlite_busy code=5 ctx=active" {
		t.Fatal("actual SQLite driver error did not keep its safe closed classification")
	}
	var count int
	if reader.QueryRowContext(ctx, "SELECT count(*) FROM diagnostic_permission").Scan(&count) != nil || count != 1 {
		t.Fatal("failed auxiliary mutation changed the synthetic grant")
	}
	if _, err := writer.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal("release real writer barrier")
	}
	locked = false
	// Independent unlocked positive control, not retry logic in the helper:
	// the preceding locked statement was required to fail and leave the row.
	result, err := reader.ExecContext(ctx, "DELETE FROM diagnostic_permission WHERE organization_id=$1 AND permission_code=$2", 1, "evidence.read")
	if err != nil {
		t.Fatal("unlocked positive-control SQL failed")
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		t.Fatal("unlocked scoped positive control did not affect exactly one row")
	}
	// Explicit comparator using the production policy values. This does not
	// modify the existing pipeline helper or claim its lock wait is fixed.
	query := url.Values{"_pragma": {"foreign_keys(1)", "busy_timeout(5000)", "journal_mode(WAL)", "synchronous(FULL)"}, "_txlock": {"immediate"}}
	configured, err := sql.Open("sqlite", path+"?"+query.Encode())
	if err != nil {
		t.Fatal("open explicit policy comparator")
	}
	defer func() {
		if err := configured.Close(); err != nil {
			t.Error("close explicit policy comparator")
		}
	}()
	configuredConn, err := configured.Conn(ctx)
	if err != nil {
		t.Fatal("pin explicit policy comparator")
	}
	defer func() {
		if err := configuredConn.Close(); err != nil {
			t.Error("close pinned policy comparator")
		}
	}()
	var busy, foreignKeys int
	if configuredConn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busy) != nil || configuredConn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys) != nil || busy != 5000 || foreignKeys != 1 {
		t.Fatal("explicit per-connection policy comparator differs from production settings")
	}
	t.Log("diagnostic: bare_busy_ms=0 bare_foreign_keys=0 journal=wal held_writer=SQLITE_BUSY ctx_active=true unchanged_rows=1 unlocked_affected=1 configured_busy_ms=5000 configured_foreign_keys=1")
}

func TestPipelineAuxiliarySQLiteOpenerUsesPerConnectionSafetyPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	db := openPipelineDatabase(t, Config{DatabaseDriver: "sqlite", DatabasePath: filepath.Join(t.TempDir(), "configured.sqlite")})
	for range 2 {
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal("pin actual auxiliary policy connection")
		}
		var busy, foreignKeys, synchronous int
		var journal string
		if conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busy) != nil || conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys) != nil || conn.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous) != nil || conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal) != nil {
			_ = conn.Close()
			t.Fatal("query actual auxiliary opener safety policy")
		}
		if busy != 5000 || foreignKeys != 1 || synchronous != 2 || journal != "wal" || db.Stats().MaxOpenConnections != 1 {
			_ = conn.Close()
			t.Fatalf("auxiliary safety policy: busy_ms=%d foreign_keys=%d synchronous=%d wal=%t max_open=%d", busy, foreignKeys, synchronous, journal == "wal", db.Stats().MaxOpenConnections)
		}
		// Force database/sql to replace the connection. A one-off PRAGMA on
		// the old pooled connection cannot satisfy the next iteration.
		if err := conn.Raw(func(any) error { return driver.ErrBadConn }); !errors.Is(err, driver.ErrBadConn) {
			_ = conn.Close()
			t.Fatal("retire actual auxiliary physical connection")
		}
		if err := conn.Close(); err != nil && !errors.Is(err, sql.ErrConnDone) {
			t.Fatal("close retired auxiliary connection")
		}
	}
}

func TestPipelineAuxiliarySQLiteOpenerWaitsForShortWriterAndRevokes(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cfg := Config{DatabaseDriver: "sqlite", DatabasePath: filepath.Join(t.TempDir(), "short-writer.sqlite")}
	db := openPipelineDatabase(t, cfg)
	writerDB := openPipelineDatabase(t, cfg)
	if _, err := db.ExecContext(ctx, "CREATE TABLE diagnostic_permission(organization_id INTEGER NOT NULL, permission_code TEXT NOT NULL, PRIMARY KEY(organization_id,permission_code))"); err != nil {
		t.Fatal("create isolated short-writer table")
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO diagnostic_permission VALUES(1,'evidence.read'),(2,'evidence.read')"); err != nil {
		t.Fatal("insert isolated scoped control rows")
	}
	writer, err := writerDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("acquire actual immediate writer transaction")
	}
	defer func() {
		if err := writer.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			t.Error("release isolated short-writer transaction")
		}
	}()
	operation, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	type result struct {
		value sql.Result
		err   error
	}
	done := make(chan result, 1)
	go func() {
		value, err := db.ExecContext(operation, "DELETE FROM diagnostic_permission WHERE organization_id=$1 AND permission_code=$2", 1, "evidence.read")
		done <- result{value: value, err: err}
	}()
	// The writer lock is already held. Observe the sole auxiliary connection
	// actually borrowed by the one DELETE before the controlled short hold.
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for db.Stats().InUse != 1 {
		select {
		case failed := <-done:
			t.Fatalf("auxiliary statement completed before writer release: %s", pipelineSQLDiagnostic(operation, failed.err))
		case <-operation.Done():
			t.Fatal("auxiliary statement never acquired its connection")
		case <-tick.C:
		}
	}
	hold := time.NewTimer(25 * time.Millisecond)
	defer hold.Stop()
	select {
	case failed := <-done:
		t.Fatalf("auxiliary statement failed instead of waiting for short writer: %s", pipelineSQLDiagnostic(operation, failed.err))
	case <-operation.Done():
		t.Fatal("short-writer operation budget expired before release")
	case <-hold.C:
	}
	if err := writer.Rollback(); err != nil {
		t.Fatal("release controlled short writer")
	}
	select {
	case finished := <-done:
		if finished.err != nil || operation.Err() != nil {
			t.Fatalf("single auxiliary revoke did not finish within original budget: %s", pipelineSQLDiagnostic(operation, finished.err))
		}
		if count, err := finished.value.RowsAffected(); err != nil || count != 1 {
			t.Fatal("single auxiliary revoke did not affect exactly its scoped row")
		}
	case <-operation.Done():
		t.Fatal("single auxiliary revoke did not finish after writer release")
	}
	var retained int
	if db.QueryRowContext(ctx, "SELECT count(*) FROM diagnostic_permission WHERE organization_id=2").Scan(&retained) != nil || retained != 1 {
		t.Fatal("short-writer positive control changed another organization")
	}
}

type pipelineSQLUnprintableError struct{ cause error }

func (pipelineSQLUnprintableError) Error() string   { panic("driver error text must never be formatted") }
func (e pipelineSQLUnprintableError) Unwrap() error { return e.cause }

func TestPipelineSQLDiagnosticsNeverFormatDriverText(t *testing.T) {
	active := context.Background()
	cancelled, cancel := context.WithCancel(active)
	cancel()
	expired, stop := context.WithDeadline(active, time.Unix(0, 0))
	defer stop()
	for _, test := range []struct {
		name string
		ctx  context.Context
		err  error
		want string
	}{
		{"none", active, nil, "class=none code=none ctx=active"},
		{"unknown", active, pipelineSQLUnprintableError{}, "class=unknown code=none ctx=active"},
		{"cancelled", cancelled, pipelineSQLUnprintableError{context.Canceled}, "class=cancelled code=none ctx=cancelled"},
		{"deadline", expired, pipelineSQLUnprintableError{context.DeadlineExceeded}, "class=deadline_exceeded code=none ctx=deadline_exceeded"},
		{"connection", active, pipelineSQLUnprintableError{sql.ErrConnDone}, "class=connection_done code=none ctx=active"},
		{"transaction", active, pipelineSQLUnprintableError{sql.ErrTxDone}, "class=transaction_done code=none ctx=active"},
		{"no_rows", active, pipelineSQLUnprintableError{sql.ErrNoRows}, "class=no_rows code=none ctx=active"},
		{"postgres_known", active, pipelineSQLUnprintableError{&pgconn.PgError{Code: "55P03", Message: "synthetic-private-message", Detail: "synthetic-private-SQL", SchemaName: "synthetic-private-schema"}}, "class=postgres_known code=55P03 ctx=active"},
		{"postgres_unknown", active, pipelineSQLUnprintableError{&pgconn.PgError{Code: "synthetic-private-code", Message: "synthetic-private-message"}}, "class=postgres_other code=none ctx=active"},
		{"missing_context", nil, pipelineSQLUnprintableError{}, "class=unknown code=none ctx=missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := pipelineSQLDiagnostic(test.ctx, test.err); got != test.want {
				t.Fatal("SQL diagnostic differs from the exact safe allowlist projection")
			}
		})
	}
}
