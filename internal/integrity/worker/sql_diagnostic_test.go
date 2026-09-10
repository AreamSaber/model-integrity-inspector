package worker

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	modernsqlite "modernc.org/sqlite"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

type workerSQLDiagnosticOperation uint8

const (
	workerDiagnosticCancelUpdate workerSQLDiagnosticOperation = iota + 1
	workerDiagnosticRawInsertProhibition
	workerDiagnosticDisplayInsertProhibition
	workerDiagnosticPrecheckRunner
	workerDiagnosticRunRunner
)

func (operation workerSQLDiagnosticOperation) labels() (string, string) {
	switch operation {
	case workerDiagnosticCancelUpdate:
		return "cancel_fixture_update", "sql_statement"
	case workerDiagnosticRawInsertProhibition:
		return "raw_insert_prohibition", "sql_statement"
	case workerDiagnosticDisplayInsertProhibition:
		return "display_insert_prohibition", "sql_statement"
	case workerDiagnosticPrecheckRunner:
		return "precheck_runner_exit", "runner_lifetime"
	case workerDiagnosticRunRunner:
		return "run_runner_exit", "runner_lifetime"
	default:
		return "other", "unknown"
	}
}

// Only a concrete native SQLite error reaches this projection. The pure code
// projection is tested separately because native Error has no public constructor.
func workerSQLiteDiagnosticClass(code int) string {
	if code >= 0 && code <= 65535 {
		switch code & 0xff {
		case 5:
			return "sqlite_busy"
		case 6:
			return "sqlite_locked"
		}
	}
	return "other_driver"
}

func workerSQLDiagnosticError(err error) (string, string) {
	switch {
	case err == nil:
		return "none", "none"
	case errors.Is(err, context.Canceled):
		return "context_canceled", "context"
	case errors.Is(err, context.DeadlineExceeded):
		return "context_deadline", "context"
	}
	var sqliteError *modernsqlite.Error
	if errors.As(err, &sqliteError) && sqliteError != nil {
		return workerSQLiteDiagnosticClass(sqliteError.Code()), "native_driver"
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError != nil || errors.Is(err, driver.ErrBadConn) || errors.Is(err, sql.ErrConnDone) {
		return "other_driver", "native_driver"
	}
	// Repository normalization deliberately removes driver details. Do not
	// report these as native BUSY/deadline, even when the context is now done.
	switch {
	case errors.Is(err, repository.ErrUnavailable):
		return "unavailable", "repository_boundary"
	case errors.Is(err, repository.ErrJobLeaseLost):
		return "job_lease_lost", "repository_boundary"
	case errors.Is(err, repository.ErrConsumerLost):
		return "consumer_lost", "repository_boundary"
	case errors.Is(err, repository.ErrConflict):
		return "conflict", "repository_boundary"
	default:
		return "other", "unknown"
	}
}

func workerSQLDiagnostic(ctx context.Context, operation workerSQLDiagnosticOperation, err error, elapsed time.Duration) string {
	state := "missing"
	if ctx != nil {
		state = "active"
		switch {
		case errors.Is(ctx.Err(), context.Canceled):
			state = "canceled"
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			state = "deadline"
		case ctx.Err() != nil:
			state = "other"
		}
	}
	// This is an output bound, not a test/operation deadline or a retry budget.
	const maximumElapsed = 10 * time.Minute
	clamped := elapsed < 0 || elapsed > maximumElapsed
	boundedElapsed := min(max(elapsed, 0), maximumElapsed)
	label, elapsedScope := operation.labels()
	class, boundary := workerSQLDiagnosticError(err)
	return fmt.Sprintf("operation=%s elapsed_scope=%s elapsed_ms=%d elapsed_clamped=%t context=%s error_class=%s boundary=%s",
		label, elapsedScope, boundedElapsed.Milliseconds(), clamped, state, class, boundary)
}

func logWorkerSQLFailure(t *testing.T, ctx context.Context, operation workerSQLDiagnosticOperation, err error, elapsed time.Duration) {
	t.Helper()
	t.Log("worker database diagnostic " + workerSQLDiagnostic(ctx, operation, err, elapsed))
}

// Record in the returning Runner goroutine, not after cleanup receives its
// result and samples an unconditionally canceled context. Cleanup may already
// have begun; the logged context is the observation here, not a causal claim.
// Preserve the original error and never call lifetime SQL lock-wait time.
func runWorkerWithFailureDiagnostic(t *testing.T, ctx context.Context, runner *Runner, operation workerSQLDiagnosticOperation) error {
	t.Helper()
	started := time.Now()
	err := runner.Run(ctx)
	if err != nil {
		logWorkerSQLFailure(t, ctx, operation, err, time.Since(started))
	}
	return err
}

type workerSQLDiagnosticOpaqueError struct{ cause error }

func (workerSQLDiagnosticOpaqueError) Error() string {
	panic("diagnostic formatted protected error text")
}
func (err workerSQLDiagnosticOpaqueError) Unwrap() error { return err.cause }

// An arbitrary Code method is not evidence of a native SQLite error.
type workerSQLDiagnosticFakeCode struct{}

func (workerSQLDiagnosticFakeCode) Error() string { panic("diagnostic formatted non-driver details") }
func (workerSQLDiagnosticFakeCode) Code() int     { return 5 }

func TestWorkerSQLDiagnosticClosedErrorClasses(t *testing.T) {
	for _, test := range []struct {
		err             error
		class, boundary string
	}{
		{nil, "none", "none"},
		{context.Canceled, "context_canceled", "context"},
		{context.DeadlineExceeded, "context_deadline", "context"},
		{&modernsqlite.Error{}, "other_driver", "native_driver"},
		{&pgconn.PgError{Message: workerCanary, Detail: workerCanary, Code: workerCanary}, "other_driver", "native_driver"},
		{driver.ErrBadConn, "other_driver", "native_driver"},
		{sql.ErrConnDone, "other_driver", "native_driver"},
		{repository.ErrUnavailable, "unavailable", "repository_boundary"},
		{repository.ErrJobLeaseLost, "job_lease_lost", "repository_boundary"},
		{repository.ErrConsumerLost, "consumer_lost", "repository_boundary"},
		{repository.ErrConflict, "conflict", "repository_boundary"},
		{workerSQLDiagnosticOpaqueError{}, "other", "unknown"},
		{workerSQLDiagnosticFakeCode{}, "other", "unknown"},
	} {
		class, boundary := workerSQLDiagnosticError(test.err)
		if class != test.class || boundary != test.boundary {
			t.Fatal("wrong closed error classification")
		}
		if test.err != nil {
			class, boundary = workerSQLDiagnosticError(workerSQLDiagnosticOpaqueError{test.err})
			if class != test.class || boundary != test.boundary {
				t.Fatal("wrapped error lost its closed classification")
			}
		}
	}
	for _, test := range []struct {
		code  int
		class string
	}{{5, "sqlite_busy"}, {261, "sqlite_busy"}, {517, "sqlite_busy"}, {6, "sqlite_locked"}, {262, "sqlite_locked"},
		{0, "other_driver"}, {9, "other_driver"}, {-251, "other_driver"}, {65541, "other_driver"}} {
		if workerSQLiteDiagnosticClass(test.code) != test.class {
			t.Fatal("native code projection expanded the allowed error classes")
		}
	}
}

func TestWorkerSQLDiagnosticNoSensitiveTextAndBoundedElapsed(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	deadline, stop := context.WithDeadline(context.Background(), time.Time{})
	defer stop()
	for _, test := range []struct {
		ctx                                context.Context
		operation                          workerSQLDiagnosticOperation
		elapsed                            time.Duration
		state, operationName, elapsedScope string
		millis                             int64
		clamped                            bool
	}{
		{context.Background(), workerDiagnosticCancelUpdate, 51 * time.Millisecond, "active", "cancel_fixture_update", "sql_statement", 51, false},
		{canceled, workerDiagnosticRawInsertProhibition, -time.Second, "canceled", "raw_insert_prohibition", "sql_statement", 0, true},
		{deadline, workerDiagnosticDisplayInsertProhibition, 11 * time.Minute, "deadline", "display_insert_prohibition", "sql_statement", 600000, true},
		{nil, workerDiagnosticPrecheckRunner, 2 * time.Second, "missing", "precheck_runner_exit", "runner_lifetime", 2000, false},
		{context.Background(), workerDiagnosticRunRunner, time.Second, "active", "run_runner_exit", "runner_lifetime", 1000, false},
		{context.Background(), workerSQLDiagnosticOperation(255), 0, "active", "other", "unknown", 0, false},
	} {
		got := workerSQLDiagnostic(test.ctx, test.operation, workerSQLDiagnosticOpaqueError{repository.ErrUnavailable}, test.elapsed)
		want := fmt.Sprintf("operation=%s elapsed_scope=%s elapsed_ms=%d elapsed_clamped=%t context=%s error_class=unavailable boundary=repository_boundary",
			test.operationName, test.elapsedScope, test.millis, test.clamped, test.state)
		if got != want || strings.Contains(got, workerCanary) {
			t.Fatal("diagnostic was not the exact closed, bounded projection")
		}
	}
}
