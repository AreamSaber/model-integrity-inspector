package repository

import (
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/pgbackup"
)

var (
	errPostgresDumpIdentity = errors.New("POSTGRES_DUMP_SESSION_IDENTITY")
	errPostgresDumpCleanup  = errors.New("POSTGRES_DUMP_SESSION_CLEANUP_UNCONFIRMED")
	errPostgresDumpUnseen   = errors.New("POSTGRES_DUMP_SESSION_START_UNOBSERVED")
)

const (
	postgresDumpPollInterval = 10 * time.Millisecond
	postgresDumpQueryLimit   = 250 * time.Millisecond
	postgresDumpCleanupLimit = 1500 * time.Millisecond
	postgresDumpSignalLimit  = 750 * time.Millisecond
	postgresDumpSignalWait   = 500
)

type postgresDumpSource struct {
	database, username string
	databaseID, roleID int64
	pid                int
	address            sql.NullString
	port               sql.NullInt64
}

type postgresDumpBackend struct {
	pid       int
	startedAt time.Time
}

type postgresDumpActivity struct {
	pid                      int
	startedAt                sql.NullTime
	databaseID, roleID       sql.NullInt64
	database, username, kind sql.NullString
}

func (a postgresDumpActivity) identify(source postgresDumpSource) (*postgresDumpBackend, error) {
	if a.pid <= 0 || a.pid == source.pid ||
		(a.databaseID.Valid && a.databaseID.Int64 != source.databaseID) ||
		(a.roleID.Valid && a.roleID.Int64 != source.roleID) ||
		(a.database.Valid && a.database.String != source.database) ||
		(a.username.Valid && a.username.String != source.username) ||
		(a.kind.Valid && a.kind.String != "client backend") {
		return nil, errPostgresDumpIdentity
	}
	// pg_stat_activity can expose application_name while startup still has
	// InvalidOid database/user fields. Non-superusers then also see privileged
	// columns (including backend_start) as NULL. Such a row is present but NOT
	// an authenticated/bound target. Never signal it using only its nonce/PID.
	if !a.databaseID.Valid || !a.roleID.Valid || !a.database.Valid || !a.username.Valid || !a.kind.Valid || !a.startedAt.Valid {
		return nil, nil
	}
	if a.startedAt.Time.IsZero() {
		return nil, errPostgresDumpIdentity
	}
	return &postgresDumpBackend{a.pid, a.startedAt.Time}, nil
}

// Diagnostics remain a closed phase/boolean vocabulary. Never retain the
// underlying driver error, which can contain SQL, connection data or secrets.
type postgresDumpControlFailure struct {
	phase       string
	timedOut    bool
	recoverable bool
}

func (e postgresDumpControlFailure) Error() string {
	return fmt.Sprintf("%s (%s timeout=%t)", errPostgresDumpCleanup, e.phase, e.timedOut)
}

func (postgresDumpControlFailure) Unwrap() error { return errPostgresDumpCleanup }

func postgresDumpControlFailed(phase string, ctx context.Context, err error) error {
	timedOut := errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded)
	recoverable := timedOut || errors.Is(err, sql.ErrConnDone) || errors.Is(err, driver.ErrBadConn) || errors.Is(err, io.EOF)
	var networkError net.Error
	var databaseError *pgconn.PgError
	if errors.As(err, &networkError) {
		recoverable = true
	}
	if errors.As(err, &databaseError) {
		// A definite server-side error wins over a coincident local deadline.
		// In particular 42501 must not become retryable merely because the
		// context expires while its permission denial is being delivered.
		recoverable = false
		switch databaseError.Code {
		case "08000", "08003", "08006", "57P01", "57P02", "57P03":
			recoverable = true
		}
	}
	return postgresDumpControlFailure{phase: phase, timedOut: timedOut, recoverable: recoverable}
}

// The control connection is borrowed from the SOURCE Store pool, not rebuilt
// from Dump's connection parameters. Those parameters cannot prove the Store's
// TLS/CRL policy: keeping both configurations equivalent is the trusted app
// adapter's responsibility. This unit never reads an environment/DSN or raises
// role privileges. A direct same-server connection is required (not a pooler
// that swaps backend identity between transactions).
type postgresDumpSession struct {
	control           *sql.Conn
	pool              *sql.DB
	source            postgresDumpSource
	name              string
	bound             *postgresDumpBackend
	ended             bool
	pending           bool
	recoveryAttempted bool
}

// dumpPostgresSnapshot is private infrastructure, not a complete backup or an
// authorization API. Call within withPostgresSnapshot's consume callback, NOT
// recursively within view.use. It owns a synchronous view.use for the entire
// native-child AND server-session lifecycle. A receipt remains unpublished
// until the outer snapshot commit and the future coordinator also succeed.
func (s *Store) dumpPostgresSnapshot(ctx context.Context, view *postgresSnapshot, executable string,
	c pgbackup.Connection, request pgbackup.DumpRequest, out io.Writer,
) (pgbackup.DumpReceipt, error) {
	if view == nil {
		return pgbackup.DumpReceipt{}, ErrConfiguration
	}
	var receipt pgbackup.DumpReceipt
	var cause error
	err := view.use(func(tx *gorm.DB, id string, _ postgresSnapshotMetadata) error {
		// Reject valid-view requests inside use so its sticky failure records
		// even preflight errors. A consumer cannot swallow these errors and
		// then resume inventory/dump work or commit the outer snapshot.
		if cause = validatePostgresDumpRequest(ctx, s, request, out); cause != nil {
			return cause
		}
		if request.Snapshot != "" && request.Snapshot != id {
			cause = ErrConfiguration
			return cause
		}
		request.Snapshot = id
		workCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		stopSnapshotWatch := context.AfterFunc(view.ctx, cancel)
		defer stopSnapshotWatch()
		session, openErr := s.openPostgresDumpSession(workCtx, tx, c)
		if openErr != nil {
			cause = openErr
			return cause
		}
		receipt, cause = session.run(workCtx, func(runCtx context.Context, name string) (pgbackup.DumpReceipt, error) {
			request.ApplicationName = name
			return pgbackup.Dump(runCtx, executable, c, request, out)
		})
		if closeErr := session.control.Close(); closeErr != nil {
			receipt, cause = pgbackup.DumpReceipt{}, errPostgresDumpCleanup
		}
		if cause == nil && workCtx.Err() != nil {
			receipt, cause = pgbackup.DumpReceipt{}, pgbackup.ErrCanceled
		}
		return cause
	})
	if err != nil {
		if cause != nil {
			return pgbackup.DumpReceipt{}, cause
		}
		return pgbackup.DumpReceipt{}, err
	}
	return receipt, nil
}

func validatePostgresDumpRequest(ctx context.Context, s *Store, request pgbackup.DumpRequest, out io.Writer) error {
	if ctx == nil || s == nil || s.sql == nil || s.db == nil || s.driver != "postgres" || out == nil || request.ApplicationName != "" {
		return ErrConfiguration
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) > maxMaintenanceDuration {
		return ErrConfiguration
	}
	if ctx.Err() != nil {
		return pgbackup.ErrCanceled
	}
	return nil
}

const postgresDumpSourceQuery = `SELECT current_database(), current_user,
(SELECT oid::bigint FROM pg_catalog.pg_database WHERE datname=current_database()),
(SELECT oid::bigint FROM pg_catalog.pg_roles WHERE rolname=current_user),
pg_catalog.pg_backend_pid(), pg_catalog.inet_server_addr()::text, pg_catalog.inet_server_port()`

func (s *Store) openPostgresDumpSession(ctx context.Context, tx *gorm.DB, c pgbackup.Connection) (*postgresDumpSession, error) {
	if tx == nil || tx.Statement == nil {
		return nil, ErrConfiguration
	}
	// The caller's active snapshot must really own a database/sql transaction;
	// accepting a root ORM here could silently use a different pool connection.
	if _, ok := tx.Statement.ConnPool.(*sql.Tx); !ok {
		return nil, ErrConfiguration
	}
	var source postgresDumpSource
	if err := scanPostgresDumpSource(tx.WithContext(ctx).Raw(postgresDumpSourceQuery).Row(), &source); err != nil {
		return nil, ErrUnavailable
	}
	if source.database != c.Database || source.username != c.Username || source.databaseID <= 0 || source.roleID <= 0 || source.pid <= 0 {
		return nil, errPostgresDumpIdentity
	}
	acquireCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	control, err := s.sql.Conn(acquireCtx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, pgbackup.ErrCanceled
		}
		return nil, ErrUnavailable
	}
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		_ = control.Close()
		return nil, ErrUnavailable
	}
	session := &postgresDumpSession{control: control, pool: s.sql, source: source, name: "mii-backup-" + hex.EncodeToString(entropy[:])}
	err = session.checkControlIdentity(ctx)
	if err == nil {
		var exists bool
		exists, err = session.observe(ctx)
		if exists {
			err = errPostgresDumpIdentity // An existing nonce must never be adopted.
		}
	}
	if err != nil {
		_ = control.Close()
		return nil, err
	}
	return session, nil
}

func (s *postgresDumpSession) checkControlIdentity(ctx context.Context) error {
	return s.withControlTransaction(ctx, postgresDumpQueryLimit, func(queryCtx context.Context, controlTx *sql.Tx) error {
		var observed postgresDumpSource
		if err := scanPostgresDumpSource(controlTx.QueryRowContext(queryCtx, postgresDumpSourceQuery), &observed); err != nil {
			return postgresDumpControlFailed("source_identity", queryCtx, err)
		}
		source := s.source
		if observed.database != source.database || observed.username != source.username || observed.databaseID != source.databaseID ||
			observed.roleID != source.roleID || observed.address != source.address || observed.port != source.port || observed.pid <= 0 || observed.pid == source.pid {
			return errPostgresDumpIdentity
		}
		return nil
	})
}

func scanPostgresDumpSource(row *sql.Row, target *postgresDumpSource) error {
	return row.Scan(&target.database, &target.username, &target.databaseID, &target.roleID, &target.pid, &target.address, &target.port)
}

// Every observation is its OWN committed READ COMMITTED transaction. Thus
// pg_stat_activity is never read through the exporting RR snapshot or a stale
// transaction statistics snapshot. SET LOCAL prevents pool-setting pollution.
func (s *postgresDumpSession) withControlTransaction(ctx context.Context, limit time.Duration, query func(context.Context, *sql.Tx) error) (result error) {
	queryCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	tx, err := s.control.BeginTx(queryCtx, &sql.TxOptions{Isolation: sql.LevelReadCommitted, ReadOnly: true})
	if err != nil {
		return postgresDumpControlFailed("begin", queryCtx, err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			result = postgresDumpControlFailed("rollback", queryCtx, err)
		}
	}()
	deadline, _ := queryCtx.Deadline()
	budget := strconv.FormatInt(max(int64(1), time.Until(deadline).Milliseconds()), 10)
	if _, err := tx.ExecContext(queryCtx, `SELECT pg_catalog.set_config('statement_timeout',$1,true), pg_catalog.set_config('lock_timeout',$1,true)`, budget); err != nil {
		return postgresDumpControlFailed("local_bounds", queryCtx, err)
	}
	if err := query(queryCtx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return postgresDumpControlFailed("commit", queryCtx, err)
	}
	return nil
}

func (s *postgresDumpSession) observe(ctx context.Context) (exists bool, result error) {
	var observed *postgresDumpBackend
	var pending bool
	var count int
	result = s.withControlTransaction(ctx, postgresDumpQueryLimit, func(queryCtx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(queryCtx, `SELECT pid,backend_start,datid::bigint,usesysid::bigint,datname,usename,backend_type
FROM pg_catalog.pg_stat_activity WHERE application_name=$1 ORDER BY pid LIMIT 2`, s.name)
		if err != nil {
			return postgresDumpControlFailed("observe_query", queryCtx, err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var activity postgresDumpActivity
			if err := rows.Scan(&activity.pid, &activity.startedAt, &activity.databaseID, &activity.roleID, &activity.database, &activity.username, &activity.kind); err != nil {
				return postgresDumpControlFailed("observe_scan", queryCtx, err)
			}
			count++
			if count > 1 || s.ended || (s.bound != nil && s.bound.pid != activity.pid) {
				return errPostgresDumpIdentity
			}
			var identifyErr error
			observed, identifyErr = activity.identify(s.source)
			if identifyErr != nil {
				return identifyErr
			}
			pending = observed == nil
		}
		if err := rows.Err(); err != nil {
			return postgresDumpControlFailed("observe_rows", queryCtx, err)
		}
		if err := rows.Close(); err != nil {
			return postgresDumpControlFailed("observe_close", queryCtx, err)
		}
		return nil
	})
	if result != nil {
		return false, result
	}
	s.pending = pending
	if pending {
		return true, nil
	}
	if observed == nil {
		if s.bound != nil {
			s.ended = true
		}
		return false, nil
	}
	if s.ended || (s.bound != nil && (s.bound.pid != observed.pid || !s.bound.startedAt.Equal(observed.startedAt))) {
		return false, errPostgresDumpIdentity
	}
	s.bound = observed
	return true, nil
}

type postgresDumpOutcome struct {
	receipt pgbackup.DumpReceipt
	err     error
}

func (s *postgresDumpSession) run(ctx context.Context, execute func(context.Context, string) (pgbackup.DumpReceipt, error)) (pgbackup.DumpReceipt, error) {
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan postgresDumpOutcome, 1)
	go func() {
		receipt, err := execute(runCtx, s.name)
		done <- postgresDumpOutcome{receipt, err}
	}()
	ticker := time.NewTicker(postgresDumpPollInterval)
	defer ticker.Stop()
	for {
		select {
		case outcome := <-done:
			return s.finish(ctx, outcome)
		case <-ctx.Done():
			stop() // Local process-tree cleanup runs concurrently with DB cleanup.
			cleanupErr := s.cleanup(false)
			<-done // Native contract: never return while our local child is alive.
			if cleanupErr != nil {
				return pgbackup.DumpReceipt{}, cleanupErr
			}
			return pgbackup.DumpReceipt{}, pgbackup.ErrCanceled
		case <-ticker.C:
			// Do not tie the dedicated control channel to caller cancellation:
			// canceling a pgx query can discard the only cleanup connection.
			if _, err := s.observe(context.Background()); err != nil {
				stop()
				var controlErr postgresDumpControlFailure
				if s.bound != nil && errors.As(err, &controlErr) && controlErr.recoverable {
					cleanupErr := s.cleanup(false)
					<-done
					if cleanupErr != nil {
						return pgbackup.DumpReceipt{}, cleanupErr
					}
					if ctx.Err() != nil {
						return pgbackup.DumpReceipt{}, pgbackup.ErrCanceled
					}
					return pgbackup.DumpReceipt{}, ErrUnavailable
				}
				// A conflicting identity cannot be safely repaired by selecting
				// one of its sessions. Fail closed, never issue a broad signal.
				<-done
				return pgbackup.DumpReceipt{}, err
			}
		}
	}
}

func (s *postgresDumpSession) finish(ctx context.Context, outcome postgresDumpOutcome) (pgbackup.DumpReceipt, error) {
	// These errors are pgbackup's explicit pre-launch exits. They do not
	// establish an observed-and-cleaned backend, and do not need one.
	prelaunch := s.bound == nil && (errors.Is(outcome.err, pgbackup.ErrConfiguration) || errors.Is(outcome.err, pgbackup.ErrVersion))
	if prelaunch {
		exists, err := s.observe(context.Background())
		if err != nil {
			return pgbackup.DumpReceipt{}, err
		}
		if exists {
			return pgbackup.DumpReceipt{}, errPostgresDumpIdentity
		}
		return pgbackup.DumpReceipt{}, outcome.err
	}
	// A successful real native exit proves the child completed its protocol
	// work; a fresh empty observation can confirm a short-lived success even
	// if polling missed the session. A canceled/failed launch cannot do that.
	if err := s.cleanup(outcome.err == nil && ctx.Err() == nil); err != nil {
		return pgbackup.DumpReceipt{}, err
	}
	if ctx.Err() != nil {
		return pgbackup.DumpReceipt{}, pgbackup.ErrCanceled
	}
	if outcome.err != nil {
		return pgbackup.DumpReceipt{}, outcome.err
	}
	if s.recoveryAttempted {
		return pgbackup.DumpReceipt{}, ErrUnavailable
	}
	return outcome.receipt, nil
}

func (s *postgresDumpSession) cleanup(successfulExit bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), postgresDumpCleanupLimit)
	defer cancel()
	ticker := time.NewTicker(postgresDumpPollInterval)
	defer ticker.Stop()
	for {
		exists, err := s.observe(ctx)
		if err != nil {
			if ctx.Err() != nil && s.bound == nil {
				return errPostgresDumpUnseen
			}
			if s.canRecoverControl(err) {
				if err := s.recoverControl(ctx); err != nil {
					return err
				}
				continue
			}
			return err
		}
		if !exists {
			if s.bound != nil || successfulExit {
				return nil
			}
			// Cancellation during startup can race visibility in pg_stat_activity.
			// Keep looking with our independent finite budget; zero rows alone
			// must not be reported as a positively observed backend cleanup.
		} else if !s.pending {
			if err := s.terminate(ctx); err != nil {
				if s.canRecoverControl(err) {
					if err := s.recoverControl(ctx); err != nil {
						return err
					}
					continue
				}
				return err
			}
		}
		select {
		case <-ctx.Done():
			if s.bound == nil {
				return errPostgresDumpUnseen
			}
			return errPostgresDumpCleanup
		case <-ticker.C:
		}
	}
}

func (s *postgresDumpSession) canRecoverControl(err error) bool {
	var failure postgresDumpControlFailure
	return s.bound != nil && s.pool != nil && !s.recoveryAttempted && errors.As(err, &failure) && failure.recoverable
}

func (s *postgresDumpSession) recoverControl(ctx context.Context) error {
	s.recoveryAttempted = true
	// Recovery is only for cleaning the already bound operation. It shares
	// the ORIGINAL 1500 ms cleanup deadline; it never restarts a dump, widens
	// identity matching, retries a permission/identity error or obtains a DSN.
	_ = s.control.Close()
	acquireCtx, cancel := context.WithTimeout(ctx, postgresDumpQueryLimit)
	defer cancel()
	control, err := s.pool.Conn(acquireCtx)
	if err != nil {
		return errPostgresDumpCleanup
	}
	s.control = control
	return s.checkControlIdentity(ctx)
}

func (s *postgresDumpSession) terminate(ctx context.Context) error {
	if s.bound == nil || s.ended || s.pending {
		return errPostgresDumpIdentity
	}
	return s.withControlTransaction(ctx, postgresDumpSignalLimit, func(queryCtx context.Context, tx *sql.Tx) error {
		// Revalidate the complete bound identity in this fresh transaction,
		// immediately before signaling. PostgreSQL's signal API ultimately
		// uses a PID and retains its documented extremely narrow reuse race;
		// this is not represented as a zero-race OS capability handle.
		var terminated bool
		err := tx.QueryRowContext(queryCtx, `SELECT pg_catalog.pg_terminate_backend(pid,$8)
FROM pg_catalog.pg_stat_activity WHERE application_name=$1 AND pid=$2 AND backend_start=$3
AND datid=$4 AND usesysid=$5 AND datname=$6 AND usename=$7 AND backend_type='client backend'`,
			s.name, s.bound.pid, s.bound.startedAt, s.source.databaseID, s.source.roleID, s.source.database, s.source.username, postgresDumpSignalWait).Scan(&terminated)
		if errors.Is(err, sql.ErrNoRows) {
			return nil // The following fresh observation must confirm absence.
		}
		if err != nil {
			return postgresDumpControlFailed("terminate", queryCtx, err)
		}
		if !terminated {
			return errPostgresDumpCleanup
		}
		return nil
	})
}
