//go:build pgbackup_integration

package repository

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/pgbackup"
)

// Administrator credentials are used only to create/drop this test's new
// isolated role/database and the negative ACL fixture. Every production method
// below receives a Store authenticated as a non-superuser without role grants.
type postgresDumpSessionFixture struct {
	*postgresDumpFixture
	store, administrator *Store
	config               Config
	connection           pgbackup.Connection
}

func newPostgresDumpSessionFixture(t *testing.T) *postgresDumpSessionFixture {
	t.Helper()
	f := newPostgresDumpFixture(t) // Explicit tag: real 18.6/tool dependencies, no skip.
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal("generate synthetic database role identity")
	}
	name := "mii_dump_role_" + hex.EncodeToString(entropy[:])
	password := "synthetic_" + hex.EncodeToString(entropy[:])
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	// Both interpolated values contain only a fixed prefix and generated hex;
	// no real credential/user SQL is interpolated or printed. Role privileges
	// are explicitly restricted; this is setup, never a production elevation.
	if _, err := f.control.ExecContext(ctx, `CREATE ROLE "`+name+`" LOGIN PASSWORD '`+password+`' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal("create uniquely owned restricted dump test role")
	}
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := f.control.ExecContext(cleanupCtx, `DROP ROLE "`+name+`"`); err != nil {
			t.Error("drop uniquely owned restricted dump test role")
		}
	})
	cfg, c := f.createDatabase(t, "src")
	administrator := postgresDumpOpenTestStore(t, cfg)
	if _, err := administrator.sql.ExecContext(ctx, `GRANT USAGE, CREATE ON SCHEMA public TO "`+name+`"`); err != nil {
		t.Fatal("grant fixture schema access in the newly owned database")
	}
	parsed, err := url.Parse(cfg.DSN)
	if err != nil {
		t.Fatal("parse synthetic test database connection")
	}
	parsed.User = url.UserPassword(name, password)
	cfg.DSN = parsed.String()
	c.Username, c.Password = name, password
	s := postgresDumpOpenTestStore(t, cfg)
	var restricted bool
	if err := s.sql.QueryRowContext(ctx, `SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls
AND NOT pg_catalog.pg_has_role(current_user,'pg_signal_backend','MEMBER') FROM pg_catalog.pg_roles WHERE rolname=current_user`).Scan(&restricted); err != nil || !restricted {
		t.Fatal("dump cleanup fixture accidentally has elevated role privileges")
	}
	return &postgresDumpSessionFixture{f, s, administrator, cfg, c}
}

type postgresDumpSessionRunning struct {
	done                chan struct{}
	cancel              context.CancelFunc
	receipt             pgbackup.DumpReceipt
	operation, snapshot error
}

func (f *postgresDumpSessionFixture) startDump(t *testing.T, parent context.Context) *postgresDumpSessionRunning {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	running := &postgresDumpSessionRunning{done: make(chan struct{}), cancel: cancel}
	go func() {
		defer close(running.done)
		running.snapshot = f.store.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
			running.receipt, running.operation = f.store.dumpPostgresSnapshot(ctx, view, f.dump, f.connection,
				pgbackup.DumpRequest{WholeDatabase: true, MaxBytes: 1 << 20}, io.Discard)
			return running.operation
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-running.done:
		case <-time.After(3 * time.Second):
			t.Error("test-owned dump did not join after cleanup cancellation")
		}
	})
	return running
}

func (f *postgresDumpSessionFixture) waitLockedDump(t *testing.T, ctx context.Context, excluded string, running *postgresDumpSessionRunning) string {
	t.Helper()
	observeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-running.done:
			t.Fatalf("dump ended before actual lock wait: operation=%v snapshot=%v", running.operation, running.snapshot)
		default:
		}
		var name string
		err := f.store.sql.QueryRowContext(observeCtx, `SELECT application_name FROM pg_catalog.pg_stat_activity
WHERE datname=$1 AND usename=$2 AND backend_type='client backend' AND application_name ~ '^mii-backup-[0-9a-f]{32}$'
AND application_name<>$3 AND wait_event_type='Lock' LIMIT 1`, f.connection.Database, f.connection.Username, excluded).Scan(&name)
		if err == nil {
			return name
		}
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatal("observe actual restricted-role dump lock wait")
		}
		select {
		case <-observeCtx.Done():
			t.Fatal("actual restricted-role dump did not reach server lock wait")
		case <-ticker.C:
		}
	}
}

func requirePostgresDumpSessionCanceled(t *testing.T, running *postgresDumpSessionRunning) {
	t.Helper()
	started := time.Now()
	running.cancel()
	select {
	case <-running.done:
		if time.Since(started) > 2*time.Second || !errors.Is(running.operation, pgbackup.ErrCanceled) || running.receipt != (pgbackup.DumpReceipt{}) || running.snapshot == nil {
			t.Fatalf("actual dump cancellation did not join server/local cleanup with a closed cancellation and zero receipt: %v", running.operation)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("actual dump cancellation exceeded unchanged two-second bound")
	}
}

func TestPostgresDumpSessionActualCancellationIsolation(t *testing.T) {
	f := newPostgresDumpSessionFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if _, err := f.store.sql.ExecContext(ctx, "CREATE TABLE public.mii_dump_session_lock(id integer PRIMARY KEY)"); err != nil {
		t.Fatal("create own actual cancellation lock fixture")
	}
	lock, err := f.store.sql.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("open own relation-lock transaction")
	}
	defer func() { _ = lock.Rollback() }()
	if _, err := lock.ExecContext(ctx, "LOCK TABLE public.mii_dump_session_lock IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal("hold exclusive lock across cancellation assertions")
	}
	side, err := f.store.sql.Conn(ctx)
	if err != nil {
		t.Fatal("open unrelated same-role session")
	}
	defer func() { _ = side.Close() }()
	if _, err := side.ExecContext(ctx, "SET application_name='mii-backup'"); err != nil {
		t.Fatal("set deliberately non-unique unrelated application name")
	}
	var sidePID int
	if err := side.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&sidePID); err != nil {
		t.Fatal("observe unrelated same-role backend")
	}
	first := f.startDump(t, ctx)
	firstName := f.waitLockedDump(t, ctx, "", first)
	second := f.startDump(t, ctx)
	secondName := f.waitLockedDump(t, ctx, firstName, second)
	if firstName == secondName {
		t.Fatal("concurrent dumps reused their operation nonce")
	}
	requirePostgresDumpSessionCanceled(t, first)
	var firstExists, secondLocked bool
	if err := f.store.sql.QueryRowContext(ctx, `SELECT
EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE application_name=$1),
EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE application_name=$2 AND wait_event_type='Lock')`, firstName, secondName).Scan(&firstExists, &secondLocked); err != nil || firstExists || !secondLocked {
		t.Fatal("canceling one dump retained its session or interrupted the other nonce")
	}
	var actualPID int
	if err := side.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&actualPID); err != nil || actualPID != sidePID {
		t.Fatal("cleanup terminated the unrelated constant-name same-role session")
	}
	requirePostgresDumpSessionCanceled(t, second)
	if err := f.store.sql.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE application_name=$1 OR application_name=$2)", firstName, secondName).Scan(&firstExists); err != nil || firstExists {
		t.Fatal("actual canceled dump session/transaction survived after local exit")
	}
	// Only now may the fixture release the still-held exclusive relation lock.
}

func TestPostgresDumpSessionActualSuccessAndSourceIdentity(t *testing.T) {
	f := newPostgresDumpSessionFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	if _, err := f.store.sql.ExecContext(ctx, "CREATE TABLE public.mii_dump_session_success(id integer PRIMARY KEY)"); err != nil {
		t.Fatal("create own actual dump success fixture")
	}
	var receipt pgbackup.DumpReceipt
	err := f.store.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
		var err error
		receipt, err = f.store.dumpPostgresSnapshot(ctx, view, f.dump, f.connection,
			pgbackup.DumpRequest{WholeDatabase: true, MaxBytes: 1 << 20}, io.Discard)
		return err
	})
	if err != nil || receipt.Bytes <= 5 || receipt.ToolVersion != "18.6" || len(receipt.SHA256) != 64 {
		t.Fatalf("actual restricted-role dump did not finish snapshot/server/native lifecycle: %v", err)
	}
	for _, mode := range []string{"database", "role", "foreign_store", "caller_nonce", "wrong_snapshot"} {
		t.Run(mode, func(t *testing.T) {
			c, store := f.connection, f.store
			r := pgbackup.DumpRequest{WholeDatabase: true, MaxBytes: 1 << 20}
			want := errPostgresDumpIdentity
			switch mode {
			case "database":
				c.Database = "mismatch_private_database_canary"
			case "role":
				c.Username = "mismatch_private_role_canary"
			case "foreign_store":
				store = f.administrator
			case "caller_nonce":
				r.ApplicationName, want = "mii-backup-"+strings.Repeat("a", 32), ErrConfiguration
			case "wrong_snapshot":
				r.Snapshot, want = "A-B-C", ErrConfiguration
			}
			var operation error
			err := f.store.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
				receipt, operation = store.dumpPostgresSnapshot(ctx, view, f.dump, c, r, io.Discard)
				return operation
			})
			if err == nil || !errors.Is(operation, want) || receipt != (pgbackup.DumpReceipt{}) || strings.Contains(fmt.Sprint(operation), "canary") {
				t.Fatalf("mismatched source identity escaped closed preflight rejection: %v", operation)
			}
		})
	}
}

func TestPostgresDumpSessionSwallowedPreflightFailureIsSticky(t *testing.T) {
	f := newPostgresDumpSessionFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	for _, mode := range []string{"caller_nonce", "precanceled_child", "unbounded_child", "nil_source"} {
		t.Run(mode, func(t *testing.T) {
			childCtx, stop := context.WithCancel(ctx)
			defer stop()
			store := f.store
			request := pgbackup.DumpRequest{WholeDatabase: true, MaxBytes: 1 << 20}
			want := ErrConfiguration
			switch mode {
			case "caller_nonce":
				request.ApplicationName = "mii-backup-" + strings.Repeat("a", 32)
			case "precanceled_child":
				stop()
				want = pgbackup.ErrCanceled
			case "unbounded_child":
				childCtx = context.Background()
			case "nil_source":
				store = nil
			}
			err := f.store.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
				receipt, operation := store.dumpPostgresSnapshot(childCtx, view, f.dump, f.connection, request, io.Discard)
				if !errors.Is(operation, want) || receipt != (pgbackup.DumpReceipt{}) {
					t.Fatalf("preflight failed without its closed cause and zero receipt: %v", operation)
				}
				called := false
				if err := view.use(func(*gorm.DB, string, postgresSnapshotMetadata) error { called = true; return nil }); !errors.Is(err, want) || called {
					t.Fatal("swallowed preflight error allowed further snapshot consumption")
				}
				return nil // Deliberately swallow; the active snapshot must remain poisoned.
			})
			if !errors.Is(err, want) {
				t.Fatalf("outer snapshot accepted swallowed preflight failure: %v", err)
			}
		})
	}
}

// A real dedicated connection, but a synthetic executor result where noted:
// these cases exercise lifecycle classification, NOT evidence of pg_dump output.
func (f *postgresDumpSessionFixture) withSession(t *testing.T, check func(context.Context, *postgresDumpSession)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	err := f.store.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
		return view.use(func(tx *gorm.DB, _ string, _ postgresSnapshotMetadata) error {
			session, err := f.store.openPostgresDumpSession(ctx, tx, f.connection)
			if err != nil {
				t.Fatal("open actual restricted-role session controller")
			}
			defer func() { _ = session.control.Close() }()
			check(ctx, session)
			return nil
		})
	})
	if err != nil {
		t.Fatalf("close controlled test snapshot: %v", err)
	}
}

func (f *postgresDumpSessionFixture) namedConnection(t *testing.T, ctx context.Context, name string) (*sql.Conn, func()) {
	t.Helper()
	// A separate test-only pool makes Close end this actual physical session.
	// Production uses only Store.sql.Conn and never rebuilds DSNs/TLS settings.
	pool, err := sql.Open("pgx", f.config.DSN)
	if err != nil {
		t.Fatal("open private synthetic named-session pool")
	}
	conn, err := pool.Conn(ctx)
	if err != nil {
		_ = pool.Close()
		t.Fatal("open private synthetic named session")
	}
	closeSession := func() { _ = conn.Close(); _ = pool.Close() }
	t.Cleanup(closeSession)
	if _, err := conn.ExecContext(ctx, "SELECT pg_catalog.set_config('application_name',$1,false)", name); err != nil {
		t.Fatal("set synthetic operation identity")
	}
	return conn, closeSession
}

func TestPostgresDumpSessionLifecycleClassification(t *testing.T) {
	f := newPostgresDumpSessionFixture(t)
	for _, mode := range []string{"prelaunch", "short_success", "cancel_unobserved", "observed_exit", "control_closed"} {
		t.Run(mode, func(t *testing.T) {
			f.withSession(t, func(ctx context.Context, session *postgresDumpSession) {
				fakeReceipt := pgbackup.DumpReceipt{Bytes: 6, SHA256: strings.Repeat("a", 64), ToolVersion: "18.6"}
				var want error
				runCtx, cancel := context.WithCancel(ctx)
				defer cancel()
				execute := func(context.Context, string) (pgbackup.DumpReceipt, error) { return fakeReceipt, nil }
				switch mode {
				case "prelaunch":
					want = pgbackup.ErrConfiguration
					execute = func(context.Context, string) (pgbackup.DumpReceipt, error) { return pgbackup.DumpReceipt{}, want }
				case "cancel_unobserved":
					want = errPostgresDumpUnseen
					execute = func(context.Context, string) (pgbackup.DumpReceipt, error) {
						cancel()
						return pgbackup.DumpReceipt{}, pgbackup.ErrCanceled
					}
				case "observed_exit":
					_, closeSession := f.namedConnection(t, ctx, session.name)
					if exists, err := session.observe(ctx); err != nil || !exists {
						t.Fatal("bind actual transient test backend")
					}
					closeSession()
				case "control_closed":
					want = errPostgresDumpCleanup
					if err := session.control.Close(); err != nil {
						t.Fatal("close owned control channel fault fixture")
					}
				}
				got, err := session.run(runCtx, execute)
				if !errors.Is(err, want) || (want != nil && got != (pgbackup.DumpReceipt{})) || (want == nil && got != fakeReceipt) {
					t.Fatalf("session lifecycle classification/receipt mismatch: %v", err)
				}
				if (mode == "short_success" || mode == "prelaunch" || mode == "cancel_unobserved") && (session.bound != nil || session.ended) {
					t.Fatal("unobserved state was mislabeled as an observed cleanup")
				}
			})
		})
	}
}

func TestPostgresDumpSessionPendingIdentity(t *testing.T) {
	source := postgresDumpSource{database: "fixture", username: "fixture_role", databaseID: 10, roleID: 20, pid: 1}
	complete := postgresDumpActivity{pid: 2, startedAt: sql.NullTime{Time: time.Unix(1700000000, 0), Valid: true},
		databaseID: sql.NullInt64{Int64: 10, Valid: true}, roleID: sql.NullInt64{Int64: 20, Valid: true},
		database: sql.NullString{String: "fixture", Valid: true}, username: sql.NullString{String: "fixture_role", Valid: true},
		kind: sql.NullString{String: "client backend", Valid: true}}
	for _, mode := range []string{"complete", "starting", "hidden_start", "missing_database", "other_role", "other_kind", "self_pid"} {
		t.Run(mode, func(t *testing.T) {
			activity := complete
			pending, rejected := false, false
			switch mode {
			case "starting":
				activity, pending = postgresDumpActivity{pid: 2}, true
			case "hidden_start":
				activity.startedAt.Valid, pending = false, true
			case "missing_database":
				activity.databaseID.Valid, activity.database.Valid, pending = false, false, true
			case "other_role":
				activity.roleID.Int64, rejected = 99, true
			case "other_kind":
				activity.kind.String, rejected = "parallel worker", true
			case "self_pid":
				activity.pid, rejected = source.pid, true
			}
			bound, err := activity.identify(source)
			if rejected {
				if !errors.Is(err, errPostgresDumpIdentity) || bound != nil {
					t.Fatal("conflicting known identity was treated as pending/authorized")
				}
			} else if err != nil || (bound == nil) != pending {
				t.Fatal("incomplete startup identity did not stay explicitly unbound")
			}
		})
	}
	closed := postgresDumpControlFailed("observe_scan", context.Background(), errors.New("private-database-error-canary"))
	if !errors.Is(closed, errPostgresDumpCleanup) || strings.Contains(closed.Error(), "canary") {
		t.Fatal("closed phase diagnostic retained the driver error")
	}
}

func TestPostgresDumpSessionControlFailureClassification(t *testing.T) {
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	for _, tc := range []struct {
		name        string
		ctx         context.Context
		err         error
		recoverable bool
	}{
		{"permission_after_deadline", expired, &pgconn.PgError{Code: "42501", Message: "private-driver-canary"}, false},
		{"sql_timeout_after_deadline", expired, &pgconn.PgError{Code: "57014", Message: "private-driver-canary"}, false},
		{"connection_state", expired, &pgconn.PgError{Code: "08006", Message: "private-driver-canary"}, true},
		{"closed_control", context.Background(), sql.ErrConnDone, true},
		{"network", context.Background(), &net.OpError{Op: "read", Net: "tcp", Err: errors.New("private-driver-canary")}, true},
		{"local_deadline", expired, context.DeadlineExceeded, true},
		{"unknown", context.Background(), errors.New("private-driver-canary"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := postgresDumpControlFailed("observe_query", tc.ctx, tc.err)
			var closed postgresDumpControlFailure
			if !errors.As(err, &closed) || !errors.Is(err, errPostgresDumpCleanup) || closed.recoverable != tc.recoverable || strings.Contains(err.Error(), "canary") {
				t.Fatal("control failure confused recovery authority or exposed driver data")
			}
		})
	}
}

func TestPostgresDumpSessionDuplicateAndReusedIdentity(t *testing.T) {
	f := newPostgresDumpSessionFixture(t)
	for _, mode := range []string{"duplicate", "changed_backend"} {
		t.Run(mode, func(t *testing.T) {
			f.withSession(t, func(ctx context.Context, session *postgresDumpSession) {
				_, closeFirst := f.namedConnection(t, ctx, session.name)
				if exists, err := session.observe(ctx); err != nil || !exists {
					t.Fatal("bind actual first test session")
				}
				if mode == "changed_backend" {
					closeFirst()
				}
				second, _ := f.namedConnection(t, ctx, session.name)
				if _, err := session.observe(ctx); !errors.Is(err, errPostgresDumpIdentity) {
					t.Fatal("ambiguous/reused nonce adopted a different session")
				}
				var one int
				if err := second.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
					t.Fatal("identity rejection signaled the unrelated replacement session")
				}
			})
		})
	}
}

func TestPostgresDumpSessionPermissionFailureClosesReceipt(t *testing.T) {
	f := newPostgresDumpSessionFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	// Function ACLs are per database. Only this freshly created disposable DB
	// is modified; neither the configured control DB nor a cluster role grant
	// changes. The restricted role is never granted pg_signal_backend.
	if _, err := f.administrator.sql.ExecContext(ctx, "REVOKE EXECUTE ON FUNCTION pg_catalog.pg_terminate_backend(integer,bigint) FROM PUBLIC"); err != nil {
		t.Fatal("create newly owned database's termination-permission negative fixture")
	}
	f.withSession(t, func(ctx context.Context, session *postgresDumpSession) {
		side, _ := f.namedConnection(t, ctx, session.name)
		if exists, err := session.observe(ctx); err != nil || !exists {
			t.Fatal("bind actual same-role permission-negative backend")
		}
		receipt, err := session.run(ctx, func(context.Context, string) (pgbackup.DumpReceipt, error) {
			return pgbackup.DumpReceipt{Bytes: 6, ToolVersion: "18.6"}, pgbackup.ErrProcess
		})
		if !errors.Is(err, errPostgresDumpCleanup) || receipt != (pgbackup.DumpReceipt{}) || session.recoveryAttempted {
			t.Fatalf("permission failure did not return closed cleanup failure and zero receipt: %v", err)
		}
		var one int
		if err := side.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
			t.Fatal("permission-negative fixture unexpectedly terminated its session")
		}
	})
}

func TestPostgresDumpSessionControlRecoveryRefusesUnavailableOrForeignPool(t *testing.T) {
	f := newPostgresDumpSessionFixture(t)
	for _, mode := range []string{"closed_pool", "foreign_role"} {
		t.Run(mode, func(t *testing.T) {
			f.withSession(t, func(ctx context.Context, session *postgresDumpSession) {
				side, _ := f.namedConnection(t, ctx, session.name)
				if exists, err := session.observe(ctx); err != nil || !exists || session.bound == nil {
					t.Fatal("bind real backend for cleanup recovery rejection")
				}
				if err := session.control.Close(); err != nil {
					t.Fatal("inject control failure after binding real backend")
				}
				want := errPostgresDumpIdentity
				if mode == "closed_pool" {
					// This test-only unopened pool is deliberately closed. No new
					// connection/DSN is used by the production recovery function.
					closedPool, err := sql.Open("pgx", f.config.DSN)
					if err != nil {
						t.Fatal("create closed recovery-pool fixture")
					}
					if err := closedPool.Close(); err != nil {
						t.Fatal("close recovery-pool fixture")
					}
					session.pool, want = closedPool, errPostgresDumpCleanup
				} else {
					session.pool = f.administrator.sql
				}
				// Synthetic executor outcome, real server/control connections.
				receipt, err := session.run(ctx, func(context.Context, string) (pgbackup.DumpReceipt, error) {
					return pgbackup.DumpReceipt{Bytes: 6}, pgbackup.ErrProcess
				})
				if !errors.Is(err, want) || receipt != (pgbackup.DumpReceipt{}) || !session.recoveryAttempted {
					t.Fatalf("unavailable/foreign recovery pool did not fail closed: %v", err)
				}
				if session.canRecoverControl(postgresDumpControlFailed("begin", ctx, sql.ErrConnDone)) {
					t.Fatal("recovery permitted a second attempt")
				}
				var one int
				if err := side.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
					t.Fatal("failed source revalidation signaled a target backend")
				}
			})
		})
	}
}

func TestPostgresDumpSessionRecoversControlForActualLockCleanup(t *testing.T) {
	f := newPostgresDumpSessionFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	if _, err := f.store.sql.ExecContext(ctx, "CREATE TABLE public.mii_dump_control_fault(id integer PRIMARY KEY)"); err != nil {
		t.Fatal("create test-owned control failure lock fixture")
	}
	lock, err := f.store.sql.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("open control failure's exclusive-lock transaction")
	}
	defer func() { _ = lock.Rollback() }()
	if _, err := lock.ExecContext(ctx, "LOCK TABLE public.mii_dump_control_fault IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal("hold actual relation lock across control failure cleanup")
	}
	otherName := "mii-backup-" + strings.Repeat("f", 32)
	other, _ := f.namedConnection(t, ctx, otherName)
	var otherPID int
	if err := other.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&otherPID); err != nil {
		t.Fatal("observe unrelated nonce's real backend identity")
	}
	err = f.store.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
		return view.use(func(tx *gorm.DB, id string, _ postgresSnapshotMetadata) error {
			session, err := f.store.openPostgresDumpSession(ctx, tx, f.connection)
			if err != nil {
				t.Fatal("open real restricted-role controller for control failure")
			}
			defer func() { _ = session.control.Close() }()
			childCtx, childCancel := context.WithCancel(ctx)
			defer childCancel()
			running := &postgresDumpSessionRunning{done: make(chan struct{}), cancel: childCancel}
			go func() {
				defer close(running.done)
				running.receipt, running.operation = pgbackup.Dump(childCtx, f.dump, f.connection,
					pgbackup.DumpRequest{Snapshot: id, ApplicationName: session.name, WholeDatabase: true, MaxBytes: 1 << 20}, io.Discard)
			}()
			defer func() {
				childCancel()
				select {
				case <-running.done:
				case <-time.After(2 * time.Second):
					t.Error("actual fault-fixture child failed to join")
				}
			}()
			if name := f.waitLockedDump(t, ctx, otherName, running); name != session.name {
				t.Fatal("control fault fixture did not observe its own dump")
			}
			if exists, err := session.observe(ctx); err != nil || !exists || session.bound == nil || session.pending {
				t.Fatal("control fault fixture lacks a fully bound actual lock-wait backend")
			}
			// Close only AFTER binding the real server lock wait. run's executor
			// below joins that already-running real child; it is not a fake dump.
			started := time.Now()
			if err := session.control.Close(); err != nil {
				t.Fatal("inject closed control channel after actual backend binding")
			}
			receipt, operation := session.run(ctx, func(runCtx context.Context, _ string) (pgbackup.DumpReceipt, error) {
				stopRelay := context.AfterFunc(runCtx, childCancel)
				defer stopRelay()
				<-running.done
				return running.receipt, running.operation
			})
			if !errors.Is(operation, ErrUnavailable) || receipt != (pgbackup.DumpReceipt{}) || !session.recoveryAttempted || time.Since(started) > 2*time.Second {
				t.Fatalf("bound actual control failure did not abort with same-pool bounded recovery: %v", operation)
			}
			var exists bool
			if err := f.store.sql.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE application_name=$1)", session.name).Scan(&exists); err != nil || exists {
				t.Fatal("recovered controller left its actual server lock/transaction alive")
			}
			var actualPID int
			if err := other.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&actualPID); err != nil || actualPID != otherPID {
				t.Fatal("control recovery signaled the unrelated nonce")
			}
			return operation
		})
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("control failure's outer snapshot did not fail closed: %v", err)
	}
	// The exclusive lock is released only after all server-cleanup assertions.
}
