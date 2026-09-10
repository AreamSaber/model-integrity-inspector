package worker

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const replacePrecheckLeaseSQL = "UPDATE integrity_jobs SET lease_owner = $1, attempt_count = attempt_count + 1, lease_until = $2 WHERE organization_id = $3 AND id = $4"

// A driver error may include SQL, DSN or protected values. Keep only bounded
// numeric SQLite codes and the five-character SQLSTATE alphabet, never Error().
func precheckFixtureDriverCodes(err error) (int, string) {
	code, state := 0, "none"
	var sqliteCode interface{ Code() int }
	if errors.As(err, &sqliteCode) && sqliteCode.Code() >= 0 && sqliteCode.Code() <= 65535 {
		code = sqliteCode.Code()
	}
	var pgState interface{ SQLState() string }
	if errors.As(err, &pgState) {
		value := pgState.SQLState()
		if len(value) == 5 && strings.IndexFunc(value, func(r rune) bool { return (r < 'A' || r > 'Z') && (r < '0' || r > '9') }) < 0 {
			state = value
		}
	}
	return code, state
}

func precheckFixtureDiagnostic(phase string, err error, elapsed time.Duration, ctx context.Context, ready bool, affected int64) string {
	code, state := precheckFixtureDriverCodes(err)
	return fmt.Sprintf("phase=%s sqlite_code=%d sql_state=%s elapsed_ms=%d context_cancelled=%t ready=%t rows=%d", phase, code, state, elapsed.Milliseconds(), ctx.Err() != nil, ready, affected)
}

// Report only closed fixture phases, bounded driver codes and timing, never
// driver error text/SQL/DSNs. The old message hid whether connection setup,
// lock contention or a missing row prevented the intended fencing injection.
func replacePrecheckLeaseForTest(t *testing.T, f workerFixture, runner *Runner, jobID int64) time.Time {
	t.Helper()
	started := time.Now()
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	fail := func(phase string, err error, affected int64) {
		t.Helper()
		t.Fatal("lease replacement fixture failed: " + precheckFixtureDiagnostic(phase, err, time.Since(started), ctx, runner.Ready(), affected))
	}
	conn, err := f.db.Conn(ctx)
	if err != nil {
		fail("connect", err, -1)
	}
	defer func() { _ = conn.Close() }()
	var replacedAt time.Time
	// This test injects lease loss, not consumer-heartbeat write contention.
	// Briefly exclude the unrelated 30ms consumer pulse while the independent
	// connection changes and verifies the real persisted lease. This does not
	// exclude execute's Renew writer, grant authority or retry a rejected write.
	// The controlled BUSY regression below still uses two independent SQL
	// connections. The original CI omitted its driver code, so its unique cause
	// remains unknown.
	if err := runner.withQueueGate(ctx, func() error {
		result, err := conn.ExecContext(ctx, replacePrecheckLeaseSQL, "replacement-owner", time.Now().UTC().Add(time.Minute), f.orgID, jobID)
		if err != nil {
			fail("update", err, -1)
		}
		// The existing HTTP stop deadline starts at the actual committed update,
		// including the readback below, rather than after fixture bookkeeping.
		replacedAt = time.Now()
		affected, err := result.RowsAffected()
		if err != nil || affected != 1 {
			fail("affected_rows", err, affected)
		}
		var status string
		var owner sql.NullString
		var generation int
		if err := conn.QueryRowContext(ctx, "SELECT status,lease_owner,attempt_count FROM integrity_jobs WHERE organization_id=$1 AND id=$2", f.orgID, jobID).Scan(&status, &owner, &generation); err != nil {
			fail("readback", err, affected)
		}
		if status != "running" || !owner.Valid || owner.String != "replacement-owner" || generation < 2 {
			fail("state", nil, affected)
		}
		return nil
	}); err != nil {
		fail("gate", err, -1)
	}
	return replacedAt
}

// An observer's bounded lock rejection is not proof that the production lease
// was replaced or that fencing failed. This uses the exact fixture UPDATE and
// a real independent database writer. Only the diagnostic observer's lock wait
// is shortened to 50ms; all Runner/HTTP business deadlines remain unchanged.
func TestPrecheckLeaseReplacementFixtureBusyIsNotLeaseLoss(t *testing.T) {
	eachWorkerDatabase(t, func(t *testing.T, f workerFixture) {
		started := make(chan struct{}, 1)
		config := tlsPrecheckConfig(t, f, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			started <- struct{}{}
			<-r.Context().Done()
		}))
		handler, err := NewPrecheckHandler(config)
		if err != nil {
			t.Fatal(err)
		}
		target := f.createTarget(t, "auto")
		queued, err := f.service.EnqueuePrecheck(f.ctx, f.orgID, target.ID, 1, "")
		if err != nil {
			t.Fatal(err)
		}
		runner, cancel, _ := startRunner(t, f, handler)
		defer cancel()
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("HTTP never started")
		}
		setupStarted := time.Now()
		fixtureCtx, stopFixture := context.WithTimeout(f.ctx, 2*time.Second)
		defer stopFixture()
		fail := func(phase string, err error, affected int64) {
			t.Helper()
			t.Fatal("lock rejection fixture failed: " + precheckFixtureDiagnostic(phase, err, time.Since(setupStarted), fixtureCtx, runner.Ready(), affected))
		}
		observer, err := f.db.Conn(fixtureCtx)
		if err != nil {
			fail("observer_connect", err, -1)
		}
		defer func() { _ = observer.Close() }()
		// sql.Conn reserves its physical connection. Holding both explicitly
		// prevents the blocker and observer from accidentally sharing one.
		blockerConnection, err := f.db.Conn(fixtureCtx)
		if err != nil {
			fail("blocker_connect", err, -1)
		}
		defer func() { _ = blockerConnection.Close() }()
		var oldOwner string
		var oldGeneration int
		if err := observer.QueryRowContext(fixtureCtx, "SELECT lease_owner,attempt_count FROM integrity_jobs WHERE organization_id=$1 AND id=$2", f.orgID, queued.JobID).Scan(&oldOwner, &oldGeneration); err != nil {
			fail("original_read", err, -1)
		}
		isSQLite := strings.HasSuffix(t.Name(), "/sqlite")
		setting := "SET lock_timeout = '50ms'"
		if isSQLite {
			setting = "PRAGMA busy_timeout=50"
		}
		if _, err := observer.ExecContext(fixtureCtx, setting); err != nil {
			fail("observer_lock_wait", err, -1)
		}
		defer func() {
			setting := "SET lock_timeout = '0'"
			if isSQLite {
				setting = "PRAGMA busy_timeout=5000"
			}
			resetCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
			defer stop()
			_, _ = observer.ExecContext(resetCtx, setting)
		}()
		var injectedErr error
		var elapsed time.Duration
		// The intended rejection is observer-versus-blocker, not setup-versus-
		// consumer. Keep only this short real lock segment behind the cancellable
		// gate, then release it before checking the lease/consumer. execute's Renew
		// is not gated: this neither suppresses every writer nor retries failures.
		// CI lacked a driver code for the previous blocker failure; don't infer
		// that its unique cause was proved by this controlled regression.
		if err := runner.withQueueGate(fixtureCtx, func() error {
			blocker, err := blockerConnection.BeginTx(fixtureCtx, nil)
			if err != nil {
				fail("blocker_begin", err, -1)
			}
			defer func() { _ = blocker.Rollback() }()
			locked, err := blocker.ExecContext(fixtureCtx, "UPDATE integrity_jobs SET updated_at=updated_at WHERE organization_id=$1 AND id=$2", f.orgID, queued.JobID)
			if err != nil {
				fail("blocker_update", err, -1)
			}
			affected, err := locked.RowsAffected()
			if err != nil || affected != 1 {
				fail("blocker_rows", err, affected)
			}
			begin := time.Now()
			_, injectedErr = observer.ExecContext(fixtureCtx, replacePrecheckLeaseSQL, "replacement-owner", time.Now().UTC().Add(time.Minute), f.orgID, queued.JobID)
			elapsed = time.Since(begin)
			// Roll back before releasing the gate, well within the unchanged
			// two-second production DB deadline. No busy retry is performed.
			if err := blocker.Rollback(); err != nil {
				fail("blocker_rollback", err, affected)
			}
			return nil
		}); err != nil {
			fail("gate", err, -1)
		}
		if injectedErr == nil || elapsed >= 2*time.Second {
			fail("observer_rejection", injectedErr, -1)
		}
		if isSQLite {
			var code interface{ Code() int }
			if !errors.As(injectedErr, &code) || code.Code()&255 != 5 {
				fail("observer_sqlite_code", injectedErr, -1)
			}
			t.Logf("expected fixture rejection: phase=update sqlite_code=%d elapsed_ms=%d", code.Code(), elapsed.Milliseconds())
		} else {
			var code interface{ SQLState() string }
			if !errors.As(injectedErr, &code) || code.SQLState() != "55P03" {
				fail("observer_postgres_code", injectedErr, -1)
			}
			t.Logf("expected fixture rejection: phase=update sql_state=55P03 elapsed_ms=%d", elapsed.Milliseconds())
		}
		var owner string
		var generation int
		if err := observer.QueryRowContext(fixtureCtx, "SELECT lease_owner,attempt_count FROM integrity_jobs WHERE organization_id=$1 AND id=$2", f.orgID, queued.JobID).Scan(&owner, &generation); err != nil {
			fail("original_readback", err, -1)
		}
		if owner != oldOwner || generation != oldGeneration || !runner.Ready() {
			fail("original_state", nil, -1)
		}
	})
}

type precheckFixtureUnsafeError struct {
	code  int
	state string
}

func (precheckFixtureUnsafeError) Error() string      { return workerCanary }
func (e precheckFixtureUnsafeError) Code() int        { return e.code }
func (e precheckFixtureUnsafeError) SQLState() string { return e.state }

func TestPrecheckFixtureDiagnosticsDoNotIncludeDriverText(t *testing.T) {
	for _, item := range []struct {
		err   precheckFixtureUnsafeError
		code  string
		state string
	}{
		{precheckFixtureUnsafeError{5, "55P03"}, "5", "55P03"},
		{precheckFixtureUnsafeError{-1, "a\nbcd"}, "0", "none"},
		{precheckFixtureUnsafeError{1 << 30, workerCanary}, "0", "none"},
	} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		message := precheckFixtureDiagnostic("blocker_update", fmt.Errorf("%s: %w", workerCanary, item.err), 51*time.Millisecond, ctx, true, 1)
		if strings.Contains(message, workerCanary) || !strings.Contains(message, "sqlite_code="+item.code+" ") || !strings.Contains(message, "sql_state="+item.state+" ") || !strings.Contains(message, "elapsed_ms=51 context_cancelled=true ready=true rows=1") {
			t.Fatal("fixture diagnostic did not stay closed and actionable")
		}
	}
}
