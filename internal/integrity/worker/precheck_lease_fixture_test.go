package worker

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const replacePrecheckLeaseSQL = "UPDATE integrity_jobs SET lease_owner = $1, attempt_count = attempt_count + 1, lease_until = $2 WHERE organization_id = $3 AND id = $4"

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
		code := 0
		var sqliteCode interface{ Code() int }
		if errors.As(err, &sqliteCode) {
			code = sqliteCode.Code()
		}
		state := "none"
		var pgState interface{ SQLState() string }
		if errors.As(err, &pgState) && len(pgState.SQLState()) == 5 {
			state = pgState.SQLState()
		}
		t.Fatalf("lease replacement fixture failed: phase=%s sqlite_code=%d sql_state=%s elapsed_ms=%d context_cancelled=%t ready=%t rows=%d", phase, code, state, time.Since(started).Milliseconds(), ctx.Err() != nil, runner.Ready(), affected)
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
	// A controlled BUSY regression below remains independent of this gate. The
	// original CI omitted its driver code, so its unique cause remains unknown.
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
		observer, err := f.db.Conn(f.ctx)
		if err != nil {
			t.Fatal("observer connection unavailable")
		}
		defer func() { _ = observer.Close() }()
		var oldOwner string
		var oldGeneration int
		if err := observer.QueryRowContext(f.ctx, "SELECT lease_owner,attempt_count FROM integrity_jobs WHERE organization_id=$1 AND id=$2", f.orgID, queued.JobID).Scan(&oldOwner, &oldGeneration); err != nil {
			t.Fatal("original lease read failed")
		}
		isSQLite := strings.HasSuffix(t.Name(), "/sqlite")
		setting := "SET lock_timeout = '50ms'"
		if isSQLite {
			setting = "PRAGMA busy_timeout=50"
		}
		if _, err := observer.ExecContext(f.ctx, setting); err != nil {
			t.Fatal("observer lock wait setup failed")
		}
		defer func() {
			setting := "SET lock_timeout = '0'"
			if isSQLite {
				setting = "PRAGMA busy_timeout=5000"
			}
			_, _ = observer.ExecContext(context.Background(), setting)
		}()
		blocker, err := f.db.BeginTx(f.ctx, nil)
		if err != nil {
			t.Fatal("bounded writer unavailable")
		}
		defer func() { _ = blocker.Rollback() }()
		if _, err := blocker.ExecContext(f.ctx, "UPDATE integrity_jobs SET updated_at=updated_at WHERE organization_id=$1 AND id=$2", f.orgID, queued.JobID); err != nil {
			t.Fatal("writer did not acquire row lock")
		}
		begin := time.Now()
		_, injectedErr := observer.ExecContext(f.ctx, replacePrecheckLeaseSQL, "replacement-owner", time.Now().UTC().Add(time.Minute), f.orgID, queued.JobID)
		elapsed := time.Since(begin)
		// Release the real writer before testing the consumer, well within the
		// existing two-second database deadline; no busy retry is performed.
		if err := blocker.Rollback(); err != nil {
			t.Fatal("writer release failed")
		}
		if injectedErr == nil || elapsed >= 2*time.Second {
			t.Fatal("fixture did not demonstrate bounded lock rejection")
		}
		if isSQLite {
			var code interface{ Code() int }
			if !errors.As(injectedErr, &code) || code.Code()&255 != 5 {
				t.Fatal("fixture failure was not SQLITE_BUSY")
			}
			t.Logf("expected fixture rejection: phase=update sqlite_code=%d elapsed_ms=%d", code.Code(), elapsed.Milliseconds())
		} else {
			var code interface{ SQLState() string }
			if !errors.As(injectedErr, &code) || code.SQLState() != "55P03" {
				t.Fatal("fixture failure was not PostgreSQL lock timeout")
			}
			t.Logf("expected fixture rejection: phase=update sql_state=55P03 elapsed_ms=%d", elapsed.Milliseconds())
		}
		var owner string
		var generation int
		if err := observer.QueryRowContext(f.ctx, "SELECT lease_owner,attempt_count FROM integrity_jobs WHERE organization_id=$1 AND id=$2", f.orgID, queued.JobID).Scan(&owner, &generation); err != nil {
			t.Fatal("original lease readback failed")
		}
		if owner != oldOwner || generation != oldGeneration || !runner.Ready() {
			t.Fatal("failed fixture injection changed lease or healthy consumer")
		}
	})
}
