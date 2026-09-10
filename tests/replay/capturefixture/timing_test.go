package capturefixture

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/worker"
	"model-integrity-inspector.local/mii/tests/replay"
)

func TestActualWorkerCaptureReservationDelayTiming(t *testing.T) {
	for _, omitDone := range []bool{false, true} {
		name := "complete"
		if omitDone {
			name = "stream-terminal-omitted"
		}
		t.Run(name, func(t *testing.T) { captureActual(t, "postgres", omitDone, false, true) })
	}
}

// Only this isolated PostgreSQL schema is locked. The actual Handler, Adapter,
// network Do, reservation timestamps, evidence and publication are unchanged.
// We first OBSERVE a genuine ReserveAttempt lock wait; the 250ms test injection
// is not a guessed startup sleep and does not relax any production deadline.
func delayedReservation(t *testing.T, cfg repository.Config, original worker.Handler) worker.Handler {
	t.Helper()
	if cfg.Driver != "postgres" {
		t.Fatal("reservation lock fixture requires PostgreSQL")
	}
	db, err := sql.Open("pgx", cfg.DSN)
	if err != nil {
		t.Fatal("reservation test connection unavailable")
	}
	db.SetMaxOpenConns(2)
	t.Cleanup(func() { _ = db.Close() })
	var once sync.Once
	return func(ctx context.Context, execution worker.Execution) (worker.Completion, error) {
		first := false
		once.Do(func() { first = true })
		if !first {
			return original(ctx, execution)
		}
		lockCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer cancel()
		tx, err := db.BeginTx(lockCtx, nil)
		if err != nil {
			return nil, errCapture
		}
		defer func() { _ = tx.Rollback() }()
		var blocker int
		if tx.QueryRowContext(lockCtx, "SELECT pg_backend_pid()").Scan(&blocker) != nil {
			return nil, errCapture
		}
		if _, err := tx.ExecContext(lockCtx, "UPDATE integrity_execution_mutex SET touched = 0 WHERE lock_name = 'global-reservation'"); err != nil {
			return nil, errCapture
		}
		released := make(chan error, 1)
		go func() {
			if err := observeReserveWait(lockCtx, db, blocker); err != nil {
				_ = tx.Rollback()
				released <- err
				return
			}
			delay := time.NewTimer(250 * time.Millisecond)
			defer delay.Stop()
			select {
			case <-delay.C:
				if err := tx.Commit(); err != nil {
					released <- errCapture
				} else {
					released <- nil
				}
			case <-lockCtx.Done():
				_ = tx.Rollback()
				released <- errCapture
			}
		}()
		completion, callErr := original(ctx, execution)
		if err := <-released; err != nil {
			return nil, err
		}
		return completion, callErr
	}
}

func observeReserveWait(ctx context.Context, db *sql.DB, blocker int) error {
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		// No SQL text, role names, DSN or payloads leave PostgreSQL. Binding the
		// blocker backend proves this is our exact test lock, not another suite.
		if err := db.QueryRowContext(ctx, `SELECT EXISTS (
		 SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))
		 AND position('UPDATE integrity_execution_mutex SET touched = 0' IN query) = 1
		 AND wait_event_type='Lock')`, blocker).Scan(&waiting); err != nil {
			return errCapture
		}
		if waiting {
			return nil
		}
		select {
		case <-ctx.Done():
			return errCapture
		case <-tick.C:
		}
	}
}

func assertSeparateTimingOrigins(t *testing.T, draft replay.CaptureDraft) {
	t.Helper()
	for _, sample := range draft.Samples {
		for _, attempt := range sample.Attempts {
			span := attempt.FinishedAt.Sub(attempt.StartedAt).Milliseconds()
			elapsed := attempt.Response.Timing.DurationMillis
			if elapsed > span+1 {
				t.Logf("observed real pre-reservation wait: adapter_ms=%d persisted_attempt_ms=%d", elapsed, span)
				return
			}
		}
	}
	t.Fatal("test did not establish distinct timing intervals")
}
