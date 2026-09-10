package worker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

// The closed notification keeps the one Runner result available to both the
// original failure assertion and cleanup. Neither consumes an error channel
// needed by the other, and only the Runner goroutine writes result.
type reportRunnerFixture struct {
	done   chan struct{}
	result error
}

func startReportRunnerFixture(t *testing.T, run func(context.Context) error) *reportRunnerFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	fixture := &reportRunnerFixture{done: make(chan struct{})}
	t.Cleanup(func() {
		cancel()
		select {
		case <-fixture.done:
		case <-time.After(7 * time.Second):
			t.Error("report fault Runner did not stop before resource cleanup")
		}
	})
	go func() {
		fixture.result = run(ctx)
		close(fixture.done)
	}()
	return fixture
}

func TestReportRunnerCleanupJoinsBeforeEarlierResourceCleanup(t *testing.T) {
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var stopped atomic.Bool
	observerDone := make(chan struct{})
	go func() {
		defer close(observerDone)
		<-canceled
		// This is a held, known cleanup barrier, not an assumption about when
		// a database operation probably started. Cleanup must still own the
		// resources throughout it, even after cancellation has been observed.
		timer := time.NewTimer(25 * time.Millisecond)
		defer timer.Stop()
		<-timer.C
		close(release)
	}()
	t.Run("early_fixture_return", func(t *testing.T) {
		t.Cleanup(func() {
			if !stopped.Load() {
				t.Error("resource cleanup overtook canceled Runner completion")
			}
		})
		startReportRunnerFixture(t, func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			close(canceled)
			<-release
			stopped.Store(true)
			return nil
		})
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("controlled Runner did not start")
		}
		// Return before the usual terminal assertion, as a failed fault
		// installation does. No fatal injection is needed to test T.Cleanup.
	})
	<-observerDone
}

func TestReportRunnerCleanupPreservesUncancelledTerminalError(t *testing.T) {
	want := errors.New("synthetic report terminal failure")
	var returned atomic.Int32
	var observed context.Context
	t.Run("terminal_error_before_cleanup", func(t *testing.T) {
		fixture := startReportRunnerFixture(t, func(ctx context.Context) error {
			observed = ctx
			returned.Add(1)
			return want
		})
		select {
		case <-fixture.done:
			if !errors.Is(fixture.result, want) || observed.Err() != nil {
				t.Fatal("cleanup canceled or replaced the actual terminal error")
			}
		case <-time.After(time.Second):
			t.Fatal("controlled Runner did not finish")
		}
		// The close notification remains readable; cleanup must not wait for
		// a second send after the normal path already observed the result.
		select {
		case <-fixture.done:
		default:
			t.Fatal("normal assertion consumed cleanup's completion signal")
		}
	})
	if returned.Load() != 1 || observed.Err() == nil {
		t.Fatal("Runner ran more than once or cleanup omitted cancellation")
	}
}

func TestReportWorkerFaultFixtureEarlyReturnJoinsActualRunner(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		tenant, run, _, realHandler, _ := prepareReportCompletionWorker(t, f)
		row, err := tenant.CreateReport(repository.ReportInput{RunID: run.ID, AnalysisRevision: 1, Format: "json", IdempotencyKey: "report-fixture-early-return"})
		if err != nil {
			t.Fatal(err)
		}
		written := make(chan struct{})
		handler := func(ctx context.Context, execution Execution) (Completion, error) {
			if _, err := realHandler(ctx, execution); err != nil {
				return nil, err
			}
			close(written)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		runner, err := New(Config{Store: f.store, Handlers: map[repository.JobType]Handler{repository.JobReportGenerate: handler}, PollInterval: 10 * time.Millisecond, HeartbeatInterval: 40 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		var process *reportRunnerFixture
		t.Run("return_before_installing_fault", func(t *testing.T) {
			process = startReportRunnerFixture(t, runner.Run)
			select {
			case <-written:
			case <-process.done:
				t.Fatal("actual report Runner stopped before early-return barrier", process.result)
			case <-time.After(5 * time.Second):
				t.Fatal("actual report file not written before early return")
			}
			// The same T.Cleanup stack runs after a failed fault installation.
			// Deliberately omit the ordinary normal-path terminal receive.
		})
		select {
		case <-process.done:
			if process.result != nil || runner.Ready() {
				t.Fatal("early-return Runner did not finish graceful cancellation")
			}
		default:
			t.Fatal("early-return cleanup left an actual Runner using the database")
		}
		var consumers int
		if err := f.db.QueryRowContext(f.ctx, "SELECT count(*) FROM integrity_queue_consumer_leases").Scan(&consumers); err != nil || consumers != 0 {
			t.Fatal("early-return cleanup did not release the actual consumer")
		}
		stored, err := tenant.GetReport(row.ID)
		if err != nil || stored.Status != "generating" || stored.FileHash != nil || stored.StoragePath != nil {
			t.Fatal("fixture cleanup fabricated report publication")
		}
	})
}
