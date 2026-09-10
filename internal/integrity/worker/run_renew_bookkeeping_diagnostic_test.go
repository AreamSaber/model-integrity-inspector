//go:build renew_bookkeeping_diagnostic

package worker

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

type renewBookkeepingObservation struct {
	err          error
	jobCause     error
	parentActive bool
	elapsed      time.Duration
}

// This is a candidate availability-contract diagnostic, not an approved runtime
// guarantee or a reproduction of CI 34183736103's unique cause. That run retained
// no raw driver code or pool
// wait diagnostic. No outbound request or external database lock is involved.
//
// An authorized, bounded pre-call transaction holds the current Job's fence.
// A competing Renew must not turn that own bookkeeping into consumer loss while
// the original lease remains valid. In particular, extending SQL deadlines or
// weakening the owner/generation predicates is not an acceptable test fix.
func TestRunWorkerOwnLeaseBookkeepingDoesNotStarveRenew(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		tenant, run, _ := f.createRun(t, []bool{false})
		entered := make(chan repository.JobLease, 1)
		release := make(chan struct{})
		observed := make(chan renewBookkeepingObservation, 1)
		var runner *Runner
		var log executionLogBuffer
		handlers := map[repository.JobType]Handler{
			repository.JobRunPlan: func(_ context.Context, execution Execution) (Completion, error) {
				return func(tx *repository.TenantTransaction) error {
					return tx.StartRun(execution.Lease.Job.ObjectID)
				}, nil
			},
			repository.JobSampleExecute: func(ctx context.Context, execution Execution) (Completion, error) {
				// The bounded transaction has no HTTP or sleep of its own. The
				// barrier controls when its caller allows bookkeeping to finish.
				bookkeepingCtx, stop := context.WithTimeout(ctx, 3*time.Second)
				defer stop()
				started := time.Now()
				// As in the existing lease-replacement fixture, exclude only the
				// unrelated consumer pulse. execute's Renew and CheckLease still
				// run unchanged; the gate grants no database authority.
				err := runner.withQueueGate(bookkeepingCtx, func() error {
					return execution.Queue.WithLease(bookkeepingCtx, execution.Lease, func(*repository.TenantTransaction) error {
						entered <- execution.Lease
						select {
						case <-release:
							return nil
						case <-bookkeepingCtx.Done():
							return bookkeepingCtx.Err()
						}
					})
				})
				observed <- renewBookkeepingObservation{err: err, jobCause: context.Cause(ctx), parentActive: f.ctx.Err() == nil, elapsed: time.Since(started)}
				if err != nil {
					return nil, err
				}
				return func(tx *repository.TenantTransaction) error {
					return tx.FailUnattemptedSample(execution.Lease.Job.ObjectID, "MI_PROTOCOL_UNSUPPORTED")
				}, nil
			},
		}
		var err error
		// Keep the normal one-second cancellation poll. The existing supported
		// 40ms heartbeat makes the writer wait observable before the next poll;
		// neither the two-second SQL limit nor 60-second lease is changed.
		runner, err = New(Config{Store: f.store, Handlers: handlers, Logger: slog.New(slog.NewTextHandler(&log, nil)), PollInterval: time.Second, HeartbeatInterval: 40 * time.Millisecond})
		if err != nil {
			t.Fatal("bookkeeping runner configuration rejected")
		}
		ctx, cancel := context.WithCancel(f.ctx)
		done := make(chan error, 1)
		go func() { done <- runner.Run(ctx) }()
		stopped, released := false, false
		t.Cleanup(func() {
			if !released {
				close(release)
			}
			cancel()
			if !stopped {
				select {
				case err := <-done:
					if err != nil {
						t.Error("bookkeeping runner did not shut down cleanly")
					}
				case <-time.After(7 * time.Second):
					t.Error("bookkeeping runner shutdown exceeded bound")
				}
			}
		})
		var lease repository.JobLease
		select {
		case lease = <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("fenced bookkeeping transaction did not reach its barrier")
		}
		// Cross the unchanged two-second Renew deadline while staying within
		// this operation's three-second bound and well inside the real lease.
		hold := time.NewTimer(2200 * time.Millisecond)
		defer hold.Stop()
		var observation renewBookkeepingObservation
		observationReceived := false
		select {
		case observation = <-observed:
			observationReceived = true
		case <-hold.C:
		}
		readyAtRelease := runner.Ready()
		close(release)
		released = true
		if !observationReceived {
			select {
			case observation = <-observed:
			case <-time.After(time.Second):
				t.Fatal("released bookkeeping did not finish within its original bound")
			}
		}
		if observation.err != nil || !readyAtRelease {
			// Read the committed fence only after the test transaction yields.
			// Never print owner IDs, SQL, driver text, credentials or snapshots.
			var status string
			var owner sql.NullString
			var generation int
			var until sql.NullTime
			inspectCtx, stop := context.WithTimeout(f.ctx, 2*time.Second)
			err := f.db.QueryRowContext(inspectCtx, "SELECT status,lease_owner,attempt_count,lease_until FROM integrity_jobs WHERE organization_id=$1 AND id=$2", f.orgID, lease.Job.ID).Scan(&status, &owner, &generation, &until)
			stop()
			fenceUnchanged := err == nil && status == "running" && owner.Valid && lease.Job.LeaseOwner != nil && owner.String == *lease.Job.LeaseOwner && generation == lease.Generation
			leaseUnexpired := until.Valid && until.Time.After(time.Now())
			var runnerErr error
			select {
			case runnerErr = <-done:
				stopped = true
			case <-time.After(5 * time.Second):
				t.Fatal("failed bookkeeping did not stop its runner within cancellation grace")
			}
			t.Fatalf("own bookkeeping interrupted: renew_failure=%t check_failure=%t consumer_failure=%t elapsed_ms=%d parent_active=%t job_cause_unavailable=%t runner_unavailable=%t ready=%t fence_unchanged=%t lease_unexpired=%t", strings.Contains(log.String(), "operation=renew"), strings.Contains(log.String(), "operation=check_lease"), strings.Contains(log.String(), "operation=consumer_heartbeat"), observation.elapsed.Milliseconds(), observation.parentActive, errors.Is(observation.jobCause, repository.ErrUnavailable), errors.Is(runnerErr, repository.ErrUnavailable), readyAtRelease, fenceUnchanged, leaseUnexpired)
		}
		finished := awaitRunClosed(t, tenant, run.ID)
		if finished.RequestCount != 0 || finished.ReservedTokens != 0 || !runner.Ready() {
			t.Fatal("healthy bookkeeping invented a request, retained a reservation or stopped the consumer")
		}
	})
}
