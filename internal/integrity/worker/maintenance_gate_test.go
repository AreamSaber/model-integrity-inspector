package worker

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func workerMaintenanceAuthority(t *testing.T, f workerFixture) repository.ManagementAuthority {
	t.Helper()
	// Resolve the actual fixture session persisted by eachWorkerDatabase; this
	// is not a context flag purporting to be a system administrator.
	session, err := f.store.GetSession(f.ctx, strings.Repeat("a", 64), time.Now())
	if err != nil {
		t.Fatal("resolve current maintenance authority", err)
	}
	return repository.ManagementAuthority{UserID: session.UserID, SessionID: session.ID}
}

func beginWorkerMaintenance(t *testing.T, f workerFixture) *repository.MaintenanceLease {
	t.Helper()
	state, err := f.store.ReadMaintenanceState(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := f.store.BeginBackupMaintenance(f.ctx, workerMaintenanceAuthority(t, f), repository.BackupMaintenanceRequest{ExpectedVersion: state.Version, ReasonCode: "backup.manual", MaxDuration: time.Hour})
	if err != nil {
		t.Fatal("begin actual Worker maintenance", err)
	}
	return lease
}

func TestMaintenanceGateRunnerDoesNotDispatchFrozenOrIsolatedPendingJobs(t *testing.T) {
	for _, mode := range []string{"backup_freeze", "restore_isolated"} {
		t.Run(mode, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				tenant, run, _ := f.createRun(t, []bool{false})
				var freeze *repository.MaintenanceLease
				if mode == "backup_freeze" {
					freeze = beginWorkerMaintenance(t, f.workerFixture)
				} else {
					// Synthetic quarantined destination only: no restore or activation
					// is implemented or inferred from this test-owned state.
					if _, err := f.db.ExecContext(f.ctx, "UPDATE system_maintenance SET mode='restore_isolated',version=2,updated_at_micros=1 WHERE id=1"); err != nil {
						t.Fatal("prepare isolated synthetic destination")
					}
				}
				var calls atomic.Int64
				config := runTLSConfig(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					calls.Add(1)
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"id":"fixture","choices":[{"message":{"content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":1,"total_tokens":11}}`)
				}))
				handlers, err := NewRunHandlers(config)
				if err != nil {
					t.Fatal(err)
				}
				var dispatched atomic.Int64
				original := handlers[repository.JobSampleExecute]
				handlers[repository.JobSampleExecute] = func(ctx context.Context, execution Execution) (Completion, error) {
					dispatched.Add(1)
					return original(ctx, execution)
				}
				observed := make(chan error, 2)
				var observeClaims atomic.Bool
				observeClaims.Store(true)
				runner, err := New(Config{Store: f.store, Handlers: handlers, PollInterval: 10 * time.Millisecond, HeartbeatInterval: 40 * time.Millisecond,
					Maintenance: func(ctx context.Context, queue *repository.JobQueue) error {
						if !observeClaims.Load() {
							return nil
						}
						// An actual Runner-owned consumer, including its initial and
						// periodic maintenance pulse, must receive no pending lease.
						lease, err := queue.Claim(ctx)
						if err == nil && lease != nil {
							err = repository.ErrJobInvalid
						}
						select {
						case observed <- err:
						default:
						}
						return err
					}})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(f.ctx)
				done := make(chan error, 1)
				go func() { done <- runner.Run(ctx) }()
				t.Cleanup(func() {
					cancel()
					select {
					case err := <-done:
						if err != nil {
							t.Error("paused Runner failed", err)
						}
					case <-time.After(7 * time.Second):
						t.Error("paused Runner failed to shut down")
					}
				})
				for range 2 {
					select {
					case err := <-observed:
						if err != nil {
							t.Fatal("real Runner consumer bypassed maintenance", err)
						}
					case <-time.After(4 * time.Second):
						t.Fatal("real Runner did not complete initial and periodic paused Claims")
					}
				}
				if calls.Load() != 0 || dispatched.Load() != 0 || !runner.Ready() {
					t.Fatal("paused Worker dispatched, made network I/O, or failed readiness")
				}
				unchanged, err := tenant.GetRun(run.ID)
				if err != nil || unchanged.RequestCount != 0 {
					t.Fatal("paused Worker reserved a new request", err)
				}
				if freeze != nil {
					if err := runner.withQueueGate(f.ctx, func() error { observeClaims.Store(false); return nil }); err != nil {
						t.Fatal(err)
					}
					if err := freeze.Abort(f.ctx); err != nil {
						t.Fatal(err)
					}
					closed := awaitRunClosed(t, tenant, run.ID)
					if closed.RequestCount != 1 || calls.Load() != 1 || dispatched.Load() != 1 {
						t.Fatal("authenticated reopen did not dispatch the original pending request exactly once")
					}
				} else {
					state, err := f.store.ReadMaintenanceState(f.ctx)
					if err != nil || state.Mode != repository.MaintenanceRestoreIsolated {
						t.Fatal("Worker startup or heartbeat unlocked isolation", err)
					}
				}
			})
		})
	}
}

func TestMaintenanceGateRunnerInFlightTLSCancellationStillSettlesAuthenticatedS1(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		if _, err := f.db.ExecContext(f.ctx, "UPDATE organizations SET full_response_retention_days=0 WHERE id=$1", f.orgID); err != nil {
			t.Fatal(err)
		}
		p := signedPricedDerivedCancellationRun(t, f)
		mac, err := f.ring.NewDerivedSourceMAC()
		if err != nil {
			t.Fatal(err)
		}
		sealer, verifier, err := features.NewDerivedCapabilitiesWithMAC("worker-test", mac)
		if err != nil {
			t.Fatal(err)
		}
		p.verifier = verifier
		started, stopped := make(chan struct{}), make(chan struct{})
		var calls atomic.Int64
		config := runTLSConfig(t, f, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			firstRequest := calls.Add(1) == 1
			if firstRequest {
				close(started)
			}
			<-r.Context().Done()
			if firstRequest {
				close(stopped)
			}
		}))
		config.RequestTimeout = 30 * time.Second
		config.DerivedBuilder, config.DerivedSealer = p.builder, sealer
		handlers, err := NewRunHandlers(config)
		if err != nil {
			t.Fatal(err)
		}
		dispatched := make(chan Execution, 1)
		completion := make(chan Completion, 1)
		original := handlers[repository.JobSampleExecute]
		var first atomic.Bool
		handlers[repository.JobSampleExecute] = func(ctx context.Context, execution Execution) (Completion, error) {
			if !first.CompareAndSwap(false, true) {
				return original(ctx, execution)
			}
			dispatched <- execution
			result, err := original(ctx, execution)
			completion <- result
			return result, err
		}
		runner, err := New(Config{Store: f.store, Handlers: handlers, PollInterval: 10 * time.Millisecond, HeartbeatInterval: 40 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(f.ctx)
		done := make(chan error, 1)
		go func() { done <- runner.Run(ctx) }()
		t.Cleanup(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error("in-flight maintenance Runner failed", err)
				}
			case <-time.After(7 * time.Second):
				t.Error("in-flight maintenance Runner failed to shut down")
			}
		})
		select {
		case execution := <-dispatched:
			p.queue, p.lease = execution.Queue, execution.Lease
		case <-time.After(5 * time.Second):
			t.Fatal("Runner never dispatched actual signed sample")
		}
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("actual TLS request did not start")
		}
		freeze := beginWorkerMaintenance(t, f.workerFixture)
		if _, err := p.queue.Renew(f.ctx, p.lease); err != nil {
			t.Fatal("freeze prevented renewal of the in-flight owner", err)
		}
		observation, err := freeze.Observe(f.ctx)
		if err != nil || !observation.RunningJobPresent || !observation.UnsettledAttemptPresent {
			t.Fatal("actual in-flight work was not observed as blocking", err)
		}
		select {
		case <-stopped:
			t.Fatal("freeze itself cancelled in-flight network I/O")
		default:
		}
		cancelPricedDerivedRun(t, p)
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Fatal("frozen Run cancellation did not stop actual TLS request")
		}
		select {
		case p.completion = <-completion:
			if p.completion == nil {
				t.Fatal("frozen in-flight handler lost settlement")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("frozen in-flight handler did not prepare settlement")
		}
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			attempts, err := p.tenant.ListAttempts(p.lease.Job.ObjectID)
			if err != nil {
				t.Fatal(err)
			}
			if len(attempts) == 1 && attempts[0].FinishedAt != nil {
				break
			}
			select {
			case <-ticker.C:
			case <-deadline.C:
				t.Fatal("frozen in-flight attempt did not settle")
			}
		}
		verifySettledDerivedAttempt(t, f, p, "COMPLETED", "NOT_APPLICABLE", "MI_EXECUTION_CANCELLED")
		if lease, err := p.queue.Claim(f.ctx); err != nil || lease != nil {
			t.Fatal("pending work was claimed while the completed owner remained frozen", err)
		}
		if err := p.queue.CompleteWith(f.ctx, p.lease, p.completion); !errors.Is(err, repository.ErrJobLeaseLost) {
			t.Fatal("maintenance bypassed terminal job fencing", err)
		}
		current, err := p.tenant.GetRun(p.run.ID)
		if err != nil || current.ReservedTokens != 0 || current.ReservedCostMicros != 0 || current.RequestCount != 1 || calls.Load() != 1 || !runner.Ready() {
			t.Fatal("frozen cancellation leaked reservations, duplicated network, or failed Runner", err)
		}
		if err := freeze.Abort(f.ctx); err != nil {
			t.Fatal(err)
		}
		closed := awaitRunClosed(t, p.tenant, p.run.ID)
		if closed.Status != "CANCELLED" || closed.RequestCount != 1 || calls.Load() != 1 {
			t.Fatal("reopening caused new I/O for the remaining cancelled samples")
		}
	})
}
