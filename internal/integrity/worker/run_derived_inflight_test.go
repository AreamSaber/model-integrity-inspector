package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
)

// The returned Runner really owns/renews/claims the queue. This test-only
// wrapper observes the first actual handler result, then gates its return to
// let assertions distinguish prepared memory from committed business state.
type derivedInflightRunner struct {
	runner    *Runner
	executing chan Execution
	observed  chan derivedCancellationObservation
	done      chan struct{}
	release   func()
	err       error // read only after done closes
}

func startDerivedInflightRunner(t *testing.T, f runFixture, handlers map[repository.JobType]Handler, expectedFailure error) *derivedInflightRunner {
	t.Helper()
	ctx, cancel := context.WithCancel(f.ctx)
	gate := make(chan struct{})
	var once sync.Once
	r := &derivedInflightRunner{executing: make(chan Execution, 1), observed: make(chan derivedCancellationObservation, 1), done: make(chan struct{}), release: func() { once.Do(func() { close(gate) }) }}
	wrapped := make(map[repository.JobType]Handler, len(handlers))
	for kind, handler := range handlers {
		wrapped[kind] = handler
	}
	original := wrapped[repository.JobSampleExecute]
	var first atomic.Bool
	wrapped[repository.JobSampleExecute] = func(jobCtx context.Context, execution Execution) (Completion, error) {
		if !first.CompareAndSwap(false, true) {
			return original(jobCtx, execution)
		}
		r.executing <- execution
		completion, err := original(jobCtx, execution)
		r.observed <- derivedCancellationObservation{completion, err, context.Cause(jobCtx)}
		select {
		case <-gate:
			return completion, err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	var log executionLogBuffer
	var err error
	r.runner, err = New(Config{Store: f.store, Handlers: wrapped, Logger: slog.New(slog.NewTextHandler(&log, nil)), PollInterval: 10 * time.Millisecond, HeartbeatInterval: 40 * time.Millisecond})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	go func() { r.err = r.runner.Run(ctx); close(r.done) }()
	t.Cleanup(func() {
		r.release()
		cancel()
		select {
		case <-r.done:
			if r.err != nil && !errors.Is(r.err, expectedFailure) {
				t.Errorf("unexpected real Runner failure: %v", r.err)
			}
		case <-time.After(7 * time.Second):
			t.Error("real Runner did not finish bounded shutdown")
		}
		if t.Failed() {
			t.Log(log.String())
		}
	})
	return r
}

func (r *derivedInflightRunner) execution(t *testing.T) Execution {
	t.Helper()
	select {
	case execution := <-r.executing:
		return execution
	case <-time.After(5 * time.Second):
		t.Fatal("real Runner did not claim execution")
		return Execution{}
	}
}

func (r *derivedInflightRunner) result(t *testing.T) derivedCancellationObservation {
	t.Helper()
	select {
	case result := <-r.observed:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("real handler did not return within cancellation bound")
		return derivedCancellationObservation{}
	}
}

func awaitDerivedInflightEvent(t *testing.T, event <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(5 * time.Second):
		t.Fatal(label)
	}
}

func derivedWaitingTLSFixture(t *testing.T, f runFixture) (derivedPendingFixture, map[repository.JobType]Handler, <-chan struct{}, <-chan struct{}, *atomic.Int64) {
	t.Helper()
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
	calls := new(atomic.Int64)
	p.config = runTLSConfig(t, f, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		first := calls.Add(1) == 1
		if first {
			close(started)
		}
		// There is no response or timeout fallback. Only real client I/O
		// cancellation can release the server-side observation barrier.
		<-request.Context().Done()
		if first {
			close(stopped)
		}
	}))
	// Use the production default (180 seconds), not the ordinary TLS fixture's
	// two-second timeout. Neither test changes the signed timeout/budget.
	p.config.RequestTimeout = 0
	p.config.DerivedBuilder, p.config.DerivedSealer = p.builder, sealer
	handlers, err := NewRunHandlers(p.config)
	if err != nil {
		t.Fatal(err)
	}
	return p, handlers, started, stopped, calls
}

func assertDerivedStillUnsettled(t *testing.T, f runFixture, p derivedPendingFixture, inFlight repository.RunRecord) repository.AttemptRecord {
	t.Helper()
	attempts, err := p.tenant.ListAttempts(p.lease.Job.ObjectID)
	if err != nil || len(attempts) != 1 || attempts[0].Status != "DISPATCHED" || attempts[0].FinishedAt != nil || attempts[0].DerivedReceipt != repository.DerivedPending || attempts[0].LeaseGeneration != p.lease.Generation {
		t.Fatal("in-flight owner wrote a terminal result")
	}
	run, err := p.tenant.GetRun(p.run.ID)
	if err != nil || run.RequestCount != 1 || run.ReservedTokens != inFlight.ReservedTokens || run.ReservedCostMicros != inFlight.ReservedCostMicros || run.TokenCount != 0 || run.EstimatedCostMicros != 0 {
		t.Fatal("in-flight owner changed reservation or settlement")
	}
	derivedCounts(t, f, p.run.ID, 0, 0)
	var count int
	if err := f.db.QueryRowContext(f.ctx, "SELECT count(*) FROM integrity_audit_logs WHERE organization_id=$1 AND action='run.attempt.finish'", f.orgID).Scan(&count); err != nil || count != 0 {
		t.Fatal("in-flight owner left a success audit")
	}
	return attempts[0]
}

func assertDerivedConservativeCharge(t *testing.T, p derivedPendingFixture, run repository.RunRecord, attempt repository.AttemptRecord) {
	t.Helper()
	sample, err := p.tenant.GetExecutionSampleForWorker(p.lease.Job.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	var request domain.SamplePlan
	if json.Unmarshal([]byte(sample.RequestPlan), &request) != nil {
		t.Fatal("decode actual reserved sample")
	}
	plan, err := p.tenant.GetExecutionPlan(p.run.ID)
	if err != nil {
		t.Fatal(err)
	}
	input, err := scheduler.UncertainTokens(request.EstimatedInputTokens)
	if err != nil {
		t.Fatal(err)
	}
	output, err := scheduler.UncertainTokens(int64(request.Request.MaxOutputTokens))
	if err != nil {
		t.Fatal(err)
	}
	cost, err := scheduler.Cost(plan.Pricing, input, output)
	if err != nil || cost == nil || *cost <= 0 {
		t.Fatal("missing independent priced expectation")
	}
	if attempt.TotalTokens == nil || *attempt.TotalTokens != input+output || run.TokenCount != input+output || attempt.BilledEstimateMicros != *cost || run.EstimatedCostMicros != *cost {
		t.Fatalf("lost conservative in-flight charge: tokens=%d want=%d cost=%d want=%d", run.TokenCount, input+output, run.EstimatedCostMicros, *cost)
	}
	if run.RequestCount != 1 || run.ReservedTokens != 0 || run.ReservedCostMicros != 0 {
		t.Fatal("recovered request was repeated or its reservation not released")
	}
}

func assertDerivedInflightFinishedOnce(t *testing.T, f runFixture, p derivedPendingFixture, runner *derivedInflightRunner) {
	t.Helper()
	derivedCounts(t, f, p.run.ID, 1, 0)
	var count int
	if err := f.db.QueryRowContext(f.ctx, "SELECT count(*) FROM integrity_audit_logs WHERE organization_id=$1 AND action='run.attempt.finish'", f.orgID).Scan(&count); err != nil || count != 1 {
		t.Fatal("terminal replay duplicated an in-flight settlement audit")
	}
	select {
	case <-runner.done:
		t.Fatal("healthy replacement/budget Runner terminated", runner.err)
	default:
	}
	if !runner.runner.Ready() {
		t.Fatal("healthy replacement/budget Runner lost readiness")
	}
}

func TestDerivedRunnerActualInflightLeaseLossAndLegitimateRecovery(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		p, handlers, started, stopped, calls := derivedWaitingTLSFixture(t, f)
		old := startDerivedInflightRunner(t, f, handlers, repository.ErrJobLeaseLost)
		execution := old.execution(t)
		p.queue, p.lease = execution.Queue, execution.Lease
		awaitDerivedInflightEvent(t, started, "actual TLS request did not begin")
		inFlight, err := p.tenant.GetRun(p.run.ID)
		if err != nil || inFlight.ReservedTokens <= 0 || inFlight.ReservedCostMicros <= 0 {
			t.Fatal("actual request did not reserve tokens and money")
		}
		select {
		case <-stopped:
			t.Fatal("request stopped before lease loss")
		default:
		}
		// Simulate a different owner holding the next generation while I/O is
		// live. The old real Runner must observe loss, not a business cancel.
		if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_jobs SET lease_owner=$1,attempt_count=attempt_count+1,lease_until=$2 WHERE organization_id=$3 AND id=$4", "synthetic-replacement-owner", time.Now().UTC().Add(time.Minute), f.orgID, p.lease.Job.ID); err != nil {
			t.Fatal("replace actual live lease", err)
		}
		awaitDerivedInflightEvent(t, stopped, "lease loss did not actually stop TLS I/O")
		result := old.result(t)
		if !errors.Is(result.jobCause, repository.ErrJobLeaseLost) || !errors.Is(result.err, repository.ErrJobLeaseLost) || result.completion != nil {
			t.Fatal("old real handler detached lease loss or prepared a completion", result.err)
		}
		original := assertDerivedStillUnsettled(t, f, p, inFlight)
		var entered bool
		if err := p.queue.CompleteWith(f.ctx, p.lease, func(*repository.TenantTransaction) error { entered = true; return nil }); !errors.Is(err, repository.ErrJobLeaseLost) || entered {
			t.Fatal("old owner entered a business write after actual lease loss", err)
		}
		old.release()
		awaitDerivedInflightEvent(t, old.done, "lost owner did not terminate")
		if !errors.Is(old.err, repository.ErrJobLeaseLost) || old.runner.Ready() {
			t.Fatal("lost owner remained healthy", old.err)
		}
		assertDerivedStillUnsettled(t, f, p, inFlight)
		// Close other samples without cancelling the recoverable Job. Recovery
		// must still settle the old Attempt before ordinary CheckExecution.
		cancelPricedDerivedRun(t, p)
		if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_jobs SET lease_until=$1 WHERE organization_id=$2 AND id=$3", time.Now().UTC().Add(-time.Second), f.orgID, p.lease.Job.ID); err != nil {
			t.Fatal("expire the replacement lease for actual reclaim", err)
		}
		rejectDerivedBodyInserts(t, f)
		next := startDerivedInflightRunner(t, f, handlers, nil)
		reclaimed := next.execution(t)
		if reclaimed.Lease.Job.ID != p.lease.Job.ID || reclaimed.Lease.Generation != p.lease.Generation+2 {
			t.Fatal("new real Runner did not reclaim the exact abandoned Job")
		}
		recovery := next.result(t)
		if recovery.err != nil || recovery.completion == nil || recovery.jobCause != nil {
			t.Fatal("legitimate reclaim did not prepare recovery", recovery.err)
		}
		assertDerivedStillUnsettled(t, f, p, inFlight)
		if err := reclaimed.Queue.CompleteWith(f.ctx, p.lease, recovery.completion); !errors.Is(err, repository.ErrJobLeaseLost) {
			t.Fatal("old generation acquired new owner's completion authority", err)
		}
		next.release()
		finished := awaitRunClosed(t, p.tenant, p.run.ID)
		verifySettledDerivedAttempt(t, f, p, "UNCERTAIN", "INVALID_RETRYABLE", "MI_UNCERTAIN_ATTEMPT")
		attempts, err := p.tenant.ListAttempts(p.lease.Job.ObjectID)
		if err != nil || len(attempts) != 1 || attempts[0].ID != original.ID || attempts[0].LeaseGeneration != original.LeaseGeneration || attempts[0].AttemptNo != 1 || attempts[0].DerivedReceipt != repository.DerivedRecovered || calls.Load() != 1 || finished.Status != "CANCELLED" {
			t.Fatal("recovery redispatched or rewrote original attempt identity")
		}
		assertDerivedConservativeCharge(t, p, finished, attempts[0])
		if err := reclaimed.Queue.CompleteWith(f.ctx, reclaimed.Lease, recovery.completion); !errors.Is(err, repository.ErrJobLeaseLost) {
			t.Fatal("recovered completion repeated after terminal settlement", err)
		}
		assertDerivedInflightFinishedOnce(t, f, p, next)
		if _, err := p.tenant.VerifyAuditFull(); err != nil {
			t.Fatal("recovery audit chain", err)
		}
	})
}

func TestDerivedRunnerActualInflightDeadlineAuthenticatesBudgetOutcome(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		p, handlers, started, stopped, calls := derivedWaitingTLSFixture(t, f)
		analysis, err := NewAnalysisHandler(AnalysisConfig{Builder: p.builder, DerivedVerifier: p.verifier})
		if err != nil {
			t.Fatal(err)
		}
		handlers[repository.JobRunAnalyze] = analysis
		runner := startDerivedInflightRunner(t, f, handlers, nil)
		execution := runner.execution(t)
		p.queue, p.lease = execution.Queue, execution.Lease
		awaitDerivedInflightEvent(t, started, "budget fixture TLS request never began")
		inFlight, err := p.tenant.GetRun(p.run.ID)
		if err != nil || inFlight.ReservedTokens <= 0 || inFlight.ReservedCostMicros <= 0 || inFlight.CancelRequestedAt != nil {
			t.Fatal("budget fixture did not reserve a live request")
		}
		rejectDerivedBodyInserts(t, f)
		select {
		case <-stopped:
			t.Fatal("network ended before Run deadline expiry")
		default:
		}
		// Advance only the persisted execution deadline after real dispatch.
		// The signed timeout/budget and the 180-second HTTP ceiling stay intact.
		if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_runs SET deadline_at=$1 WHERE organization_id=$2 AND id=$3", time.Now().UTC().Add(-time.Second), f.orgID, p.run.ID); err != nil {
			t.Fatal("expire actual live execution deadline", err)
		}
		awaitDerivedInflightEvent(t, stopped, "Run deadline did not actually stop TLS I/O")
		result := runner.result(t)
		if result.err != nil || result.completion == nil || result.jobCause != nil {
			t.Fatal("budget watcher stopped the Job or lost its completion", result.err)
		}
		if err := p.queue.CheckLease(f.ctx, p.lease); err != nil {
			t.Fatal("Run budget expiry invalidated the live Job fence", err)
		}
		assertDerivedStillUnsettled(t, f, p, inFlight)
		runner.release()
		finished := awaitRunClosed(t, p.tenant, p.run.ID)
		verifySettledDerivedAttempt(t, f, p, "COMPLETED", "NOT_APPLICABLE", "MI_EXECUTION_BUDGET_EXCEEDED")
		attempts, err := p.tenant.ListAttempts(p.lease.Job.ObjectID)
		if err != nil || len(attempts) != 1 || attempts[0].DerivedReceipt != repository.DerivedRecorded || attempts[0].LeaseGeneration != p.lease.Generation || finished.CancelRequestedAt != nil || calls.Load() != 1 {
			t.Fatal("budget interruption became cancellation, recovery, or redispatch")
		}
		assertDerivedConservativeCharge(t, p, finished, attempts[0])
		samples, err := p.tenant.ListExecutionSamples(p.run.ID)
		if err != nil || len(samples) != p.expected {
			t.Fatal("budget closure lost signed samples")
		}
		for _, sample := range samples {
			if sample.CompletedAt == nil || sample.Validity != "NOT_APPLICABLE" || (sample.ID != p.lease.Job.ObjectID && (sample.AttemptCount != 0 || sample.FinalAttemptID != nil)) {
				t.Fatal("budget closure dispatched or abandoned another sample")
			}
		}
		if err := p.queue.CompleteWith(f.ctx, p.lease, result.completion); !errors.Is(err, repository.ErrJobLeaseLost) {
			t.Fatal("budget completion bypassed terminal fence", err)
		}
		assertDerivedInflightFinishedOnce(t, f, p, runner)
	})
}
