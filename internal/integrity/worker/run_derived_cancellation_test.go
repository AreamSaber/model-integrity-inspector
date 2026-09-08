package worker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
)

// Unlike the ordinary analysis fixture, this signs nonzero synthetic prices.
// The in-flight assertions therefore prove release of real money reservations,
// not merely that an unknown-price zero stayed zero. Nothing edits a Manifest
// or execution snapshot after signing or creates a hand-written S1 feature.
func signedPricedDerivedCancellationRun(t *testing.T, f runFixture) derivedPendingFixture {
	t.Helper()
	target := f.createTarget(t, "max_tokens")
	s, err := f.service.Snapshot(f.ctx, f.orgID, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	artifact, hash, err := templates.Builtin().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := generator.New(artifact, hash, f.tokens, f.ring)
	if err != nil {
		t.Fatal(err)
	}
	builder, err := features.New(features.Config{Verifier: compiler, Tokenizer: f.tokens, TemplateArtifact: artifact, TrustedTemplateHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	price := int64(1000000)
	// Match the production service's pre-signing policy projection. Omitting
	// this priced ceiling would let CreateRun add a field after signing and
	// legitimately fail the exact frozen-plan authentication.
	ceiling := int64(1000000)
	opts := generator.Options{
		AnalysisSourceVersion: domain.AnalysisSourceDerivedV1,
		OrganizationID:        f.orgID,
		Target: domain.ExecutionTarget{ID: s.TargetID, Version: s.TargetVersion, SecretID: s.SecretID, SecretVersion: s.SecretVersion,
			Endpoint: s.Endpoint, Model: s.Model, Protocol: s.Protocol, MaxOutputParameter: "max_tokens", AuthType: s.AuthType,
			AuthHeaderName: s.AuthHeaderName, TimeoutSeconds: s.Options.TimeoutSeconds},
		Package: "quick", Budget: domain.ExecutionBudget{MaxRequests: 20, MaxTokens: 50000, MaxCostMicros: &ceiling, TimeoutSeconds: 900},
		Pricing:     domain.ExecutionPricing{InputMicrosPerMillion: &price, OutputMicrosPerMillion: &price},
		RuleVersion: scoring.Version, ScoringVersion: scoring.Version, ContextWindow: 128000, MaxOutputTokens: 4096,
		SupportsStream: true, Concurrency: 1, MaxRetries: 2,
	}
	manifest, err := compiler.Generate(opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, digest, err := manifest.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := compiler.ExecutionPlan(raw, digest, f.orgID)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := scheduler.NewPolicy(scheduler.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := f.store.WithOrganization(f.ctx, f.orgID)
	if err != nil {
		t.Fatal(err)
	}
	run, err := tenant.CreateRun(plan, policy, "priced-real-cancellation")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Samples) != 18 || plan.Target.TimeoutSeconds < 10 {
		t.Fatal("fixture needs eighteen signed samples and a timeout beyond the cancellation observation window")
	}
	return derivedPendingFixture{tenant: tenant, run: run, builder: builder, expected: len(manifest.Samples)}
}

type derivedCancellationObservation struct {
	completion Completion
	err        error
	jobCause   error
}

func cancelPricedDerivedRun(t *testing.T, p derivedPendingFixture) {
	t.Helper()
	for range 20 {
		run, err := p.tenant.GetRun(p.run.ID)
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.tenant.CancelRun(run.ID, run.Version)
		if errors.Is(err, repository.ErrConflict) {
			continue
		}
		if err != nil {
			t.Fatal("cancel actual signed Run", err)
		}
		return
	}
	t.Fatal("actual Run cancellation remained conflicted")
}

// Both subcases run the real Runner and production handlers. The wrapper only
// observes its actual jobCtx cause and gates the returned completion. For the
// job-only cancellation, this proves Runner.CheckLease cancelled the network
// before subsequently cancelling the business Run to close its other samples.
func TestDerivedWorkerRunnerInFlightTLSCancellationRecordsAuthenticatedOutcome(t *testing.T) {
	for _, mode := range []string{"run_cancel", "runner_job_cancel"} {
		t.Run(mode, func(t *testing.T) {
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
					first := calls.Add(1) == 1
					if first {
						close(started)
					}
					// No response, timer, or test-side context cancellation: the only
					// event which stops this actual TLS handler is client disconnection.
					<-r.Context().Done()
					if first {
						close(stopped)
					}
				}))
				config.RequestTimeout = 30 * time.Second
				config.DerivedBuilder, config.DerivedSealer = p.builder, sealer
				handlers, err := NewRunHandlers(config)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(f.ctx)
				defer cancel()
				dispatched := make(chan Execution, 1)
				observed := make(chan derivedCancellationObservation, 1)
				release := make(chan struct{})
				var releaseOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				original := handlers[repository.JobSampleExecute]
				var first atomic.Bool
				handlers[repository.JobSampleExecute] = func(jobCtx context.Context, execution Execution) (Completion, error) {
					if !first.CompareAndSwap(false, true) {
						return original(jobCtx, execution)
					}
					dispatched <- execution
					completion, err := original(jobCtx, execution)
					observed <- derivedCancellationObservation{completion, err, context.Cause(jobCtx)}
					select {
					case <-release:
						return completion, err
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				var log executionLogBuffer
				runner, err := New(Config{Store: f.store, Handlers: handlers, Logger: slog.New(slog.NewTextHandler(&log, nil)), PollInterval: 10 * time.Millisecond, HeartbeatInterval: 40 * time.Millisecond})
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan struct{})
				var runnerError error
				go func() { runnerError = runner.Run(ctx); close(done) }()
				t.Cleanup(func() {
					unblock()
					cancel()
					select {
					case <-done:
						if runnerError != nil {
							t.Errorf("real Runner failed during cancellation: %v", runnerError)
						}
					case <-time.After(7 * time.Second):
						t.Error("real Runner did not stop within shutdown bound")
					}
					if t.Failed() {
						t.Log(log.String())
					}
				})
				select {
				case execution := <-dispatched:
					p.queue, p.lease = execution.Queue, execution.Lease
				case <-time.After(5 * time.Second):
					t.Fatal("real Runner did not dispatch the first signed sample")
				}
				select {
				case <-started:
				case <-time.After(5 * time.Second):
					t.Fatal("real TLS request did not start")
				}
				inFlight, err := p.tenant.GetRun(p.run.ID)
				if err != nil || inFlight.RequestCount != 1 || inFlight.ReservedTokens <= 0 || inFlight.ReservedCostMicros <= 0 || !inFlight.CostKnown {
					t.Fatal("in-flight request did not hold actual token and money reservations")
				}
				rejectDerivedBodyInserts(t, f)
				select {
				case <-stopped:
					t.Fatal("TLS request ended before any cancellation was requested")
				default:
				}
				began := time.Now()
				if mode == "run_cancel" {
					cancelPricedDerivedRun(t, p)
					if err := p.queue.CheckLease(f.ctx, p.lease); err != nil {
						t.Fatal("business cancellation incorrectly cancelled the Job lease", err)
					}
				} else {
					// The actual Runner must discover this Job flag itself. Neither
					// this test nor the handler wrapper cancels jobCtx or callCtx.
					if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_jobs SET cancel_requested_at=$1 WHERE organization_id=$2 AND id=$3", time.Now().UTC(), f.orgID, p.lease.Job.ID); err != nil {
						t.Fatal("set actual Job cancellation request", err)
					}
				}
				select {
				case <-stopped:
					if time.Since(began) >= 5*time.Second {
						t.Fatal("actual network cancellation exceeded observation window")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("TLS server never observed client cancellation")
				}
				var observation derivedCancellationObservation
				select {
				case observation = <-observed:
				case <-time.After(3 * time.Second):
					t.Fatal("production handler did not prepare cancellation completion")
				}
				if observation.err != nil || observation.completion == nil {
					t.Fatal("production handler lost its cancellation settlement", observation.err)
				}
				if mode == "run_cancel" {
					if observation.jobCause != nil {
						t.Fatal("business Run cancellation was not isolated to callCtx", observation.jobCause)
					}
				} else {
					if !errors.Is(observation.jobCause, repository.ErrJobCancelled) {
						t.Fatal("actual Runner did not supply the typed Job cancellation cause", observation.jobCause)
					}
					unchanged, err := p.tenant.GetRun(p.run.ID)
					if err != nil || unchanged.CancelRequestedAt != nil || unchanged.Status != "RUNNING" {
						t.Fatal("business Run cancellation contaminated the Runner cause test")
					}
					// Only after real network stop and the typed Runner cause have
					// been observed, close the other seventeen unattempted samples.
					cancelPricedDerivedRun(t, p)
				}
				p.completion = observation.completion
				unblock()
				finished := awaitRunClosed(t, p.tenant, p.run.ID)
				if finished.Status != "CANCELLED" || finished.RequestCount != 1 || finished.ValidSampleCount != 0 || finished.ReservedTokens != 0 || finished.ReservedCostMicros != 0 || calls.Load() != 1 {
					t.Fatal("cancelled Run did not release reservations and close without redispatch")
				}
				select {
				case <-done:
					t.Fatal("closing the eighteen-sample Run terminated the live Runner", runnerError)
				default:
				}
				if !runner.Ready() {
					t.Fatal("Runner lost readiness while closing unattempted samples")
				}
				verifySettledDerivedAttempt(t, f, p, "COMPLETED", "NOT_APPLICABLE", "MI_EXECUTION_CANCELLED")
				attempts, err := p.tenant.ListAttempts(p.lease.Job.ObjectID)
				if err != nil || len(attempts) != 1 || attempts[0].DerivedReceipt != repository.DerivedRecorded || attempts[0].FinishedAt == nil || attempts[0].LeaseGeneration != p.lease.Generation || attempts[0].AttemptNo != 1 {
					t.Fatal("cancellation fell through to uncertain recovery or a different generation")
				}
				if attempts[0].TotalTokens == nil || finished.TokenCount != *attempts[0].TotalTokens || finished.EstimatedCostMicros != attempts[0].BilledEstimateMicros || finished.EstimatedCostMicros <= 0 {
					t.Fatal("cancelled in-flight request lost its one conservative charge")
				}
				samples, err := p.tenant.ListExecutionSamples(p.run.ID)
				if err != nil || len(samples) != p.expected {
					t.Fatal("wrong closed logical sample set")
				}
				for _, sample := range samples {
					if sample.CompletedAt == nil || sample.Validity != "NOT_APPLICABLE" {
						t.Fatal("unattempted cancellation samples did not close")
					}
					if sample.ID != p.lease.Job.ObjectID && (sample.AttemptCount != 0 || sample.FinalAttemptID != nil) {
						t.Fatal("cancelled unattempted sample acquired an Attempt")
					}
				}
				var incompleteJobs int
				if err := f.db.QueryRowContext(f.ctx, "SELECT count(*) FROM integrity_jobs j JOIN integrity_logical_samples s ON s.organization_id=j.organization_id AND s.job_id=j.id WHERE s.organization_id=$1 AND s.run_id=$2 AND j.status<>'completed'", f.orgID, p.run.ID).Scan(&incompleteJobs); err != nil || incompleteJobs != 0 {
					t.Fatal("closing unattempted samples failed or abandoned their Jobs")
				}
				derivedCounts(t, f, p.run.ID, 1, 0)
				if err := p.queue.CompleteWith(f.ctx, p.lease, p.completion); !errors.Is(err, repository.ErrJobLeaseLost) {
					t.Fatal("original cancellation completion bypassed terminal fencing", err)
				}
				derivedCounts(t, f, p.run.ID, 1, 0)
				var finishes int
				if err := f.db.QueryRowContext(f.ctx, "SELECT count(*) FROM integrity_audit_logs WHERE organization_id=$1 AND action='run.attempt.finish'", f.orgID).Scan(&finishes); err != nil || finishes != 1 {
					t.Fatal("terminal replay duplicated the cancellation audit")
				}
			})
		})
	}
}
