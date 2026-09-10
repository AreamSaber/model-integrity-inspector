package worker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

type runRecoveryTestMAC struct {
	inner features.DerivedAuthenticator
	calls atomic.Int32
	hook  func()
}

func (m *runRecoveryTestMAC) DerivedMAC(version string, data []byte) ([]byte, error) {
	m.calls.Add(1)
	if m.hook != nil {
		m.hook()
	}
	return m.inner.DerivedMAC(version, data)
}

func TestRunRecoveryPrepareLegacyAndUnattemptedDoNotSign(t *testing.T) {
	for _, mode := range []string{"legacy-with-attempt", "legacy-unattempted", "derived-unattempted"} {
		t.Run(mode, func(t *testing.T) {
			f := newRunDerivedFixture(t)
			mac := &runRecoveryTestMAC{inner: f.mac, hook: func() { t.Error("non-derived recovery used MAC capability") }}
			sealer, _, err := features.NewDerivedCapabilitiesWithMAC("PREPARE.v1", mac)
			if err != nil {
				t.Fatal(err)
			}
			prepare, err := NewRunRecoveryPreparer(f.config.DerivedBuilder, sealer)
			if err != nil {
				t.Fatal(err)
			}
			data := runRecoveryTestData(f)
			if mode != "derived-unattempted" {
				data.Run.AnalysisSourceVersion, data.Plan.AnalysisSourceVersion = repository.AnalysisSourceLegacyV1, ""
			}
			if mode != "legacy-with-attempt" {
				data.Attempt = nil
			}
			result, err := prepare(t.Context(), runRecoveryTestSource(func(fn func(repository.ExecutionReconciliationData) error) error { return fn(data) }))
			if err != nil || result != nil || mac.calls.Load() != 0 {
				t.Fatal("legacy or unattempted source acquired fabricated S1", err)
			}
		})
	}
}

func TestRunRecoveryPrepareRejectsNilBindingsAndCancelledSources(t *testing.T) {
	f := newRunDerivedFixture(t)
	for _, mode := range []string{"nil-context", "nil-source", "typed-nil-source", "cancel-before", "deadline-before", "run-id", "run-org", "run-manifest", "plan-version", "legacy-derived-plan", "legacy-unknown-plan", "job-id", "job-org", "job-object", "job-type", "generation-zero", "generation-future", "MAC-failure", "MAC-cancel"} {
		t.Run(mode, func(t *testing.T) {
			data := runRecoveryTestData(f)
			attempt := *data.Attempt
			data.Attempt = &attempt
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			mac := &runRecoveryTestMAC{inner: f.mac}
			sealer, _, err := features.NewDerivedCapabilitiesWithMAC("PREPARE.v1", mac)
			if err != nil {
				t.Fatal(err)
			}
			prepare, err := NewRunRecoveryPreparer(f.config.DerivedBuilder, sealer)
			if err != nil {
				t.Fatal(err)
			}
			var source RunRecoverySource = runRecoveryTestSource(func(fn func(repository.ExecutionReconciliationData) error) error { return fn(data) })
			switch mode {
			case "nil-context":
				ctx = nil
			case "nil-source":
				source = nil
			case "typed-nil-source":
				source = runRecoveryTestSource(nil)
			case "cancel-before":
				cancel()
			case "deadline-before":
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(ctx, time.Unix(1, 0))
				defer stop()
			case "run-id":
				data.Run.ID++
			case "run-org":
				data.Run.OrganizationID++
			case "run-manifest":
				data.Run.ManifestHash = "invalid"
			case "plan-version":
				data.Plan.AnalysisSourceVersion = "unknown-source-v99"
			case "legacy-derived-plan":
				data.Run.AnalysisSourceVersion = repository.AnalysisSourceLegacyV1
			case "legacy-unknown-plan":
				data.Run.AnalysisSourceVersion = repository.AnalysisSourceLegacyV1
				data.Plan.AnalysisSourceVersion = "unknown-source-v99"
			case "job-id":
				data.Job.ID++
			case "job-org":
				data.Job.OrganizationID++
			case "job-object":
				data.Job.ObjectID++
			case "job-type":
				data.Job.Type = string(repository.JobRunPlan)
			case "generation-zero":
				data.Attempt.LeaseGeneration = 0
			case "generation-future":
				data.Attempt.LeaseGeneration = data.Job.AttemptCount + 1
			case "MAC-failure":
				mac.inner = &runDerivedFailMAC{inner: f.mac, fail: 1}
			case "MAC-cancel":
				mac.hook = cancel
			}
			result, err := prepare(ctx, source)
			if err == nil || result != nil {
				t.Fatal("invalid authority-free source was accepted or released a candidate")
			}
			if (mode == "cancel-before" || mode == "MAC-cancel") && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation was hidden", err)
			}
		})
	}
	if prepare, err := NewRunRecoveryPreparer(nil, f.config.DerivedSealer); prepare != nil || !errors.Is(err, ErrConfiguration) {
		t.Fatal("missing builder accepted")
	}
	if prepare, err := NewRunRecoveryPreparer(f.config.DerivedBuilder, nil); prepare != nil || !errors.Is(err, ErrConfiguration) {
		t.Fatal("missing sealer accepted")
	}
}

func TestRunRecoveryPrepareSourceAndMACPanicsAreClosed(t *testing.T) {
	for _, where := range []string{"source-before", "source-after", "MAC"} {
		for _, value := range []any{"private-canary-panic", nil} {
			t.Run(fmt.Sprintf("%s/nil_%v", where, value == nil), func(t *testing.T) {
				f := newRunDerivedFixture(t)
				mac := &runRecoveryTestMAC{inner: f.mac}
				if where == "MAC" {
					mac.hook = func() { panic(value) }
				}
				sealer, _, err := features.NewDerivedCapabilitiesWithMAC("PREPARE.v1", mac)
				if err != nil {
					t.Fatal(err)
				}
				prepare, err := NewRunRecoveryPreparer(f.config.DerivedBuilder, sealer)
				if err != nil {
					t.Fatal(err)
				}
				result, err := prepare(t.Context(), runRecoveryTestSource(func(fn func(repository.ExecutionReconciliationData) error) error {
					if where == "source-before" {
						panic(value)
					}
					if err := fn(runRecoveryTestData(f)); err != nil {
						return err
					}
					if where == "source-after" {
						panic(value)
					}
					return nil
				}))
				if result != nil || !errors.Is(err, repository.ErrAnalysisSource) {
					t.Fatal("panic escaped scoped zero-result boundary", err)
				}
			})
		}
	}
}

func TestRunRecoveryPrepareReentrantAndLateBorrowersCannotSign(t *testing.T) {
	for _, reentrant := range []bool{false, true} {
		t.Run(fmt.Sprintf("reentrant_%v", reentrant), func(t *testing.T) {
			f := newRunDerivedFixture(t)
			data := runRecoveryTestData(f)
			var borrowed func(repository.ExecutionReconciliationData) error
			mac := &runRecoveryTestMAC{inner: f.mac}
			if reentrant {
				mac.hook = func() {
					if err := borrowed(data); !errors.Is(err, repository.ErrAnalysisSource) {
						t.Error("reentrant borrower succeeded")
					}
				}
			}
			sealer, _, err := features.NewDerivedCapabilitiesWithMAC("PREPARE.v1", mac)
			if err != nil {
				t.Fatal(err)
			}
			prepare, err := NewRunRecoveryPreparer(f.config.DerivedBuilder, sealer)
			if err != nil {
				t.Fatal(err)
			}
			result, err := prepare(t.Context(), runRecoveryTestSource(func(fn func(repository.ExecutionReconciliationData) error) error {
				borrowed = fn
				_ = fn(data) // Deliberately swallow reentry failure.
				return nil
			}))
			if reentrant {
				if result != nil || err == nil {
					t.Fatal("swallowed reentry released candidates")
				}
			} else if result == nil || err != nil {
				t.Fatal("valid synchronous borrower failed", err)
			}
			if mac.calls.Load() != 1 {
				t.Fatal("reentry invoked the actual MAC twice")
			}
			if err := borrowed(data); !errors.Is(err, repository.ErrAnalysisSource) || mac.calls.Load() != 1 {
				t.Fatal("escaped borrower signed after scope completion")
			}
			if result != nil {
				verifyRunDerivedCandidate(t, f, result.Items[0], nil)
			}
		})
	}
}

func TestRunRecoveryPrepareReturningWithActiveBorrowerCancelsAndJoins(t *testing.T) {
	f := newRunDerivedFixture(t)
	entered, release, sourceReturning := make(chan struct{}), make(chan struct{}), make(chan struct{})
	finished, callbackFinished := make(chan struct{}), make(chan struct{})
	var callbackStarted atomic.Bool
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	ctx, cancel := context.WithCancel(t.Context())
	mac := &runRecoveryTestMAC{inner: f.mac, hook: func() { close(entered); <-release }}
	sealer, _, err := features.NewDerivedCapabilitiesWithMAC("PREPARE.v1", mac)
	if err != nil {
		t.Fatal(err)
	}
	prepare, err := NewRunRecoveryPreparer(f.config.DerivedBuilder, sealer)
	if err != nil {
		t.Fatal(err)
	}
	var result *repository.AttemptDerivedCandidates
	var prepareErr error
	t.Cleanup(func() {
		cancel()
		unblock()
		<-finished
		if callbackStarted.Load() {
			<-callbackFinished
		}
	})
	go func() {
		defer close(finished)
		result, prepareErr = prepare(ctx, runRecoveryTestSource(func(fn func(repository.ExecutionReconciliationData) error) error {
			callbackStarted.Store(true)
			go func() { defer close(callbackFinished); _ = fn(runRecoveryTestData(f)) }()
			select {
			case <-entered:
			case <-callbackFinished:
				return repository.ErrAnalysisSource
			case <-ctx.Done():
				return ctx.Err()
			}
			close(sourceReturning)
			return nil // Deliberate synchronous-source contract violation.
		}))
	}()
	select {
	case <-sourceReturning:
	case <-time.After(5 * time.Second):
		t.Fatal("actual MAC barrier was not reached")
	}
	cancel()
	select {
	case <-finished:
		t.Fatal("scope returned before its admitted borrower stopped")
	case <-time.After(25 * time.Millisecond):
	}
	unblock()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("scope failed to join released borrower")
	}
	if result != nil || !errors.Is(prepareErr, context.Canceled) || mac.calls.Load() != 1 {
		t.Fatal("active callback escaped cancellation or produced a success result", prepareErr)
	}
}

func TestRunRecoveryPreparePreservesPendingAndRunningJobIdentity(t *testing.T) {
	for _, status := range []string{"pending", "running", "failed", "cancelled"} {
		t.Run(status, func(t *testing.T) {
			f := newRunDerivedFixture(t)
			prepare, err := NewRunRecoveryPreparer(f.config.DerivedBuilder, f.config.DerivedSealer)
			if err != nil {
				t.Fatal(err)
			}
			data := runRecoveryTestData(f)
			data.Job.Status = status
			data.Attempt.ResponseMeta = "private-body-canary-not-a-response-source"
			result, err := prepare(t.Context(), runRecoveryTestSource(func(fn func(repository.ExecutionReconciliationData) error) error { return fn(data) }))
			if err != nil || result == nil || result.Scope.JobID != data.Job.ID || data.Job.Status != status || data.Run.AnalysisSourceVersion != domain.AnalysisSourceDerivedV1 {
				t.Fatal("preparation terminalized or rewrote original input", err)
			}
			verifyRunDerivedCandidate(t, f, result.Items[0], nil)
		})
	}
}

func TestRunRecoveryPrepareOwnedCandidatesClearOnLateFailure(t *testing.T) {
	f := newRunDerivedFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	scope := &runRecoveryPrepareScope{ctx: ctx, cancel: cancel, builder: f.config.DerivedBuilder, sealer: f.config.DerivedSealer}
	if err := scope.use(runRecoveryTestData(f)); err != nil || scope.prepared == nil || len(scope.prepared.Items) != 1 {
		t.Fatal("actual candidate was not prepared", err)
	}
	owned := scope.prepared
	payload, mac := owned.Items[0].Record.Payload, owned.Items[0].Record.MAC
	result, err := scope.finish(t.Context(), errors.New("private-canary-after-actual-MAC"))
	if result != nil || !errors.Is(err, repository.ErrAnalysisSource) || len(owned.Items) != 0 || owned.Scope != (repository.AttemptDerivedScope{}) || scope.prepared != nil || scope.builder != nil || scope.sealer != nil || scope.ctx != nil || scope.cancel != nil {
		t.Fatal("failed scope retained owned candidates or capabilities", err)
	}
	for _, value := range append(payload, mac...) {
		if value != 0 {
			t.Fatal("failed scope did not clear actual owned payload/MAC buffers")
		}
	}
}

type runRecoveryTestReentrantError struct {
	use   func(repository.ExecutionReconciliationData) error
	data  repository.ExecutionReconciliationData
	panic bool
}

func (*runRecoveryTestReentrantError) Error() string { panic("private-canary-must-not-format") }
func (e *runRecoveryTestReentrantError) Is(error) bool {
	_ = e.use(e.data)
	if e.panic {
		panic(nil)
	}
	return false
}

func TestRunRecoveryPrepareErrorInspectionDoesNotHoldBorrowerLock(t *testing.T) {
	for _, panicIs := range []bool{false, true} {
		t.Run(fmt.Sprintf("panic_%v", panicIs), func(t *testing.T) {
			f := newRunDerivedFixture(t)
			prepare, err := NewRunRecoveryPreparer(f.config.DerivedBuilder, f.config.DerivedSealer)
			if err != nil {
				t.Fatal(err)
			}
			result, err := prepare(t.Context(), runRecoveryTestSource(func(fn func(repository.ExecutionReconciliationData) error) error {
				data := runRecoveryTestData(f)
				if err := fn(data); err != nil {
					return err
				}
				return &runRecoveryTestReentrantError{fn, data, panicIs}
			}))
			if result != nil || !errors.Is(err, repository.ErrAnalysisSource) {
				t.Fatal("custom source error escaped closed normalization")
			}
		})
	}
}
