package worker

import (
	"context"
	"errors"
	"reflect"
	"sync"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

// RunRecoverySource is a trusted, synchronous, owned recovery-source borrower.
// Use must invoke its callback exactly once and finish it before returning. It
// must not retain/mutate borrowed data concurrently. Implementations supply the
// original repository source, not an HTTP DTO; implementing this interface is
// NOT database authorization. Apply must recheck the original private binding.
type RunRecoverySource interface {
	Use(func(repository.ExecutionReconciliationData) error) error
}

// NewRunRecoveryPreparer only captures feature construction and purpose-only
// derived authentication capabilities, never a credential service or queue.
// The caller supplies a bounded context. No response body, credential, SQL,
// dispatch, queue claim or clock lookup is performed. The result is preparation,
// not a persisted S1 receipt or a drain/backup completion permission.
func NewRunRecoveryPreparer(builder *features.Builder, sealer *features.DerivedSealer) (func(context.Context, RunRecoverySource) (*repository.AttemptDerivedCandidates, error), error) {
	if builder == nil || sealer == nil {
		return nil, ErrConfiguration
	}
	return func(ctx context.Context, source RunRecoverySource) (result *repository.AttemptDerivedCandidates, err error) {
		if ctx == nil || nilRunRecoverySource(source) {
			return nil, ErrConfiguration
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		work, cancel := context.WithCancel(ctx)
		scope := &runRecoveryPrepareScope{ctx: work, cancel: cancel, builder: builder, sealer: sealer}
		returned := false
		defer func() {
			// The explicit returned bit also closes panic(nil) under panicnil=1.
			if !returned {
				_ = recover()
				err = repository.ErrAnalysisSource
			}
			result, err = scope.finish(ctx, err)
		}()
		err = source.Use(scope.use)
		returned = true
		return nil, err
	}, nil
}

type runRecoveryPrepareScope struct {
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	builder  *features.Builder
	sealer   *features.DerivedSealer
	called   bool
	active   bool
	closed   bool
	done     chan struct{}
	failure  error
	prepared *repository.AttemptDerivedCandidates
}

func (s *runRecoveryPrepareScope) use(data repository.ExecutionReconciliationData) (err error) {
	s.mu.Lock()
	if s.closed || s.called {
		s.failure = repository.ErrAnalysisSource
		s.mu.Unlock()
		return repository.ErrAnalysisSource
	}
	s.called, s.active, s.done = true, true, make(chan struct{})
	s.mu.Unlock()
	var prepared *repository.AttemptDerivedCandidates
	returned := false
	defer func() {
		if !returned {
			_ = recover()
			err = repository.ErrAnalysisSource
		}
		err = runRecoveryPrepareError(err)
		s.mu.Lock()
		defer s.mu.Unlock()
		if err != nil && s.failure == nil {
			s.failure = err
		}
		if s.failure != nil || s.closed {
			clearRunRecoveryCandidates(prepared)
			err = s.failure
			if err == nil {
				err = repository.ErrAnalysisSource
			}
		} else {
			s.prepared = prepared
		}
		s.active = false
		close(s.done)
	}()
	prepared, err = prepareRunRecoveryData(s.ctx, s.builder, s.sealer, data)
	returned = true
	return err
}

func (s *runRecoveryPrepareScope) finish(parent context.Context, sourceErr error) (*repository.AttemptDerivedCandidates, error) {
	s.mu.Lock()
	s.closed = true
	if !s.called || s.active {
		s.failure = repository.ErrAnalysisSource
	}
	done, active := s.done, s.active
	s.mu.Unlock()
	s.cancel()
	// A source returning with active work violates the synchronous contract.
	// Cancel and join admitted work before releasing/clearing its buffers. A
	// retained callback invoked after this boundary is rejected without signing;
	// it cannot retroactively revoke a result already returned to the caller.
	if active {
		<-done
	}
	// Error implementations are outside the mutex: even their Is method must
	// not deadlock by attempting to reenter the now-closed borrower.
	sourceErr = runRecoveryPrepareError(sourceErr)
	contextErr := parent.Err()
	s.mu.Lock()
	defer s.mu.Unlock()
	if sourceErr != nil {
		s.failure = sourceErr
	}
	if contextErr != nil {
		s.failure = contextErr
	}
	prepared := s.prepared
	s.prepared = nil
	s.builder, s.sealer, s.ctx, s.cancel, s.done = nil, nil, nil, nil, nil
	if s.failure != nil {
		clearRunRecoveryCandidates(prepared)
		return nil, s.failure
	}
	return prepared, nil
}

func nilRunRecoverySource(source RunRecoverySource) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func prepareRunRecoveryData(ctx context.Context, builder *features.Builder, sealer *features.DerivedSealer, data repository.ExecutionReconciliationData) (*repository.AttemptDerivedCandidates, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch data.Run.AnalysisSourceVersion {
	case repository.AnalysisSourceLegacyV1:
		// Match the repository's original planAnalysisSource mapping: only the
		// empty frozen-plan mode maps to the persisted legacy discriminator.
		if data.Plan.AnalysisSourceVersion != "" {
			return nil, repository.ErrAnalysisSource
		}
		return nil, nil // Preserve legacy; neither inspect S2 nor invent a MAC.
	case domain.AnalysisSourceDerivedV1:
		if data.Plan.AnalysisSourceVersion != domain.AnalysisSourceDerivedV1 {
			return nil, repository.ErrAnalysisSource
		}
	default:
		return nil, repository.ErrAnalysisSource
	}
	if data.Attempt == nil {
		return nil, nil // A real unattempted source has no unavailable S1 to sign.
	}
	// These relationships supplement the original signed-plan/request checks.
	// Do not require terminal Job.status: backup Apply terminalizes a genuinely
	// expired running/pending intent and its domain facts in the SAME transaction.
	if data.Run.ID != data.Sample.RunID || data.Run.OrganizationID != data.Sample.OrganizationID || data.Run.ManifestHash != data.Plan.ManifestHash || data.Job.OrganizationID != data.Sample.OrganizationID || data.Job.ID != data.Attempt.JobID || data.Job.Type != string(repository.JobSampleExecute) || data.Job.ObjectID != data.Sample.ID || data.Attempt.LeaseGeneration <= 0 || data.Attempt.LeaseGeneration > data.Job.AttemptCount {
		return nil, repository.ErrAnalysisSource
	}
	prepared, err := prepareRunDerived(ctx, RunConfig{DerivedBuilder: builder, DerivedSealer: sealer}, data.Plan, data.Sample, *data.Attempt, nil, domain.AttemptOutcome{Validity: "INVALID_RETRYABLE", ErrorCode: "MI_UNCERTAIN_ATTEMPT"}, true)
	if err != nil {
		return nil, err
	}
	return &prepared, nil
}

func clearRunRecoveryCandidates(prepared *repository.AttemptDerivedCandidates) {
	if prepared == nil {
		return
	}
	for i := range prepared.Items {
		clear(prepared.Items[i].Record.Payload)
		clear(prepared.Items[i].Record.MAC)
	}
	*prepared = repository.AttemptDerivedCandidates{}
}

func runRecoveryPrepareError(err error) (safe error) {
	if err == nil {
		return nil
	}
	safe = repository.ErrAnalysisSource
	// Never format an unknown source error. Even a misbehaving custom Is method
	// must not turn a sensitive error or panic into an escaping diagnostic.
	defer func() { _ = recover() }()
	for _, known := range []error{context.Canceled, context.DeadlineExceeded, repository.ErrAnalysisSource, repository.ErrAnalysisLimit, features.ErrBinding, features.ErrLimit, features.ErrConfiguration, ErrConfiguration} {
		if errors.Is(err, known) {
			return known
		}
	}
	return safe
}
