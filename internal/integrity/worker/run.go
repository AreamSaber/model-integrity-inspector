package worker

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/evidencedisplay"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/safehttp"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

type RunConfig struct {
	Store        *repository.Store
	Secrets      *secret.Service
	EvidenceKeys *secret.KeyRing
	// Optional trusted startup override; otherwise derived once from EvidenceKeys.
	// This capability cannot decrypt either credentials or analysis evidence.
	DisplaySealer *secret.DisplaySealer
	// Both capabilities are required for signed derived-source Runs. Legacy
	// confirmed Runs keep their original source mode; missing capabilities never
	// authorize a derived-to-raw fallback.
	DerivedBuilder *features.Builder
	DerivedSealer  *features.DerivedSealer
	Tokenizer      *tokenizer.Engine
	URLPolicy      safehttp.URLPolicy
	Resolver       safehttp.Resolver
	DialContext    safehttp.DialContextFunc
	RootCAs        *x509.CertPool
	// Trusted administrator/test ceilings, never request-controlled overrides.
	RequestTimeout   time.Duration
	LivenessInterval time.Duration
}

func NewRunHandlers(config RunConfig) (map[repository.JobType]Handler, error) {
	if config.Store == nil || config.Secrets == nil || config.EvidenceKeys == nil {
		return nil, ErrConfiguration
	}
	if (config.DerivedBuilder == nil) != (config.DerivedSealer == nil) {
		return nil, ErrConfiguration
	}
	if config.DisplaySealer == nil {
		var err error
		config.DisplaySealer, _, err = config.EvidenceKeys.NewDisplayCapabilities(nil)
		if err != nil {
			return nil, ErrConfiguration
		}
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 180 * time.Second
	}
	if config.LivenessInterval == 0 {
		config.LivenessInterval = 250 * time.Millisecond
	}
	if config.RequestTimeout <= 0 || config.RequestTimeout > 180*time.Second || config.LivenessInterval <= 0 || config.LivenessInterval > time.Second {
		return nil, ErrConfiguration
	}
	if _, err := safehttp.ValidateEndpoint("https://validation.invalid/v1", config.URLPolicy); err != nil {
		return nil, ErrConfiguration
	}
	if config.Tokenizer == nil {
		engine, err := tokenizer.NewBuiltin()
		if err != nil {
			return nil, ErrConfiguration
		}
		config.Tokenizer = engine
	}
	config.URLPolicy.PrivateCIDRAllowlist = append([]string(nil), config.URLPolicy.PrivateCIDRAllowlist...)
	config.URLPolicy.BlockedCIDRs = append([]string(nil), config.URLPolicy.BlockedCIDRs...)
	if config.RootCAs != nil {
		config.RootCAs = config.RootCAs.Clone()
	}
	return map[repository.JobType]Handler{
		repository.JobRunPlan: func(ctx context.Context, execution Execution) (Completion, error) {
			if execution.Queue == nil || repository.JobType(execution.Lease.Job.Type) != repository.JobRunPlan {
				return nil, repository.ErrJobInvalid
			}
			tenant, err := config.Store.WithOrganization(ctx, execution.Lease.Job.OrganizationID)
			if err != nil {
				return nil, err
			}
			plan, err := tenant.GetExecutionPlan(execution.Lease.Job.ObjectID)
			if err != nil {
				return nil, err
			}
			if plan.AnalysisSourceVersion == domain.AnalysisSourceDerivedV1 {
				if config.DerivedBuilder == nil || config.DerivedSealer == nil {
					return nil, ErrConfiguration
				}
				return func(tx *repository.TenantTransaction) error {
					return tx.StartRunWithDerivedSource(execution.Lease.Job.ObjectID)
				}, nil
			}
			if plan.AnalysisSourceVersion != "" {
				return nil, repository.ErrAnalysisSource
			}
			return func(tx *repository.TenantTransaction) error { return tx.StartRun(execution.Lease.Job.ObjectID) }, nil
		},
		repository.JobSampleExecute: func(ctx context.Context, execution Execution) (Completion, error) {
			return executeRunSample(ctx, execution, config)
		},
	}, nil
}

// ReconcileRunJobs plugs into maintenance on the Runner's existing queue. It
// does not open another SQLite consumer and never executes an analysis handler.
func ReconcileRunJobs(ctx context.Context, queue *repository.JobQueue) error {
	if queue == nil {
		return ErrConfiguration
	}
	return queue.ReconcileRunJobs(ctx)
}

func executeRunSample(ctx context.Context, execution Execution, config RunConfig) (Completion, error) {
	if execution.Queue == nil || repository.JobType(execution.Lease.Job.Type) != repository.JobSampleExecute {
		return nil, repository.ErrJobInvalid
	}
	tenant, err := config.Store.WithOrganization(ctx, execution.Lease.Job.OrganizationID)
	if err != nil {
		return nil, err
	}
	sample, err := tenant.GetExecutionSampleForWorker(execution.Lease.Job.ObjectID)
	if err != nil {
		return nil, err
	}
	if sample.JobID == nil || *sample.JobID != execution.Lease.Job.ID {
		return nil, repository.ErrJobInvalid
	}
	unstarted := func() (Completion, error) {
		return func(tx *repository.TenantTransaction) error { return tx.FinishUnattemptedSample(sample.ID) }, nil
	}
	failLocal := func(code string) (Completion, error) {
		return func(tx *repository.TenantTransaction) error { return tx.FailUnattemptedSample(sample.ID, code) }, nil
	}
	attempts, err := tenant.ListAttempts(sample.ID)
	if err != nil {
		return nil, err
	}
	plan, err := tenant.GetExecutionPlan(sample.RunID)
	if err != nil {
		return nil, err
	}
	derived := plan.AnalysisSourceVersion == domain.AnalysisSourceDerivedV1
	if plan.AnalysisSourceVersion != "" && !derived {
		return nil, repository.ErrAnalysisSource
	}
	if derived && (config.DerivedBuilder == nil || config.DerivedSealer == nil) {
		return nil, ErrConfiguration
	}
	for _, attempt := range attempts {
		if attempt.Status == "DISPATCHED" {
			if derived {
				deriveCtx, stop := runDerivationContext(ctx)
				defer stop()
				candidates, err := prepareRunDerived(deriveCtx, config, plan, sample, attempt, nil, domain.AttemptOutcome{Validity: "INVALID_RETRYABLE", ErrorCode: "MI_UNCERTAIN_ATTEMPT"}, true)
				if err != nil {
					return nil, err
				}
				return func(tx *repository.TenantTransaction) error {
					return tx.RecoverInterruptedSampleWithDerived(sample.ID, attempt.ID, candidates)
				}, nil
			}
			return func(tx *repository.TenantTransaction) error { return tx.RecoverInterruptedSample(sample.ID) }, nil
		}
	}
	if err := tenant.CheckExecution(sample.RunID); err != nil {
		if executionStop(err) {
			return unstarted()
		}
		return nil, err
	}
	var samplePlan domain.SamplePlan
	if len(plan.Manifest) == 0 || json.Unmarshal([]byte(sample.RequestPlan), &samplePlan) != nil || plan.Versions.Tokenizer != config.Tokenizer.Version() || plan.Target.Protocol != "openai_chat" || (plan.Target.AuthType != "bearer" && plan.Target.AuthType != "custom_header") || plan.Target.TimeoutSeconds < 1 || plan.Target.TimeoutSeconds > 180 {
		return failLocal("MI_PROTOCOL_UNSUPPORTED")
	}
	callCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		ticker := time.NewTicker(config.LivenessInterval)
		defer ticker.Stop()
		for {
			select {
			case <-callCtx.Done():
				return
			case <-ticker.C:
				checkCtx, stop := context.WithTimeout(callCtx, 2*time.Second)
				bound, e := config.Store.WithOrganization(checkCtx, sample.OrganizationID)
				if e == nil {
					e = bound.CheckExecution(sample.RunID)
				}
				stop()
				if e != nil {
					cancel(e)
					return
				}
			}
		}
	}()
	defer func() { cancel(nil); <-watchDone }()
	var result runCallResult
	credentialError := config.Secrets.WithCredentialsForWorker(callCtx, secret.Scope{OrganizationID: sample.OrganizationID, SecretID: plan.Target.SecretID, SecretVersion: plan.Target.SecretVersion}, func(credentials secret.Credentials) error {
		return credentials.Use(func(key []byte, headers map[string][]byte) error {
			result = callRunSample(callCtx, execution, config, plan, sample, samplePlan, key, headers)
			if result.attempt.ID != 0 {
				result.bodies, result.display = captureRunResponseBody(callCtx, execution, config.DisplaySealer, samplePlan.Request, result, key, headers)
			}
			return nil
		})
	})
	if result.attempt.ID == 0 {
		guard := result.guardError
		if guard == nil {
			guard = context.Cause(callCtx)
		}
		if executionStop(guard) {
			return unstarted()
		}
		if errors.Is(guard, repository.ErrExecutionLimit) || errors.Is(guard, repository.ErrExecutionRPM) {
			return func(tx *repository.TenantTransaction) error { return tx.DeferExecutionSample(sample.ID) }, nil
		}
		if guard != nil {
			return nil, guard
		}
		if credentialError != nil {
			return failLocal("MI_SECRET_UNAVAILABLE")
		}
		return failLocal("MI_PROTOCOL_UNSUPPORTED")
	}
	if credentialError != nil {
		return nil, repository.ErrUnavailable
	}
	if cause := context.Cause(callCtx); cause != nil {
		if errors.Is(cause, repository.ErrUnavailable) || errors.Is(cause, repository.ErrJobLeaseLost) {
			return nil, cause
		}
		if errors.Is(cause, repository.ErrExecutionCancelled) || errors.Is(cause, repository.ErrJobCancelled) {
			result.outcome.Validity = "NOT_APPLICABLE"
			result.outcome.ErrorCode = "MI_EXECUTION_CANCELLED"
		} else if errors.Is(cause, repository.ErrExecutionStale) {
			result.outcome.Validity = "NOT_APPLICABLE"
			result.outcome.ErrorCode = "MI_EXECUTION_TARGET_STALE"
		} else if errors.Is(cause, repository.ErrExecutionCircuitOpen) && (result.outcome.ErrorCode == "MI_EXECUTION_CANCELLED" || result.outcome.ErrorCode == "MI_NETWORK_TEMPORARY" || result.outcome.ErrorCode == "MI_TIMEOUT") {
			// A fully received result remains evidence; only I/O interrupted by
			// the circuit is labelled as stopped by it, never as user cancellation.
			// net/http can surface a typed context cancellation cause as a network
			// error, so the trusted watcher cause disambiguates those failures.
			result.outcome.Validity = "NOT_APPLICABLE"
			result.outcome.ErrorCode = "MI_EXECUTION_CIRCUIT_OPEN"
		}
	}
	scope := secret.EvidenceScope{OrganizationID: sample.OrganizationID, RunID: sample.RunID, LogicalSampleID: sample.ID, AttemptID: result.attempt.ID, RequestHash: result.attempt.RequestHash}
	sealed, err := config.EvidenceKeys.EncryptResponseEvidence(scope, result.response)
	if errors.Is(err, secret.ErrEvidenceLimit) {
		result.outcome.Validity = "INVALID_SAFETY_LIMIT"
		result.outcome.ErrorCode = "MI_EVIDENCE_LIMIT"
		// Preserve the loss classification without disguising a truncated body as
		// complete evidence. Usage/cost remain on the separately settled Attempt.
		minimal := domain.NormalizedResponse{HTTPStatus: result.response.HTTPStatus, ParseStatus: "invalid", EndCause: "client_safety_limit", ParseWarnings: []string{"MI_EVIDENCE_LIMIT"}, DurationMs: result.response.DurationMs}
		result.response = minimal
		sealed, err = config.EvidenceKeys.EncryptResponseEvidence(scope, minimal)
	}
	if err != nil {
		return nil, repository.ErrUnavailable
	}
	evidence := repository.ResponseEvidenceRecord{OrganizationID: scope.OrganizationID, RunID: scope.RunID, LogicalSampleID: scope.LogicalSampleID, AttemptID: scope.AttemptID, RequestHash: scope.RequestHash, KeyVersion: sealed.KeyVersion, Nonce: sealed.Nonce, Ciphertext: sealed.Ciphertext, PlaintextBytes: sealed.PlaintextBytes, ContentHash: sealed.ContentHash}
	var bodies *repository.AttemptBodyCapture
	if result.bodies != nil {
		bodies, err = result.bodies.WithRecords(evidence, result.display)
		if err != nil {
			return nil, err
		}
	}
	if derived {
		deriveCtx, stop := runDerivationContext(ctx)
		defer stop()
		candidates, err := prepareRunDerived(deriveCtx, config, plan, sample, result.attempt, &result.response, result.outcome, false)
		if err != nil {
			return nil, err
		}
		return func(tx *repository.TenantTransaction) error {
			return tx.FinishAttemptWithDerived(sample.ID, result.attempt.ID, result.outcome, result.jitter, candidates, bodies)
		}, nil
	}
	return func(tx *repository.TenantTransaction) error {
		return tx.FinishLegacyAttemptWithCapture(sample.ID, result.attempt.ID, result.outcome, result.jitter, bodies)
	}, nil
}

// captureRunDisplay is called only inside the actual Credentials.Use callback,
// after the adapter/tokenizer have finalized the unchanged analysis response.
// Its independent bounded failure never mutates response, outcome or parent ctx.
func captureRunDisplay(ctx context.Context, execution Execution, sealer *secret.DisplaySealer, request domain.NormalizedRequest, result runCallResult, key []byte, headers map[string][]byte) repository.DisplayEvidenceRecord {
	return captureRunDisplayUsingBinding(ctx, execution, sealer, request, result, key, headers, nil)
}

func captureRunDisplayUsingBinding(ctx context.Context, execution Execution, sealer *secret.DisplaySealer, request domain.NormalizedRequest, result runCallResult, key []byte, headers map[string][]byte, captured *repository.DisplayEvidenceRecord) repository.DisplayEvidenceRecord {
	base := repository.DisplayEvidenceRecord{OrganizationID: result.attempt.OrganizationID, RunID: result.attempt.RunID, LogicalSampleID: result.attempt.LogicalSampleID, AttemptID: result.attempt.ID, RequestHash: result.attempt.RequestHash, Policy: repository.DisplayEvidencePolicy}
	failure := func(state string) repository.DisplayEvidenceRecord { v := base; v.State = state; return v }
	displayCtx, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	if displayCtx.Err() != nil {
		return failure(repository.DisplayUnavailableCancelled)
	}
	// Bound before decoding. This is the already-persisted pre-auth snapshot,
	// never the outbound request whose Header map contains authentication.
	if len(result.attempt.RequestSnapshot) == 0 || len(result.attempt.RequestSnapshot) > (2<<20) {
		return failure(repository.DisplayUnavailableSource)
	}
	var snapshot domain.RequestSnapshot
	decoder := json.NewDecoder(bytes.NewBufferString(result.attempt.RequestSnapshot))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&snapshot) != nil || decoder.Decode(new(any)) != io.EOF || snapshot.RequestHash != result.attempt.RequestHash {
		return failure(repository.DisplayUnavailableSource)
	}
	defer clear(snapshot.Payload)
	var bound repository.DisplayEvidenceRecord
	var err error
	if captured != nil {
		bound = *captured
	} else {
		err = execution.Queue.WithLease(displayCtx, execution.Lease, func(tx *repository.TenantTransaction) error {
			var err error
			bound, err = tx.BindAttemptDisplayCapture(result.attempt.LogicalSampleID, result.attempt.ID, result.attempt.RequestHash)
			return err
		})
	}
	if err != nil {
		if displayCtx.Err() != nil {
			return failure(repository.DisplayUnavailableCancelled)
		}
		return failure(repository.DisplayUnavailableCapture)
	}
	prepared, err := evidencedisplay.Prepare(displayCtx, evidencedisplay.Source{Request: request, Snapshot: snapshot, Response: result.response}, key, headers)
	if err != nil {
		switch {
		case errors.Is(err, evidencedisplay.ErrCancelled):
			return failure(repository.DisplayUnavailableCancelled)
		case errors.Is(err, evidencedisplay.ErrPolicy):
			return failure(repository.DisplayUnavailablePolicy)
		case errors.Is(err, evidencedisplay.ErrLimit):
			return failure(repository.DisplayUnavailableLimit)
		default:
			return failure(repository.DisplayUnavailableSource)
		}
	}
	defer prepared.Close()
	sourceHash, _ := prepared.Hashes()
	binding := secret.DisplayBinding{Scope: secret.EvidenceScope{OrganizationID: bound.OrganizationID, RunID: bound.RunID, LogicalSampleID: bound.LogicalSampleID, AttemptID: bound.AttemptID, RequestHash: bound.RequestHash}, SourceHash: sourceHash, CapturedAtMicros: bound.CapturedAtMicros, ExpiresAtMicros: bound.ExpiresAtMicros}
	sealed, err := sealer.Seal(displayCtx, binding, prepared)
	if err != nil {
		if errors.Is(err, evidencedisplay.ErrCancelled) {
			return failure(repository.DisplayUnavailableCancelled)
		}
		// Includes unavailable keys or worker/database clock skew. Never adjust
		// the authenticated database times or fall back to raw evidence.
		return failure(repository.DisplayUnavailableSeal)
	}
	bound.SourceHash, bound.Version, bound.KeyVersion = sourceHash, sealed.Version, sealed.KeyVersion
	bound.Nonce, bound.Ciphertext, bound.PlaintextBytes, bound.PayloadHash = sealed.Nonce, sealed.Ciphertext, sealed.PlaintextBytes, sealed.PayloadHash
	return bound
}

func executionStop(err error) bool {
	return errors.Is(err, repository.ErrExecutionCancelled) || errors.Is(err, repository.ErrExecutionClosed) || errors.Is(err, repository.ErrExecutionBudget) || errors.Is(err, repository.ErrExecutionStale) || errors.Is(err, repository.ErrExecutionCircuitOpen)
}
