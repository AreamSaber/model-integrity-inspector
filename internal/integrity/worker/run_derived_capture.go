package worker

import (
	"context"
	"errors"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

// Only a business Job cancellation can detach bounded, pure S1 preparation
// from the handler context. This grants no network/credential or commit lease;
// Runner shutdown, lost ownership and ordinary deadlines remain cancellation.
// CompleteWith still verifies the exact current lease before and after writes.
func runDerivationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if errors.Is(context.Cause(ctx), repository.ErrJobCancelled) {
		ctx = context.WithoutCancel(ctx)
	}
	return context.WithTimeout(ctx, 3*time.Second)
}

// Called within the actual Credentials.Use scope. Bind time and policy once
// after receiving the response, then prepare/seal outside database locks.
// A disabled capture is retained as an explicit private no-body receipt, never
// retried later under a more permissive policy. S1 preparation is independent.
func captureRunDerivedBody(ctx context.Context, execution Execution, sealer *secret.DisplaySealer, request domain.NormalizedRequest, result runCallResult, key []byte, headers map[string][]byte) (*repository.AttemptBodyCapture, repository.DisplayEvidenceRecord) {
	captureCtx, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	var capture *repository.AttemptBodyCapture
	err := execution.Queue.WithLease(captureCtx, execution.Lease, func(tx *repository.TenantTransaction) error {
		var err error
		capture, err = tx.BindAttemptResponseCapture(result.attempt.LogicalSampleID, result.attempt.ID, result.attempt.RequestHash)
		return err
	})
	if err != nil {
		return nil, repository.DisplayEvidenceRecord{}
	}
	bound := capture.DisplayBinding()
	if bound.State != repository.DisplayCaptured {
		return capture, bound
	}
	return capture, captureRunDisplayUsingBinding(captureCtx, execution, sealer, request, result, key, headers, &bound)
}
