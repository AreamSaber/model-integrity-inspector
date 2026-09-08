package worker

import (
	"context"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

// NewRunReconciler uses the Runner's existing consumer and bounded maintenance
// context. One real terminal Job is prepared outside SQL locks per invocation;
// a new transaction revalidates its private source before applying settlement.
// No credentials, current target or response-body decryption are required.
func NewRunReconciler(config RunConfig) (func(context.Context, *repository.JobQueue) error, error) {
	if config.DerivedBuilder == nil || config.DerivedSealer == nil {
		return nil, ErrConfiguration
	}
	return func(ctx context.Context, queue *repository.JobQueue) error {
		if ctx == nil || queue == nil {
			return ErrConfiguration
		}
		sources, err := queue.LoadExecutionReconciliations(ctx, 1)
		if err != nil {
			return err
		}
		for _, source := range sources {
			var candidates *repository.AttemptDerivedCandidates
			err := source.Use(func(data repository.ExecutionReconciliationData) error {
				if data.Run.AnalysisSourceVersion != domain.AnalysisSourceDerivedV1 || data.Attempt == nil {
					return nil
				}
				prepared, err := prepareRunDerived(ctx, config, data.Plan, data.Sample, *data.Attempt, nil, domain.AttemptOutcome{Validity: "INVALID_RETRYABLE", ErrorCode: "MI_UNCERTAIN_ATTEMPT"}, true)
				if err != nil {
					return err
				}
				candidates = &prepared
				return nil
			})
			if err != nil {
				return err
			}
			// Already-completed or stale receipts are normal concurrent progress;
			// errors (integrity, storage, consumer fence) remain visible failures.
			if _, err := queue.ReconcileExecutionWithDerived(ctx, source, candidates); err != nil {
				return err
			}
		}
		// Preserve the original maintenance's analysis-Job failure reconciliation.
		return queue.ReconcileAnalyses(ctx)
	}, nil
}
