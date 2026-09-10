package worker

import (
	"context"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

// The scheduler persists the exact batch and Job. The handler cannot choose a
// tenant, object, expiry clock or batch size; deletion happens only inside the
// Runner's fenced CompleteWith transaction, together with its audit receipt.
func NewResponseRetentionHandler() Handler {
	return func(ctx context.Context, execution Execution) (Completion, error) {
		if ctx == nil || execution.Queue == nil || repository.JobType(execution.Lease.Job.Type) != repository.JobRetentionDelete {
			return nil, repository.ErrJobInvalid
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return func(tx *repository.TenantTransaction) error {
			if tx == nil {
				return repository.ErrJobInvalid
			}
			return tx.DeleteResponseEvidenceBatch()
		}, nil
	}
}
