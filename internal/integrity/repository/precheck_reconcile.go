package repository

import (
	"time"

	"gorm.io/gorm"
)

// Reconciliation is a queue recovery action, not a successful upstream call.
// This runs only after the existing queue predicate permits terminal recovery,
// in the exact transaction that marks the job cancelled/failed.
func (q *JobQueue) reconcilePrecheck(tx *gorm.DB, job Job, status, errorCode string, now time.Time) error {
	_, err := q.store.reconcilePrecheckDomain(tx, job, status, errorCode, now)
	return err
}
