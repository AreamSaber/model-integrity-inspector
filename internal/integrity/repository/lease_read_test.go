package repository

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLeasePollingDoesNotAcquireWriterLock(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, cfg Config) {
		initial, tenant, queue := queueFixture(t, store)
		mustEnqueue(t, tenant, retentionJob(initial.Organization.ID, "read-only-lease-check"))
		lease := mustClaim(t, queue)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		// A genuine independent connection holds a writer transaction. SQLite
		// WAL and PostgreSQL MVCC must still permit advisory committed reads.
		writer := other.db.Begin()
		if writer.Error != nil {
			t.Fatal(writer.Error)
		}
		defer writer.Rollback()
		if err := writer.Model(&Job{}).Where("organization_id = ? AND id = ?", tenant.orgID, lease.Job.ID).Update("cancel_requested_at", time.Now().UTC()).Error; err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
		defer cancel()
		if err := queue.CheckLease(ctx, lease); err != nil {
			t.Fatal("poll tried to compete with writer", err)
		}
		if err := writer.Commit().Error; err != nil {
			t.Fatal(err)
		}
		if err := queue.CheckLease(t.Context(), lease); !errors.Is(err, ErrJobCancelled) {
			t.Fatal("committed cancellation not observed", err)
		}
		called := false
		if err := queue.WithLease(t.Context(), lease, func(*TenantTransaction) error { called = true; return nil }); !errors.Is(err, ErrJobLeaseLost) || called {
			t.Fatal("advisory read bypassed dispatch fence", err)
		}
	})
}
