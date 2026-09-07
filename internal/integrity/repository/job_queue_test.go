package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"model-integrity-inspector.local/mii/migrations"
)

func queueFixture(t *testing.T, store *Store) (InitializationResult, *Tenant, *JobQueue) {
	t.Helper()
	requireMigrate(t, store)
	initial := requireInitialize(t, store)
	tenant, err := store.WithOrganization(t.Context(), initial.Organization.ID)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := store.OpenJobQueue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queue.Close(context.Background()) })
	return initial, tenant, queue
}

func retentionJob(orgID int64, key string) JobSpec {
	return JobSpec{Type: JobRetentionDelete, ObjectID: orgID, IdempotencyKey: key}
}

func mustEnqueue(t *testing.T, tenant *Tenant, spec JobSpec) Job {
	t.Helper()
	job, err := tenant.Enqueue(spec)
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func mustClaim(t *testing.T, queue *JobQueue) JobLease {
	t.Helper()
	lease, err := queue.Claim(t.Context())
	if err != nil || lease == nil {
		t.Fatalf("claim: %+v %v", lease, err)
	}
	return *lease
}

func expireJob(t *testing.T, store *Store, job Job) {
	t.Helper()
	if err := store.db.Model(&Job{}).Where("organization_id = ? AND id = ?", job.OrganizationID, job.ID).Update("lease_until", time.Unix(1, 0).UTC()).Error; err != nil {
		t.Fatal(err)
	}
}

func TestJobEnqueueIdempotencyAndRollback(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		initial, tenant, _ := queueFixture(t, store)
		spec := retentionJob(initial.Organization.ID, "same-command")
		var wg sync.WaitGroup
		results := make(chan Job, 12)
		errs := make(chan error, 12)
		for range 12 {
			wg.Go(func() {
				job, err := tenant.Enqueue(spec)
				results <- job
				errs <- err
			})
		}
		wg.Wait()
		close(results)
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		var id int64
		for job := range results {
			if id == 0 {
				id = job.ID
			}
			if job.ID != id || job.Status != "pending" {
				t.Fatal("repeated idempotency key created multiple jobs")
			}
		}
		spec.Priority = 10
		if _, err := tenant.Enqueue(spec); !errors.Is(err, ErrConflict) {
			t.Fatalf("same key with changed options accepted: %v", err)
		}
		var escaped *TenantTransaction
		err := tenant.InTransaction(func(tx *TenantTransaction) error {
			escaped = tx
			if _, err := tx.Enqueue(retentionJob(initial.Organization.ID, "rollback-command")); err != nil {
				return err
			}
			return ErrConflict
		})
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("rollback result: %v", err)
		}
		if _, err := escaped.Enqueue(retentionJob(initial.Organization.ID, "escaped-command")); !errors.Is(err, ErrTransactionClosed) {
			t.Fatal("expired transaction capability was usable")
		}
		var count int64
		if err := store.db.Model(&Job{}).Where("organization_id = ?", initial.Organization.ID).Count(&count).Error; err != nil || count != 1 {
			t.Fatal("transaction rollback left queued work")
		}
	})
}

func TestJobClaimCompleteAndStaleGeneration(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		initial, tenant, queue := queueFixture(t, store)
		job := mustEnqueue(t, tenant, retentionJob(initial.Organization.ID, "claim-fence"))
		first := mustClaim(t, queue)
		if first.Job.ID != job.ID || first.Generation != 1 || first.ExpiresAt.Sub(first.Job.UpdatedAt) != JobLeaseDuration || JobHeartbeatEvery != 15*time.Second {
			t.Fatal("incorrect lease parameters")
		}
		if next, err := queue.Claim(t.Context()); err != nil || next != nil {
			t.Fatal("active leased job was claimed twice")
		}
		renewed, err := queue.Renew(t.Context(), first)
		if err != nil || renewed.ExpiresAt.Before(first.ExpiresAt) {
			t.Fatalf("renew failed: %v", err)
		}
		expireJob(t, store, job)
		if _, err := queue.Renew(t.Context(), renewed); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("expired worker resurrected lease")
		}
		if err := queue.Complete(t.Context(), first); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("expired worker completed job before recovery")
		}
		second := mustClaim(t, queue)
		if second.Job.ID != first.Job.ID || second.Generation != 2 {
			t.Fatal("expired job did not recover with a new attempt generation")
		}
		if err := queue.Complete(t.Context(), first); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("old generation completed recovered job")
		}
		if err := queue.Retry(t.Context(), first, "RETRYABLE_ERROR", 0); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("old generation requeued recovered job")
		}
		if err := queue.Complete(t.Context(), second); err != nil {
			t.Fatal(err)
		}
		if err := queue.Complete(t.Context(), second); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("completion occurred twice")
		}
		completed, err := tenant.GetJob(job.ID)
		if err != nil || completed.Status != "completed" || completed.LeaseOwner != nil || completed.LeaseUntil != nil || completed.CompletedAt == nil {
			t.Fatalf("completion state: %+v %v", completed, err)
		}
	})
}

func TestJobCompletionAndDependentEnqueueAtomicity(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		initial, tenant, queue := queueFixture(t, store)
		job := mustEnqueue(t, tenant, retentionJob(initial.Organization.ID, "first-stage"))
		lease := mustClaim(t, queue)
		fn := func(tx *TenantTransaction) error {
			_, err := tx.Enqueue(retentionJob(initial.Organization.ID, "next-stage"))
			return err
		}
		if err := queue.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error {
			if err := fn(tx); err != nil {
				return err
			}
			return ErrConflict
		}); !errors.Is(err, ErrConflict) {
			t.Fatalf("completion rollback: %v", err)
		}
		current, err := tenant.GetJob(job.ID)
		if err != nil || current.Status != "running" {
			t.Fatal("failed dependent enqueue committed completion")
		}
		var count int64
		if err := store.db.Model(&Job{}).Where("organization_id = ?", initial.Organization.ID).Count(&count).Error; err != nil || count != 1 {
			t.Fatal("completion rollback left a dependent job")
		}
		if err := queue.CompleteWith(t.Context(), lease, fn); err != nil {
			t.Fatal(err)
		}
		if next := mustClaim(t, queue); next.Job.IdempotencyKey != "next-stage" {
			t.Fatal("dependent job did not commit with completion")
		}
	})
}

func TestJobConsumerExclusionAndOwnerFence(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, cfg Config) {
		initial, tenant, firstQueue := queueFixture(t, store)
		job := mustEnqueue(t, tenant, retentionJob(initial.Organization.ID, "consumer-fence"))
		first := mustClaim(t, firstQueue)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		if store.driver == "sqlite" {
			if _, err := other.OpenJobQueue(t.Context()); !errors.Is(err, ErrConsumerActive) {
				t.Fatalf("second SQLite consumer accepted: %v", err)
			}
			if err := firstQueue.HeartbeatConsumer(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := store.db.Exec("UPDATE integrity_queue_consumer_leases SET lease_until = ? WHERE lock_name = ?", time.Unix(1, 0).UTC(), queueConsumerName).Error; err != nil {
				t.Fatal(err)
			}
		}
		secondQueue, err := other.OpenJobQueue(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = secondQueue.Close(context.Background()) }()
		expireJob(t, store, job)
		second := mustClaim(t, secondQueue)
		if first.Job.LeaseOwner == nil || second.Job.LeaseOwner == nil || *first.Job.LeaseOwner == *second.Job.LeaseOwner {
			t.Fatal("new consumer reused old owner fence")
		}
		err = firstQueue.Complete(t.Context(), first)
		if !errors.Is(err, ErrJobLeaseLost) && !errors.Is(err, ErrConsumerLost) {
			t.Fatalf("old consumer completed recovered job: %v", err)
		}
		if err := secondQueue.Complete(t.Context(), second); err != nil {
			t.Fatal(err)
		}
	})
}

func TestJobQueueConcurrentClaimsNoDuplicates(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, cfg Config) {
		initial, tenant, queue := queueFixture(t, store)
		for i := range 30 {
			mustEnqueue(t, tenant, retentionJob(initial.Organization.ID, fmt.Sprintf("concurrent-%d", i)))
		}
		queues := []*JobQueue{queue}
		if store.driver == "postgres" {
			for range 3 {
				other, err := Open(t.Context(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = other.Close() })
				consumer, err := other.OpenJobQueue(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = consumer.Close(context.Background()) })
				queues = append(queues, consumer)
			}
		}
		var wg sync.WaitGroup
		var seen sync.Map
		errs := make(chan error, 30)
		for i := range 8 {
			wg.Go(func() {
				consumer := queues[i%len(queues)]
				for range 60 {
					lease, err := consumer.Claim(t.Context())
					if err != nil {
						errs <- err
						return
					}
					if lease == nil {
						return
					}
					if _, exists := seen.LoadOrStore(lease.Job.ID, true); exists {
						errs <- errors.New("duplicate claim")
						return
					}
					if err := consumer.Complete(t.Context(), *lease); err != nil {
						errs <- err
						return
					}
				}
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Error(err)
			}
		}
		var count int64
		if err := store.db.Model(&Job{}).Where("organization_id = ? AND status = 'completed'", initial.Organization.ID).Count(&count).Error; err != nil || count != 30 {
			t.Fatalf("completed %d jobs, want30: %v", count, err)
		}
	})
}

func TestJobFairnessPriorityFutureAndPoison(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		initial, tenantA, queue := queueFixture(t, store)
		now := time.Now().UTC()
		orgB := Organization{ID: 2, Name: "Tenant B", Status: "active", Timezone: "UTC", QuotaJSON: "{}", CreatedAt: now, UpdatedAt: now}
		if err := store.db.Create(&orgB).Error; err != nil {
			t.Fatal(err)
		}
		tenantB, _ := store.WithOrganization(t.Context(), orgB.ID)
		low := retentionJob(initial.Organization.ID, "a-low")
		low.Priority = -10
		high := retentionJob(initial.Organization.ID, "a-high")
		high.Priority = 100
		mustEnqueue(t, tenantA, low)
		mustEnqueue(t, tenantA, high)
		mustEnqueue(t, tenantB, retentionJob(orgB.ID, "b-first"))
		if first := mustClaim(t, queue); first.Job.IdempotencyKey != "a-high" {
			t.Fatal("priority was ignored within ready organizations")
		}
		if second := mustClaim(t, queue); second.Job.OrganizationID != orgB.ID {
			t.Fatal("busy tenant starved a waiting organization")
		}
		_ = mustClaim(t, queue)
		future := retentionJob(orgB.ID, "future")
		future.AvailableAt = now.Add(time.Hour)
		mustEnqueue(t, tenantB, future)
		if lease, err := queue.Claim(t.Context()); err != nil || lease != nil {
			t.Fatal("future job was claimed early")
		}
		for _, spec := range []JobSpec{{Type: "unsupported", ObjectID: orgB.ID, IdempotencyKey: "bad-type"}, {Type: JobRetentionDelete, ObjectID: initial.Organization.ID, IdempotencyKey: "wrong-tenant"}, {Type: JobRunPlan, ObjectID: 999, IdempotencyKey: "missing-run"}} {
			if _, err := tenantB.Enqueue(spec); !errors.Is(err, ErrJobInvalid) {
				t.Fatalf("invalid payload accepted: %v", err)
			}
		}
		poison := mustEnqueue(t, tenantB, retentionJob(orgB.ID, "forged-after-enqueue"))
		if err := store.db.Model(&Job{}).Where("organization_id = ? AND id = ?", orgB.ID, poison.ID).Update("object_id", initial.Organization.ID).Error; err != nil {
			t.Fatal(err)
		}
		if lease, err := queue.Claim(t.Context()); err != nil || lease != nil {
			t.Fatal("forged payload escaped consumer tenant validation")
		}
		failed, err := tenantB.GetJob(poison.ID)
		if err != nil || failed.Status != "failed" || failed.LastErrorCode == nil || *failed.LastErrorCode != "JOB_PAYLOAD_INVALID" {
			t.Fatal("forged job was not terminally rejected")
		}
		if _, err := tenantA.GetJob(poison.ID); !errors.Is(err, ErrNotFound) {
			t.Fatal("job query crossed tenant")
		}
	})
}

func TestJobRetryExhaustionAndCancellationReconcile(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		initial, tenant, queue := queueFixture(t, store)
		spec := retentionJob(initial.Organization.ID, "retry")
		spec.MaxAttempts = 2
		job := mustEnqueue(t, tenant, spec)
		first := mustClaim(t, queue)
		if err := queue.Retry(t.Context(), first, "UPSTREAM_RATE_LIMIT", time.Hour); err != nil {
			t.Fatal(err)
		}
		if lease, err := queue.Claim(t.Context()); err != nil || lease != nil {
			t.Fatal("Retry-After delay ignored")
		}
		if err := store.db.Model(&Job{}).Where("organization_id = ? AND id = ?", job.OrganizationID, job.ID).Update("available_at", time.Unix(1, 0).UTC()).Error; err != nil {
			t.Fatal(err)
		}
		second := mustClaim(t, queue)
		if second.Generation != 2 {
			t.Fatal("retry attempt did not increment generation")
		}
		expireJob(t, store, job)
		if lease, err := queue.Claim(t.Context()); err != nil || lease != nil {
			t.Fatal("exhausted crashed job was claimed again")
		}
		failed, err := tenant.GetJob(job.ID)
		if err != nil || failed.Status != "failed" || failed.CompletedAt == nil {
			t.Fatal("exhausted crashed job remained running")
		}
		cancelled := mustEnqueue(t, tenant, retentionJob(initial.Organization.ID, "cancel-pending"))
		if err := store.db.Model(&Job{}).Where("organization_id = ? AND id = ?", cancelled.OrganizationID, cancelled.ID).Update("cancel_requested_at", time.Now().UTC()).Error; err != nil {
			t.Fatal(err)
		}
		if lease, err := queue.Claim(t.Context()); err != nil || lease != nil {
			t.Fatal("cancelled pending work was dispatched")
		}
		cancelled, err = tenant.GetJob(cancelled.ID)
		if err != nil || cancelled.Status != "cancelled" {
			t.Fatal("cancelled job remained pending")
		}
	})
}

func TestJobQueueDatabaseOutageFailsClosed(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		initial, tenant, queue := queueFixture(t, store)
		mustEnqueue(t, tenant, retentionJob(initial.Organization.ID, "outage"))
		lease := mustClaim(t, queue)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if claimed, err := queue.Claim(t.Context()); !errors.Is(err, ErrUnavailable) || claimed != nil {
			t.Fatalf("outage fabricated a claim: %v", err)
		}
		if err := queue.Complete(t.Context(), lease); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("outage fabricated completion: %v", err)
		}
	})
}

func TestQueueMigrationUpgradesExistingJobs(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		set, err := migrations.ForDialect(store.driver)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.migrate(t.Context(), set[:1]); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		// Historical fixtures use their historical column shape: today's models
		// deliberately require columns introduced by later migrations.
		if err := store.db.Exec("INSERT INTO organizations (id,name,status,timezone,quota_json,created_at,updated_at) VALUES (1,'Legacy','active','UTC','{}',?,?)", now, now).Error; err != nil {
			t.Fatal(err)
		}
		legacy := Job{ID: 10, OrganizationID: 1, Type: string(JobRetentionDelete), ObjectID: 1, IdempotencyKey: "pre-upgrade", Status: "pending", AvailableAt: now, MaxAttempts: 3, CreatedAt: now, UpdatedAt: now}
		if err := store.db.Create(&legacy).Error; err != nil {
			t.Fatal(err)
		}
		requireMigrate(t, store)
		queue, err := store.OpenJobQueue(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = queue.Close(context.Background()) }()
		if lease := mustClaim(t, queue); lease.Job.ID != legacy.ID {
			t.Fatal("existing job was lost during queue migration")
		}
	})
}

func TestSQLiteConsumerProcessHelper(t *testing.T) {
	path := os.Getenv("MII_TEST_QUEUE_PROCESS_SQLITE")
	if path == "" {
		t.Skip("only runs as an isolated process helper")
	}
	store, err := Open(t.Context(), Config{Driver: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if _, err := store.OpenJobQueue(t.Context()); !errors.Is(err, ErrConsumerActive) {
		t.Fatalf("separate process was not excluded: %v", err)
	}
	t.Log("SEPARATE_PROCESS_CONSUMER_REJECTED")
}

func TestSQLiteConsumerExcludesOtherProcess(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, cfg Config) {
		if store.driver != "sqlite" {
			t.Skip("SQLite-only cross-process exclusion policy")
		}
		_, _, _ = queueFixture(t, store)
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, "-test.run=^TestSQLiteConsumerProcessHelper$", "-test.v") // #nosec G204 -- os.Executable selects this trusted test binary; no user-controlled command or arguments.
		command.Env = append(os.Environ(), "MII_TEST_QUEUE_PROCESS_SQLITE="+cfg.DSN)
		output, err := command.CombinedOutput()
		if err != nil || !strings.Contains(string(output), "SEPARATE_PROCESS_CONSUMER_REJECTED") {
			t.Fatalf("process exclusion failed: %v %s", err, output)
		}
	})
}

func TestPostgresClaimSkipsLockedJob(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		if store.driver != "postgres" {
			t.Skip("PostgreSQL SKIP LOCKED behavior")
		}
		initial, tenant, queue := queueFixture(t, store)
		high := retentionJob(initial.Organization.ID, "locked-high-priority")
		high.Priority = 100
		lockedJob := mustEnqueue(t, tenant, high)
		available := mustEnqueue(t, tenant, retentionJob(initial.Organization.ID, "unlocked-next-job"))
		ready := make(chan struct{})
		release := make(chan struct{})
		finished := make(chan error, 1)
		go func() {
			finished <- store.db.WithContext(t.Context()).Transaction(func(tx *gorm.DB) error {
				var job Job
				if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("organization_id = ? AND id = ?", lockedJob.OrganizationID, lockedJob.ID).First(&job).Error; err != nil {
					return err
				}
				close(ready)
				<-release
				return nil
			})
		}()
		defer close(release)
		select {
		case <-ready:
		case err := <-finished:
			t.Fatalf("row lock failed: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("row lock setup timed out")
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		lease, err := queue.Claim(ctx)
		if err != nil || lease == nil || lease.Job.ID != available.ID {
			t.Fatalf("claim waited on/chose locked row: %+v %v", lease, err)
		}
	})
}

func TestJobTerminalRetryAndInvalidRunningRecovery(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		initial, tenant, queue := queueFixture(t, store)
		spec := retentionJob(initial.Organization.ID, "one-attempt")
		spec.MaxAttempts = 1
		job := mustEnqueue(t, tenant, spec)
		lease := mustClaim(t, queue)
		if err := queue.Retry(t.Context(), lease, "raw error with secret material", 0); !errors.Is(err, ErrConfiguration) {
			t.Fatal("unsanitized error text was accepted into job record")
		}
		if err := queue.Retry(t.Context(), lease, "RETRYABLE_ERROR", -time.Second); !errors.Is(err, ErrConfiguration) {
			t.Fatal("negative retry delay accepted")
		}
		if err := queue.Retry(t.Context(), lease, "RETRYABLE_ERROR", 0); err != nil {
			t.Fatal(err)
		}
		job, err := tenant.GetJob(job.ID)
		if err != nil || job.Status != "failed" {
			t.Fatal("last permitted retry remained pending")
		}
		broken := mustEnqueue(t, tenant, retentionJob(initial.Organization.ID, "broken-lease"))
		if err := store.db.Model(&Job{}).Where("organization_id = ? AND id = ?", broken.OrganizationID, broken.ID).Updates(map[string]any{"status": "running", "attempt_count": 1, "lease_until": nil}).Error; err != nil {
			t.Fatal(err)
		}
		if next, err := queue.Claim(t.Context()); err != nil || next != nil {
			t.Fatal("broken running lease entered handler")
		}
		broken, err = tenant.GetJob(broken.ID)
		if err != nil || broken.Status != "failed" || broken.LastErrorCode == nil || *broken.LastErrorCode != "JOB_LEASE_INVALID" {
			t.Fatal("broken job remained permanently running")
		}
	})
}

func TestJobCompletionExpiredDuringBusinessTransactionRollsBack(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		initial, tenant, queue := queueFixture(t, store)
		job := mustEnqueue(t, tenant, retentionJob(initial.Organization.ID, "long-completion"))
		lease := mustClaim(t, queue)
		err := queue.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error {
			if _, err := tx.Enqueue(retentionJob(initial.Organization.ID, "must-rollback")); err != nil {
				return err
			}
			// Simulate the lease boundary occurring during the short business txn.
			return tx.db.Model(&Job{}).Where("organization_id = ? AND id = ?", job.OrganizationID, job.ID).Update("lease_until", time.Unix(1, 0).UTC()).Error
		})
		if !errors.Is(err, ErrJobLeaseLost) {
			t.Fatalf("expired business transaction committed: %v", err)
		}
		var count int64
		if err := store.db.Model(&Job{}).Where("organization_id = ?", initial.Organization.ID).Count(&count).Error; err != nil || count != 1 {
			t.Fatal("expired completion persisted dependent job")
		}
	})
}
