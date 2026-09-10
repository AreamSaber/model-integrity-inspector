package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"gorm.io/gorm"
)

func TestExecutionLeaseLookupErrorPreservesFailureClass(t *testing.T) {
	opaque := errors.New("synthetic-protected-driver-diagnostic")
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{"nil", nil, nil},
		{"not_found", gorm.ErrRecordNotFound, ErrJobLeaseLost},
		{"wrapped_not_found", fmt.Errorf("lookup: %w", gorm.ErrRecordNotFound), ErrJobLeaseLost},
		{"canceled", context.Canceled, context.Canceled},
		{"deadline", context.DeadlineExceeded, context.DeadlineExceeded},
		{"driver", opaque, opaque},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := executionLeaseLookupError(test.err)
			if !errors.Is(result, test.want) {
				t.Fatal("internal lookup error classification changed")
			}
			if result != nil && !errors.Is(result, ErrJobLeaseLost) {
				if sanitized := queueError(result); !errors.Is(sanitized, ErrUnavailable) || strings.Contains(sanitized.Error(), opaque.Error()) {
					t.Fatal("queue boundary did not sanitize the internal lookup error")
				}
			}
		})
	}
}

// Exercise the actual leased transaction and its real SQL context. Only the
// opaque-driver branch injects an error; cancellation runs the query with its
// genuinely canceled transaction context. Missing records remain real misses.
func TestExecutionLeaseLookupsDistinguishStorageFailureFromMissingFence(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		_, queue, samples := executionStart(t, tenant, plan, policy)
		lease, err := queue.Claim(tenant.ctx)
		if err != nil || lease == nil {
			t.Fatal("claim lookup fixture")
		}
		sample := samples[0]
		attempt := reserveTestAttempt(t, tenant, queue, *lease, sample)
		for _, lookup := range []struct {
			name       string
			table      string
			completing bool
			invoke     func(*TenantTransaction, bool) error
		}{
			{"execution_job", "integrity_jobs", true, func(tx *TenantTransaction, missing bool) error {
				id := sample.ID
				if missing {
					id++
				}
				_, err := tx.executionJob(JobSampleExecute, id, true)
				return err
			}},
			{"derived_completion_job", "integrity_jobs", true, func(tx *TenantTransaction, missing bool) error {
				id := sample.ID
				if missing {
					id++
				}
				_, err := tx.derivedCompletionJob(id)
				return err
			}},
			{"locked_sample", "integrity_logical_samples", true, func(tx *TenantTransaction, missing bool) error {
				id := sample.ID
				if missing {
					id++
				}
				_, _, err := tx.lockedExecutionSample(id)
				return err
			}},
			{"finish_attempt", "integrity_sample_attempts", true, func(tx *TenantTransaction, missing bool) error {
				id := attempt.ID
				if missing {
					id++
				}
				return tx.FinishAttempt(sample.ID, id, successOutcome(), 0)
			}},
			{"recover_attempt", "integrity_sample_attempts", true, func(tx *TenantTransaction, _ bool) error {
				// This owner's pending Attempt is not an older recoverable one.
				// Thus the no-injection control is an actual predicate miss.
				return tx.RecoverInterruptedSample(sample.ID)
			}},
			{"response_capture", "integrity_sample_attempts", false, func(tx *TenantTransaction, missing bool) error {
				id := attempt.ID
				if missing {
					id++
				}
				_, err := tx.BindAttemptResponseCapture(sample.ID, id, attempt.RequestHash)
				return err
			}},
			{"display_binding", "integrity_sample_attempts", false, func(tx *TenantTransaction, missing bool) error {
				id := attempt.ID
				if missing {
					id++
				}
				_, err := tx.BindAttemptDisplayCapture(sample.ID, id, attempt.RequestHash)
				return err
			}},
		} {
			t.Run(lookup.name, func(t *testing.T) {
				for _, failure := range []string{"cancel_query", "opaque_driver", "missing_record"} {
					t.Run(failure, func(t *testing.T) {
						ctx, cancel := context.WithCancel(tenant.ctx)
						defer cancel()
						const callback = "execution_lookup_failure"
						const canary = "synthetic-protected-driver-diagnostic"
						armed, intercepted := false, false
						if err := store.db.Callback().Query().Before("gorm:query").Register(callback, func(db *gorm.DB) {
							if !armed || db.Statement.Table != lookup.table || failure == "missing_record" {
								return
							}
							armed, intercepted = false, true
							if failure == "cancel_query" {
								cancel()
							} else {
								_ = db.AddError(errors.New(canary))
							}
						}); err != nil {
							t.Fatal("install lookup failure barrier")
						}
						defer func() { _ = store.db.Callback().Query().Remove(callback) }()
						fn := func(tx *TenantTransaction) error {
							armed = true
							return lookup.invoke(tx, failure == "missing_record")
						}
						var result error
						if lookup.completing {
							result = queue.CompleteWith(ctx, *lease, fn)
						} else {
							result = queue.WithLease(ctx, *lease, fn)
						}
						want := ErrUnavailable
						if failure == "missing_record" {
							want = ErrJobLeaseLost
						} else if !intercepted {
							t.Fatal("requested SQL failure was not reached")
						}
						if !errors.Is(result, want) {
							t.Fatalf("lookup classification mismatch: unavailable=%t lease_lost=%t expected_missing=%t", errors.Is(result, ErrUnavailable), errors.Is(result, ErrJobLeaseLost), failure == "missing_record")
						}
						if strings.Contains(result.Error(), canary) {
							t.Fatal("raw driver diagnostic escaped the queue boundary")
						}
						armed = false
						if err := queue.CheckLease(tenant.ctx, *lease); err != nil {
							t.Fatal("rejected lookup changed the original valid lease")
						}
					})
				}
			})
		}
		wrongGeneration := *lease
		wrongGeneration.Generation++
		called := false
		if err := queue.CompleteWith(tenant.ctx, wrongGeneration, func(*TenantTransaction) error { called = true; return nil }); !errors.Is(err, ErrJobLeaseLost) || called {
			t.Fatal("real generation mismatch did not retain its fence rejection")
		}
		// Change the actual persisted owner, not the public copy in JobLease.
		// The consumer remains current, so this exercises the Job fence itself.
		if err := store.db.Model(&Job{}).Where("organization_id = ? AND id = ?", tenant.orgID, lease.Job.ID).Update("lease_owner", "synthetic-replacement-owner").Error; err != nil {
			t.Fatal("replace fixture job owner")
		}
		called = false
		if err := queue.CompleteWith(tenant.ctx, *lease, func(*TenantTransaction) error { called = true; return nil }); !errors.Is(err, ErrJobLeaseLost) || called {
			t.Fatal("actual owner replacement did not retain its fence rejection")
		}
	})
}
