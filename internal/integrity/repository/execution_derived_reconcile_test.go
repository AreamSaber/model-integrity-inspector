package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func TestDerivedExecutionMaintenanceSourceIsImmutableAtomicAndIdempotent(t *testing.T) {
	for _, terminal := range []string{"failed", "cancelled"} {
		t.Run(terminal, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				tenant, run, queue, sample, attempt, lease := derivedExecutionFixture(t, store)
				if err := queue.Fail(tenant.ctx, lease, "MI_TEST_INTERRUPTED"); err != nil {
					t.Fatal(err)
				}
				if terminal == "cancelled" {
					if err := store.db.Model(&Job{}).Where("id = ?", lease.Job.ID).Update("status", terminal).Error; err != nil {
						t.Fatal(err)
					}
				}
				sources, err := queue.LoadExecutionReconciliations(tenant.ctx, 1)
				if err != nil || len(sources) != 1 {
					t.Fatal("load terminal source", err)
				}
				source := sources[0]
				if err := source.Use(func(data ExecutionReconciliationData) error {
					if data.Attempt == nil || data.Attempt.ID != attempt.ID || data.Job.Status != terminal {
						t.Fatal("wrong recovery source")
					}
					data.Attempt.ID++
					data.Attempt.RequestSnapshot = "changed"
					*data.Attempt.StartedAt = time.Time{}
					*data.Run.StartedAt = time.Time{}
					*data.Sample.JobID = 0
					if data.Sample.PairID != nil {
						*data.Sample.PairID = "changed"
					}
					data.Plan.Manifest[0] = 'x'
					data.Plan.Probes[0].Samples[0].Request.Messages[0].Content = "changed"
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err := source.Use(func(data ExecutionReconciliationData) error {
					if data.Attempt.ID != attempt.ID || data.Attempt.RequestSnapshot != attempt.RequestSnapshot || !data.Attempt.StartedAt.Equal(*attempt.StartedAt) || data.Run.StartedAt.IsZero() || *data.Sample.JobID != lease.Job.ID || string(data.Plan.Manifest) != `{"fixture":"repository-scope-only"}` || data.Plan.Probes[0].Samples[0].Request.Messages[0].Content != "Return OK" {
						t.Fatal("Use mutated private source or later borrower")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err := queue.ReconcileExecution(tenant.ctx, tenant.orgID); !errors.Is(err, ErrAnalysisSource) {
					t.Fatal("legacy maintenance bypassed derived obligation", err)
				}
				if _, err := queue.ReconcileExecutionWithDerived(tenant.ctx, source, nil); !errors.Is(err, ErrAnalysisSource) {
					t.Fatal("missing maintenance S1 accepted", err)
				}
				candidates := derivedRecoveryCandidates(run, sample, attempt)
				var wg sync.WaitGroup
				results := make(chan ExecutionReconciliationResult, 2)
				failures := make(chan error, 2)
				for range 2 {
					wg.Go(func() {
						result, err := queue.ReconcileExecutionWithDerived(tenant.ctx, source, &candidates)
						results <- result
						failures <- err
					})
				}
				wg.Wait()
				close(results)
				close(failures)
				for err := range failures {
					if err != nil {
						t.Fatal("concurrent maintenance", err)
					}
				}
				applied, duplicate := 0, 0
				for result := range results {
					if result == ReconciliationApplied {
						applied++
					}
					if result == ReconciliationAlreadyCompleted {
						duplicate++
					}
				}
				if applied != 1 || duplicate != 1 {
					t.Fatal("maintenance did not serialize exact source once")
				}
				changed := candidates
				changed.Items = append([]AttemptDerivedCandidate(nil), candidates.Items...)
				changed.Items[0].Record.KeyVersion = "other-version"
				if _, err := queue.ReconcileExecutionWithDerived(tenant.ctx, source, &changed); !errors.Is(err, ErrAnalysisSource) {
					t.Fatal("duplicate accepted different key receipt", err)
				}
				current, _ := tenant.GetRun(run.ID)
				if current.ReservedTokens != 0 || current.TokenCount != 38 || current.RequestCount != 1 {
					t.Fatal("maintenance charged or released twice")
				}
				var count int64
				if err := store.db.Model(&AttemptDerivedRecord{}).Count(&count).Error; err != nil || count != 1 {
					t.Fatal("maintenance S1 count")
				}
				remaining, err := queue.LoadExecutionReconciliations(tenant.ctx, 1)
				if err != nil || len(remaining) != 0 {
					t.Fatal("completed source still selected", err)
				}
				if err := store.VerifyAllAudit(tenant.ctx, true); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestDerivedExecutionMaintenanceSQLFailureScopeAndLimitsFailClosed(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, cfg Config) {
		tenant, run, queue, sample, attempt, lease := derivedExecutionFixture(t, store)
		if err := queue.Fail(tenant.ctx, lease, "MI_TEST_INTERRUPTED"); err != nil {
			t.Fatal(err)
		}
		for _, limit := range []int{0, 9} {
			if _, err := queue.LoadExecutionReconciliations(tenant.ctx, limit); !errors.Is(err, ErrConfiguration) {
				t.Fatal("unbounded maintenance batch")
			}
		}
		if err := store.db.Model(&LogicalSampleRecord{}).Where("id = ?", sample.ID).Update("request_plan", strings.Repeat("x", (2<<20)+1)).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := queue.LoadExecutionReconciliations(tenant.ctx, 1); !errors.Is(err, ErrAnalysisLimit) {
			t.Fatal("sample S2 loaded/decoded before byte guard", err)
		}
		if err := store.db.Model(&LogicalSampleRecord{}).Where("id = ?", sample.ID).Update("request_plan", sample.RequestPlan).Error; err != nil {
			t.Fatal(err)
		}
		sources, err := queue.LoadExecutionReconciliations(tenant.ctx, 1)
		if err != nil || len(sources) != 1 {
			t.Fatal(err)
		}
		candidates := derivedRecoveryCandidates(run, sample, attempt)
		foreign := &JobQueue{store: store, owner: "wrong-consumer"}
		if _, err := foreign.ReconcileExecutionWithDerived(tenant.ctx, sources[0], &candidates); !errors.Is(err, ErrAnalysisSource) {
			t.Fatal("foreign consumer used source")
		}
		statement := "ALTER TABLE integrity_audit_logs ADD CONSTRAINT derived_maintenance_fail CHECK (action <> 'run.attempt.finish') NOT VALID"
		if cfg.Driver == "sqlite" {
			statement = "CREATE TRIGGER derived_maintenance_fail BEFORE INSERT ON integrity_audit_logs WHEN NEW.action = 'run.attempt.finish' BEGIN SELECT RAISE(ABORT, 'MAINTENANCE_FAILURE'); END"
		}
		if err := store.db.Exec(statement).Error; err != nil {
			t.Fatal("install maintenance SQL fault")
		}
		if _, err := queue.ReconcileExecutionWithDerived(tenant.ctx, sources[0], &candidates); err == nil {
			t.Fatal("failed maintenance committed")
		}
		current, _ := tenant.GetRun(run.ID)
		attempts, _ := tenant.ListAttempts(sample.ID)
		if current.TokenCount != 0 || current.ReservedTokens != 30 || attempts[0].DerivedReceipt != DerivedPending || attempts[0].Status != "DISPATCHED" {
			t.Fatal("maintenance failure partially settled")
		}
		var count int64
		if err := store.db.Model(&AttemptDerivedRecord{}).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("failed maintenance left S1")
		}
		if err := store.VerifyAllAudit(tenant.ctx, true); err != nil {
			t.Fatal(err)
		}
		if err := queue.Close(tenant.ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := queue.LoadExecutionReconciliations(tenant.ctx, 1); !errors.Is(err, ErrConsumerLost) {
			t.Fatal("closed consumer loaded source", err)
		}
		if _, err := queue.ReconcileExecutionWithDerived(tenant.ctx, sources[0], &candidates); !errors.Is(err, ErrConsumerLost) {
			t.Fatal("closed consumer committed source", err)
		}
	})
}

func TestDerivedExecutionMaintenanceWithoutDerivedAttempt(t *testing.T) {
	for _, scenario := range []string{"legacy_unstarted", "derived_unstarted", "legacy_unattempted", "derived_unattempted", "legacy_attempt"} {
		t.Run(scenario, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				tenant, _, plan, policy := executionFixture(t, store, 1)
				derived := strings.HasPrefix(scenario, "derived")
				if derived {
					plan.AnalysisSourceVersion = domain.AnalysisSourceDerivedV1
					plan.Manifest = []byte(`{"fixture":"repository-scope-only"}`)
					digest := sha256.Sum256(plan.Manifest)
					plan.ManifestHash = hex.EncodeToString(digest[:])
				}
				run, err := tenant.CreateRun(plan, policy, "maintenance-without-s1")
				if err != nil {
					t.Fatal(err)
				}
				queue, err := store.OpenJobQueue(tenant.ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = queue.Close(t.Context()) })
				lease, err := queue.Claim(tenant.ctx)
				if err != nil || lease == nil {
					t.Fatal("claim plan", err)
				}
				var sample LogicalSampleRecord
				unstarted := strings.HasSuffix(scenario, "unstarted")
				if !unstarted {
					if err := queue.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error {
						if derived {
							return tx.StartRunWithDerivedSource(run.ID)
						}
						return tx.StartRun(run.ID)
					}); err != nil {
						t.Fatal(err)
					}
					samples, err := tenant.ListExecutionSamples(run.ID)
					if err != nil || len(samples) != 1 {
						t.Fatal("load sample", err)
					}
					sample = samples[0]
					lease, err = queue.Claim(tenant.ctx)
					if err != nil || lease == nil {
						t.Fatal("claim sample", err)
					}
					if scenario == "legacy_attempt" {
						reserveTestAttempt(t, tenant, queue, *lease, sample)
					}
				}
				if err := queue.Fail(tenant.ctx, *lease, "MI_TEST_INTERRUPTED"); err != nil {
					t.Fatal(err)
				}
				// The real Runner context has no caller-supplied actor. Audit
				// identity must come from the persisted Job, not the test tenant.
				sources, err := queue.LoadExecutionReconciliations(t.Context(), 1)
				if err != nil || len(sources) != 1 {
					t.Fatal("load maintenance", err)
				}
				if err := sources[0].Use(func(data ExecutionReconciliationData) error {
					if (data.Attempt != nil) != (scenario == "legacy_attempt") || (data.Sample.ID == 0) != unstarted {
						t.Fatal("unexpected maintenance source")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				for _, want := range []ExecutionReconciliationResult{ReconciliationApplied, ReconciliationAlreadyCompleted} {
					result, err := queue.ReconcileExecutionWithDerived(t.Context(), sources[0], nil)
					if err != nil || result != want {
						t.Fatal("maintenance without S1", err, result)
					}
				}
				current, err := tenant.GetRun(run.ID)
				if err != nil || current.ExecutionClosedAt == nil || current.ReservedTokens != 0 {
					t.Fatal("maintenance did not close", err)
				}
				if unstarted && current.Status != "FAILED" || !unstarted && current.Status != "ANALYZING" {
					t.Fatal("wrong run outcome")
				}
				if scenario == "legacy_attempt" {
					attempts, err := tenant.ListAttempts(sample.ID)
					if err != nil || len(attempts) != 1 || attempts[0].Status != "UNCERTAIN" || attempts[0].DerivedReceipt != DerivedLegacy || current.TokenCount != 38 || current.RequestCount != 1 {
						t.Fatal("legacy attempt was upgraded or charged incorrectly", err)
					}
				} else if current.TokenCount != 0 || current.RequestCount != 0 {
					t.Fatal("request invented for unattempted work")
				}
				var count int64
				if err := store.db.Model(&AttemptDerivedRecord{}).Count(&count).Error; err != nil || count != 0 {
					t.Fatal("fake S1 inserted")
				}
				if err := store.VerifyAllAudit(t.Context(), true); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}
