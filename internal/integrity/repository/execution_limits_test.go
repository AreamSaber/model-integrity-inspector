package repository

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
)

func TestExecutionHierarchicalLimitsAcrossRunsTargetsAndOrganizations(t *testing.T) {
	for _, scope := range []string{"target", "organization", "global"} {
		t.Run(scope, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				tenant, target, plan, _ := executionFixture(t, store, 1)
				limits := scheduler.DefaultLimits()
				limits.Global = 3
				limits.Organization = 3
				limits.Target = 2
				limits.Run = 1
				if scope == "organization" {
					limits.Organization = 2
				}
				if scope == "global" {
					limits.Global = 2
					limits.Organization = 2
				}
				policy, err := scheduler.NewPolicy(limits)
				if err != nil {
					t.Fatal(err)
				}
				plan.Concurrency = 1
				type fixture struct {
					tenant *Tenant
					run    RunRecord
					sample LogicalSampleRecord
				}
				fixtures := make([]fixture, 3)
				for i := range fixtures {
					current := tenant
					state := target
					if i > 0 && scope == "global" {
						authority := tenant.ctx.Value(controlAuthorityKey{}).(controlAuthority)
						roles := managementFixtureRoles()
						roles[0].Permissions = append(roles[0].Permissions, "run.create", "run.custom", "run.high-cost")
						org, err := store.ManageCreateOrganization(tenant.ctx, authority.identity, ManagedOrganizationCreate{Name: fmt.Sprintf("scope-%d", i), Timezone: "UTC", Roles: roles})
						if err != nil {
							t.Fatal(err)
						}
						ctx := bindTargetTestSession(t, store, tenant.ctx, authority.identity.SessionID, org.ID)
						current, err = store.WithOrganization(ctx, org.ID)
						if err != nil {
							t.Fatal(err)
						}
					}
					if i > 0 && scope != "target" {
						record := targetRecordFixture()
						record.Name = fmt.Sprintf("scope-target-%d", i)
						state, err = current.CreateTargetWithSecret(record, encryptedFixture(t, current.orgID))
						if err != nil {
							t.Fatal(err)
						}
					}
					candidate := plan
					candidate.Target = domain.ExecutionTarget{ID: state.Target.ID, Version: 1, SecretID: state.Secret.ID, SecretVersion: 1, Endpoint: state.Target.Endpoint, Model: state.Target.Model, Protocol: state.Target.Protocol, MaxOutputParameter: "max_tokens"}
					run, err := current.CreateRun(candidate, policy, fmt.Sprintf("scope-run-%d", i))
					if err != nil {
						t.Fatal(err)
					}
					fixtures[i] = fixture{tenant: current, run: run}
				}
				queue, err := store.OpenJobQueue(tenant.ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = queue.Close(t.Context()) })
				for range fixtures {
					lease, err := queue.Claim(tenant.ctx)
					if err != nil || lease == nil || JobType(lease.Job.Type) != JobRunPlan {
						t.Fatal("plan not ordered", err)
					}
					if err := queue.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error { return tx.StartRun(lease.Job.ObjectID) }); err != nil {
						t.Fatal(err)
					}
				}
				bySample := map[int64]fixture{}
				for i, f := range fixtures {
					samples, err := f.tenant.ListExecutionSamples(f.run.ID)
					if err != nil || len(samples) != 1 {
						t.Fatal(err)
					}
					fixtures[i].sample = samples[0]
					bySample[samples[0].ID] = fixtures[i]
				}
				accepted, denied := 0, 0
				for range fixtures {
					lease, err := queue.Claim(tenant.ctx)
					if err != nil || lease == nil {
						t.Fatal(err)
					}
					f := bySample[lease.Job.ObjectID]
					err = queue.WithLease(f.tenant.ctx, *lease, func(tx *TenantTransaction) error {
						_, err := tx.ReserveAttempt(f.sample.ID, testWireSnapshot(t, f.sample))
						return err
					})
					if err == nil {
						accepted++
					} else if errors.Is(err, ErrExecutionLimit) {
						denied++
					} else {
						t.Fatal(err)
					}
				}
				if accepted != 2 || denied != 1 {
					t.Fatalf("%s scope not enforced: %d/%d", scope, accepted, denied)
				}
			})
		})
	}
}

func TestExecutionRequestMoneyTimeAndRPMBudgets(t *testing.T) {
	for _, kind := range []string{"requests", "money", "time", "rpm", "unknown-price"} {
		t.Run(kind, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				tenant, _, plan, policy := executionFixture(t, store, 2)
				want := ErrExecutionBudget
				switch kind {
				case "requests":
					plan.Budget.MaxRequests = 1
				case "money":
					amount := int64(30)
					plan.Budget.MaxCostMicros = &amount
				case "rpm":
					limits := scheduler.DefaultLimits()
					limits.TargetRPM = 1
					policy, _ = scheduler.NewPolicy(limits)
					want = ErrExecutionRPM
				case "unknown-price":
					plan.Pricing = domain.ExecutionPricing{}
				}
				run, q, samples := executionStart(t, tenant, plan, policy)
				first, _ := q.Claim(tenant.ctx)
				if kind == "time" {
					if err := store.db.Model(&RunRecord{}).Where("id = ?", run.ID).Update("deadline_at", time.Now().UTC().Add(-time.Second)).Error; err != nil {
						t.Fatal(err)
					}
				} else {
					attempt := reserveTestAttempt(t, tenant, q, *first, samples[0])
					if kind == "rpm" || kind == "unknown-price" {
						if err := q.CompleteWith(tenant.ctx, *first, func(tx *TenantTransaction) error {
							return tx.FinishAttempt(samples[0].ID, attempt.ID, successOutcome(), 0)
						}); err != nil {
							t.Fatal(err)
						}
					}
				}
				if kind == "unknown-price" {
					current, _ := tenant.GetRun(run.ID)
					if current.CostKnown || current.TokenCount != 15 {
						t.Fatal("unknown price not retained")
					}
					return
				}
				lease := first
				sample := samples[0]
				if kind != "time" {
					lease, _ = q.Claim(tenant.ctx)
					sample = samples[1]
				}
				err := q.WithLease(tenant.ctx, *lease, func(tx *TenantTransaction) error {
					_, err := tx.ReserveAttempt(sample.ID, testWireSnapshot(t, sample))
					return err
				})
				if !errors.Is(err, want) {
					t.Fatalf("%s budget was not enforced: %v", kind, err)
				}
				current, _ := tenant.GetRun(run.ID)
				expected := int64(1)
				if kind == "time" {
					expected = 0
				}
				if current.RequestCount != expected {
					t.Fatal("denied dispatch changed counter")
				}
			})
		})
	}
}

func TestExecutionTerminalRecoveryAtomicAndNoDuplicateCalls(t *testing.T) {
	for _, terminal := range []string{"failed", "cancelled"} {
		t.Run(terminal, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				tenant, _, plan, policy := executionFixture(t, store, 1)
				run, q, samples := executionStart(t, tenant, plan, policy)
				lease, _ := q.Claim(tenant.ctx)
				_ = reserveTestAttempt(t, tenant, q, *lease, samples[0])
				if err := store.db.Model(&Job{}).Where("id = ?", lease.Job.ID).Updates(map[string]any{"status": terminal, "lease_owner": nil, "lease_until": nil}).Error; err != nil {
					t.Fatal(err)
				}
				signer := &switchAuditSigner{}
				signer.fail.Store(true)
				store.auditSigner = signer
				if err := q.ReconcileExecution(tenant.ctx, tenant.orgID); !errors.Is(err, audit.ErrUnavailable) {
					t.Fatal("reconcile audit not atomic", err)
				}
				current, _ := tenant.GetRun(run.ID)
				if current.TokenCount != 0 || current.ReservedTokens != 30 {
					t.Fatal("reconcile partially committed")
				}
				store.auditSigner = testAuditSigner{}
				if err := q.ReconcileExecution(tenant.ctx, tenant.orgID); err != nil {
					t.Fatal(err)
				}
				if err := q.ReconcileExecution(tenant.ctx, tenant.orgID); err != nil {
					t.Fatal("idempotent reconcile", err)
				}
				current, _ = tenant.GetRun(run.ID)
				attempts, _ := tenant.ListAttempts(samples[0].ID)
				if current.RequestCount != 1 || current.TokenCount != 38 || current.ValidSampleCount != 0 || current.ReservedTokens != 0 || len(attempts) != 1 || attempts[0].Status != "UNCERTAIN" {
					t.Fatal("recovery duplicated/refunded uncertain work")
				}
			})
		})
	}
}

func TestExecutionTargetChangeBlocksNewDispatchAndInvalidatesInflight(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, target, plan, policy := executionFixture(t, store, 2)
		run, q, samples := executionStart(t, tenant, plan, policy)
		first, _ := q.Claim(tenant.ctx)
		attempt := reserveTestAttempt(t, tenant, q, *first, samples[0])
		second, _ := q.Claim(tenant.ctx)
		// This fixture simulates a committed target disable/rotation. Target CRUD
		// locking itself is covered by the existing target dual-database suite.
		if err := store.db.Model(&TargetRecord{}).Where("id = ?", target.Target.ID).Updates(map[string]any{"status": "disabled", "version": 2}).Error; err != nil {
			t.Fatal(err)
		}
		if err := tenant.CheckExecution(run.ID); !errors.Is(err, ErrExecutionStale) {
			t.Fatal("target mutation invisible")
		}
		err := q.WithLease(tenant.ctx, *second, func(tx *TenantTransaction) error {
			_, err := tx.ReserveAttempt(samples[1].ID, testWireSnapshot(t, samples[1]))
			return err
		})
		if !errors.Is(err, ErrExecutionStale) {
			t.Fatal("new dispatch accepted", err)
		}
		if err := q.CompleteWith(tenant.ctx, *first, func(tx *TenantTransaction) error {
			return tx.FinishAttempt(samples[0].ID, attempt.ID, successOutcome(), 0)
		}); err != nil {
			t.Fatal(err)
		}
		if err := q.CompleteWith(tenant.ctx, *second, func(tx *TenantTransaction) error { return tx.FinishUnattemptedSample(samples[1].ID) }); err != nil {
			t.Fatal(err)
		}
		current, _ := tenant.GetRun(run.ID)
		attempts, _ := tenant.ListAttempts(samples[0].ID)
		if current.RequestCount != 1 || current.ValidSampleCount != 0 || attempts[0].ErrorCode == nil || *attempts[0].ErrorCode != "MI_EXECUTION_TARGET_STALE" {
			t.Fatal("stale response counted as valid")
		}
	})
}

func TestExecutionCreateAndCancelRequireCurrentControlAuthority(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		unbound, _ := store.WithOrganization(testActorContext(t, tenant.ctx.Value(controlAuthorityKey{}).(controlAuthority).identity.UserID), tenant.orgID)
		if _, err := unbound.CreateRun(plan, policy, "unbound"); !errors.Is(err, ErrManagementSession) {
			t.Fatal("actor-only create bypass", err)
		}
		run, err := tenant.CreateRun(plan, policy, "before-revocation")
		if err != nil {
			t.Fatal(err)
		}
		authority := tenant.ctx.Value(controlAuthorityKey{}).(controlAuthority)
		if err := store.db.Model(&Session{}).Where("id = ?", authority.identity.SessionID).Update("revoked_at", time.Now().UTC()).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.CreateRun(plan, policy, "after-revocation"); !errors.Is(err, ErrManagementSession) {
			t.Fatal("stale session created run", err)
		}
		if _, err := tenant.CancelRun(run.ID, run.Version); !errors.Is(err, ErrManagementSession) {
			t.Fatal("stale session cancelled run", err)
		}
		var count int64
		if err := store.db.Model(&RunRecord{}).Where("organization_id = ?", tenant.orgID).Count(&count).Error; err != nil || count != 1 {
			t.Fatal("unauthorized run persisted")
		}
	})
}

func TestExecutionUnstartedCancellationAndExhaustedPlanCloseTruthfully(t *testing.T) {
	for _, kind := range []string{"cancel", "plan-failed"} {
		t.Run(kind, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				tenant, _, plan, policy := executionFixture(t, store, 2)
				run, err := tenant.CreateRun(plan, policy, "unstarted")
				if err != nil {
					t.Fatal(err)
				}
				q, err := store.OpenJobQueue(tenant.ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = q.Close(t.Context()) })
				lease, err := q.Claim(tenant.ctx)
				if err != nil || lease == nil {
					t.Fatal(err)
				}
				if kind == "cancel" {
					if _, err := tenant.CancelRun(run.ID, run.Version); err != nil {
						t.Fatal(err)
					}
					if err := q.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error { return tx.StartRun(run.ID) }); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := q.Fail(tenant.ctx, *lease, "JOB_HANDLER_FAILED"); err != nil {
						t.Fatal(err)
					}
					if err := q.ReconcileExecution(tenant.ctx, tenant.orgID); err != nil {
						t.Fatal(err)
					}
				}
				current, _ := tenant.GetRun(run.ID)
				want := "CANCELLED"
				if kind == "plan-failed" {
					want = "FAILED"
				}
				if current.Status != want || current.RequestCount != 0 || current.ExecutionClosedAt == nil {
					t.Fatal("unstarted run did not close truthfully")
				}
				samples, _ := tenant.ListExecutionSamples(run.ID)
				for _, sample := range samples {
					if sample.CompletedAt == nil || sample.FinalAttemptID != nil {
						t.Fatal("unstarted sample fabricated attempt")
					}
				}
				var count int64
				if err := store.db.Model(&Job{}).Where("organization_id = ? AND type IN (?,?)", tenant.orgID, string(JobSampleExecute), string(JobRunAnalyze)).Count(&count).Error; err != nil || count != 0 {
					t.Fatal("cancelled or failed plan queued work")
				}
			})
		})
	}
}
