package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
)

func executionFixture(t *testing.T, store *Store, count int) (*Tenant, TargetState, domain.ExecutionPlan, scheduler.Policy) {
	t.Helper()
	requireMigrate(t, store)
	input := initialState()
	input.Roles[0].Permissions = append(input.Roles[0].Permissions, "run.cancel-own", "run.cancel-any", "run.custom", "run.high-cost", "target.delete", "secret.replace")
	initial, err := store.Initialize(testActorContext(t, 0), input)
	if err != nil {
		t.Fatal(err)
	}
	session := managementSession(t, store, initial.User)
	ctx := bindTargetTestSession(t, store, testActorContext(t, initial.User.ID), session.SessionID, initial.Organization.ID)
	tenant, err := store.WithOrganization(ctx, initial.Organization.ID)
	if err != nil {
		t.Fatal(err)
	}
	target := mustCreateTarget(t, tenant)
	price := int64(1_000_000)
	plan := domain.ExecutionPlan{Target: domain.ExecutionTarget{ID: target.Target.ID, Version: 1, SecretID: target.Secret.ID, SecretVersion: 1, Endpoint: target.Target.Endpoint, Model: target.Target.Model, Protocol: target.Target.Protocol, MaxOutputParameter: "max_tokens"}, Package: "custom", ManifestHash: strings.Repeat("c", 64), Versions: domain.BundleVersions{Rule: "1", Template: "1", Scoring: "1", Tokenizer: "1"}, Budget: domain.ExecutionBudget{MaxRequests: 50, MaxTokens: 10000, TimeoutSeconds: 2700}, Pricing: domain.ExecutionPricing{InputMicrosPerMillion: &price, OutputMicrosPerMillion: &price}, Concurrency: 3, MaxRetries: 2}
	probe := domain.ProbePlan{Type: "contract", TemplateID: "contract-basic", TemplateVersion: "1", Category: "format", Variant: "en"}
	for i := range count {
		probe.Samples = append(probe.Samples, domain.SamplePlan{Ordinal: i, PairID: fmt.Sprintf("pair-%d", i), Nonce: fmt.Sprintf("nonce-%d", i), EstimatedInputTokens: 10, Request: domain.NormalizedRequest{Model: target.Target.Model, Messages: []domain.NormalizedMessage{{Role: "user", Content: "Return OK"}}, MaxOutputTokens: 20}})
	}
	plan.Probes = []domain.ProbePlan{probe}
	policy, err := scheduler.NewPolicy(scheduler.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return tenant, target, plan, policy
}

func executionStart(t *testing.T, tenant *Tenant, plan domain.ExecutionPlan, policy scheduler.Policy) (RunRecord, *JobQueue, []LogicalSampleRecord) {
	t.Helper()
	run, err := tenant.CreateRun(plan, policy, "request-key")
	if err != nil {
		t.Fatal("create", err)
	}
	queue, err := tenant.store.OpenJobQueue(tenant.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queue.Close(t.Context()) })
	lease, err := queue.Claim(tenant.ctx)
	if err != nil || lease == nil {
		t.Fatal("claim plan", err)
	}
	if err := queue.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error { return tx.StartRun(run.ID) }); err != nil {
		t.Fatal("start", err)
	}
	samples, err := tenant.ListExecutionSamples(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	run, err = tenant.GetRun(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	return run, queue, samples
}

func testWireSnapshot(t *testing.T, sample LogicalSampleRecord) domain.RequestSnapshot {
	t.Helper()
	var plan domain.SamplePlan
	if json.Unmarshal([]byte(sample.RequestPlan), &plan) != nil {
		t.Fatal("decode sample")
	}
	encoded, err := json.Marshal(map[string]any{"model": plan.Request.Model, "messages": plan.Request.Messages, "stream": false, "max_tokens": plan.Request.MaxOutputTokens})
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(encoded)
	return domain.RequestSnapshot{Model: plan.Request.Model, MaxOutputTokens: plan.Request.MaxOutputTokens, MaxOutputParameter: "max_tokens", Payload: encoded, PayloadBytes: len(encoded), RequestHash: hex.EncodeToString(hash[:])}
}

func reserveTestAttempt(t *testing.T, tenant *Tenant, q *JobQueue, lease JobLease, sample LogicalSampleRecord) AttemptRecord {
	t.Helper()
	var attempt AttemptRecord
	err := q.WithLease(tenant.ctx, lease, func(tx *TenantTransaction) error {
		var err error
		attempt, err = tx.ReserveAttempt(sample.ID, testWireSnapshot(t, sample))
		return err
	})
	if err != nil {
		t.Fatal("reserve", err)
	}
	return attempt
}

func successOutcome() domain.AttemptOutcome {
	input, output := int64(10), int64(5)
	return domain.AttemptOutcome{Validity: "VALID", HTTPStatus: 200, PromptTokens: &input, CompletionTokens: &output, LocalCompletionTokens: 5, DurationMillis: 10}
}

func TestExecutionLifecycleFrozenIdempotentAndTenantScoped(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, target, plan, policy := executionFixture(t, store, 1)
		run, q, samples := executionStart(t, tenant, plan, policy)
		same, err := tenant.CreateRun(plan, policy, "request-key")
		if err != nil || same.ID != run.ID {
			t.Fatal("duplicate run")
		}
		if err := tenant.DeleteTarget(target.Target.ID, 1); !errors.Is(err, ErrConflict) {
			t.Fatal("active run did not protect credentials")
		}
		foreign, _ := store.WithOrganization(t.Context(), tenant.orgID+1)
		if _, err := foreign.GetRun(run.ID); !errors.Is(err, ErrNotFound) {
			t.Fatal("cross organization run read")
		}
		plan.Probes[0].Samples[0].Request.Messages[0].Content = "changed"
		if _, err := tenant.CreateRun(plan, policy, "request-key"); !errors.Is(err, ErrConflict) {
			t.Fatal("idempotent key silently changed plan")
		}
		frozen, err := tenant.GetExecutionPlan(run.ID)
		if err != nil || frozen.Probes[0].Samples[0].Request.Messages[0].Content != "Return OK" {
			t.Fatal("not frozen")
		}
		lease, err := q.Claim(tenant.ctx)
		if err != nil || lease == nil {
			t.Fatal(err)
		}
		attempt := reserveTestAttempt(t, tenant, q, *lease, samples[0])
		reserved, _ := tenant.GetRun(run.ID)
		if reserved.RequestCount != 1 || reserved.TokenCount != 0 || reserved.ReservedTokens != 30 || reserved.ReservedCostMicros != 30 {
			t.Fatal("reservation not atomic")
		}
		if err := q.WithLease(tenant.ctx, *lease, func(tx *TenantTransaction) error {
			return tx.FinishAttempt(samples[0].ID, attempt.ID, successOutcome(), 0)
		}); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("completion without CompleteWith")
		}
		if err := q.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error {
			return tx.FinishAttempt(samples[0].ID, attempt.ID, successOutcome(), 0)
		}); err != nil {
			t.Fatal(err)
		}
		finished, _ := tenant.GetRun(run.ID)
		if finished.Status != "ANALYZING" || finished.ExecutionClosedAt == nil || finished.ValidSampleCount != 1 || finished.RequestCount != 1 || finished.TokenCount != 15 || finished.EstimatedCostMicros != 15 || finished.ReservedTokens != 0 {
			t.Fatalf("bad closed state: %+v", finished)
		}
		job, _ := tenant.GetJob(lease.Job.ID)
		if job.Status != "completed" {
			t.Fatal("job/result not atomic")
		}
		if err := q.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error {
			return tx.FinishAttempt(samples[0].ID, attempt.ID, successOutcome(), 0)
		}); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("duplicate completion")
		}
		attempts, _ := tenant.ListAttempts(samples[0].ID)
		if len(attempts) != 1 || attempts[0].Validity != "VALID" {
			t.Fatal("attempt not persisted")
		}
		analysis, err := q.Claim(tenant.ctx)
		if err != nil || analysis == nil || JobType(analysis.Job.Type) != JobRunAnalyze {
			t.Fatal("analysis not queued")
		}
	})
}

func TestExecutionRetriesPreserveOneSampleAndChargeEveryAttempt(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		run, q, samples := executionStart(t, tenant, plan, policy)
		for n := 1; n <= 3; n++ {
			lease, err := q.Claim(tenant.ctx)
			if err != nil || lease == nil {
				t.Fatal("retry claim", n, err)
			}
			attempt := reserveTestAttempt(t, tenant, q, *lease, samples[0])
			if attempt.AttemptNo != n {
				t.Fatal("attempt numbering")
			}
			outcome := domain.AttemptOutcome{Validity: "INVALID_RETRYABLE", ErrorCode: "MI_RATE_LIMITED", HTTPStatus: 429, RetryAfterSeconds: 10}
			if n == 3 {
				outcome = successOutcome()
			}
			if err := q.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error { return tx.FinishAttempt(samples[0].ID, attempt.ID, outcome, 500) }); err != nil {
				t.Fatal(err)
			}
			current, _ := tenant.GetRun(run.ID)
			if current.RequestCount != int64(n) {
				t.Fatal("retry request not charged")
			}
			if n < 3 {
				var pending Job
				if err := store.db.Where("organization_id = ? AND type = ? AND status = 'pending'", tenant.orgID, string(JobSampleExecute)).First(&pending).Error; err != nil {
					t.Fatal(err)
				}
				if time.Until(pending.AvailableAt) < 9*time.Second {
					t.Fatal("Retry-After lost")
				}
				if err := store.db.Model(&Job{}).Where("id = ?", pending.ID).Update("available_at", time.Now().UTC().Add(-time.Second)).Error; err != nil {
					t.Fatal(err)
				}
			}
		}
		final, _ := tenant.GetRun(run.ID)
		attempts, _ := tenant.ListAttempts(samples[0].ID)
		logical, _ := tenant.ListExecutionSamples(run.ID)
		if final.ValidSampleCount != 1 || len(attempts) != 3 || len(logical) != 1 || logical[0].FinalAttemptID == nil || *logical[0].FinalAttemptID != attempts[2].ID || attempts[0].RequestHash != attempts[2].RequestHash {
			t.Fatal("retries became extra statistical samples or changed request")
		}
	})
}

func TestExecutionBudgetsNoDispatchAndPayloadInjection(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 2)
		plan.Budget.MaxTokens = 30
		run, q, samples := executionStart(t, tenant, plan, policy)
		first, _ := q.Claim(tenant.ctx)
		attempt := reserveTestAttempt(t, tenant, q, *first, samples[0])
		second, _ := q.Claim(tenant.ctx)
		err := q.WithLease(tenant.ctx, *second, func(tx *TenantTransaction) error {
			_, err := tx.ReserveAttempt(samples[1].ID, testWireSnapshot(t, samples[1]))
			return err
		})
		if !errors.Is(err, ErrExecutionBudget) {
			t.Fatalf("token reservation overbooked: %v", err)
		}
		if err := q.CompleteWith(tenant.ctx, *first, func(tx *TenantTransaction) error {
			return tx.FinishAttempt(samples[0].ID, attempt.ID, successOutcome(), 0)
		}); err != nil {
			t.Fatal(err)
		}
		if err := q.CompleteWith(tenant.ctx, *second, func(tx *TenantTransaction) error { return tx.FinishUnattemptedSample(samples[1].ID) }); err != nil {
			t.Fatal(err)
		}
		final, _ := tenant.GetRun(run.ID)
		if final.RequestCount != 1 || final.ReservedTokens != 0 {
			t.Fatal("denied request was charged")
		}
		bad := testWireSnapshot(t, samples[0])
		var payload map[string]any
		_ = json.Unmarshal(bad.Payload, &payload)
		payload["api_key"] = "must-not-persist"
		bad.Payload, _ = json.Marshal(payload)
		hash := sha256.Sum256(bad.Payload)
		bad.RequestHash = hex.EncodeToString(hash[:])
		bad.PayloadBytes = len(bad.Payload)
		var frozen domain.SamplePlan
		_ = json.Unmarshal([]byte(samples[0].RequestPlan), &frozen)
		if validDispatchSnapshot(frozen, bad) {
			t.Fatal("credential payload accepted with self-consistent hash")
		}
	})
}

func TestExecutionConcurrencyReservationIsAtomic(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 8)
		plan.Concurrency = 3
		run, q, samples := executionStart(t, tenant, plan, policy)
		leases := make([]JobLease, len(samples))
		for i := range samples {
			lease, err := q.Claim(tenant.ctx)
			if err != nil || lease == nil {
				t.Fatal(err)
			}
			leases[i] = *lease
		}
		var won, limited atomic.Int64
		var wg sync.WaitGroup
		for i, sample := range samples {
			wg.Go(func() {
				err := q.WithLease(tenant.ctx, leases[i], func(tx *TenantTransaction) error {
					_, err := tx.ReserveAttempt(sample.ID, testWireSnapshot(t, sample))
					return err
				})
				if err == nil {
					won.Add(1)
				} else if errors.Is(err, ErrExecutionLimit) {
					limited.Add(1)
				} else {
					t.Errorf("unexpected reservation result %v", err)
				}
			})
		}
		wg.Wait()
		current, _ := tenant.GetRun(run.ID)
		if won.Load() != 3 || limited.Load() != 5 || current.RequestCount != 3 || current.ReservedTokens != 90 {
			t.Fatalf("reservation race winners=%d limited=%d", won.Load(), limited.Load())
		}
	})
}

func TestExecutionCancelStaleLeaseAndUnknownRecovery(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		run, q, samples := executionStart(t, tenant, plan, policy)
		old, _ := q.Claim(tenant.ctx)
		_ = reserveTestAttempt(t, tenant, q, *old, samples[0])
		if err := store.db.Model(&Job{}).Where("id = ?", old.Job.ID).Update("lease_until", time.Now().UTC().Add(-time.Second)).Error; err != nil {
			t.Fatal(err)
		}
		fresh, err := q.Claim(tenant.ctx)
		if err != nil || fresh == nil || fresh.Generation == old.Generation {
			t.Fatal("no recovered generation")
		}
		if err := q.WithLease(tenant.ctx, *old, func(tx *TenantTransaction) error {
			_, err := tx.ReserveAttempt(samples[0].ID, testWireSnapshot(t, samples[0]))
			return err
		}); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("stale lease accepted")
		}
		err = q.WithLease(tenant.ctx, *fresh, func(tx *TenantTransaction) error {
			_, err := tx.ReserveAttempt(samples[0].ID, testWireSnapshot(t, samples[0]))
			return err
		})
		if !errors.Is(err, ErrAttemptUncertain) {
			t.Fatal("uncertain request was replayed")
		}
		if err := q.CompleteWith(tenant.ctx, *fresh, func(tx *TenantTransaction) error { return tx.RecoverInterruptedSample(samples[0].ID) }); err != nil {
			t.Fatal(err)
		}
		final, _ := tenant.GetRun(run.ID)
		attempts, _ := tenant.ListAttempts(samples[0].ID)
		if final.RequestCount != 1 || final.TokenCount != 38 || final.ValidSampleCount != 0 || attempts[0].Status != "UNCERTAIN" {
			t.Fatal("uncertain accounting not conservative")
		}
	})
}

func TestExecutionCancellationPreservesAlreadyBilledWork(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 2)
		run, q, samples := executionStart(t, tenant, plan, policy)
		first, _ := q.Claim(tenant.ctx)
		attempt := reserveTestAttempt(t, tenant, q, *first, samples[0])
		second, _ := q.Claim(tenant.ctx)
		current, _ := tenant.GetRun(run.ID)
		if _, err := tenant.CancelRun(run.ID, current.Version-1); !errors.Is(err, ErrConflict) {
			t.Fatal("cancel stale version accepted")
		}
		if _, err := tenant.CancelRun(run.ID, current.Version); err != nil {
			t.Fatal(err)
		}
		if err := tenant.CheckExecution(run.ID); !errors.Is(err, ErrExecutionCancelled) {
			t.Fatal("cancel invisible to outbound guard")
		}
		if err := q.WithLease(tenant.ctx, *second, func(tx *TenantTransaction) error {
			_, err := tx.ReserveAttempt(samples[1].ID, testWireSnapshot(t, samples[1]))
			return err
		}); !errors.Is(err, ErrExecutionCancelled) {
			t.Fatal("new outbound after cancel")
		}
		if err := q.CompleteWith(tenant.ctx, *first, func(tx *TenantTransaction) error {
			return tx.FinishAttempt(samples[0].ID, attempt.ID, successOutcome(), 0)
		}); err != nil {
			t.Fatal(err)
		}
		if err := q.CompleteWith(tenant.ctx, *second, func(tx *TenantTransaction) error { return tx.FinishUnattemptedSample(samples[1].ID) }); err != nil {
			t.Fatal(err)
		}
		final, _ := tenant.GetRun(run.ID)
		if final.Status != "CANCELLED" || final.RequestCount != 1 || final.TokenCount != 15 || final.ValidSampleCount != 0 || final.ExecutionClosedAt == nil {
			t.Fatal("cancel lost billed work or counted invalid response")
		}
	})
}

func TestExecutionAuditFailureRollsBackResultAndJob(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		run, q, samples := executionStart(t, tenant, plan, policy)
		lease, _ := q.Claim(tenant.ctx)
		attempt := reserveTestAttempt(t, tenant, q, *lease, samples[0])
		signer := &switchAuditSigner{}
		signer.fail.Store(true)
		store.auditSigner = signer
		err := q.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error {
			return tx.FinishAttempt(samples[0].ID, attempt.ID, successOutcome(), 0)
		})
		if !errors.Is(err, audit.ErrUnavailable) {
			t.Fatalf("audit failure %v", err)
		}
		current, _ := tenant.GetRun(run.ID)
		job, _ := tenant.GetJob(lease.Job.ID)
		attempts, _ := tenant.ListAttempts(samples[0].ID)
		if current.ValidSampleCount != 0 || current.TokenCount != 0 || current.ReservedTokens != 30 || job.Status != "running" || attempts[0].Status != "DISPATCHED" {
			t.Fatal("partial completion committed")
		}
		store.auditSigner = testAuditSigner{}
		if err := q.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error {
			return tx.FinishAttempt(samples[0].ID, attempt.ID, successOutcome(), 0)
		}); err != nil {
			t.Fatal(err)
		}
	})
}
