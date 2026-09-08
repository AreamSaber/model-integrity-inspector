package repository

import (
	"bytes"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/migrations"
)

type breakerAuditSigner struct{}

func (breakerAuditSigner) ActiveVersion() string { return "test-v1" }
func (breakerAuditSigner) AuditMAC(version string, message []byte) ([]byte, error) {
	if bytes.Contains(message, []byte("run.circuit.open")) {
		return nil, errors.New("synthetic circuit audit failure")
	}
	return testAuditSigner{}.AuditMAC(version, message)
}

func TestExecutionBreakerAuditRollbackIncludesSequenceEvidenceAndSkips(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 3)
		run, q, samples := executionStart(t, tenant, plan, policy)
		completeBreakerSample(t, tenant, q, samples[0], breakerOutcome("MI_AUTH_FAILED", 401))
		lease, err := q.Claim(tenant.ctx)
		if err != nil || lease == nil {
			t.Fatal(err)
		}
		attempt := reserveTestAttempt(t, tenant, q, *lease, samples[1])
		outcome := breakerOutcome("MI_AUTH_FAILED", 403)
		body := responseFixtureBody(t, tenant, q, *lease, samples[1], attempt)
		store.auditSigner = breakerAuditSigner{}
		finish := func(tx *TenantTransaction) error {
			return tx.FinishLegacyAttemptWithCapture(samples[1].ID, attempt.ID, outcome, 0, body)
		}
		if err := q.CompleteWith(tenant.ctx, *lease, finish); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatal("circuit audit failure not atomic", err)
		}
		current, _ := tenant.GetRun(run.ID)
		rows, _ := tenant.ListExecutionSamples(run.ID)
		attempts, _ := tenant.ListAttempts(samples[1].ID)
		if current.CircuitBreakerCode != "" || current.FinalizedSampleCount != 1 || current.ReservedTokens != 30 || rows[1].CompletionSequence != nil || rows[2].CompletedAt != nil || attempts[0].Status != "DISPATCHED" {
			t.Fatal("failed circuit audit partially committed")
		}
		if _, err := tenant.GetResponseEvidenceForAnalysis(run.ID, samples[1].ID, attempt.ID); !errors.Is(err, ErrNotFound) {
			t.Fatal("failed circuit audit left evidence")
		}
		store.auditSigner = testAuditSigner{}
		if err := q.CompleteWith(tenant.ctx, *lease, finish); err != nil {
			t.Fatal(err)
		}
		if err := q.CompleteWith(tenant.ctx, *lease, finish); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("duplicate completion accepted")
		}
		current, _ = tenant.GetRun(run.ID)
		var count int64
		if err := store.db.Model(&audit.Event{}).Where("organization_id = ? AND action = 'run.circuit.open'", tenant.orgID).Count(&count).Error; err != nil || count != 1 || current.FinalizedSampleCount != 3 {
			t.Fatal("circuit audit or final sequence duplicated")
		}
	})
}

func TestExecutionBreakerLegacyBackfillDeterministicAndUnique(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 4)
		run, _, samples := executionStart(t, tenant, plan, policy)
		stamp := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
		for _, i := range []int{3, 1, 0} {
			at := stamp
			if i == 0 {
				at = stamp.Add(time.Second)
			}
			if err := store.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND id = ?", tenant.orgID, samples[i].ID).Updates(map[string]any{"completed_at": at, "validity": "NOT_APPLICABLE"}).Error; err != nil {
				t.Fatal(err)
			}
		}
		set, err := migrations.ForDialect(store.driver)
		if err != nil {
			t.Fatal(err)
		}
		// Exercise the exact embedded legacy UPDATEs without re-running DDL on
		// an already-expanded test schema. Blank and upgrade DDL are tested by
		// the normal real dual-database migration suite.
		for _, migration := range set {
			if migration.Name != "execution_breaker" {
				continue
			}
			offset := strings.Index(migration.SQL, "UPDATE integrity_logical_samples SET completion_sequence")
			if offset < 0 {
				t.Fatal("missing embedded backfill")
			}
			for _, statement := range strings.Split(migration.SQL[offset:], ";") {
				if strings.HasPrefix(strings.TrimSpace(statement), "UPDATE ") {
					if err := store.db.Exec(statement).Error; err != nil {
						t.Fatal("backfill failed", err)
					}
				}
			}
		}
		rows, _ := tenant.ListExecutionSamples(run.ID)
		current, _ := tenant.GetRun(run.ID)
		first, second := 1, 3
		if rows[first].ID > rows[second].ID {
			first, second = second, first
		}
		if rows[first].CompletionSequence == nil || *rows[first].CompletionSequence != 1 || rows[second].CompletionSequence == nil || *rows[second].CompletionSequence != 2 || rows[0].CompletionSequence == nil || *rows[0].CompletionSequence != 3 || rows[2].CompletionSequence != nil || current.FinalizedSampleCount != 3 {
			t.Fatal("legacy backfill did not honor completed_at,id")
		}
		if err := store.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND id = ?", tenant.orgID, samples[2].ID).Update("completion_sequence", 1).Error; err == nil {
			t.Fatal("duplicate completion sequence accepted")
		}
	})
}

func breakerOutcome(code string, status int) domain.AttemptOutcome {
	if code == "" {
		return successOutcome()
	}
	return domain.AttemptOutcome{Validity: "INVALID_PROTOCOL", ErrorCode: code, HTTPStatus: status}
}

func completeBreakerSample(t *testing.T, tenant *Tenant, q *JobQueue, sample LogicalSampleRecord, outcome domain.AttemptOutcome) {
	t.Helper()
	lease, err := q.Claim(tenant.ctx)
	if err != nil || lease == nil || lease.Job.ObjectID != sample.ID {
		t.Fatal("claim expected breaker sample", err)
	}
	attempt := reserveTestAttempt(t, tenant, q, *lease, sample)
	if err := q.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error { return tx.FinishAttempt(sample.ID, attempt.ID, outcome, 0) }); err != nil {
		t.Fatal(err)
	}
}

func TestExecutionBreakerClosedClassesThresholdsAndReset(t *testing.T) {
	auth := breakerOutcome("MI_AUTH_FAILED", 401)
	for _, scenario := range []struct {
		name     string
		outcomes []domain.AttemptOutcome
		code     string
	}{
		{"mixed-auth-401-403", []domain.AttemptOutcome{auth, breakerOutcome("MI_AUTH_FAILED", 403)}, "MI_CIRCUIT_AUTH_FAILURES"},
		{"model", []domain.AttemptOutcome{breakerOutcome("MI_MODEL_NOT_FOUND", 404), breakerOutcome("MI_MODEL_NOT_FOUND", 404)}, "MI_CIRCUIT_MODEL_FAILURES"},
		{"protocol-four", []domain.AttemptOutcome{breakerOutcome("MI_PROTOCOL_UNSUPPORTED", 400), breakerOutcome("MI_PROTOCOL_UNSUPPORTED", 200), breakerOutcome("MI_PROTOCOL_UNSUPPORTED", 400), breakerOutcome("MI_PROTOCOL_UNSUPPORTED", 200)}, ""},
		{"protocol-five", []domain.AttemptOutcome{breakerOutcome("MI_PROTOCOL_UNSUPPORTED", 400), breakerOutcome("MI_PROTOCOL_UNSUPPORTED", 200), breakerOutcome("MI_PROTOCOL_UNSUPPORTED", 400), breakerOutcome("MI_PROTOCOL_UNSUPPORTED", 200), breakerOutcome("MI_PROTOCOL_UNSUPPORTED", 400)}, "MI_CIRCUIT_PROTOCOL_FAILURES"},
		{"success-reset", []domain.AttemptOutcome{auth, successOutcome(), auth}, ""},
		{"different-class-reset", []domain.AttemptOutcome{auth, breakerOutcome("MI_MODEL_NOT_FOUND", 404), auth}, ""},
		{"unknown-status-not-auth", []domain.AttemptOutcome{auth, breakerOutcome("MI_AUTH_FAILED", 404)}, ""},
		{"safety-reset", []domain.AttemptOutcome{auth, {Validity: "INVALID_SAFETY_LIMIT", ErrorCode: "MI_CLIENT_SAFETY_LIMIT", HTTPStatus: 200}, auth}, ""},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				tenant, _, plan, policy := executionFixture(t, store, len(scenario.outcomes)+1)
				run, q, samples := executionStart(t, tenant, plan, policy)
				for i, outcome := range scenario.outcomes {
					completeBreakerSample(t, tenant, q, samples[i], outcome)
				}
				current, err := tenant.GetRun(run.ID)
				if err != nil || current.CircuitBreakerCode != scenario.code || current.RequestCount != int64(len(scenario.outcomes)) {
					t.Fatal("incorrect breaker state", err)
				}
				rows, err := tenant.ListExecutionSamples(run.ID)
				if err != nil {
					t.Fatal(err)
				}
				for i := range scenario.outcomes {
					if rows[i].CompletionSequence == nil || *rows[i].CompletionSequence != int64(i+1) {
						t.Fatal("logical sample completion order missing")
					}
				}
				if scenario.code != "" {
					if current.CircuitBreakerOpenedAt == nil || current.CancelRequestedAt != nil || current.Status != "ANALYZING" || current.FinalizedSampleCount != int64(len(samples)) || current.ReservedTokens != 0 || rows[len(rows)-1].FailureCode != "MI_EXECUTION_CIRCUIT_OPEN" || rows[len(rows)-1].FinalAttemptID != nil {
						t.Fatal("breaker fabricated cancellation/attempt or left dispatch pending")
					}
					if err := tenant.CheckExecution(run.ID); !errors.Is(err, ErrExecutionCircuitOpen) {
						t.Fatal("breaker did not block dispatch", err)
					}
				} else if current.CircuitBreakerOpenedAt != nil || current.FinalizedSampleCount != int64(len(scenario.outcomes)) || rows[len(rows)-1].CompletionSequence != nil {
					t.Fatal("nonconsecutive failures opened breaker")
				}
			})
		})
	}
}

func TestExecutionBreakerRetriesAreNotFinalSamples(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 3)
		run, q, samples := executionStart(t, tenant, plan, policy)
		completeBreakerSample(t, tenant, q, samples[0], breakerOutcome("MI_AUTH_FAILED", 401))
		completeBreakerSample(t, tenant, q, samples[1], domain.AttemptOutcome{Validity: "INVALID_RETRYABLE", ErrorCode: "MI_SERVICE_UNAVAILABLE", HTTPStatus: 503})
		current, _ := tenant.GetRun(run.ID)
		if current.FinalizedSampleCount != 1 || current.CircuitBreakerCode != "" {
			t.Fatal("retry counted as final sample")
		}
		if err := store.db.Model(&Job{}).Where("organization_id = ? AND object_id = ?", tenant.orgID, samples[2].ID).Update("available_at", time.Now().UTC().Add(time.Hour)).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.db.Model(&Job{}).Where("organization_id = ? AND object_id = ? AND status = 'pending'", tenant.orgID, samples[1].ID).Update("available_at", time.Now().UTC().Add(-time.Second)).Error; err != nil {
			t.Fatal(err)
		}
		completeBreakerSample(t, tenant, q, samples[1], breakerOutcome("MI_AUTH_FAILED", 403))
		current, _ = tenant.GetRun(run.ID)
		rows, _ := tenant.ListExecutionSamples(run.ID)
		attempts, _ := tenant.ListAttempts(samples[1].ID)
		if current.CircuitBreakerCode != "MI_CIRCUIT_AUTH_FAILURES" || current.RequestCount != 3 || current.FinalizedSampleCount != 3 || len(attempts) != 2 || rows[1].CompletionSequence == nil || *rows[1].CompletionSequence != 2 || rows[2].FailureCode != "MI_EXECUTION_CIRCUIT_OPEN" || current.ExecutionClosedAt == nil {
			t.Fatal("retry reset/duplicated final sequence or delayed breaker close")
		}
	})
}

func TestExecutionBreakerCompletesAlreadyClaimedDeferredJobWithoutNewWork(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 3)
		run, q, samples := executionStart(t, tenant, plan, policy)
		leases := make([]JobLease, 3)
		attempts := make([]AttemptRecord, 2)
		for i := range samples {
			lease, err := q.Claim(tenant.ctx)
			if err != nil || lease == nil {
				t.Fatal(err)
			}
			leases[i] = *lease
			if i < 2 {
				attempts[i] = reserveTestAttempt(t, tenant, q, *lease, samples[i])
			}
		}
		for i := 0; i < 2; i++ {
			if err := q.CompleteWith(tenant.ctx, leases[i], func(tx *TenantTransaction) error {
				return tx.FinishAttempt(samples[i].ID, attempts[i].ID, breakerOutcome("MI_AUTH_FAILED", 401), 0)
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := q.CompleteWith(tenant.ctx, leases[2], func(tx *TenantTransaction) error { return tx.DeferExecutionSample(samples[2].ID) }); err != nil {
			t.Fatal("claimed deferral raced breaker", err)
		}
		current, _ := tenant.GetRun(run.ID)
		job, _ := tenant.GetJob(leases[2].Job.ID)
		skipped, _ := tenant.GetExecutionSampleForWorker(samples[2].ID)
		if current.RequestCount != 2 || current.FinalizedSampleCount != 3 || job.Status != "completed" || skipped.JobID == nil || *skipped.JobID != job.ID || skipped.FinalAttemptID != nil {
			t.Fatal("breaker deferral invented job/attempt/sequence")
		}
	})
}

func TestExecutionBreakerConcurrentCompletionOrderIsSerialized(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 3)
		run, q, samples := executionStart(t, tenant, plan, policy)
		leases := make([]JobLease, 3)
		attempts := make([]AttemptRecord, 3)
		for i := range samples {
			lease, err := q.Claim(tenant.ctx)
			if err != nil || lease == nil {
				t.Fatal(err)
			}
			leases[i] = *lease
			attempts[i] = reserveTestAttempt(t, tenant, q, *lease, samples[i])
		}
		outcomes := []domain.AttemptOutcome{breakerOutcome("MI_AUTH_FAILED", 401), successOutcome(), breakerOutcome("MI_AUTH_FAILED", 403)}
		var wg sync.WaitGroup
		failures := make(chan error, 3)
		start := make(chan struct{})
		for i := range samples {
			wg.Go(func() {
				<-start
				failures <- q.CompleteWith(tenant.ctx, leases[i], func(tx *TenantTransaction) error {
					return tx.FinishAttempt(samples[i].ID, attempts[i].ID, outcomes[i], 0)
				})
			})
		}
		close(start)
		wg.Wait()
		close(failures)
		for err := range failures {
			if err != nil {
				t.Fatal(err)
			}
		}
		rows, _ := tenant.ListExecutionSamples(run.ID)
		for _, row := range rows {
			if row.CompletionSequence == nil {
				t.Fatal("concurrent completion sequence missing")
			}
		}
		sort.Slice(rows, func(i, j int) bool { return *rows[i].CompletionSequence < *rows[j].CompletionSequence })
		expectOpen := false
		for i, row := range rows {
			if *row.CompletionSequence != int64(i+1) {
				t.Fatal("duplicate or gapped completion sequence")
			}
			if i > 0 && row.Validity == "INVALID_PROTOCOL" && rows[i-1].Validity == "INVALID_PROTOCOL" {
				expectOpen = true
			}
		}
		current, _ := tenant.GetRun(run.ID)
		if (current.CircuitBreakerCode != "") != expectOpen || current.FinalizedSampleCount != 3 || current.ValidSampleCount != 1 || current.RequestCount != 3 || current.ReservedTokens != 0 {
			t.Fatal("concurrent final order/counters inconsistent")
		}
	})
}

func TestExecutionBreakerMaximumPlanStopsInBoundedBatch(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1000)
		run, q, samples := executionStart(t, tenant, plan, policy)
		completeBreakerSample(t, tenant, q, samples[0], breakerOutcome("MI_AUTH_FAILED", 401))
		completeBreakerSample(t, tenant, q, samples[1], breakerOutcome("MI_AUTH_FAILED", 403))
		current, _ := tenant.GetRun(run.ID)
		var completed int64
		if err := store.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND run_id = ? AND completed_at IS NOT NULL AND completion_sequence BETWEEN 1 AND 1000", tenant.orgID, run.ID).Count(&completed).Error; err != nil {
			t.Fatal(err)
		}
		if completed != 1000 || current.FinalizedSampleCount != 1000 || current.RequestCount != 2 || current.ReservedTokens != 0 || current.Status != "ANALYZING" {
			t.Fatal("maximum batch exceeded completion/budget bounds")
		}
	})
}
