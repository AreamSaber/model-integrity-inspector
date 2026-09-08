package repository

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func TestResponseEvidenceStructuredLogRedaction(t *testing.T) {
	const canary = "S2-record-ciphertext-canary"
	record := ResponseEvidenceRecord{Ciphertext: []byte(canary), ContentHash: canary, KeyVersion: canary}
	var output bytes.Buffer
	for _, handler := range []slog.Handler{slog.NewJSONHandler(&output, nil), slog.NewTextHandler(&output, nil)} {
		slog.New(handler).Info("safe", "record", record, "pointer", &record, slog.Group("nested", "record", record))
	}
	if strings.Contains(output.String(), canary) || !strings.Contains(output.String(), "encrypted response evidence") {
		t.Fatal("structured logger bypassed evidence redaction")
	}
}

// Structurally valid synthetic ciphertext. Real AES/AAD tests live in secret
// and Worker TLS integration, avoiding the repository->secret import cycle.
func testEvidenceRecord(tenant *Tenant, sample LogicalSampleRecord, attempt AttemptRecord) ResponseEvidenceRecord {
	return ResponseEvidenceRecord{OrganizationID: tenant.orgID, RunID: sample.RunID, LogicalSampleID: sample.ID, AttemptID: attempt.ID, RequestHash: attempt.RequestHash, KeyVersion: "fixture", Nonce: bytes.Repeat([]byte{1}, 12), Ciphertext: bytes.Repeat([]byte{2}, 48), PlaintextBytes: 32, ContentHash: strings.Repeat("d", 64)}
}

func responseFixtureBody(t *testing.T, tenant *Tenant, queue *JobQueue, lease JobLease, sample LogicalSampleRecord, attempt AttemptRecord) *AttemptBodyCapture {
	t.Helper()
	var capture *AttemptBodyCapture
	if err := queue.WithLease(tenant.ctx, lease, func(tx *TenantTransaction) error {
		var err error
		capture, err = tx.BindAttemptResponseCapture(sample.ID, attempt.ID, attempt.RequestHash)
		return err
	}); err != nil {
		t.Fatal("bind response fixture", err)
	}
	display := DisplayEvidenceRecord{OrganizationID: tenant.orgID, RunID: sample.RunID, LogicalSampleID: sample.ID, AttemptID: attempt.ID, RequestHash: attempt.RequestHash, Policy: DisplayEvidencePolicy, State: DisplayUnavailableCapture}
	return attachFixtureBody(t, capture, testEvidenceRecord(tenant, sample, attempt), display)
}

func attachFixtureBody(t *testing.T, capture *AttemptBodyCapture, evidence ResponseEvidenceRecord, display DisplayEvidenceRecord) *AttemptBodyCapture {
	t.Helper()
	body, err := capture.WithRecords(evidence, display)
	if err != nil {
		t.Fatal("attach response fixture", err)
	}
	return body
}

func TestResponseEvidenceAtomicLeaseScopeAuditAndExpiry(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		run, q, samples := executionStart(t, tenant, plan, policy)
		lease, _ := q.Claim(tenant.ctx)
		attempt := reserveTestAttempt(t, tenant, q, *lease, samples[0])
		record := testEvidenceRecord(tenant, samples[0], attempt)
		body := responseFixtureBody(t, tenant, q, *lease, samples[0], attempt)
		wrong := record
		wrong.RequestHash = strings.Repeat("e", 64)
		if _, err := body.WithRecords(wrong, *body.display); !errors.Is(err, ErrAnalysisSource) {
			t.Fatal("wrong request binding accepted", err)
		}
		wrong = record
		wrong.OrganizationID++
		if _, err := body.WithRecords(wrong, *body.display); !errors.Is(err, ErrAnalysisSource) {
			t.Fatal("wrong tenant binding accepted", err)
		}
		signer := &switchAuditSigner{}
		signer.fail.Store(true)
		store.auditSigner = signer
		if err := q.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error {
			return tx.FinishLegacyAttemptWithCapture(samples[0].ID, attempt.ID, successOutcome(), 0, body)
		}); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatal("audit failure not propagated", err)
		}
		var count int64
		if err := store.db.Model(&ResponseEvidenceRecord{}).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("orphan evidence after rollback")
		}
		current, _ := tenant.GetRun(run.ID)
		if current.ValidSampleCount != 0 || current.ReservedTokens != 30 {
			t.Fatal("attempt completed without evidence")
		}
		store.auditSigner = testAuditSigner{}
		if err := q.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error {
			return tx.FinishLegacyAttemptWithCapture(samples[0].ID, attempt.ID, successOutcome(), 0, body)
		}); err != nil {
			t.Fatal(err)
		}
		stored, err := tenant.GetResponseEvidenceForAnalysis(run.ID, samples[0].ID, attempt.ID)
		if err != nil || stored.PlaintextBytes != 32 || stored.ExpiresAt.Sub(stored.CreatedAt) != 30*24*time.Hour {
			t.Fatal("wrong persisted ciphertext/TTL", err)
		}
		if _, err := json.Marshal(stored); !errors.Is(err, ErrEvidenceSerialization) {
			t.Fatal("evidence JSON exported")
		}
		if strings.Contains(fmt.Sprintf("%+v", stored), stored.ContentHash) {
			t.Fatal("evidence formatted")
		}
		foreign, _ := store.WithOrganization(tenant.ctx, tenant.orgID+1)
		if _, err := foreign.GetResponseEvidenceForAnalysis(run.ID, samples[0].ID, attempt.ID); !errors.Is(err, ErrNotFound) {
			t.Fatal("cross-tenant evidence read")
		}
		if err := store.db.Model(&ResponseEvidenceRecord{}).Where("organization_id = ? AND attempt_id = ?", tenant.orgID, attempt.ID).Update("expires_at", time.Now().UTC().Add(-time.Second)).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.GetResponseEvidenceForAnalysis(run.ID, samples[0].ID, attempt.ID); !errors.Is(err, ErrNotFound) {
			t.Fatal("expired evidence exposed")
		}
	})
}

func TestExecutionCustomAndHighCostPermissionsRevalidated(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		if err := store.db.Exec("DELETE FROM role_permissions WHERE organization_id = ? AND permission_code IN ('run.custom','run.high-cost')", tenant.orgID).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.CreateRun(plan, policy, "custom-denied"); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("custom permission bypass", err)
		}
		plan.Package = "standard"
		plan.Budget.MaxRequests = 61
		if _, err := tenant.CreateRun(plan, policy, "request-high-denied"); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("request high-cost permission bypass", err)
		}
		plan.Budget.MaxRequests = 60
		plan.Budget.MaxTokens = 50001
		if _, err := tenant.CreateRun(plan, policy, "token-high-denied"); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("token high-cost permission bypass", err)
		}
		plan.Budget.MaxTokens = 50000
		money := int64(2000001)
		plan.Budget.MaxCostMicros = &money
		if _, err := tenant.CreateRun(plan, policy, "money-high-denied"); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("money high-cost permission bypass", err)
		}
		plan.Budget.MaxCostMicros = nil
		plan.Package = "deep"
		if _, err := tenant.CreateRun(plan, policy, "deep-denied"); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("deep permission bypass", err)
		}
		plan.Package = "standard"
		if _, err := tenant.CreateRun(plan, policy, "nil-money-high-denied"); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("known-price nil money bypassed high-cost ceiling", err)
		}
		money = 2000000 // The public service's ordinary known-price default.
		plan.Budget.MaxCostMicros = &money
		if _, err := tenant.CreateRun(plan, policy, "standard-allowed"); err != nil {
			t.Fatal("standard baseline unexpectedly denied", err)
		}
	})
}

func TestExecutionCapacityDeferralDoesNotCreateAttemptOrBurnBudget(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 2)
		plan.Concurrency = 1
		run, q, samples := executionStart(t, tenant, plan, policy)
		first, _ := q.Claim(tenant.ctx)
		_ = reserveTestAttempt(t, tenant, q, *first, samples[0])
		second, _ := q.Claim(tenant.ctx)
		if err := q.WithLease(tenant.ctx, *second, func(tx *TenantTransaction) error {
			_, err := tx.ReserveAttempt(samples[1].ID, testWireSnapshot(t, samples[1]))
			return err
		}); !errors.Is(err, ErrExecutionLimit) {
			t.Fatal(err)
		}
		if err := q.CompleteWith(tenant.ctx, *second, func(tx *TenantTransaction) error { return tx.DeferExecutionSample(samples[1].ID) }); err != nil {
			t.Fatal(err)
		}
		current, _ := tenant.GetRun(run.ID)
		attempts, _ := tenant.ListAttempts(samples[1].ID)
		sample, _ := tenant.GetExecutionSampleForWorker(samples[1].ID)
		if current.RequestCount != 1 || len(attempts) != 0 || sample.JobID == nil || *sample.JobID == second.Job.ID {
			t.Fatal("deferral changed request budget/sample identity")
		}
		job, _ := tenant.GetJob(*sample.JobID)
		if job.Status != "pending" || time.Until(job.AvailableAt) <= 0 {
			t.Fatal("deferral not scheduled")
		}
	})
}
