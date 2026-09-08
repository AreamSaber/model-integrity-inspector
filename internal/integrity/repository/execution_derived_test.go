package repository

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

// These are repository scope/atomicity fixtures, not cryptographic S1. Real
// compiler, purpose MAC, TLS and analyzer equivalence belong to worker tests.
func derivedExecutionFixture(t *testing.T, store *Store) (*Tenant, RunRecord, *JobQueue, LogicalSampleRecord, AttemptRecord, JobLease) {
	t.Helper()
	tenant, _, plan, policy := executionFixture(t, store, 1)
	plan.AnalysisSourceVersion = domain.AnalysisSourceDerivedV1
	plan.Manifest = []byte(`{"fixture":"repository-scope-only"}`)
	hash := sha256.Sum256(plan.Manifest)
	plan.ManifestHash = hex.EncodeToString(hash[:])
	run, err := tenant.CreateRun(plan, policy, "derived-request")
	if err != nil {
		t.Fatal("create derived run", err)
	}
	queue, err := store.OpenJobQueue(tenant.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queue.Close(t.Context()) })
	start, err := queue.Claim(tenant.ctx)
	if err != nil || start == nil {
		t.Fatal("claim derived plan", err)
	}
	if err := queue.CompleteWith(tenant.ctx, *start, func(tx *TenantTransaction) error { return tx.StartRun(run.ID) }); err == nil {
		t.Fatal("legacy start accepted derived mode")
	}
	if err := queue.CompleteWith(tenant.ctx, *start, func(tx *TenantTransaction) error { return tx.StartRunWithDerivedSource(run.ID) }); err != nil {
		t.Fatal("start derived run", err)
	}
	samples, err := tenant.ListExecutionSamples(run.ID)
	if err != nil || len(samples) != 1 {
		t.Fatal("derived sample source", err)
	}
	lease, err := queue.Claim(tenant.ctx)
	if err != nil || lease == nil {
		t.Fatal("claim derived attempt", err)
	}
	attempt := reserveTestAttempt(t, tenant, queue, *lease, samples[0])
	if attempt.DerivedReceipt != DerivedPending || attempt.ResponseBodyReceipt != BodyNotCaptured {
		t.Fatal("reserve did not declare derived obligation")
	}
	run, err = tenant.GetRun(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	return tenant, run, queue, samples[0], attempt, *lease
}

func derivedFixtureCandidates(run RunRecord, sample LogicalSampleRecord, attempt AttemptRecord, base domain.AttemptOutcome) AttemptDerivedCandidates {
	result := AttemptDerivedCandidates{Scope: derivedScopeFor(run, sample, attempt)}
	keys := [][3]string{{"COMPLETED", base.Validity, base.ErrorCode}, {"COMPLETED", "NOT_APPLICABLE", "MI_EXECUTION_CANCELLED"}, {"COMPLETED", "NOT_APPLICABLE", "MI_EXECUTION_TARGET_STALE"}, {"COMPLETED", "NOT_APPLICABLE", "MI_EXECUTION_BUDGET_EXCEEDED"}}
	seen := map[[3]string]bool{}
	for _, key := range keys {
		if seen[key] {
			continue
		}
		seen[key] = true
		result.Items = append(result.Items, AttemptDerivedCandidate{Status: key[0], Validity: key[1], ErrorCode: key[2], Record: DerivedRecord{Version: domain.AnalysisSourceDerivedV1, KeyVersion: "fixture", Payload: []byte("opaque-fixture:" + key[1] + ":" + key[2]), MAC: bytes.Repeat([]byte{7}, 32)}})
	}
	return result
}

func derivedFixtureBody(t *testing.T, tenant *Tenant, queue *JobQueue, lease JobLease, sample LogicalSampleRecord, attempt AttemptRecord) *AttemptBodyCapture {
	t.Helper()
	var capture *AttemptBodyCapture
	if err := queue.WithLease(tenant.ctx, lease, func(tx *TenantTransaction) error {
		var err error
		capture, err = tx.BindAttemptResponseCapture(sample.ID, attempt.ID, attempt.RequestHash)
		return err
	}); err != nil {
		t.Fatal("bind body capture", err)
	}
	display := capture.DisplayBinding()
	if display.State == DisplayCaptured {
		display.SourceHash, display.PayloadHash = strings.Repeat("b", 64), strings.Repeat("c", 64)
		display.Version, display.KeyVersion, display.PlaintextBytes = 1, "fixture", 32
		display.Nonce, display.Ciphertext = bytes.Repeat([]byte{3}, 12), bytes.Repeat([]byte{4}, 48)
	}
	attached, err := capture.WithRecords(testEvidenceRecord(tenant, sample, attempt), display)
	if err != nil {
		t.Fatal("attach scoped evidence", err)
	}
	return attached
}

func derivedFixtureRetention(t *testing.T, tenant *Tenant, days int) {
	t.Helper()
	actor, err := tenant.targetActor()
	if err != nil {
		t.Fatal(err)
	}
	user, err := tenant.store.GetUser(tenant.ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	auth := managementSession(t, tenant.store, user)
	updateRetention(t, tenant.store, tenant.ctx, auth, tenant.orgID, days)
}

func TestDerivedExecutionFinalOutcomeCandidates(t *testing.T) {
	for _, scenario := range []string{"normal", "cancel", "stale", "budget", "stale_budget", "cancel_stale_budget", "job_cancel"} {
		t.Run(scenario, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				tenant, run, queue, sample, attempt, lease := derivedExecutionFixture(t, store)
				candidates := derivedFixtureCandidates(run, sample, attempt, successOutcome())
				body := derivedFixtureBody(t, tenant, queue, lease, sample, attempt)
				want := ""
				if strings.Contains(scenario, "stale") {
					if err := store.db.Model(&TargetRecord{}).Where("id = ?", run.TargetID).Update("version", 2).Error; err != nil {
						t.Fatal(err)
					}
					want = "MI_EXECUTION_TARGET_STALE"
				}
				if strings.Contains(scenario, "budget") {
					if err := store.db.Model(&RunRecord{}).Where("id = ?", run.ID).Update("deadline_at", time.Now().UTC().Add(-time.Second)).Error; err != nil {
						t.Fatal(err)
					}
					want = "MI_EXECUTION_BUDGET_EXCEEDED"
				}
				if strings.HasPrefix(scenario, "cancel") {
					if err := store.db.Model(&RunRecord{}).Where("id = ?", run.ID).Update("cancel_requested_at", time.Now().UTC()).Error; err != nil {
						t.Fatal(err)
					}
					want = "MI_EXECUTION_CANCELLED"
				}
				if scenario == "job_cancel" {
					if err := store.db.Model(&Job{}).Where("id = ?", lease.Job.ID).Update("cancel_requested_at", time.Now().UTC()).Error; err != nil {
						t.Fatal(err)
					}
					want = "MI_EXECUTION_CANCELLED"
				}
				if err := queue.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error {
					return tx.FinishAttemptWithDerived(sample.ID, attempt.ID, successOutcome(), 0, candidates, body)
				}); err != nil {
					t.Fatal("derived actual outcome settlement", err)
				}
				var record AttemptDerivedRecord
				if err := store.db.Where("organization_id = ? AND attempt_id = ?", tenant.orgID, attempt.ID).First(&record).Error; err != nil {
					t.Fatal(err)
				}
				attempts, err := tenant.ListAttempts(sample.ID)
				if err != nil || len(attempts) != 1 || attempts[0].DerivedReceipt != DerivedRecorded || attempts[0].ErrorCode == nil || *attempts[0].ErrorCode != want || record.ErrorCode != want || record.Status != "COMPLETED" || attempts[0].FinishedAt == nil || !record.CreatedAt.Equal(*attempts[0].FinishedAt) {
					t.Fatal("S1 not bound to actual committed outcome/time")
				}
				var count int64
				if err := store.db.Model(&AttemptDerivedRecord{}).Count(&count).Error; err != nil || count != 1 {
					t.Fatal("candidate set persisted more than once")
				}
				current, _ := tenant.GetRun(run.ID)
				if current.ReservedTokens != 0 || current.RequestCount != 1 || current.TokenCount != 15 {
					t.Fatal("candidate changed measured usage/settlement")
				}
				if err := store.VerifyAllAudit(tenant.ctx, true); err != nil {
					t.Fatal(err)
				}
				if err := store.db.Model(&AttemptRecord{}).Where("id = ?", attempt.ID).Updates(map[string]any{"status": "DISPATCHED", "derived_receipt": DerivedPending}).Error; err == nil {
					t.Fatal("terminal derived receipt moved back to pending")
				}
			})
		})
	}
}

func TestDerivedExecutionBodyRetentionZeroThrough180(t *testing.T) {
	for _, days := range []int{0, 1, 7, 30, 180} {
		t.Run(fmt.Sprint(days), func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, cfg Config) {
				tenant, run, queue, sample, attempt, lease := derivedExecutionFixture(t, store)
				derivedFixtureRetention(t, tenant, days)
				body := derivedFixtureBody(t, tenant, queue, lease, sample, attempt)
				if days == 0 {
					for _, table := range []string{"integrity_response_evidence", "integrity_display_evidence"} {
						statement := "ALTER TABLE " + table + " ADD CONSTRAINT forbid_body_insert CHECK (false) NOT VALID"
						if cfg.Driver == "sqlite" {
							statement = "CREATE TRIGGER forbid_" + table + " BEFORE INSERT ON " + table + " BEGIN SELECT RAISE(ABORT, 'BODY_INSERT_FORBIDDEN'); END"
						}
						if err := store.db.Exec(statement).Error; err != nil {
							t.Fatal("install no-insert assertion")
						}
					}
				}
				candidates := derivedFixtureCandidates(run, sample, attempt, successOutcome())
				if err := queue.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error {
					return tx.FinishAttemptWithDerived(sample.ID, attempt.ID, successOutcome(), 0, candidates, body)
				}); err != nil {
					t.Fatal("retention settlement", err)
				}
				want := int64(1)
				if days == 0 {
					want = 0
				}
				for _, model := range []any{&ResponseEvidenceRecord{}, &DisplayEvidenceRecord{}} {
					var count int64
					if err := store.db.Model(model).Count(&count).Error; err != nil || count != want {
						t.Fatal("wrong retained body count")
					}
				}
				if days > 0 {
					var raw ResponseEvidenceRecord
					var display DisplayEvidenceRecord
					if err := store.db.First(&raw).Error; err != nil {
						t.Fatal(err)
					}
					if err := store.db.First(&display).Error; err != nil {
						t.Fatal(err)
					}
					if raw.CreatedAt.UnixMicro() != body.CapturedAtMicros() || raw.ExpiresAt.UnixMicro() != body.ExpiresAtMicros() || display.CapturedAtMicros != body.CapturedAtMicros() || display.ExpiresAtMicros-display.CapturedAtMicros != int64(days)*responseRetentionDayMicros {
						t.Fatal("capture timestamps/expiry rewritten")
					}
				}
				attempts, _ := tenant.ListAttempts(sample.ID)
				if attempts[0].DerivedReceipt != DerivedRecorded || (days == 0 && attempts[0].ResponseBodyReceipt != BodyNotRetained) || (days > 0 && attempts[0].ResponseBodyReceipt != BodyRecorded) {
					t.Fatal("body retention changed mandatory S1 receipt")
				}
			})
		})
	}
}

func TestDerivedExecutionLegacyEntrypointsRejectBypass(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, run, queue, sample, attempt, lease := derivedExecutionFixture(t, store)
		body := derivedFixtureBody(t, tenant, queue, lease, sample, attempt)
		for _, finish := range []func(*TenantTransaction) error{
			func(tx *TenantTransaction) error { return tx.FinishAttempt(sample.ID, attempt.ID, successOutcome(), 0) },
			func(tx *TenantTransaction) error {
				return tx.FinishAttemptWithEvidence(sample.ID, attempt.ID, successOutcome(), 0, *body.raw)
			},
			func(tx *TenantTransaction) error {
				return tx.FinishAttemptWithEvidenceAndDisplay(sample.ID, attempt.ID, successOutcome(), 0, *body.raw, *body.display)
			},
		} {
			if err := queue.CompleteWith(tenant.ctx, lease, finish); err == nil {
				t.Fatal("legacy settlement bypassed mandatory S1")
			}
			assertDisplaySettlementRolledBack(t, tenant, run.ID, sample, attempt, lease)
		}
		bad := derivedFixtureCandidates(run, sample, attempt, successOutcome())
		bad.Scope.JobID++
		if err := queue.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error {
			return tx.FinishAttemptWithDerived(sample.ID, attempt.ID, successOutcome(), 0, bad, body)
		}); err == nil {
			t.Fatal("wrong candidate scope accepted")
		}
		if err := store.db.Model(&RunRecord{}).Where("id = ?", run.ID).Update("analysis_source_version", AnalysisSourceLegacyV1).Error; err == nil {
			t.Fatal("SQL source downgrade accepted")
		}
		if _, err := tenant.GetExecutionPlan(run.ID); err != nil {
			t.Fatal("rejected SQL downgrade damaged source", err)
		}
		var wrong *AttemptBodyCapture
		if _, err := wrong.WithRecords(ResponseEvidenceRecord{}, DisplayEvidenceRecord{}); !errors.Is(err, ErrConfiguration) {
			t.Fatal("forged zero capture accepted")
		}
	})
}
