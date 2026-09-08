package repository

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func derivedRecoveryCandidates(run RunRecord, sample LogicalSampleRecord, attempt AttemptRecord) AttemptDerivedCandidates {
	return AttemptDerivedCandidates{Scope: derivedScopeFor(run, sample, attempt), Items: []AttemptDerivedCandidate{{Status: "UNCERTAIN", Validity: "INVALID_RETRYABLE", ErrorCode: "MI_UNCERTAIN_ATTEMPT", Record: DerivedRecord{Version: domain.AnalysisSourceDerivedV1, KeyVersion: "fixture", Payload: []byte("opaque-explicit-unavailable"), MAC: bytes.Repeat([]byte{8}, 32)}}}}
}

func TestDerivedExecutionReclaimedAttemptNeedsExactUnavailableReceipt(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, run, queue, sample, attempt, old := derivedExecutionFixture(t, store)
		if err := store.db.Model(&Job{}).Where("id = ?", old.Job.ID).Update("lease_until", time.Now().UTC().Add(-time.Second)).Error; err != nil {
			t.Fatal(err)
		}
		fresh, err := queue.Claim(tenant.ctx)
		if err != nil || fresh == nil || fresh.Generation <= old.Generation {
			t.Fatal("reclaim old job", err)
		}
		candidates := derivedRecoveryCandidates(run, sample, attempt)
		if err := queue.CompleteWith(tenant.ctx, old, func(tx *TenantTransaction) error {
			return tx.RecoverInterruptedSampleWithDerived(sample.ID, attempt.ID, candidates)
		}); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("old fence recovered attempt", err)
		}
		if err := queue.CompleteWith(tenant.ctx, *fresh, func(tx *TenantTransaction) error { return tx.RecoverInterruptedSample(sample.ID) }); !errors.Is(err, ErrAnalysisSource) {
			t.Fatal("legacy recovery bypassed derived receipt", err)
		}
		if err := queue.CompleteWith(tenant.ctx, *fresh, func(tx *TenantTransaction) error {
			return tx.RecoverInterruptedSampleWithDerived(sample.ID, attempt.ID+1, candidates)
		}); err == nil {
			t.Fatal("wrong recovered attempt accepted")
		}
		if err := store.db.Model(&AttemptRecord{}).Where("id = ?", attempt.ID).Update("request_snapshot", "{}").Error; err != nil {
			t.Fatal(err)
		}
		if err := queue.CompleteWith(tenant.ctx, *fresh, func(tx *TenantTransaction) error {
			return tx.RecoverInterruptedSampleWithDerived(sample.ID, attempt.ID, candidates)
		}); !errors.Is(err, ErrAnalysisSource) {
			t.Fatal("corrupt old wire recovered", err)
		}
		if err := store.db.Model(&AttemptRecord{}).Where("id = ?", attempt.ID).Update("request_snapshot", attempt.RequestSnapshot).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.db.Model(&TargetRecord{}).Where("id = ?", run.TargetID).Updates(map[string]any{"version": 2, "deleted_at": time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.db.Table("integrity_secrets").Where("id IN (SELECT secret_id FROM integrity_targets WHERE id = ?)", run.TargetID).Update("deleted_at", time.Now().UTC()).Error; err != nil {
			t.Fatal(err)
		}
		if err := queue.CompleteWith(tenant.ctx, *fresh, func(tx *TenantTransaction) error {
			return tx.RecoverInterruptedSampleWithDerived(sample.ID, attempt.ID, candidates)
		}); err != nil {
			t.Fatal("recover with unavailable target/secret", err)
		}
		attempts, err := tenant.ListAttempts(sample.ID)
		if err != nil || len(attempts) != 1 || attempts[0].ID != attempt.ID || attempts[0].JobID != attempt.JobID || attempts[0].LeaseGeneration != old.Generation || attempts[0].DerivedReceipt != DerivedRecovered || attempts[0].Status != "UNCERTAIN" {
			t.Fatal("recovery changed old request identity")
		}
		var record AttemptDerivedRecord
		if err := store.db.First(&record).Error; err != nil || record.Status != "UNCERTAIN" || record.ErrorCode != "MI_UNCERTAIN_ATTEMPT" || attempts[0].FinishedAt == nil || !record.CreatedAt.Equal(*attempts[0].FinishedAt) {
			t.Fatal("recovery S1 does not match persisted unknown outcome")
		}
		current, _ := tenant.GetRun(run.ID)
		if current.RequestCount != 1 || current.ReservedTokens != 0 || current.TokenCount != 38 || current.ValidSampleCount != 0 {
			t.Fatal("recovery lost conservative accounting")
		}
		for _, model := range []any{&ResponseEvidenceRecord{}, &DisplayEvidenceRecord{}} {
			var count int64
			if err := store.db.Model(model).Count(&count).Error; err != nil || count != 0 {
				t.Fatal("recovery invented unavailable response")
			}
		}
		if err := queue.CompleteWith(tenant.ctx, *fresh, func(tx *TenantTransaction) error {
			return tx.RecoverInterruptedSampleWithDerived(sample.ID, attempt.ID, candidates)
		}); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("duplicate recovery recommitted")
		}
		if err := store.VerifyAllAudit(tenant.ctx, true); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDerivedExecutionSQLFailureAndFinalFenceRollBackWholeSettlement(t *testing.T) {
	for _, fault := range []string{"derived", "raw", "display", "audit", "dependent_job", "final_fence"} {
		t.Run(fault, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, cfg Config) {
				tenant, run, queue, sample, attempt, lease := derivedExecutionFixture(t, store)
				body := derivedFixtureBody(t, tenant, queue, lease, sample, attempt)
				candidates := derivedFixtureCandidates(run, sample, attempt, successOutcome())
				if fault != "final_fence" {
					table, condition := "", ""
					switch fault {
					case "derived":
						table, condition = "integrity_attempt_derived", "version = 'mii.derived-s1.v1'"
					case "raw":
						table, condition = "integrity_response_evidence", "plaintext_bytes > 0"
					case "display":
						table, condition = "integrity_display_evidence", "state = 'captured'"
					case "audit":
						table, condition = "integrity_audit_logs", "action = 'run.attempt.finish'"
					case "dependent_job":
						table, condition = "integrity_jobs", "type = 'integrity.run.analyze'"
					}
					statement := "ALTER TABLE " + table + " ADD CONSTRAINT derived_fixture_failure CHECK (NOT (" + condition + ")) NOT VALID"
					if cfg.Driver == "sqlite" {
						statement = "CREATE TRIGGER derived_fixture_failure BEFORE INSERT ON " + table + " WHEN NEW." + condition + " BEGIN SELECT RAISE(ABORT, 'DERIVED_FIXTURE_FAILURE'); END"
					}
					if err := store.db.Exec(statement).Error; err != nil {
						t.Fatal("install actual SQL fault")
					}
				}
				err := queue.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error {
					if err := tx.FinishAttemptWithDerived(sample.ID, attempt.ID, successOutcome(), 0, candidates, body); err != nil {
						return err
					}
					if fault == "final_fence" {
						return tx.db.Model(&Job{}).Where("id = ?", lease.Job.ID).Update("lease_until", time.Now().UTC().Add(-time.Second)).Error
					}
					return nil
				})
				if err == nil {
					t.Fatal("failed settlement committed")
				}
				assertDisplaySettlementRolledBack(t, tenant, run.ID, sample, attempt, lease)
				var count int64
				if err := store.db.Model(&AttemptDerivedRecord{}).Count(&count).Error; err != nil || count != 0 {
					t.Fatal("S1 survived failed settlement")
				}
				attempts, _ := tenant.ListAttempts(sample.ID)
				if attempts[0].DerivedReceipt != DerivedPending {
					t.Fatal("receipt survived rollback")
				}
				if err := store.VerifyAllAudit(tenant.ctx, true); err != nil {
					t.Fatal("failed settlement damaged audit chain", err)
				}
			})
		})
	}
}
