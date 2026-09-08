package repository

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func legacyBodyFixture(t *testing.T, store *Store) (*Tenant, RunRecord, *JobQueue, LogicalSampleRecord, AttemptRecord, JobLease) {
	t.Helper()
	tenant, _, plan, policy := executionFixture(t, store, 1)
	run, queue, samples := executionStart(t, tenant, plan, policy)
	lease, err := queue.Claim(tenant.ctx)
	if err != nil || lease == nil {
		t.Fatal("claim legacy sample", err)
	}
	attempt := reserveTestAttempt(t, tenant, queue, *lease, samples[0])
	run, err = tenant.GetRun(run.ID)
	if err != nil || run.AnalysisSourceVersion != AnalysisSourceLegacyV1 || attempt.DerivedReceipt != DerivedLegacy {
		t.Fatal("fixture silently upgraded source", err)
	}
	return tenant, run, queue, samples[0], attempt, *lease
}

func forbidLegacyBodyInsert(t *testing.T, store *Store, config Config) {
	t.Helper()
	for _, table := range []string{"integrity_response_evidence", "integrity_display_evidence"} {
		statement := "ALTER TABLE " + table + " ADD CONSTRAINT legacy_body_insert_forbidden CHECK (false) NOT VALID"
		if config.Driver == "sqlite" {
			statement = "CREATE TRIGGER forbid_legacy_" + table + " BEFORE INSERT ON " + table + " BEGIN SELECT RAISE(ABORT, 'LEGACY_BODY_INSERT_FORBIDDEN'); END"
		}
		if err := store.db.Exec(statement).Error; err != nil {
			t.Fatal("install no-body-insert assertion", err)
		}
	}
}

func TestLegacyBodyCaptureRetainsPolicyWithoutUpgradingSource(t *testing.T) {
	for _, days := range []int{0, 7, 30, 180} {
		t.Run(fmt.Sprint(days), func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, config Config) {
				tenant, run, queue, sample, attempt, lease := legacyBodyFixture(t, store)
				derivedFixtureRetention(t, tenant, days)
				body := derivedFixtureBody(t, tenant, queue, lease, sample, attempt)
				if days == 0 {
					forbidLegacyBodyInsert(t, store, config)
				}
				if err := queue.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error {
					return tx.FinishLegacyAttemptWithCapture(sample.ID, attempt.ID, successOutcome(), 0, body)
				}); err != nil {
					t.Fatal("legacy policy settlement", err)
				}
				current, err := tenant.GetRun(run.ID)
				if err != nil || current.ConfigSnapshot != run.ConfigSnapshot || current.ManifestHash != run.ManifestHash || current.AnalysisSourceVersion != AnalysisSourceLegacyV1 || current.TokenCount != 15 || current.ReservedTokens != 0 {
					t.Fatal("legacy signed source or accounting changed", err)
				}
				attempts, err := tenant.ListAttempts(sample.ID)
				want := BodyRecorded
				if days == 0 {
					want = BodyNotRetained
				}
				if err != nil || len(attempts) != 1 || attempts[0].DerivedReceipt != DerivedLegacy || attempts[0].ResponseBodyReceipt != want {
					t.Fatal("legacy receipt changed mode", err)
				}
				var count int64
				if err := store.db.Model(&AttemptDerivedRecord{}).Count(&count).Error; err != nil || count != 0 {
					t.Fatal("legacy created fake S1")
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
					if raw.CreatedAt.UnixMicro() != body.captured || raw.ExpiresAt.UnixMicro() != body.expires || raw.ExpiresAt.Sub(raw.CreatedAt) != time.Duration(days)*24*time.Hour || display.CapturedAtMicros != body.captured || display.ExpiresAtMicros != body.expires {
						t.Fatal("legacy original capture/expiry changed")
					}
				}
				analysisLease, err := queue.Claim(tenant.ctx)
				if err != nil || analysisLease == nil {
					t.Fatal("claim legacy analysis", err)
				}
				source, err := queue.LoadRunAnalysis(tenant.ctx, *analysisLease)
				if err != nil {
					t.Fatal("load legacy analysis", err)
				}
				if err := source.Use(func(data AnalysisData) error {
					if len(data.Attempts) != 1 || (len(data.Evidence) == 0) != (days == 0) {
						t.Fatal("legacy history hidden or missing raw replaced")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err := store.VerifyAllAudit(tenant.ctx, true); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestLegacyBodyCapturePolicyTransitionsNeverRevive(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		initial     int
		ageDays     int
		transitions []int
		retained    bool
	}{
		{"disabled_capture_then_180", 0, 0, []int{180}, false},
		{"capture_then_zero_then_180", 30, 0, []int{0, 180}, false},
		{"aged_capture_shorten_then_180", 30, 8, []int{7, 180}, false},
		{"seven_then_180_preserves_original_expiry", 7, 0, []int{180}, true},
		{"expired_seven_then_180", 7, 8, []int{180}, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, config Config) {
				tenant, run, queue, sample, attempt, lease := legacyBodyFixture(t, store)
				derivedFixtureRetention(t, tenant, scenario.initial)
				body := derivedFixtureBody(t, tenant, queue, lease, sample, attempt)
				if scenario.ageDays > 0 {
					// Internal test-only passage of days, not a public constructor:
					// shift the existing private DB observation and matching fixture
					// timestamps. Real policy updates and final commit still use DB now.
					delta := int64(scenario.ageDays) * responseRetentionDayMicros
					body.captured, body.expires = body.captured-delta, body.expires-delta
					body.raw.CreatedAt, body.raw.ExpiresAt = time.UnixMicro(body.captured).UTC(), time.UnixMicro(body.expires).UTC()
					body.display.CapturedAtMicros, body.display.ExpiresAtMicros = body.captured, body.expires
					started := attempt.StartedAt.Add(-time.Duration(scenario.ageDays) * 24 * time.Hour)
					if err := store.db.Model(&AttemptRecord{}).Where("id = ?", attempt.ID).Update("started_at", started).Error; err != nil {
						t.Fatal(err)
					}
				}
				for _, days := range scenario.transitions {
					derivedFixtureRetention(t, tenant, days)
				}
				if !scenario.retained {
					forbidLegacyBodyInsert(t, store, config)
				}
				if err := queue.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error {
					return tx.FinishLegacyAttemptWithCapture(sample.ID, attempt.ID, successOutcome(), 0, body)
				}); err != nil {
					t.Fatal("legacy cutoff settlement", err)
				}
				attempts, _ := tenant.ListAttempts(sample.ID)
				want := BodyNotRetained
				if scenario.retained {
					want = BodyRecorded
					var raw ResponseEvidenceRecord
					if err := store.db.First(&raw).Error; err != nil || raw.ExpiresAt.UnixMicro() != body.expires || !bytes.Equal(raw.Ciphertext, body.raw.Ciphertext) {
						t.Fatal("extension changed original envelope/expiry", err)
					}
				}
				current, _ := tenant.GetRun(run.ID)
				if attempts[0].ResponseBodyReceipt != want || current.ConfigSnapshot != run.ConfigSnapshot || current.TokenCount != 15 {
					t.Fatal("policy changed analysis source/accounting or revived body")
				}
				if err := store.VerifyAllAudit(tenant.ctx, true); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestLegacyBodyCaptureRejectsPublicEnvelopesAndWrongCapability(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, run, queue, sample, attempt, lease := legacyBodyFixture(t, store)
		body := derivedFixtureBody(t, tenant, queue, lease, sample, attempt)
		for _, finish := range []func(*TenantTransaction) error{
			func(tx *TenantTransaction) error {
				return tx.FinishAttemptWithEvidence(sample.ID, attempt.ID, successOutcome(), 0, *body.raw)
			},
			func(tx *TenantTransaction) error {
				return tx.FinishAttemptWithEvidenceAndDisplay(sample.ID, attempt.ID, successOutcome(), 0, *body.raw, *body.display)
			},
		} {
			if err := queue.CompleteWith(tenant.ctx, lease, finish); !errors.Is(err, ErrAnalysisSource) {
				t.Fatal("public envelope acquired capture authority", err)
			}
		}
		for _, mutate := range []func(*AttemptBodyCapture){
			func(c *AttemptBodyCapture) { c.sourceMode = domain.AnalysisSourceDerivedV1 },
			func(c *AttemptBodyCapture) { c.scope.OrganizationID++ },
			func(c *AttemptBodyCapture) { c.scope.AttemptID++ },
			func(c *AttemptBodyCapture) { c.scope.RequestHash = "wrong" },
			func(c *AttemptBodyCapture) { c.generation++ },
			func(c *AttemptBodyCapture) { c.store = &Store{} },
		} {
			wrong := *body
			mutate(&wrong)
			if err := queue.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error {
				return tx.FinishLegacyAttemptWithCapture(sample.ID, attempt.ID, successOutcome(), 0, &wrong)
			}); !errors.Is(err, ErrAnalysisSource) {
				t.Fatal("wrong private capability accepted", err)
			}
			assertDisplaySettlementRolledBack(t, tenant, run.ID, sample, attempt, lease)
		}
		if err := store.db.Model(&Job{}).Where("id = ?", lease.Job.ID).Update("cancel_requested_at", time.Now().UTC()).Error; err != nil {
			t.Fatal(err)
		}
		if err := queue.WithLease(tenant.ctx, lease, func(tx *TenantTransaction) error {
			_, err := tx.BindAttemptResponseCapture(sample.ID, attempt.ID, attempt.RequestHash)
			return err
		}); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("cancelled Job gained new capture", err)
		}
		if err := queue.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error {
			return tx.FinishLegacyAttemptWithCapture(sample.ID, attempt.ID, successOutcome(), 0, body)
		}); err != nil {
			t.Fatal("fenced legacy final cancellation", err)
		}
		attempts, _ := tenant.ListAttempts(sample.ID)
		if attempts[0].ErrorCode == nil || *attempts[0].ErrorCode != "MI_EXECUTION_CANCELLED" || attempts[0].DerivedReceipt != DerivedLegacy {
			t.Fatal("legacy final cancellation lost actual outcome")
		}
		if err := store.VerifyAllAudit(tenant.ctx, true); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLegacyBodyCaptureZeroAuditSQLFailureRollsBackReceipt(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, config Config) {
		tenant, run, queue, sample, attempt, lease := legacyBodyFixture(t, store)
		derivedFixtureRetention(t, tenant, 0)
		body := derivedFixtureBody(t, tenant, queue, lease, sample, attempt)
		forbidLegacyBodyInsert(t, store, config)
		statement := "ALTER TABLE integrity_audit_logs ADD CONSTRAINT legacy_zero_audit_failure CHECK (action <> 'run.attempt.finish') NOT VALID"
		removeFault := "ALTER TABLE integrity_audit_logs DROP CONSTRAINT legacy_zero_audit_failure"
		if config.Driver == "sqlite" {
			statement = "CREATE TRIGGER legacy_zero_audit_failure BEFORE INSERT ON integrity_audit_logs WHEN NEW.action = 'run.attempt.finish' BEGIN SELECT RAISE(ABORT, 'LEGACY_ZERO_AUDIT_FAILURE'); END"
			removeFault = "DROP TRIGGER legacy_zero_audit_failure"
		}
		if err := store.db.Exec(statement).Error; err != nil {
			t.Fatal("install zero-day audit SQL fault", err)
		}
		finish := func(tx *TenantTransaction) error {
			return tx.FinishLegacyAttemptWithCapture(sample.ID, attempt.ID, successOutcome(), 0, body)
		}
		if err := queue.CompleteWith(tenant.ctx, lease, finish); err == nil {
			t.Fatal("zero-day audit failure committed")
		}
		assertDisplaySettlementRolledBack(t, tenant, run.ID, sample, attempt, lease)
		attempts, _ := tenant.ListAttempts(sample.ID)
		if attempts[0].ResponseBodyReceipt != attempt.ResponseBodyReceipt || attempts[0].DerivedReceipt != DerivedLegacy {
			t.Fatal("failed zero-day settlement changed receipt")
		}
		if err := store.db.Exec(removeFault).Error; err != nil {
			t.Fatal("remove exact test-only audit fault", err)
		}
		if err := queue.CompleteWith(tenant.ctx, lease, finish); err != nil {
			t.Fatal("zero-day completion after rollback", err)
		}
		attempts, _ = tenant.ListAttempts(sample.ID)
		if attempts[0].ResponseBodyReceipt != BodyNotRetained || attempts[0].DerivedReceipt != DerivedLegacy {
			t.Fatal("zero-day receipt after rollback retry incorrect")
		}
		if err := store.VerifyAllAudit(tenant.ctx, true); err != nil {
			t.Fatal(err)
		}
	})
}
