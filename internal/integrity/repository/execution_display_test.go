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
)

// Only structural ciphertext is used here; real keys, TLS and exact-AAD opening
// are tested in worker. Repository does not import crypto or analysis packages.
func displayFixtureRecord(t *testing.T, tenant *Tenant, q *JobQueue, lease JobLease, sample LogicalSampleRecord, attempt AttemptRecord) DisplayEvidenceRecord {
	t.Helper()
	var record DisplayEvidenceRecord
	if err := q.WithLease(tenant.ctx, lease, func(tx *TenantTransaction) error {
		var err error
		record, err = tx.BindAttemptDisplayCapture(sample.ID, attempt.ID, attempt.RequestHash)
		return err
	}); err != nil {
		t.Fatal("display capture binding", err)
	}
	record.SourceHash, record.PayloadHash = strings.Repeat("b", 64), strings.Repeat("c", 64)
	record.Version, record.KeyVersion, record.PlaintextBytes = 1, "fixture", 32
	record.Nonce, record.Ciphertext = bytes.Repeat([]byte{3}, 12), bytes.Repeat([]byte{4}, 48)
	return record
}

func assertDisplaySettlementRolledBack(t *testing.T, tenant *Tenant, runID int64, sample LogicalSampleRecord, attempt AttemptRecord, lease JobLease) {
	t.Helper()
	for _, model := range []any{&DisplayEvidenceRecord{}, &ResponseEvidenceRecord{}} {
		var count int64
		if err := tenant.store.db.Model(model).Where("organization_id = ? AND attempt_id = ?", tenant.orgID, attempt.ID).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("orphan evidence after failed settlement")
		}
	}
	current, err := tenant.GetRun(runID)
	if err != nil || current.TokenCount != 0 || current.ValidSampleCount != 0 || current.ReservedTokens != 30 || current.ExecutionClosedAt != nil {
		t.Fatal("failed settlement changed run counters")
	}
	stored, err := tenant.GetExecutionSampleForWorker(sample.ID)
	if err != nil || stored.FinalAttemptID != nil || stored.CompletedAt != nil {
		t.Fatal("failed settlement selected a final attempt")
	}
	attempts, err := tenant.ListAttempts(sample.ID)
	if err != nil || len(attempts) != 1 || attempts[0].Status != "DISPATCHED" || attempts[0].FinishedAt != nil {
		t.Fatal("failed settlement completed attempt")
	}
	job, err := tenant.GetJob(lease.Job.ID)
	if err != nil || job.Status != "running" || job.CompletedAt != nil {
		t.Fatal("failed settlement completed job")
	}
	var count int64
	if err := tenant.store.db.Model(&Job{}).Where("organization_id = ? AND type = ? AND object_id = ?", tenant.orgID, string(JobRunAnalyze), runID).Count(&count).Error; err != nil || count != 0 {
		t.Fatal("failed settlement created dependent analysis job")
	}
	if err := tenant.store.db.Table("integrity_audit_logs").Where("organization_id = ? AND action = 'run.attempt.finish'", tenant.orgID).Count(&count).Error; err != nil || count != 0 {
		t.Fatal("failed settlement committed audit")
	}
}

func TestDisplayEvidenceBindingValidationAndLegacyRemainSeparate(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		run, queue, samples := executionStart(t, tenant, plan, policy)
		lease, err := queue.Claim(tenant.ctx)
		if err != nil || lease == nil {
			t.Fatal("claim display fixture")
		}
		attempt := reserveTestAttempt(t, tenant, queue, *lease, samples[0])
		display := displayFixtureRecord(t, tenant, queue, *lease, samples[0], attempt)
		evidence := testEvidenceRecord(tenant, samples[0], attempt)
		for _, change := range []struct {
			name   string
			mutate func(*DisplayEvidenceRecord)
		}{
			{"organization", func(v *DisplayEvidenceRecord) { v.OrganizationID++ }},
			{"run", func(v *DisplayEvidenceRecord) { v.RunID++ }},
			{"sample", func(v *DisplayEvidenceRecord) { v.LogicalSampleID++ }},
			{"attempt", func(v *DisplayEvidenceRecord) { v.AttemptID++ }},
			{"request", func(v *DisplayEvidenceRecord) { v.RequestHash = strings.Repeat("d", 64) }},
			{"source", func(v *DisplayEvidenceRecord) { v.SourceHash = "" }},
			{"policy", func(v *DisplayEvidenceRecord) { v.Policy = "unknown" }},
			{"version", func(v *DisplayEvidenceRecord) { v.Version++ }},
			{"state", func(v *DisplayEvidenceRecord) { v.State = "unknown" }},
			{"missing_tag", func(v *DisplayEvidenceRecord) { v.Ciphertext = v.Ciphertext[:32] }},
			{"extended_expiry", func(v *DisplayEvidenceRecord) { v.ExpiresAtMicros++ }},
			{"pre_dispatch", func(v *DisplayEvidenceRecord) {
				v.CapturedAtMicros = attempt.StartedAt.UnixMicro() - 1
				v.ExpiresAtMicros = v.CapturedAtMicros + displayRetentionMicros
			}},
			{"future_capture", func(v *DisplayEvidenceRecord) {
				v.CapturedAtMicros += int64(time.Hour / time.Microsecond)
				v.ExpiresAtMicros += int64(time.Hour / time.Microsecond)
			}},
			{"unavailable_ciphertext", func(v *DisplayEvidenceRecord) { v.State = DisplayUnavailablePolicy }},
		} {
			t.Run(change.name, func(t *testing.T) {
				bad := display
				change.mutate(&bad)
				err := queue.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error {
					return tx.FinishAttemptWithEvidenceAndDisplay(samples[0].ID, attempt.ID, successOutcome(), 0, evidence, bad)
				})
				if !errors.Is(err, ErrConfiguration) {
					t.Fatal("invalid display binding accepted", err)
				}
				assertDisplaySettlementRolledBack(t, tenant, run.ID, samples[0], attempt, *lease)
			})
		}
		if err := queue.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error {
			return tx.FinishAttemptWithEvidence(samples[0].ID, attempt.ID, successOutcome(), 0, evidence)
		}); err != nil {
			t.Fatal(err)
		}
		var count int64
		if err := store.db.Model(&DisplayEvidenceRecord{}).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("legacy settlement invented display provenance")
		}
	})
}

func TestDisplayEvidenceCapturedAndUnavailableAtomicallySettle(t *testing.T) {
	for _, state := range []string{DisplayCaptured, DisplayUnavailablePolicy, DisplayUnavailableLimit, DisplayUnavailableSource, DisplayUnavailableCancelled, DisplayUnavailableCapture, DisplayUnavailableSeal} {
		t.Run(state, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				tenant, _, plan, policy := executionFixture(t, store, 1)
				run, queue, samples := executionStart(t, tenant, plan, policy)
				lease, err := queue.Claim(tenant.ctx)
				if err != nil || lease == nil {
					t.Fatal("claim display fixture")
				}
				attempt := reserveTestAttempt(t, tenant, queue, *lease, samples[0])
				display := displayFixtureRecord(t, tenant, queue, *lease, samples[0], attempt)
				if state != DisplayCaptured {
					display = DisplayEvidenceRecord{OrganizationID: tenant.orgID, RunID: run.ID, LogicalSampleID: samples[0].ID, AttemptID: attempt.ID, RequestHash: attempt.RequestHash, Policy: DisplayEvidencePolicy, State: state}
				}
				if err := queue.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error {
					return tx.FinishAttemptWithEvidenceAndDisplay(samples[0].ID, attempt.ID, successOutcome(), 0, testEvidenceRecord(tenant, samples[0], attempt), display)
				}); err != nil {
					t.Fatal(err)
				}
				var actual DisplayEvidenceRecord
				if err := store.db.Where("organization_id = ? AND attempt_id = ?", tenant.orgID, attempt.ID).First(&actual).Error; err != nil {
					t.Fatal("read stored display")
				}
				if !validDisplayRecord(actual) || actual.State != state || actual.CapturedAtMicros != display.CapturedAtMicros || actual.ExpiresAtMicros != display.ExpiresAtMicros || !bytes.Equal(actual.Ciphertext, display.Ciphertext) || actual.CreatedAt.IsZero() {
					t.Fatal("display binding changed at commit")
				}
				current, err := tenant.GetRun(run.ID)
				if err != nil || current.ValidSampleCount != 1 || current.TokenCount != 15 || current.ReservedTokens != 0 {
					t.Fatal("display failure changed truthful analysis settlement")
				}
			})
		})
	}
}

func TestDisplayEvidenceSQLFailuresAndLostLeaseRollBackEverything(t *testing.T) {
	for _, fault := range []string{"display_insert", "raw_insert", "finish_audit", "dependent_job", "final_fence"} {
		t.Run(fault, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, config Config) {
				tenant, _, plan, policy := executionFixture(t, store, 1)
				run, queue, samples := executionStart(t, tenant, plan, policy)
				lease, err := queue.Claim(tenant.ctx)
				if err != nil || lease == nil {
					t.Fatal("claim display fixture")
				}
				attempt := reserveTestAttempt(t, tenant, queue, *lease, samples[0])
				display := displayFixtureRecord(t, tenant, queue, *lease, samples[0], attempt)
				if fault != "final_fence" {
					table, condition := "", ""
					switch fault {
					case "display_insert":
						table, condition = "integrity_display_evidence", "state = 'captured'"
					case "raw_insert":
						table, condition = "integrity_response_evidence", "plaintext_bytes > 0"
					case "finish_audit":
						table, condition = "integrity_audit_logs", "action = 'run.attempt.finish'"
					case "dependent_job":
						table, condition = "integrity_jobs", "type = 'integrity.run.analyze'"
					}
					statement := "ALTER TABLE " + table + " ADD CONSTRAINT display_fixture_failure CHECK (NOT (" + condition + ")) NOT VALID"
					if config.Driver == "sqlite" {
						statement = "CREATE TRIGGER display_fixture_failure BEFORE INSERT ON " + table + " WHEN NEW." + condition + " BEGIN SELECT RAISE(ABORT, 'synthetic display fixture failure'); END"
					}
					if err := store.db.Exec(statement).Error; err != nil {
						t.Fatal("install bounded SQL fault")
					}
				}
				err = queue.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error {
					if err := tx.FinishAttemptWithEvidenceAndDisplay(samples[0].ID, attempt.ID, successOutcome(), 0, testEvidenceRecord(tenant, samples[0], attempt), display); err != nil {
						return err
					}
					if fault == "final_fence" {
						return tx.db.Model(&Job{}).Where("organization_id = ? AND id = ?", tenant.orgID, lease.Job.ID).Update("lease_until", time.Now().UTC().Add(-time.Hour)).Error
					}
					return nil
				})
				if err == nil {
					t.Fatal("faulting settlement committed")
				}
				if fault == "final_fence" && !errors.Is(err, ErrJobLeaseLost) {
					t.Fatal("final lease fence did not reject")
				}
				assertDisplaySettlementRolledBack(t, tenant, run.ID, samples[0], attempt, *lease)
			})
		})
	}
}

func TestDisplayEvidenceCannotFormatOrSerialize(t *testing.T) {
	const canary = "synthetic-display-record-canary"
	v := DisplayEvidenceRecord{RequestHash: canary, SourceHash: canary, PayloadHash: canary, KeyVersion: canary, Ciphertext: []byte(canary)}
	var buffer bytes.Buffer
	for _, handler := range []slog.Handler{slog.NewJSONHandler(&buffer, nil), slog.NewTextHandler(&buffer, nil)} {
		slog.New(handler).Info("safe", "display", v, "pointer", &v)
	}
	for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
		_, _ = fmt.Fprintf(&buffer, format, v)
		_, _ = fmt.Fprintf(&buffer, format, &v)
	}
	for _, value := range []any{v, &v} {
		if _, err := json.Marshal(value); !errors.Is(err, ErrEvidenceSerialization) {
			t.Fatal("display record serialized")
		}
	}
	if strings.Contains(buffer.String(), canary) {
		t.Fatal("display record formatting exposed content")
	}
}

func TestDisplayEvidenceCaptureAndCommitRequireCurrentOwnerAndTransaction(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		run, queue, samples := executionStart(t, tenant, plan, policy)
		lease, err := queue.Claim(tenant.ctx)
		if err != nil || lease == nil {
			t.Fatal("claim display fixture")
		}
		attempt := reserveTestAttempt(t, tenant, queue, *lease, samples[0])
		display := displayFixtureRecord(t, tenant, queue, *lease, samples[0], attempt)
		var escaped *TenantTransaction
		if err := queue.WithLease(tenant.ctx, *lease, func(tx *TenantTransaction) error { escaped = tx; return nil }); err != nil {
			t.Fatal(err)
		}
		if _, err := escaped.BindAttemptDisplayCapture(samples[0].ID, attempt.ID, attempt.RequestHash); !errors.Is(err, ErrTransactionClosed) {
			t.Fatal("escaped capture transaction usable")
		}
		if err := escaped.FinishAttemptWithEvidenceAndDisplay(samples[0].ID, attempt.ID, successOutcome(), 0, testEvidenceRecord(tenant, samples[0], attempt), display); !errors.Is(err, ErrTransactionClosed) {
			t.Fatal("escaped settlement transaction usable")
		}
		if err := queue.WithLease(tenant.ctx, *lease, func(tx *TenantTransaction) error {
			return tx.FinishAttemptWithEvidenceAndDisplay(samples[0].ID, attempt.ID, successOutcome(), 0, testEvidenceRecord(tenant, samples[0], attempt), display)
		}); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("display settlement bypassed CompleteWith")
		}
		for _, wrong := range []struct {
			sample, attempt int64
			hash            string
		}{{samples[0].ID + 1, attempt.ID, attempt.RequestHash}, {samples[0].ID, attempt.ID + 1, attempt.RequestHash}, {samples[0].ID, attempt.ID, strings.Repeat("f", 64)}} {
			err := queue.WithLease(tenant.ctx, *lease, func(tx *TenantTransaction) error {
				_, err := tx.BindAttemptDisplayCapture(wrong.sample, wrong.attempt, wrong.hash)
				return err
			})
			if !errors.Is(err, ErrJobLeaseLost) {
				t.Fatal("capture authorized wrong persistent scope")
			}
		}
		if err := store.db.Model(&Job{}).Where("organization_id = ? AND id = ?", tenant.orgID, lease.Job.ID).Update("lease_owner", "replacement-owner").Error; err != nil {
			t.Fatal(err)
		}
		if err := queue.WithLease(tenant.ctx, *lease, func(tx *TenantTransaction) error {
			_, err := tx.BindAttemptDisplayCapture(samples[0].ID, attempt.ID, attempt.RequestHash)
			return err
		}); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("lost owner captured")
		}
		if err := queue.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error {
			return tx.FinishAttemptWithEvidenceAndDisplay(samples[0].ID, attempt.ID, successOutcome(), 0, testEvidenceRecord(tenant, samples[0], attempt), display)
		}); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("lost owner committed presealed display")
		}
		assertDisplaySettlementRolledBack(t, tenant, run.ID, samples[0], attempt, *lease)
	})
}
