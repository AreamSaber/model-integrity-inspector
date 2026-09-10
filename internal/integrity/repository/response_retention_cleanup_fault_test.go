package repository

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func TestResponseRetentionCleanupByteBoundAndIndependentContinuation(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, s, 2)
		_, q, samples := executionStart(t, tenant, plan, policy)
		for range samples {
			lease, err := q.Claim(tenant.ctx)
			if err != nil || lease == nil {
				t.Fatal(err)
			}
			var sample LogicalSampleRecord
			for _, candidate := range samples {
				if candidate.ID == lease.Job.ObjectID {
					sample = candidate
				}
			}
			attempt := reserveTestAttempt(t, tenant, q, *lease, sample)
			body := derivedFixtureBody(t, tenant, q, *lease, sample, attempt)
			if err := q.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error {
				return tx.FinishLegacyAttemptWithCapture(sample.ID, attempt.ID, successOutcome(), 0, body)
			}); err != nil {
				t.Fatal(err)
			}
		}
		// Repository crypto-opaque fixture: exercise real byte-sized SQL objects,
		// not a claim that modified ciphertext authenticates or renders plaintext.
		if err := s.db.Model(&ResponseEvidenceRecord{}).Where("organization_id=?", tenant.orgID).Updates(map[string]any{"plaintext_bytes": 1 << 20, "ciphertext": bytes.Repeat([]byte{6}, (1<<20)+16)}).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Model(&DisplayEvidenceRecord{}).Where("organization_id=?", tenant.orgID).Updates(map[string]any{"plaintext_bytes": 4 << 20, "ciphertext": bytes.Repeat([]byte{7}, (4<<20)+16)}).Error; err != nil {
			t.Fatal(err)
		}
		// Retention can clean completed attempts while analysis remains queued.
		analysis, err := q.Claim(tenant.ctx)
		if err != nil || analysis == nil {
			t.Fatal(err)
		}
		if err := q.Fail(tenant.ctx, *analysis, "RETENTION_FIXTURE_ANALYSIS_UNUSED"); err != nil {
			t.Fatal(err)
		}
		derivedFixtureRetention(t, tenant, 0)
		lease := claimResponseCleanup(t, tenant, q)
		if err := q.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() }); err != nil {
			t.Fatal(err)
		}
		assertCleanupRows(t, s, tenant.orgID, 0, 1, 3)
		var first responseRetentionBatch
		if err := s.db.Where("organization_id=? AND id=?", tenant.orgID, lease.Job.ObjectID).Take(&first).Error; err != nil || first.DeletedBytes != (6<<20)+48 {
			t.Fatal("byte-bound batch", first.DeletedBytes, err)
		}
		lease = claimResponseCleanup(t, tenant, q)
		if err := q.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() }); err != nil {
			t.Fatal(err)
		}
		assertCleanupRows(t, s, tenant.orgID, 0, 0, 4)
	})
}

func TestResponseRetentionCleanupOversizedObjectCannotBecomeSuccessfulSkip(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, q, _ := responseCleanupFixture(t, s, false)
		derivedFixtureRetention(t, tenant, 0)
		if cfg.Driver == "postgres" {
			if err := s.db.Exec("ALTER TABLE integrity_display_evidence DROP CONSTRAINT integrity_display_retention_shape").Error; err != nil {
				t.Fatal(err)
			}
		} else {
			if err := s.db.Exec("PRAGMA ignore_check_constraints=ON").Error; err != nil {
				t.Fatal(err)
			}
		}
		if err := s.db.Model(&DisplayEvidenceRecord{}).Where("organization_id=?", tenant.orgID).Updates(map[string]any{"plaintext_bytes": 8 << 20, "ciphertext": bytes.Repeat([]byte{9}, (8<<20)+16)}).Error; err != nil {
			t.Fatal(err)
		}
		if cfg.Driver == "sqlite" {
			if err := s.db.Exec("PRAGMA ignore_check_constraints=OFF").Error; err != nil {
				t.Fatal(err)
			}
		}
		lease := claimResponseCleanup(t, tenant, q)
		if err := q.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() }); err == nil {
			t.Fatal("oversized object skipped as successful small/zero batch")
		}
		assertCleanupRows(t, s, tenant.orgID, 1, 1, 0)
	})
}

func installRetentionFailure(t *testing.T, s *Store, phase string) func() {
	t.Helper()
	if phase == "commit" {
		if err := s.db.Exec("CREATE TABLE retention_commit_failure (user_id BIGINT REFERENCES users(id) DEFERRABLE INITIALLY DEFERRED)").Error; err != nil {
			t.Fatal(err)
		}
		if s.driver == "postgres" {
			if err := s.db.Exec("CREATE FUNCTION retention_fault_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO retention_commit_failure(user_id) VALUES (-1); RETURN NEW; END; $$").Error; err != nil {
				t.Fatal(err)
			}
			if err := s.db.Exec("CREATE TRIGGER retention_fault AFTER INSERT ON integrity_evidence_deletions FOR EACH ROW EXECUTE FUNCTION retention_fault_fn()").Error; err != nil {
				t.Fatal(err)
			}
			return func() {
				if err := s.db.Exec("DROP TRIGGER retention_fault ON integrity_evidence_deletions").Error; err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := s.db.Exec("CREATE TRIGGER retention_fault AFTER INSERT ON integrity_evidence_deletions BEGIN INSERT INTO retention_commit_failure(user_id) VALUES (-1); END").Error; err != nil {
			t.Fatal(err)
		}
		return func() {
			if err := s.db.Exec("DROP TRIGGER retention_fault").Error; err != nil {
				t.Fatal(err)
			}
		}
	}
	table, operation := "integrity_response_evidence", "DELETE"
	switch phase {
	case "raw_delete", "zero_delete":
	case "display_delete":
		table = "integrity_display_evidence"
	case "item_insert":
		table = "integrity_evidence_deletions"
		operation = "INSERT"
	case "batch_update":
		table = "integrity_response_retention_batches"
		operation = "UPDATE"
	case "audit_insert":
		table = "integrity_audit_logs"
		operation = "INSERT"
	default:
		t.Fatal("unknown fault")
	}
	if s.driver == "postgres" {
		body := "RAISE EXCEPTION 'synthetic retention failure';"
		if phase == "zero_delete" {
			body = "RETURN NULL;"
		}
		if err := s.db.Exec("CREATE FUNCTION retention_fault_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END; $$").Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Exec("CREATE TRIGGER retention_fault BEFORE " + operation + " ON " + table + " FOR EACH ROW EXECUTE FUNCTION retention_fault_fn()").Error; err != nil {
			t.Fatal(err)
		}
		return func() {
			if err := s.db.Exec("DROP TRIGGER retention_fault ON " + table).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
	raise := "RAISE(ABORT, 'synthetic retention failure')"
	if phase == "zero_delete" {
		raise = "RAISE(IGNORE)"
	}
	if err := s.db.Exec("CREATE TRIGGER retention_fault BEFORE " + operation + " ON " + table + " BEGIN SELECT " + raise + "; END").Error; err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := s.db.Exec("DROP TRIGGER retention_fault").Error; err != nil {
			t.Fatal(err)
		}
	}
}

func TestResponseRetentionCleanupAllWritesAndCommitFailAtomically(t *testing.T) {
	for _, phase := range []string{"raw_delete", "display_delete", "item_insert", "batch_update", "audit_insert", "zero_delete", "commit", "cancel", "final_fence"} {
		t.Run(phase, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				tenant, q, _ := responseCleanupFixture(t, s, false)
				derivedFixtureRetention(t, tenant, 0)
				lease := claimResponseCleanup(t, tenant, q)
				ctx, cancel := context.WithCancel(tenant.ctx)
				defer cancel()
				undo := func() {}
				if phase != "cancel" && phase != "final_fence" {
					undo = installRetentionFailure(t, s, phase)
				}
				if phase == "cancel" {
					if err := s.db.Callback().Create().Before("gorm:create").Register("retention_cancel", func(db *gorm.DB) {
						if event, ok := db.Statement.Dest.(*audit.Event); ok && event.Action == retentionAuditAction {
							cancel()
						}
					}); err != nil {
						t.Fatal(err)
					}
					undo = func() {
						if err := s.db.Callback().Create().Remove("retention_cancel"); err != nil {
							t.Fatal(err)
						}
					}
				}
				reachedCompletion := false
				err := q.CompleteWith(ctx, lease, func(tx *TenantTransaction) error {
					err := tx.DeleteResponseEvidenceBatch()
					if err != nil {
						return err
					}
					reachedCompletion = true
					if phase == "final_fence" {
						return tx.db.Model(&Job{}).Where("organization_id=? AND id=?", tenant.orgID, lease.Job.ID).Update("lease_until", time.Now().UTC().Add(-time.Second)).Error
					}
					return nil
				})
				if err == nil {
					t.Fatal("fault did not fail deletion")
				}
				if phase == "commit" && !reachedCompletion {
					t.Fatal("commit fixture failed before real COMMIT")
				}
				assertCleanupRows(t, s, tenant.orgID, 1, 1, 0)
				var count int64
				if err := s.db.Table("integrity_audit_logs").Where("action=?", retentionAuditAction).Count(&count).Error; err != nil || count != 0 {
					t.Fatal("failed cleanup left success audit", err)
				}
				var batch responseRetentionBatch
				if err := s.db.Where("organization_id=? AND id=?", tenant.orgID, lease.Job.ObjectID).Take(&batch).Error; err != nil || batch.State != "planned" || batch.ReceiptHash != "" {
					t.Fatal("failed cleanup left success receipt", err)
				}
				undo()
				if err := q.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() }); err != nil {
					t.Fatal("same lease after rollback", err)
				}
				assertCleanupRows(t, s, tenant.orgID, 0, 0, 2)
				if _, err := tenant.VerifyAuditFull(); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestResponseRetentionCleanupDeletionReceiptTamperAndCoexistence(t *testing.T) {
	for _, kind := range []string{"audit_signature", "item_hash", "coexistence", "missing_without_receipt", "receipt_conflict"} {
		t.Run(kind, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				tenant, q, selection := responseCleanupFixture(t, s, false)
				var original DisplayEvidenceRecord
				if err := s.db.First(&original).Error; err != nil {
					t.Fatal(err)
				}
				if kind == "missing_without_receipt" {
					if err := s.db.Where("organization_id=? AND attempt_id=?", tenant.orgID, selection.AttemptID).Delete(&DisplayEvidenceRecord{}).Error; err != nil {
						t.Fatal(err)
					}
				} else {
					derivedFixtureRetention(t, tenant, 0)
					derivedFixtureRetention(t, tenant, 30)
					lease := claimResponseCleanup(t, tenant, q)
					if err := q.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() }); err != nil {
						t.Fatal(err)
					}
					switch kind {
					case "audit_signature":
						if err := s.db.Table("integrity_audit_logs").Where("action=?", retentionAuditAction).Update("event_hmac", strings.Repeat("0", 64)).Error; err != nil {
							t.Fatal(err)
						}
					case "item_hash":
						statement := "DROP TRIGGER integrity_evidence_deletion_immutable"
						if s.driver == "postgres" {
							statement += " ON integrity_evidence_deletions"
						}
						if err := s.db.Exec(statement).Error; err != nil {
							t.Fatal(err)
						}
						if err := s.db.Model(&evidenceDeletion{}).Where("organization_id=? AND source_kind=?", tenant.orgID, retentionDisplaySource).Update("content_hash", strings.Repeat("d", 64)).Error; err != nil {
							t.Fatal(err)
						}
					case "coexistence":
						statement := "DROP TRIGGER integrity_display_no_resurrection"
						if s.driver == "postgres" {
							statement += " ON integrity_display_evidence"
						}
						if err := s.db.Exec(statement).Error; err != nil {
							t.Fatal(err)
						}
						if err := s.db.Create(&original).Error; err != nil {
							t.Fatal(err)
						}
					case "receipt_conflict":
						if err := s.db.Model(&AttemptRecord{}).Where("organization_id=? AND id=?", tenant.orgID, selection.AttemptID).Update("response_body_receipt", BodyNotCaptured).Error; err != nil {
							t.Fatal(err)
						}
					}
				}
				if source, err := tenant.PrepareEvidenceDisplay(selection); err == nil || source != nil {
					if source != nil {
						source.Close()
					}
					t.Fatal("bad deletion fact became ordinary unavailable", err)
				}
				if _, err := tenant.ReadResponseRetentionSummary(selection.RunID); !errors.Is(err, ErrRetentionSource) {
					t.Fatal("summary accepted corrupt deletion fact", err)
				}
			})
		})
	}
}

func TestResponseRetentionCleanupConcurrentScheduleAndCompletion(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, q, _ := responseCleanupFixture(t, s, false)
		derivedFixtureRetention(t, tenant, 0)
		var wg sync.WaitGroup
		results := make(chan error, 4)
		for range 4 {
			wg.Go(func() { results <- q.ScheduleResponseRetention(tenant.ctx) })
		}
		wg.Wait()
		close(results)
		for err := range results {
			if err != nil {
				t.Fatal("concurrent schedule", err)
			}
		}
		var count int64
		if err := s.db.Model(&responseRetentionBatch{}).Count(&count).Error; err != nil || count != 1 {
			t.Fatal("duplicate active batches", count, err)
		}
		lease, err := q.Claim(tenant.ctx)
		if err != nil || lease == nil {
			t.Fatal(err)
		}
		results = make(chan error, 2)
		for range 2 {
			wg.Go(func() {
				results <- q.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() })
			})
		}
		wg.Wait()
		close(results)
		wins, denied := 0, 0
		for err := range results {
			if err == nil {
				wins++
			} else if errors.Is(err, ErrJobLeaseLost) {
				denied++
			} else {
				t.Fatal("unexpected completion", err)
			}
		}
		if wins != 1 || denied != 1 {
			t.Fatal("completion was not fenced", wins, denied)
		}
		assertCleanupRows(t, s, tenant.orgID, 0, 0, 2)
		if _, err := tenant.VerifyAuditFull(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestResponseRetentionCleanupBoundedRowsAndDurableResume(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, _, plan, policy := executionFixture(t, s, 17)
		run, q, samples := executionStart(t, tenant, plan, policy)
		for _, sample := range samples {
			lease, err := q.Claim(tenant.ctx)
			if err != nil || lease == nil {
				t.Fatal(err)
			}
			// Claim ordering is Job-ID based; obtain the real selected sample.
			for _, candidate := range samples {
				if candidate.ID == lease.Job.ObjectID {
					sample = candidate
					break
				}
			}
			attempt := reserveTestAttempt(t, tenant, q, *lease, sample)
			body := derivedFixtureBody(t, tenant, q, *lease, sample, attempt)
			if err := q.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error {
				return tx.FinishLegacyAttemptWithCapture(sample.ID, attempt.ID, successOutcome(), 0, body)
			}); err != nil {
				t.Fatal(err)
			}
		}
		analysis, err := q.Claim(tenant.ctx)
		if err != nil || analysis == nil {
			t.Fatal(err)
		}
		source, err := q.LoadRunAnalysis(tenant.ctx, *analysis)
		if err != nil {
			t.Fatal(err)
		}
		run, _ = tenant.GetRun(run.ID)
		if err := q.CompleteWith(tenant.ctx, *analysis, func(tx *TenantTransaction) error {
			return tx.PublishRunAnalysis(source, analysisPublicationFixture(t, run, samples))
		}); err != nil {
			t.Fatal(err)
		}
		derivedFixtureRetention(t, tenant, 0)
		lease := claimResponseCleanup(t, tenant, q)
		if err := q.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() }); err != nil {
			t.Fatal(err)
		}
		assertCleanupRows(t, s, tenant.orgID, 0, 2, 32)
		if err := q.Close(tenant.ctx); err != nil {
			t.Fatal(err)
		}
		other, err := Open(tenant.ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		resumed, err := other.OpenJobQueue(tenant.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resumed.Close(context.Background()) }()
		lease = claimResponseCleanup(t, tenant, resumed)
		if err := resumed.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() }); err != nil {
			t.Fatal("resume durable sweep", err)
		}
		assertCleanupRows(t, s, tenant.orgID, 0, 0, 34)
		var batch responseRetentionBatch
		if err := s.db.Where("organization_id=? AND id=?", tenant.orgID, lease.Job.ObjectID).Take(&batch).Error; err != nil || batch.DeletedRows != 2 {
			t.Fatal(fmt.Sprint("bounded continuation", err))
		}
	})
}
