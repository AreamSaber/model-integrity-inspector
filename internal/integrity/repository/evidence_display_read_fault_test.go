package repository

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func TestEvidenceDisplayReadAuditWaitCrossesNaturalExpiry(t *testing.T) {
	for _, boundary := range []string{"body", "session"} {
		t.Run(boundary, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				tenant, selection := displayReadFixture(t, store)
				expiry := time.Now().UTC().Add(900 * time.Millisecond).Truncate(time.Microsecond)
				if boundary == "body" {
					captured := expiry.UnixMicro() - 30*responseRetentionDayMicros
					if err := store.db.Model(&AttemptRecord{}).Where("id=?", selection.AttemptID).Update("started_at", time.UnixMicro(captured-1000).UTC()).Error; err != nil {
						t.Fatal(err)
					}
					if err := store.db.Model(&DisplayEvidenceRecord{}).Where("attempt_id=?", selection.AttemptID).Updates(map[string]any{"captured_at_micros": captured, "expires_at_micros": expiry.UnixMicro()}).Error; err != nil {
						t.Fatal(err)
					}
				} else {
					auth := tenant.ctx.Value(controlAuthorityKey{}).(controlAuthority).identity
					if err := store.db.Model(&Session{}).Where("id=?", auth.SessionID).Update("expires_at", expiry).Error; err != nil {
						t.Fatal(err)
					}
				}
				source, err := tenant.PrepareEvidenceDisplay(selection)
				if err != nil || source.Metadata().Status != DisplayReadAvailable {
					t.Fatal("source not initially eligible", err)
				}
				defer source.Close()
				ready, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				resume := func() { once.Do(func() { close(release) }) }
				defer resume()
				if err := store.db.Callback().Create().Before("gorm:create").Register("display_test_audit_wait", func(db *gorm.DB) {
					event, ok := db.Statement.Dest.(*audit.Event)
					if !ok || event.Action != "evidence.body.read" {
						return
					}
					close(ready)
					select {
					case <-release:
					case <-tenant.ctx.Done():
						_ = db.AddError(tenant.ctx.Err())
					}
				}); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() {
					permit, err := tenant.CommitEvidenceDisplayRead(source, displaySummaryFixture())
					if permit != nil {
						permit.Close()
						done <- errors.New("permit escaped expired audit wait")
						return
					}
					done <- err
				}()
				select {
				case <-ready:
				case err := <-done:
					t.Fatal("did not reach audit wait", err)
				case <-time.After(3 * time.Second):
					t.Fatal("audit wait absent")
				}
				if !expiry.After(time.Now()) {
					t.Fatal("test did not enter wait before expiry")
				}
				timer := time.NewTimer(time.Until(expiry) + 50*time.Millisecond)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-t.Context().Done():
					t.Fatal("test cancelled")
				}
				resume()
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("expired grant succeeded")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("grant did not finish")
				}
				noDisplayGrants(t, store)
				if err := store.VerifyAllAudit(t.Context(), true); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestEvidenceDisplayReadCommitFailureCannotMintPermit(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, config Config) {
		tenant, selection := displayReadFixture(t, store)
		source, err := tenant.PrepareEvidenceDisplay(selection)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		if err := store.db.Exec("CREATE TABLE display_commit_failure (user_id BIGINT REFERENCES users(id) DEFERRABLE INITIALLY DEFERRED)").Error; err != nil {
			t.Fatal(err)
		}
		statements := []string{"CREATE TRIGGER display_commit_failure AFTER INSERT ON integrity_evidence_disclosures BEGIN INSERT INTO display_commit_failure(user_id) VALUES (-1); END"}
		if config.Driver == "postgres" {
			statements = []string{"CREATE FUNCTION display_commit_failure_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO display_commit_failure(user_id) VALUES (-1); RETURN NEW; END; $$", "CREATE TRIGGER display_commit_failure AFTER INSERT ON integrity_evidence_disclosures FOR EACH ROW EXECUTE FUNCTION display_commit_failure_fn()"}
		}
		for _, statement := range statements {
			if err := store.db.Exec(statement).Error; err != nil {
				t.Fatal(err)
			}
		}
		var auditTailWritten atomic.Bool
		if err := store.db.Callback().Update().After("gorm:update").Register("display_test_commit_observer", func(db *gorm.DB) {
			if db.Statement.Table == "integrity_audit_chain_heads" && db.Error == nil {
				auditTailWritten.Store(true)
			}
		}); err != nil {
			t.Fatal(err)
		}
		permit, err := tenant.CommitEvidenceDisplayRead(source, displaySummaryFixture())
		if err == nil || permit != nil || !auditTailWritten.Load() {
			t.Fatal("deferred COMMIT failure did not fail after audit", err)
		}
		noDisplayGrants(t, store)
		if err := store.VerifyAllAudit(tenant.ctx, true); err != nil {
			t.Fatal(err)
		}
	})
}

func TestEvidenceDisplayReadPermitRechecksFreshAuthorityAndOriginalContext(t *testing.T) {
	for _, scenario := range []string{"policy", "permission", "original_cancel", "missing"} {
		t.Run(scenario, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				tenant, selection := displayReadFixture(t, store)
				originalCtx, cancel := context.WithCancel(tenant.ctx)
				defer cancel()
				original := &Tenant{store: store, orgID: tenant.orgID, ctx: originalCtx}
				source, err := original.PrepareEvidenceDisplay(selection)
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				permit, err := original.CommitEvidenceDisplayRead(source, displaySummaryFixture())
				if err != nil {
					t.Fatal(err)
				}
				defer permit.Close()
				if err := permit.Begin(originalCtx, displaySummaryFixture()); err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "policy":
					derivedFixtureRetention(t, tenant, 0)
				case "permission":
					err = store.db.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code='evidence.body'", tenant.orgID).Error
				case "original_cancel":
					cancel()
				case "missing":
					err = store.db.Where("attempt_id=?", selection.AttemptID).Delete(&DisplayEvidenceRecord{}).Error
				}
				if err != nil {
					t.Fatal(err)
				}
				// The earlier parent context is still live and has the same actor;
				// it cannot revive the original cancelled prepared operation.
				if err := permit.Revalidate(tenant.ctx); err == nil {
					t.Fatal("fresh prohibition bypassed by existing permit")
				}
				var count int64
				if err := store.db.Model(&evidenceDisclosureReceipt{}).Count(&count).Error; err != nil || count != 1 {
					t.Fatal("post-grant check invented another grant", err)
				}
			})
		})
	}
}

func TestEvidenceDisplayReadPostgresRealAuditAndEnvelopeLocks(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, config Config) {
		if config.Driver != "postgres" {
			t.Skip("real PostgreSQL row-lock scheduling")
		}
		tenant, selection := displayReadFixture(t, store)
		other, err := Open(t.Context(), config)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		expiry := time.Now().UTC().Add(1500 * time.Millisecond).Truncate(time.Microsecond)
		captured := expiry.UnixMicro() - 30*responseRetentionDayMicros
		if err := store.db.Model(&AttemptRecord{}).Where("id=?", selection.AttemptID).Update("started_at", time.UnixMicro(captured-1000).UTC()).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.db.Model(&DisplayEvidenceRecord{}).Where("attempt_id=?", selection.AttemptID).Updates(map[string]any{"captured_at_micros": captured, "expires_at_micros": expiry.UnixMicro()}).Error; err != nil {
			t.Fatal(err)
		}
		source, err := tenant.PrepareEvidenceDisplay(selection)
		if err != nil || source.Metadata().Status != DisplayReadAvailable {
			t.Fatal("initial live source", err)
		}
		defer source.Close()
		release, held := make(chan struct{}), make(chan int, 1)
		var once sync.Once
		resume := func() { once.Do(func() { close(release) }) }
		defer resume()
		holderDone := make(chan error, 1)
		go func() {
			holderDone <- other.db.WithContext(t.Context()).Transaction(func(db *gorm.DB) error {
				var head auditChainHead
				if err := db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("organization_id=?", tenant.orgID).Take(&head).Error; err != nil {
					return err
				}
				var pid int
				if err := db.Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
					return err
				}
				held <- pid
				select {
				case <-release:
					return nil
				case <-t.Context().Done():
					return t.Context().Err()
				}
			})
		}()
		var holderPID int
		select {
		case holderPID = <-held:
		case err := <-holderDone:
			t.Fatal("lock audit head", err)
		case <-time.After(time.Second):
			t.Fatal("audit head not held")
		}
		grantDone := make(chan error, 1)
		go func() {
			permit, err := tenant.CommitEvidenceDisplayRead(source, displaySummaryFixture())
			if permit != nil {
				permit.Close()
				grantDone <- errors.New("expired blocked grant returned permit")
				return
			}
			grantDone <- err
		}()
		observed := false
		until := time.Now().Add(600 * time.Millisecond)
		for time.Now().Before(until) {
			var blockers int64
			if err := other.db.Raw("SELECT COUNT(*) FROM pg_stat_activity WHERE ?=ANY(pg_blocking_pids(pid))", holderPID).Scan(&blockers).Error; err != nil {
				t.Fatal(err)
			}
			if blockers > 0 {
				observed = true
				break
			}
			timer := time.NewTimer(10 * time.Millisecond)
			<-timer.C
		}
		if !observed || !expiry.After(time.Now()) {
			t.Fatal("real audit lock wait not proved before expiry")
		}
		// The grant must still hold the display FOR SHARE while awaiting audit.
		writeCtx, cancelWrite := context.WithTimeout(t.Context(), 100*time.Millisecond)
		err = other.db.WithContext(writeCtx).Model(&DisplayEvidenceRecord{}).Where("attempt_id=?", selection.AttemptID).Update("ciphertext", bytes.Repeat([]byte{9}, 48)).Error
		cancelWrite()
		if err == nil {
			t.Fatal("display UPDATE passed final SHARE lock")
		}
		timer := time.NewTimer(time.Until(expiry) + 50*time.Millisecond)
		defer timer.Stop()
		<-timer.C
		dbNow, err := queueTime(other.db, config.Driver)
		if err != nil || dbNow.Before(expiry) {
			t.Fatal("database expiry not crossed", err)
		}
		resume()
		if err := <-holderDone; err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-grantDone:
			if err == nil {
				t.Fatal("expired grant succeeded")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("grant stuck after audit release")
		}
		noDisplayGrants(t, store)
		if err := store.VerifyAllAudit(t.Context(), true); err != nil {
			t.Fatal(err)
		}
	})
}

func TestEvidenceDisplayReadRejectsOversizedCipherBeforeAllocation(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, config Config) {
		tenant, selection := displayReadFixture(t, store)
		oversized := bytes.Repeat([]byte{5}, (4<<20)+17)
		if config.Driver == "postgres" {
			if err := store.db.Exec("ALTER TABLE integrity_display_evidence DROP CONSTRAINT integrity_display_retention_shape").Error; err != nil {
				t.Fatal(err)
			}
			if err := store.db.Model(&DisplayEvidenceRecord{}).Where("attempt_id=?", selection.AttemptID).Update("ciphertext", oversized).Error; err != nil {
				t.Fatal(err)
			}
		} else {
			if err := store.db.Connection(func(db *gorm.DB) error {
				if err := db.Exec("PRAGMA ignore_check_constraints=ON").Error; err != nil {
					return err
				}
				defer db.Exec("PRAGMA ignore_check_constraints=OFF")
				return db.Model(&DisplayEvidenceRecord{}).Where("attempt_id=?", selection.AttemptID).Update("ciphertext", oversized).Error
			}); err != nil {
				t.Fatal(err)
			}
		}
		var cipherFetched atomic.Bool
		if err := store.db.Callback().Query().Before("gorm:query").Register("display_test_no_oversized_fetch", func(db *gorm.DB) {
			for _, column := range db.Statement.Selects {
				if column == "nonce,ciphertext" {
					cipherFetched.Store(true)
				}
			}
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.PrepareEvidenceDisplay(selection); !errors.Is(err, ErrDisplaySource) || cipherFetched.Load() {
			t.Fatal("oversized body reached cipher projection", err)
		}
		noDisplayGrants(t, store)
	})
}
