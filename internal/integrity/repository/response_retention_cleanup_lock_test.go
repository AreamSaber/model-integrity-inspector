package repository

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func TestResponseRetentionCleanupDeleteLostConsumerRollsBack(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		if cfg.Driver != "sqlite" {
			t.Skip("SQLite persistent consumer expiry boundary")
		}
		tenant, q, _ := responseCleanupFixture(t, s, false)
		derivedFixtureRetention(t, tenant, 0)
		lease := claimResponseCleanup(t, tenant, q)
		expiry := time.Now().UTC().Add(350 * time.Millisecond)
		if err := s.db.Table("integrity_queue_consumer_leases").Where("lock_name=? AND owner=?", queueConsumerName, q.owner).Update("lease_until", expiry).Error; err != nil {
			t.Fatal(err)
		}
		entered := false
		if err := s.db.Callback().Create().After("gorm:create").Register("retention_delete_consumer_expiry", func(db *gorm.DB) {
			event, ok := db.Statement.Dest.(*audit.Event)
			if !ok || event.Action != retentionAuditAction {
				return
			}
			entered = true
			if !expiry.After(time.Now()) {
				_ = db.AddError(errors.New("fixture entered after expiry"))
				return
			}
			// Real elapsed expiry while the sensitive transaction already contains
			// physical DELETEs, receipts and its signed audit INSERT. Job lease
			// remains valid; only the independently persisted consumer has expired.
			timer := time.NewTimer(time.Until(expiry) + 35*time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-db.Statement.Context.Done():
				_ = db.AddError(db.Statement.Context.Err())
			}
		}); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.db.Callback().Create().Remove("retention_delete_consumer_expiry") }()
		err := q.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() })
		if !entered || !errors.Is(err, ErrConsumerLost) {
			t.Fatal("expired consumer committed sensitive deletion", entered, err)
		}
		assertCleanupRows(t, s, tenant.orgID, 1, 1, 0)
		var count int64
		if err := s.db.Model(&audit.Event{}).Where("organization_id=? AND action=?", tenant.orgID, retentionAuditAction).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("expired consumer left deletion audit", count, err)
		}
		if err := s.db.Model(&responseRetentionBatch{}).Where("organization_id=? AND id=? AND state='planned'", tenant.orgID, lease.Job.ObjectID).Count(&count).Error; err != nil || count != 1 {
			t.Fatal("expired consumer changed batch state", count, err)
		}
		if err := s.db.Model(&Job{}).Where("organization_id=? AND id=? AND status='running'", tenant.orgID, lease.Job.ID).Count(&count).Error; err != nil || count != 1 {
			t.Fatal("expired consumer completed Job", count, err)
		}
	})
}

func TestResponseRetentionCleanupDatabaseClockAuditReceipt(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		if cfg.Driver != "postgres" {
			t.Skip("PostgreSQL database/Worker clock skew boundary")
		}
		tenant, q, selection := responseCleanupFixture(t, s, false)
		derivedFixtureRetention(t, tenant, 0)
		derivedFixtureRetention(t, tenant, 30)
		lease := claimResponseCleanup(t, tenant, q)
		clockReads := 0
		if err := s.db.Callback().Row().Before("gorm:row").Register("retention_server_clock_skew", func(db *gorm.DB) {
			if db.Statement.SQL.String() == "SELECT clock_timestamp()" {
				// An actual server-side clock expression simulates the remote DB
				// being ahead of this Worker without changing either machine clock.
				db.Statement.SQL.Reset()
				db.Statement.SQL.WriteString("SELECT clock_timestamp() + INTERVAL '5 seconds'")
				clockReads++
			}
		}); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.db.Callback().Row().Remove("retention_server_clock_skew") }()
		if err := q.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() }); err != nil {
			t.Fatal("clock-skew deletion", err)
		}
		batch, _, err := verifyResponseRetentionBatch(s, s.db, tenant.orgID, lease.Job.ObjectID)
		if err != nil || clockReads == 0 || batch.CompletedAt == nil || !batch.CompletedAt.After(time.Now().UTC().Add(3*time.Second)) {
			t.Fatal("committed database-clock receipt cannot authenticate", clockReads, err)
		}
		source, err := tenant.PrepareEvidenceDisplay(selection)
		if err != nil {
			t.Fatal("clock-skew deleted body read", err)
		}
		defer source.Close()
		if source.Metadata().Status != DisplayReadDeleted {
			t.Fatal("clock-skew body lacks verified deletion")
		}
		if summary, err := tenant.ReadResponseRetentionSummary(selection.RunID); err != nil || summary.RawDeletedCount != 1 || summary.DisplayDeletedCount != 1 {
			t.Fatal("clock-skew retention summary", summary, err)
		}
		if _, err := tenant.VerifyAuditFull(); err != nil {
			t.Fatal("clock-skew audit chain", err)
		}
	})
}

func TestResponseRetentionCleanupScheduleEarlyReturnLostConsumerRollsBack(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		if cfg.Driver != "sqlite" {
			t.Skip("SQLite persistent consumer expiry boundary")
		}
		tenant, q, _ := responseCleanupFixture(t, s, false)
		expiry := time.Now().UTC().Add(350 * time.Millisecond)
		if err := s.db.Table("integrity_queue_consumer_leases").Where("lock_name=? AND owner=?", queueConsumerName, q.owner).Update("lease_until", expiry).Error; err != nil {
			t.Fatal(err)
		}
		entered := false
		if err := s.db.Callback().Create().After("gorm:create").Register("retention_schedule_expiry", func(db *gorm.DB) {
			row, ok := db.Statement.Dest.(*responseRetentionSchedule)
			if !ok {
				return
			}
			entered = true
			// Force the no-eligible early return after a real schedule INSERT.
			if err := db.Session(&gorm.Session{NewDB: true}).Model(&responseRetentionSchedule{}).Where("organization_id=?", row.OrganizationID).Update("next_due_at", expiry.Add(24*time.Hour)).Error; err != nil {
				_ = db.AddError(err)
				return
			}
			if !expiry.After(time.Now()) {
				_ = db.AddError(errors.New("fixture entered after expiry"))
				return
			}
			timer := time.NewTimer(time.Until(expiry) + 35*time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-db.Statement.Context.Done():
				_ = db.AddError(db.Statement.Context.Err())
			}
		}); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.db.Callback().Create().Remove("retention_schedule_expiry") }()
		err := q.ScheduleResponseRetention(tenant.ctx)
		if !entered || !errors.Is(err, ErrConsumerLost) {
			t.Fatal("expired consumer committed an early-return schedule", entered, err)
		}
		var count int64
		if err := s.db.Model(&responseRetentionSchedule{}).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("expired maintenance left schedule", count, err)
		}
	})
}

func TestResponseRetentionCleanupPostgresActualLockWaits(t *testing.T) {
	for _, boundary := range []string{"organization", "display", "audit"} {
		t.Run(boundary, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
				if cfg.Driver != "postgres" {
					t.Skip("actual PostgreSQL row locks")
				}
				tenant, q, selection := responseCleanupFixture(t, s, false)
				derivedFixtureRetention(t, tenant, 0)
				lease := claimResponseCleanup(t, tenant, q)
				other, err := Open(t.Context(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = other.Close() }()
				release, held := make(chan struct{}), make(chan int, 1)
				var once sync.Once
				resume := func() { once.Do(func() { close(release) }) }
				defer resume()
				holderDone := make(chan error, 1)
				go func() {
					holderDone <- other.db.WithContext(t.Context()).Transaction(func(db *gorm.DB) error {
						statement := "SELECT id FROM organizations WHERE id=? FOR NO KEY UPDATE"
						id := tenant.orgID
						if boundary == "display" {
							statement = "SELECT attempt_id FROM integrity_display_evidence WHERE attempt_id=? FOR SHARE"
							id = selection.AttemptID
						}
						if boundary == "audit" {
							statement = "SELECT organization_id FROM integrity_audit_chain_heads WHERE organization_id=? FOR UPDATE"
						}
						var selected int64
						if err := db.Raw(statement, id).Scan(&selected).Error; err != nil {
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
					t.Fatal(err)
				case <-time.After(time.Second):
					t.Fatal("holder missing")
				}
				deleteCtx, cancel := context.WithTimeout(tenant.ctx, 2*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() {
					done <- q.CompleteWith(deleteCtx, lease, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() })
				}()
				observed := false
				until := time.Now().Add(800 * time.Millisecond)
				for time.Now().Before(until) {
					var count int64
					if err := other.db.Raw("SELECT COUNT(*) FROM pg_stat_activity WHERE ?=ANY(pg_blocking_pids(pid))", holderPID).Scan(&count).Error; err != nil {
						t.Fatal(err)
					}
					if count > 0 {
						observed = true
						break
					}
					timer := time.NewTimer(5 * time.Millisecond)
					<-timer.C
				}
				if !observed {
					t.Fatal("real cleanup lock wait absent")
				}
				select {
				case err := <-done:
					t.Fatal("cleanup escaped held lock", err)
				default:
				}
				resume()
				if err := <-holderDone; err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal("cleanup after lock release", err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("cleanup hung after release")
				}
				assertCleanupRows(t, s, tenant.orgID, 0, 0, 2)
				if _, err := tenant.VerifyAuditFull(); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}
