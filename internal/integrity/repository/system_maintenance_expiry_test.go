package repository

import (
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

// This intentionally waits for the real production 60-second lease. Neither
// persisted times nor a production clock/timeout are rewritten by the test.
// The renewal starts while authorized, then its real audit insert is held
// across natural expiry to prove the original authority is rechecked at commit.
func TestSystemMaintenanceNaturalLeaseExpiryFencesLateRenewalAndTakeover(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, auth, ctx := managementFixture(t, s)
		old := beginTestMaintenance(t, s, ctx, auth)
		var before maintenanceState
		if err := s.db.Where("id=1").Take(&before).Error; err != nil {
			t.Fatal(err)
		}
		if before.LeaseUntilMicros-before.UpdatedAtMicros != MaintenanceLeaseDuration.Microseconds() {
			t.Fatal("fixture did not receive the unmodified production lease duration")
		}
		expires := time.UnixMicro(before.LeaseUntilMicros)
		wait := time.NewTimer(time.Until(expires) - 500*time.Millisecond)
		defer wait.Stop()
		select {
		case <-wait.C:
		case <-ctx.Done():
			t.Fatal("test cancelled before the natural lease expiry window")
		}
		insertObserved := false
		if err := s.db.Callback().Create().After("gorm:create").Register("maintenance_expiry_hold_renew_audit", func(db *gorm.DB) {
			event, ok := db.Statement.Dest.(*audit.Event)
			if !ok || event.Action != "system.maintenance.renew" || db.Error != nil {
				return
			}
			insertObserved = true
			delay := time.NewTimer(time.Until(expires) + 25*time.Millisecond)
			defer delay.Stop()
			select {
			case <-delay.C:
			case <-db.Statement.Context.Done():
				_ = db.AddError(db.Statement.Context.Err())
			}
		}); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.db.Callback().Create().Remove("maintenance_expiry_hold_renew_audit") }()
		if err := old.Renew(ctx); !errors.Is(err, ErrMaintenanceLeaseLost) || !insertObserved {
			t.Fatal("renewal did not reach its audit or resurrected expired original authority", err)
		}
		if err := s.db.Callback().Create().Remove("maintenance_expiry_hold_renew_audit"); err != nil {
			t.Fatal(err)
		}
		now, err := queueTime(s.db, cfg.Driver)
		if err != nil || now.UnixMicro() < before.LeaseUntilMicros {
			t.Fatal("database authority did not actually expire", err)
		}
		var after maintenanceState
		if err := s.db.Where("id=1").Take(&after).Error; err != nil || after.Version != before.Version || after.LeaseUntilMicros != before.LeaseUntilMicros {
			t.Fatal("late renewal partially committed", err)
		}
		var events, audits int64
		if err := s.db.Model(&maintenanceEvent{}).Where("operation_id=?", old.operationID).Count(&events).Error; err != nil || events != 1 {
			t.Fatal("late renewal left an immutable event", err)
		}
		if err := s.db.Model(&audit.Event{}).Where("action='system.maintenance.renew'").Count(&audits).Error; err != nil || audits != 0 {
			t.Fatal("late renewal left an audit event", err)
		}
		if _, err := s.ManageCreateUser(ctx, auth, ManagedUserCreate{Username: "expired-is-still-frozen", PasswordHash: "synthetic-only"}); !errors.Is(err, ErrSystemMaintenance) {
			t.Fatal("expiry automatically reopened admission", err)
		}
		if err := old.Abort(ctx); !errors.Is(err, ErrMaintenanceLeaseLost) {
			t.Fatal("expired owner reopened admission", err)
		}
		if _, err := old.Observe(ctx); !errors.Is(err, ErrMaintenanceLeaseLost) {
			t.Fatal("expired owner received an observation", err)
		}
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		next, err := other.TakeOverExpiredBackup(ctx, auth, BackupMaintenanceRequest{ExpectedVersion: before.Version, ReasonCode: "backup.recovery", MaxDuration: time.Hour})
		if err != nil || next.generation != old.generation+1 {
			t.Fatal("authorized second instance could not fence the expired owner", err)
		}
		if err := old.Renew(ctx); !errors.Is(err, ErrMaintenanceLeaseLost) {
			t.Fatal("superseded owner changed the new operation", err)
		}
		if err := old.Abort(ctx); !errors.Is(err, ErrMaintenanceLeaseLost) {
			t.Fatal("superseded owner reopened admission", err)
		}
		var previous maintenanceOperation
		if err := s.db.Where("id=?", old.operationID).Take(&previous).Error; err != nil || previous.Status != "superseded" {
			t.Fatal("old operation was not terminally superseded", err)
		}
		if _, err := s.verifyMaintenanceOperation(s.db, previous); err != nil {
			t.Fatal("takeover lost authenticated previous terminal facts", err)
		}
		state, err := other.ReadMaintenanceState(ctx)
		if err != nil || state.Mode != MaintenanceBackupFreeze || state.Generation != next.generation {
			t.Fatal("takeover reopened or lost current state", err)
		}
		if err := next.Abort(ctx); err != nil {
			t.Fatal("new live owner could not abort", err)
		}
		if err := other.VerifyAllAudit(ctx, true); err != nil {
			t.Fatal("natural expiry rollback/takeover audit chain", err)
		}
	})
}
