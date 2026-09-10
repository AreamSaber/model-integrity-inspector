package repository

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

// This is one full original production 60-second window per database. It is
// deliberately separate from repeatable fast cases; no lease/clock is rewritten.
func TestBackupDrainExecutionNaturalLeaseExpiry(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, freeze, candidate, _, _, _ := backupDrainExecutionFixture(t, s, "pending", true)
		source, err := freeze.LoadBackupExecutionSource(tenant.ctx, candidate)
		if err != nil {
			t.Fatal(err)
		}
		before := reconciliationAtomicRows(t, s)
		var state maintenanceState
		if err := s.db.Where("id=1").Take(&state).Error; err != nil {
			t.Fatal(err)
		}
		if state.LeaseUntilMicros-state.UpdatedAtMicros != MaintenanceLeaseDuration.Microseconds() {
			t.Fatal("not original production lease")
		}
		expires := time.UnixMicro(state.LeaseUntilMicros)
		timer := time.NewTimer(time.Until(expires) - 500*time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-tenant.ctx.Done():
			t.Fatal(tenant.ctx.Err())
		}
		entered := false
		name := "backup_execution_actual_lease_expiry"
		if err := s.db.Callback().Create().After("gorm:create").Register(name, func(db *gorm.DB) {
			event, ok := db.Statement.Dest.(*audit.Event)
			if !ok || !strings.HasPrefix(event.Action, "system.backup.drain.execution.") || db.Error != nil {
				return
			}
			if !time.Now().Before(expires) {
				_ = db.AddError(errors.New("test entered after actual lease"))
				return
			}
			entered = true
			wait := time.NewTimer(time.Until(expires) + 25*time.Millisecond)
			defer wait.Stop()
			select {
			case <-wait.C:
			case <-db.Statement.Context.Done():
				_ = db.AddError(db.Statement.Context.Err())
			}
		}); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.db.Callback().Create().Remove(name) }()
		got, err := freeze.ApplyBackupExecutionSource(tenant.ctx, source, nil)
		if !entered || !errors.Is(err, ErrMaintenanceLeaseLost) || got != "" {
			t.Fatal("original lease expiry committed settlement", entered, got, err)
		}
		if err := s.db.Callback().Create().Remove(name); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, reconciliationAtomicRows(t, s)) {
			t.Fatal("original lease expiry failed full rollback")
		}
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		next, err := other.TakeOverExpiredBackup(tenant.ctx, freeze.auth, BackupMaintenanceRequest{ExpectedVersion: state.Version, ReasonCode: "backup.recovery", MaxDuration: time.Hour})
		if err != nil {
			t.Fatal("real second Store takeover", err)
		}
		if got, err := next.ApplyBackupExecutionSource(tenant.ctx, source, nil); !errors.Is(err, ErrBackupDrainSource) || got != "" {
			t.Fatal("new Store accepted old source", got, err)
		}
		if got, err := freeze.ApplyBackupExecutionSource(tenant.ctx, source, nil); !errors.Is(err, ErrMaintenanceLeaseLost) || got != "" {
			t.Fatal("old lease regained authority", got, err)
		}
		fresh, _, err := next.LoadBackupDrainCandidate(tenant.ctx)
		if err != nil {
			t.Fatal(err)
		}
		reloaded, err := next.LoadBackupExecutionSource(tenant.ctx, fresh)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := next.ApplyBackupExecutionSource(tenant.ctx, reloaded, nil); err != nil || got != ReconciliationApplied {
			t.Fatal("takeover could not settle original intent", got, err)
		}
		if err := other.VerifyAllAudit(tenant.ctx, true); err != nil {
			t.Fatal(err)
		}
	})
}
