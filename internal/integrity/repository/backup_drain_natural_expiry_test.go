package repository

import (
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

// Deliberately one original production 60-second lease per database. Fast
// regressions may repeat separately; this test remains part of ordinary CI.
// Neither the lease window, persisted maintenance clock nor production timeout
// is shortened. The hold is inside the actual Pause audit, after its Job UPDATE.
func TestBackupDrainNaturalLeaseExpiry(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, freeze, source := backupDrainPauseFixture(t, s)
		var state maintenanceState
		if err := s.db.Where("id=1").Take(&state).Error; err != nil {
			t.Fatal(err)
		}
		if state.LeaseUntilMicros-state.UpdatedAtMicros != MaintenanceLeaseDuration.Microseconds() {
			t.Fatal("test did not receive real production lease")
		}
		expires := time.UnixMicro(state.LeaseUntilMicros)
		timer := time.NewTimer(time.Until(expires) - 500*time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-tenant.ctx.Done():
			t.Fatal("test cancelled before original lease window")
		}
		entered := false
		callback := "backup_drain_original_lease_expiry"
		if err := s.db.Callback().Create().After("gorm:create").Register(callback, func(db *gorm.DB) {
			event, ok := db.Statement.Dest.(*audit.Event)
			if !ok || event.Action != "system.backup.drain.pause_running" || db.Error != nil {
				return
			}
			if !time.Now().Before(expires) {
				_ = db.AddError(errors.New("test failed to enter authorized lease window"))
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
		defer func() { _ = s.db.Callback().Create().Remove(callback) }()
		result, err := freeze.PauseBackupDrainCandidate(tenant.ctx, source)
		if !entered || !errors.Is(err, ErrMaintenanceLeaseLost) || result != (BackupDrainPauseResult{}) {
			t.Fatal("expired original window committed pause", entered, result, err)
		}
		if err := s.db.Callback().Create().Remove(callback); err != nil {
			t.Fatal(err)
		}
		backupDrainAssertUnchanged(t, s, source.job)
		if got, observation, err := freeze.LoadBackupDrainCandidate(tenant.ctx); !errors.Is(err, ErrMaintenanceLeaseLost) || got != nil || observation != (BackupDrainObservation{}) {
			t.Fatal("expired owner still loaded sources", err)
		}
		if result, err := freeze.PauseBackupDrainCandidate(tenant.ctx, source); !errors.Is(err, ErrMaintenanceLeaseLost) || result != (BackupDrainPauseResult{}) {
			t.Fatal("expired owner replayed source", result, err)
		}
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		next, err := other.TakeOverExpiredBackup(tenant.ctx, freeze.auth, BackupMaintenanceRequest{ExpectedVersion: state.Version, ReasonCode: "backup.recovery", MaxDuration: time.Hour})
		if err != nil || next.generation != freeze.generation+1 {
			t.Fatal("actual takeover failed", err)
		}
		if result, err := next.PauseBackupDrainCandidate(tenant.ctx, source); !errors.Is(err, ErrBackupDrainSource) || result != (BackupDrainPauseResult{}) {
			t.Fatal("takeover adopted old Store/source", result, err)
		}
		if result, err := freeze.PauseBackupDrainCandidate(tenant.ctx, source); !errors.Is(err, ErrMaintenanceLeaseLost) || result != (BackupDrainPauseResult{}) {
			t.Fatal("old owner wrote after takeover", result, err)
		}
		fresh, observation, err := next.LoadBackupDrainCandidate(tenant.ctx)
		if err != nil || fresh == nil || !observation.ExpiredJobPresent {
			t.Fatal("new owner could not observe original work", err)
		}
		if result, err := next.PauseBackupDrainCandidate(tenant.ctx, fresh); err != nil || !result.Applied {
			t.Fatal("new authorized owner failed safe pause", result, err)
		}
		if err := other.VerifyAllAudit(tenant.ctx, true); err != nil {
			t.Fatal("takeover/pause audit chain", err)
		}
	})
}
