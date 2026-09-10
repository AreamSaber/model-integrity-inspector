package repository

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

// One real 60-second production lease per database, independently of Pause.
// No fake clock, shortened authority window or skipped normal-CI coverage.
func TestBackupDrainTerminalApplyNaturalLeaseExpiry(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		f, freeze, source := backupDrainTerminalFixture(t, s, JobRunAnalyze)
		var state maintenanceState
		if err := s.db.Where("id=1").Take(&state).Error; err != nil {
			t.Fatal(err)
		}
		if state.LeaseUntilMicros-state.UpdatedAtMicros != MaintenanceLeaseDuration.Microseconds() {
			t.Fatal("not the original production lease")
		}
		before := backupDrainTerminalRows(t, s)
		expires := time.UnixMicro(state.LeaseUntilMicros)
		timer := time.NewTimer(time.Until(expires) - 600*time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-f.tenant.ctx.Done():
			t.Fatal("cancelled before expiry proof")
		}
		entered := false
		const callback = "backup_terminal_original_lease_expiry"
		if err := s.db.Callback().Create().After("gorm:create").Register(callback, func(db *gorm.DB) {
			event, ok := db.Statement.Dest.(*audit.Event)
			if !ok || event.Action != "system.backup.drain.terminalize" || db.Error != nil {
				return
			}
			if !time.Now().Before(expires) {
				_ = db.AddError(errors.New("test missed original lease window"))
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
		result, err := freeze.ApplyBackupTerminalCandidate(f.tenant.ctx, source)
		if !entered || !errors.Is(err, ErrMaintenanceLeaseLost) || result != (BackupDrainTerminalResult{}) || !reflect.DeepEqual(before, backupDrainTerminalRows(t, s)) {
			t.Fatal("original lease expiry committed Job/domain/audit", entered, result, err)
		}
		if err := s.db.Callback().Create().Remove(callback); err != nil {
			t.Fatal(err)
		}
		if result, err := freeze.ApplyBackupTerminalCandidate(f.tenant.ctx, source); !errors.Is(err, ErrMaintenanceLeaseLost) || result != (BackupDrainTerminalResult{}) {
			t.Fatal("expired lease replayed source", err)
		}
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		next, err := other.TakeOverExpiredBackup(f.tenant.ctx, freeze.auth, BackupMaintenanceRequest{ExpectedVersion: state.Version, ReasonCode: "backup.recovery", MaxDuration: time.Hour})
		if err != nil || next.generation != freeze.generation+1 {
			t.Fatal("actual takeover failed", err)
		}
		if result, err := next.ApplyBackupTerminalCandidate(f.tenant.ctx, source); !errors.Is(err, ErrBackupDrainSource) || result != (BackupDrainTerminalResult{}) {
			t.Fatal("takeover adopted foreign source", err)
		}
		if result, err := freeze.ApplyBackupTerminalCandidate(f.tenant.ctx, source); !errors.Is(err, ErrMaintenanceLeaseLost) || result != (BackupDrainTerminalResult{}) {
			t.Fatal("old owner wrote after takeover", err)
		}
		fresh := backupDrainTerminalLoad(t, next, f.tenant.ctx, source.job.ID)
		if result, err := next.ApplyBackupTerminalCandidate(f.tenant.ctx, fresh); err != nil || !result.Applied {
			t.Fatal("new owner cannot apply original untouched domain", err)
		}
		if err := other.VerifyAllAudit(f.tenant.ctx, true); err != nil {
			t.Fatal("takeover terminal chain", err)
		}
	})
}
