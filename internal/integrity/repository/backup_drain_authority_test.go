package repository

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func backupDrainPauseFixture(t *testing.T, s *Store) (*Tenant, *MaintenanceLease, *BackupDrainSource) {
	t.Helper()
	tenant, _, job := backupDrainRealProducer(t, s, JobRunPlan)
	expireJob(t, s, job.Job)
	freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
	source, _, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
	if err != nil || source == nil || source.Kind() != BackupDrainPauseSafe {
		t.Fatal("pause authority fixture", source, err)
	}
	return tenant, freeze, source
}

func backupDrainAssertUnchanged(t *testing.T, s *Store, original backupDrainJob) {
	t.Helper()
	now, err := queueTime(s.db, s.driver)
	if err != nil {
		t.Fatal(err)
	}
	got, err := backupDrainReadJob(s.db, original.ID, now)
	if err != nil || got != original {
		t.Fatal("failed pause changed original job", err)
	}
	var count int64
	if err := s.db.Model(&audit.Event{}).Where("action='system.backup.drain.pause_running'").Count(&count).Error; err != nil || count != 0 {
		t.Fatal("failed pause left audit", err)
	}
}

func TestBackupDrainAuditAndLateCancellationRollback(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, freeze, source := backupDrainPauseFixture(t, s)
		before := backupDrainDomainRows(t, s)
		for _, mode := range []string{"sql-audit", "cancel-after-audit"} {
			t.Run(mode, func(t *testing.T) {
				ctx, cancel := context.WithCancel(tenant.ctx)
				defer cancel()
				entered := false
				callback := "backup_drain_late_failure"
				if err := s.db.Callback().Create().After("gorm:create").Register(callback, func(db *gorm.DB) {
					event, ok := db.Statement.Dest.(*audit.Event)
					if !ok || event.Action != "system.backup.drain.pause_running" || db.Error != nil {
						return
					}
					entered = true
					if mode == "sql-audit" {
						_ = db.AddError(errors.New("private-sql-error-canary"))
					} else {
						cancel()
					}
				}); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = s.db.Callback().Create().Remove(callback) }()
				result, err := freeze.PauseBackupDrainCandidate(ctx, source)
				want := ErrUnavailable
				if mode == "cancel-after-audit" {
					want = context.Canceled
				}
				if !entered || !errors.Is(err, want) || result != (BackupDrainPauseResult{}) {
					t.Fatal("late failure committed or leaked", entered, result, err)
				}
				if err := s.db.Callback().Create().Remove(callback); err != nil {
					t.Fatal(err)
				}
				backupDrainAssertUnchanged(t, s, source.job)
				if !reflect.DeepEqual(before, backupDrainDomainRows(t, s)) {
					t.Fatal("late failure mutated domain")
				}
			})
		}
	})
}

func TestBackupDrainNaturalSessionExpiryAtFinalAudit(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, freeze, source := backupDrainPauseFixture(t, s)
		expires := time.Now().UTC().Add(300 * time.Millisecond)
		if err := s.db.Model(&Session{}).Where("id=?", freeze.auth.SessionID).Update("expires_at", expires).Error; err != nil {
			t.Fatal(err)
		}
		entered := false
		callback := "backup_drain_session_expiry"
		if err := s.db.Callback().Create().After("gorm:create").Register(callback, func(db *gorm.DB) {
			event, ok := db.Statement.Dest.(*audit.Event)
			if !ok || event.Action != "system.backup.drain.pause_running" || db.Error != nil {
				return
			}
			if !time.Now().Before(expires) {
				_ = db.AddError(errors.New("test failed to enter the authorized window"))
				return
			}
			entered = true
			timer := time.NewTimer(time.Until(expires) + 20*time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-db.Statement.Context.Done():
				_ = db.AddError(db.Statement.Context.Err())
			}
		}); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.db.Callback().Create().Remove(callback) }()
		result, err := freeze.PauseBackupDrainCandidate(tenant.ctx, source)
		if !entered || !errors.Is(err, ErrManagementSession) || result != (BackupDrainPauseResult{}) {
			t.Fatal("natural late session expiry committed", entered, result, err)
		}
		backupDrainAssertUnchanged(t, s, source.job)
	})
}

func TestBackupDrainRevocationAndDifferentOperationDoNotAdoptSource(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, freeze, source := backupDrainPauseFixture(t, s)
		if err := s.db.Model(&Session{}).Where("id=?", freeze.auth.SessionID).Update("revoked_at", time.Now().UTC()).Error; err != nil {
			t.Fatal(err)
		}
		result, err := freeze.PauseBackupDrainCandidate(tenant.ctx, source)
		if !errors.Is(err, ErrManagementSession) || result != (BackupDrainPauseResult{}) {
			t.Fatal("revoked authority paused", result, err)
		}
		if got, observation, err := freeze.LoadBackupDrainCandidate(tenant.ctx); !errors.Is(err, ErrManagementSession) || got != nil || observation != (BackupDrainObservation{}) {
			t.Fatal("revoked authority loaded metadata", err)
		}
		backupDrainAssertUnchanged(t, s, source.job)
		if err := s.db.Model(&Session{}).Where("id=?", freeze.auth.SessionID).Update("revoked_at", nil).Error; err != nil {
			t.Fatal(err)
		}
		if err := freeze.Abort(tenant.ctx); err != nil {
			t.Fatal(err)
		}
		next := beginTestMaintenance(t, s, tenant.ctx, freeze.auth)
		if result, err := next.PauseBackupDrainCandidate(tenant.ctx, source); !errors.Is(err, ErrBackupDrainSource) || result != (BackupDrainPauseResult{}) {
			t.Fatal("different operation adopted old source", result, err)
		}
		if result, err := freeze.PauseBackupDrainCandidate(tenant.ctx, source); !errors.Is(err, ErrMaintenanceLeaseLost) || result != (BackupDrainPauseResult{}) {
			t.Fatal("old owner paused after new operation", result, err)
		}
		backupDrainAssertUnchanged(t, s, source.job)
	})
}

func TestBackupDrainOriginalJobChangesAreExactlyStale(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, freeze, source := backupDrainPauseFixture(t, s)
		var original Job
		if err := s.db.First(&original, source.job.ID).Error; err != nil {
			t.Fatal(err)
		}
		for _, item := range []struct {
			name   string
			update map[string]any
		}{
			{"priority", map[string]any{"priority": original.Priority + 1}},
			{"key", map[string]any{"idempotency_key": "different-original-key"}},
			{"type", map[string]any{"type": "invalid-kind"}},
			{"max", map[string]any{"max_attempts": original.MaxAttempts + 1}},
			{"lease", map[string]any{"lease_until": nil}},
			{"owner", map[string]any{"lease_owner": "other-owner"}},
			{"cancel", map[string]any{"cancel_requested_at": time.Now().UTC()}},
			{"error", map[string]any{"last_error_code": "JOB_CHANGED"}},
			{"updated", map[string]any{"updated_at": time.Unix(2, 0).UTC()}},
			{"completed", map[string]any{"completed_at": time.Now().UTC()}},
		} {
			t.Run(item.name, func(t *testing.T) {
				if err := s.db.Model(&Job{}).Where("id=?", original.ID).Updates(item.update).Error; err != nil {
					t.Fatal(err)
				}
				var changed Job
				if err := s.db.First(&changed, original.ID).Error; err != nil {
					t.Fatal(err)
				}
				result, err := freeze.PauseBackupDrainCandidate(tenant.ctx, source)
				if !errors.Is(err, ErrBackupDrainStale) || result != (BackupDrainPauseResult{}) {
					t.Fatal("changed original Job not stale", result, err)
				}
				var after Job
				if err := s.db.First(&after, original.ID).Error; err != nil || !reflect.DeepEqual(changed, after) {
					t.Fatal("stale pause overwrote changed Job", err)
				}
				if err := s.db.Model(&Job{}).Where("id=?", original.ID).Select("*").Updates(&original).Error; err != nil {
					t.Fatal(err)
				}
			})
		}
	})
}

func TestBackupDrainDomainChangeCannotUseOldPauseProof(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, freeze, source := backupDrainPauseFixture(t, s)
		if err := s.db.Model(&RunRecord{}).Where("id=?", source.domain.RunID).Update("version", source.domain.Version+1).Error; err != nil {
			t.Fatal(err)
		}
		if result, err := freeze.PauseBackupDrainCandidate(tenant.ctx, source); !errors.Is(err, ErrBackupDrainStale) || result != (BackupDrainPauseResult{}) {
			t.Fatal("changed domain accepted old pause proof", result, err)
		}
		backupDrainAssertUnchanged(t, s, source.job)
	})
}
