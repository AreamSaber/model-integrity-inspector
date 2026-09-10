package repository

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func backupDrainTerminalFixture(t *testing.T, s *Store, kind JobType) (backupDomainFixture, *MaintenanceLease, *BackupDrainSource) {
	t.Helper()
	f := newBackupDomainFixture(t, s, kind, 1)
	backupDrainTerminalExpire(t, s, f.lease.Job.ID)
	if err := s.db.Model(&Job{}).Where("id=?", f.lease.Job.ID).UpdateColumn("attempt_count", f.lease.Job.MaxAttempts).Error; err != nil {
		t.Fatal(err)
	}
	freeze := beginTestMaintenance(t, s, f.tenant.ctx, backupDrainTestAuthority(t, s, f.tenant.ctx))
	return f, freeze, backupDrainTerminalLoad(t, freeze, f.tenant.ctx, f.lease.Job.ID)
}

func backupDrainTerminalFaults(t *testing.T, kind JobType, table, predicate string) {
	t.Helper()
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		f, freeze, source := backupDrainTerminalFixture(t, s, kind)
		before := backupDrainTerminalRows(t, s)
		for _, mode := range []string{"ignored-job", "ignored-domain", "ignored-head", "late-system-sql", "late-system-cancel"} {
			t.Run(mode, func(t *testing.T) {
				ctx, cancel := context.WithCancel(f.tenant.ctx)
				defer cancel()
				entered := false
				switch mode {
				case "ignored-job":
					t.Cleanup(backupDomainIgnoreUpdate(t, s, cfg, "integrity_jobs", "OLD.status='running' AND NEW.status='failed'"))
				case "ignored-domain":
					t.Cleanup(backupDomainIgnoreUpdate(t, s, cfg, table, predicate))
				case "ignored-head":
					t.Cleanup(backupDomainIgnoreUpdate(t, s, cfg, "integrity_audit_chain_heads", "NEW.event_count>OLD.event_count"))
				case "late-system-sql":
					t.Cleanup(backupDomainAuditSQLFault(t, s, cfg, "system.backup.drain.terminalize"))
				case "late-system-cancel":
					const callback = "backup_terminal_cancel_after_system_audit"
					if err := s.db.Callback().Create().After("gorm:create").Register(callback, func(db *gorm.DB) {
						event, ok := db.Statement.Dest.(*audit.Event)
						if ok && event.Action == "system.backup.drain.terminalize" && db.Error == nil {
							entered = true
							cancel()
						}
					}); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = s.db.Callback().Create().Remove(callback) })
				}
				result, err := freeze.ApplyBackupTerminalCandidate(ctx, source)
				if err == nil || result != (BackupDrainTerminalResult{}) || strings.Contains(err.Error(), "domain-fault") || (mode == "late-system-cancel" && (!entered || !errors.Is(err, context.Canceled))) {
					t.Fatal("failed terminal apply returned progress or nonclosed error", result, err)
				}
				if !reflect.DeepEqual(before, backupDrainTerminalRows(t, s)) {
					t.Fatal("late failure left Job/domain/audit partial facts")
				}
			})
		}
		if result, err := freeze.ApplyBackupTerminalCandidate(f.tenant.ctx, source); err != nil || !result.Applied {
			t.Fatal("removing actual faults did not restore valid Apply", err)
		}
		if err := s.VerifyAllAudit(t.Context(), true); err != nil {
			t.Fatal("actual chain after faults", err)
		}
	})
}

func TestBackupDrainTerminalApplyAnalysisAtomicFaults(t *testing.T) {
	backupDrainTerminalFaults(t, JobRunAnalyze, "integrity_runs", "OLD.status='ANALYZING' AND NEW.status='FAILED'")
}
func TestBackupDrainTerminalApplyReportAtomicFaults(t *testing.T) {
	backupDrainTerminalFaults(t, JobReportGenerate, "integrity_reports", "OLD.status='generating' AND NEW.status='failed'")
}
func TestBackupDrainTerminalApplyPrecheckAtomicFaults(t *testing.T) {
	backupDrainTerminalFaults(t, JobTargetPrecheck, "integrity_target_prechecks", "OLD.status='running' AND NEW.status='failed'")
}

func TestBackupDrainTerminalApplyNaturalSessionExpiry(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		f, freeze, source := backupDrainTerminalFixture(t, s, JobRunAnalyze)
		expires := time.Now().UTC().Add(400 * time.Millisecond)
		if err := s.db.Model(&Session{}).Where("id=?", freeze.auth.SessionID).UpdateColumn("expires_at", expires).Error; err != nil {
			t.Fatal(err)
		}
		before := backupDrainTerminalRows(t, s)
		entered := false
		const callback = "backup_terminal_session_expiry"
		if err := s.db.Callback().Create().After("gorm:create").Register(callback, func(db *gorm.DB) {
			event, ok := db.Statement.Dest.(*audit.Event)
			if !ok || event.Action != "system.backup.drain.terminalize" || db.Error != nil {
				return
			}
			if !time.Now().Before(expires) {
				_ = db.AddError(errors.New("test missed original authority window"))
				return
			}
			entered = true
			timer := time.NewTimer(time.Until(expires) + 25*time.Millisecond)
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
		result, err := freeze.ApplyBackupTerminalCandidate(f.tenant.ctx, source)
		if !entered || !errors.Is(err, ErrManagementSession) || result != (BackupDrainTerminalResult{}) || !reflect.DeepEqual(before, backupDrainTerminalRows(t, s)) {
			t.Fatal("late session expiry committed a terminal outcome", entered, result, err)
		}
	})
}

func TestBackupDrainTerminalApplySourceAndAuthority(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		f, freeze, source := backupDrainTerminalFixture(t, s, JobRunAnalyze)
		before := backupDrainTerminalRows(t, s)
		for _, mode := range []string{"nil-source", "different-owner", "different-generation", "different-operation", "different-store", "no-actor", "cancelled", "revoked"} {
			t.Run(mode, func(t *testing.T) {
				copySource := *source
				candidate := &copySource
				ctx := f.tenant.ctx
				want := ErrBackupDrainSource
				switch mode {
				case "nil-source":
					candidate = nil
				case "different-owner":
					copySource.owner += "-other"
				case "different-generation":
					copySource.generation++
				case "different-operation":
					copySource.operationID++
				case "different-store":
					other, err := Open(t.Context(), cfg)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = other.Close() })
					copySource.store = other
				case "no-actor":
					ctx, want = context.Background(), audit.ErrActorRequired
				case "cancelled":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
					want = context.Canceled
				case "revoked":
					if err := s.db.Model(&Session{}).Where("id=?", freeze.auth.SessionID).UpdateColumn("revoked_at", time.Now().UTC()).Error; err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := s.db.Model(&Session{}).Where("id=?", freeze.auth.SessionID).UpdateColumn("revoked_at", nil).Error; err != nil {
							t.Fatal(err)
						}
					})
					want = ErrManagementSession
				}
				result, err := freeze.ApplyBackupTerminalCandidate(ctx, candidate)
				if !errors.Is(err, want) || result != (BackupDrainTerminalResult{}) || !reflect.DeepEqual(before, backupDrainTerminalRows(t, s)) {
					t.Fatal("invalid source/authority changed facts", result, err)
				}
			})
		}
		if err := freeze.Abort(f.tenant.ctx); err != nil {
			t.Fatal(err)
		}
		next := beginTestMaintenance(t, s, f.tenant.ctx, freeze.auth)
		before = backupDrainTerminalRows(t, s)
		if result, err := next.ApplyBackupTerminalCandidate(f.tenant.ctx, source); !errors.Is(err, ErrBackupDrainSource) || result != (BackupDrainTerminalResult{}) {
			t.Fatal("new operation adopted old source", err)
		}
		if result, err := freeze.ApplyBackupTerminalCandidate(f.tenant.ctx, source); !errors.Is(err, ErrMaintenanceLeaseLost) || result != (BackupDrainTerminalResult{}) || !reflect.DeepEqual(before, backupDrainTerminalRows(t, s)) {
			t.Fatal("old owner committed after replacement", err)
		}
	})
}
