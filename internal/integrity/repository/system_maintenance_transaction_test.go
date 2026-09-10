package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func TestSystemMaintenanceSQLiteScopedConnectionRestoresOrDiscards(t *testing.T) {
	for _, mode := range []string{"success", "rollback", "cancel", "restore_failure"} {
		t.Run(mode, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
				if cfg.Driver != "sqlite" {
					t.Skip("SQLite per-connection busy handler contract")
				}
				if err := s.db.Exec("CREATE TABLE maintenance_scoped_probe (id INTEGER PRIMARY KEY)").Error; err != nil {
					t.Fatal(err)
				}
				if err := s.db.Exec("CREATE TEMP TABLE maintenance_connection_identity (id INTEGER)").Error; err != nil {
					t.Fatal(err)
				}
				configPool, statementPool := s.db.ConnPool, s.db.Statement.ConnPool
				injected := errors.New("synthetic maintenance transaction failure; never public")
				restoreObserved := false
				if mode == "restore_failure" {
					if err := s.db.Callback().Raw().Before("gorm:raw").Register("maintenance_test_restore_failure", func(db *gorm.DB) {
						if db.Statement.SQL.String() == "PRAGMA busy_timeout = 5000" {
							restoreObserved = true
							_ = db.AddError(injected)
						}
					}); err != nil {
						t.Fatal(err)
					}
					defer func() { _ = s.db.Callback().Raw().Remove("maintenance_test_restore_failure") }()
				}
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				defer cancel()
				entered := false
				err := managementError(s.maintenanceTransaction(ctx, func(db *gorm.DB) error {
					entered = true
					if db.Config == s.db.Config || db.Statement == s.db.Statement || s.db.ConnPool != configPool || s.db.Statement.ConnPool != statementPool {
						return ErrMaintenanceSource
					}
					var wait, foreignKeys int
					if err := db.Raw("PRAGMA busy_timeout").Scan(&wait).Error; err != nil {
						return err
					}
					if err := db.Raw("PRAGMA foreign_keys").Scan(&foreignKeys).Error; err != nil {
						return err
					}
					if wait < 1 || wait > 2000 || foreignKeys != 1 {
						return ErrMaintenanceSource
					}
					if err := db.Exec("INSERT INTO maintenance_scoped_probe (id) VALUES (1)").Error; err != nil {
						return err
					}
					switch mode {
					case "rollback":
						return injected
					case "cancel":
						cancel()
						return ctx.Err()
					default:
						return nil
					}
				}))
				if !entered {
					t.Fatal("scoped coordinator transaction never started", err)
				}
				if (mode == "success" && err != nil) || (mode != "success" && !errors.Is(err, ErrUnavailable)) {
					t.Fatal("scoped transaction returned wrong closed outcome", mode, err)
				}
				if s.db.ConnPool != configPool || s.db.Statement.ConnPool != statementPool {
					t.Fatal("private coordinator connection mutated Store pools")
				}
				var wait, foreignKeys, rows int
				if err := s.db.Raw("PRAGMA busy_timeout").Scan(&wait).Error; err != nil || wait != 5000 {
					t.Fatal("temporary coordinator busy policy leaked to the pool", err)
				}
				if err := s.db.Raw("PRAGMA foreign_keys").Scan(&foreignKeys).Error; err != nil || foreignKeys != 1 {
					t.Fatal("coordinator changed foreign-key safety", err)
				}
				if err := s.db.Raw("SELECT count(*) FROM maintenance_scoped_probe").Scan(&rows).Error; err != nil {
					t.Fatal(err)
				}
				wantRows := 1
				if mode == "rollback" || mode == "cancel" {
					wantRows = 0
				}
				if rows != wantRows {
					t.Fatal("transaction commit/rollback fact was misreported", mode, rows)
				}
				if mode == "restore_failure" {
					var tempTables int
					if err := s.db.Raw("SELECT count(*) FROM sqlite_temp_master WHERE name='maintenance_connection_identity'").Scan(&tempTables).Error; err != nil || tempTables != 0 || !restoreObserved {
						t.Fatal("failed cleanup did not physically discard the original connection", err)
					}
					// Cleanup failed AFTER commit, so error does not mean rollback.
					// A real coordinator caller must inspect durable state before a
					// new operation; the committed freeze cannot silently reopen.
				}
			})
		})
	}
}

func TestSystemMaintenanceSQLiteCleanupFailurePreservesCommittedFreeze(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		if cfg.Driver != "sqlite" {
			t.Skip("SQLite coordinator cleanup boundary")
		}
		_, auth, ctx := managementFixture(t, s)
		if err := s.db.Callback().Raw().Before("gorm:raw").Register("maintenance_test_begin_restore_failure", func(db *gorm.DB) {
			if db.Statement.SQL.String() == "PRAGMA busy_timeout = 5000" {
				_ = db.AddError(ErrUnavailable)
			}
		}); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.db.Callback().Raw().Remove("maintenance_test_begin_restore_failure") }()
		lease, err := s.BeginBackupMaintenance(ctx, auth, BackupMaintenanceRequest{ExpectedVersion: 1, ReasonCode: "backup.manual", MaxDuration: time.Hour})
		if !errors.Is(err, ErrUnavailable) || lease != nil {
			t.Fatal("cleanup failure issued success or a usable owner capability", err)
		}
		if err := s.db.Callback().Raw().Remove("maintenance_test_begin_restore_failure"); err != nil {
			t.Fatal(err)
		}
		state, err := s.ReadMaintenanceState(ctx)
		if err != nil || state.Mode != MaintenanceBackupFreeze || state.Version != 2 || state.Generation != 1 {
			t.Fatal("post-commit cleanup failure was incorrectly treated as rollback", err)
		}
		for _, model := range []any{&maintenanceOperation{}, &maintenanceEvent{}} {
			var count int64
			if err := s.db.Model(model).Count(&count).Error; err != nil || count != 1 {
				t.Fatal("committed freeze operation or event was lost", err)
			}
		}
		var signed int64
		if err := s.db.Model(&audit.Event{}).Where("action='system.maintenance.begin'").Count(&signed).Error; err != nil || signed != 1 {
			t.Fatal("committed freeze audit was lost", err)
		}
		if err := s.VerifyAllAudit(ctx, true); err != nil {
			t.Fatal("cleanup failure broke the committed audit chain", err)
		}
		if _, err := s.ManageCreateUser(ctx, auth, ManagedUserCreate{Username: "still-frozen", PasswordHash: "synthetic-only"}); !errors.Is(err, ErrSystemMaintenance) {
			t.Fatal("caller-visible cleanup error silently reopened admission", err)
		}
		if _, err := s.TakeOverExpiredBackup(ctx, auth, BackupMaintenanceRequest{ExpectedVersion: 2, ReasonCode: "backup.recovery", MaxDuration: time.Hour}); !errors.Is(err, ErrMaintenanceLeaseLost) {
			t.Fatal("cleanup error authorized an early takeover of an unexpired operation", err)
		}
	})
}
