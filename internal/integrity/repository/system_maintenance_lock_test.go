package repository

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestSystemMaintenanceCancelledLockWaitDoesNotCreateOperation(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, auth, ctx := managementFixture(t, s)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		observer, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = observer.Close() }()
		held := make(chan int, 1)
		release := make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		holderDone := make(chan error, 1)
		go func() {
			holderDone <- s.db.WithContext(ctx).Transaction(func(db *gorm.DB) error {
				if _, err := s.lockMaintenance(db, true); err != nil {
					return err
				}
				var pid int
				if cfg.Driver == "postgres" {
					if err := db.Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
						return err
					}
				}
				held <- pid
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
		}()
		var holderPID int
		select {
		case holderPID = <-held:
		case err := <-holderDone:
			t.Fatal("gate holder did not acquire its lock", err)
		case <-time.After(3 * time.Second):
			t.Fatal("gate holder timed out")
		}
		waitingPID := make(chan int, 1)
		if cfg.Driver == "postgres" {
			if err := other.db.Callback().Query().Before("gorm:query").Register("maintenance_cancel_observe_waiter", func(db *gorm.DB) {
				if db.Statement.Table != "system_maintenance" {
					return
				}
				var pid int
				if err := db.Session(&gorm.Session{NewDB: true}).Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
					_ = db.AddError(err)
					return
				}
				waitingPID <- pid
			}); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = other.db.Callback().Query().Remove("maintenance_cancel_observe_waiter") }()
		}
		waitCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		if cfg.Driver == "sqlite" {
			// BEGIN IMMEDIATE is itself the blocked operation, before any ORM
			// Query callback. A real deadline must cancel this held-writer wait.
			waitCtx, cancel = context.WithTimeout(ctx, 200*time.Millisecond)
			defer cancel()
		}
		waitingDone := make(chan error, 1)
		go func() {
			_, err := other.BeginBackupMaintenance(waitCtx, auth, BackupMaintenanceRequest{ExpectedVersion: 1, ReasonCode: "backup.manual", MaxDuration: time.Hour})
			waitingDone <- err
		}()
		if cfg.Driver == "postgres" {
			select {
			case pid := <-waitingPID:
				responseRetentionWaitForBlocker(t, ctx, observer, pid, holderPID)
			case err := <-waitingDone:
				t.Fatal("waiting coordinator never attempted its gate lock", err)
			case <-time.After(2 * time.Second):
				t.Fatal("waiting coordinator backend not observed")
			}
			cancel()
		}
		select {
		case err := <-waitingDone:
			if !errors.Is(err, ErrUnavailable) || (cfg.Driver == "postgres" && waitCtx.Err() == nil) {
				t.Fatal("cancelled SQL wait was successful or misclassified as a lost owner", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("cancelled gate wait did not respect its bounded SQL context")
		}
		unblock()
		select {
		case err := <-holderDone:
			if err != nil {
				t.Fatal("original gate holder failed", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("original gate holder did not release")
		}
		assertMaintenanceNoOperation(t, observer, ctx)
		// A fresh authorized attempt, without retrying a failed operation, can
		// use the unchanged initial version after the cancelled waiter is gone.
		lease := beginTestMaintenance(t, observer, ctx, auth)
		if err := lease.Abort(ctx); err != nil {
			t.Fatal(err)
		}
	})
}
