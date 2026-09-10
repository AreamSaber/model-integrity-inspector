package repository

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestSystemMaintenanceTwoInstancesFreezeHasOneOwner(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, auth, ctx := managementFixture(t, s)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		start := make(chan struct{})
		type outcome struct {
			lease *MaintenanceLease
			err   error
		}
		results := make(chan outcome, 2)
		for _, candidate := range []*Store{s, other} {
			go func() {
				<-start
				lease, err := candidate.BeginBackupMaintenance(ctx, auth, BackupMaintenanceRequest{ExpectedVersion: 1, ReasonCode: "backup.manual", MaxDuration: time.Hour})
				results <- outcome{lease, err}
			}()
		}
		close(start)
		var winner *MaintenanceLease
		for range 2 {
			select {
			case result := <-results:
				if result.err == nil {
					if winner != nil {
						t.Fatal("two system owners")
					}
					winner = result.lease
				} else if !errors.Is(result.err, ErrConflict) {
					t.Fatal("unexpected loser classification", result.err)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("freeze contention did not terminate")
			}
		}
		if winner == nil {
			t.Fatal("no owner acquired")
		}
		if err := winner.Abort(ctx); err != nil {
			t.Fatal(err)
		}
		next := beginTestMaintenance(t, other, ctx, auth)
		if next.generation <= winner.generation {
			t.Fatal("generation did not advance")
		}
		for _, operation := range []func(context.Context) error{winner.Renew, winner.Abort} {
			if err := operation(ctx); !errors.Is(err, ErrMaintenanceLeaseLost) {
				t.Fatal("old owner changed newer operation", err)
			}
		}
		if _, err := winner.Observe(ctx); !errors.Is(err, ErrMaintenanceLeaseLost) {
			t.Fatal("old owner observed newer operation", err)
		}
		if err := next.Abort(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

// The actual business transaction owns its admission lock when blocked. Freeze
// must wait without reaching its UPDATE-protected business body. Release is a
// control barrier, not a guessed delay or a larger production timeout.
func TestSystemMaintenanceFreezeSerializesWithAdmittedBusinessTransaction(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, auth, ctx := managementFixture(t, s)
		business, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = business.Close() }()
		entered := make(chan struct{})
		businessPID := make(chan int, 1)
		release := make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		if err := business.db.Callback().Create().Before("gorm:create").Register("maintenance_business_barrier", func(db *gorm.DB) {
			user, ok := db.Statement.Dest.(*User)
			if !ok || user.Username != "admitted-writer" {
				return
			}
			if cfg.Driver == "postgres" {
				var pid int
				if err := db.Session(&gorm.Session{NewDB: true}).Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
					_ = db.AddError(err)
					return
				}
				businessPID <- pid
			}
			close(entered)
			select {
			case <-release:
			case <-db.Statement.Context.Done():
				_ = db.AddError(db.Statement.Context.Err())
			}
		}); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = business.db.Callback().Create().Remove("maintenance_business_barrier") }()
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		businessDone := make(chan error, 1)
		go func() {
			_, err := business.ManageCreateUser(bounded, auth, ManagedUserCreate{Username: "admitted-writer", PasswordHash: "synthetic-only"})
			businessDone <- err
		}()
		select {
		case <-entered:
		case <-bounded.Done():
			t.Fatal("business never reached post-admission barrier")
		}
		freezeStarted := make(chan struct{})
		freezePID := make(chan int, 1)
		if err := s.db.Callback().Query().Before("gorm:query").Register("maintenance_freeze_query_started", func(db *gorm.DB) {
			if db.Statement.Table == "system_maintenance" {
				select {
				case <-freezeStarted:
				default:
					if cfg.Driver == "postgres" {
						var pid int
						if err := db.Session(&gorm.Session{NewDB: true}).Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
							_ = db.AddError(err)
							return
						}
						freezePID <- pid
					}
					close(freezeStarted)
				}
			}
		}); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.db.Callback().Query().Remove("maintenance_freeze_query_started") }()
		freezeDone := make(chan error, 1)
		var owner *MaintenanceLease
		go func() {
			var err error
			owner, err = s.BeginBackupMaintenance(ctx, auth, BackupMaintenanceRequest{ExpectedVersion: 1, ReasonCode: "backup.manual", MaxDuration: time.Hour})
			freezeDone <- err
		}()
		if cfg.Driver == "postgres" {
			select {
			case <-freezeStarted:
			case <-bounded.Done():
				t.Fatal("freeze never attempted admission lock")
			}
			observer, err := Open(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = observer.Close() }()
			responseRetentionWaitForBlocker(t, bounded, observer, <-freezePID, <-businessPID)
		}
		// SQLite blocks BEGIN IMMEDIATE before a Query callback can fire. Both
		// dialects must remain uncommitted while the actual writer owns its lock.
		select {
		case err := <-freezeDone:
			t.Fatal("freeze bypassed an admitted writer", err)
		default:
		}
		unblock()
		select {
		case err := <-businessDone:
			if err != nil {
				t.Fatal("admitted writer failed", err)
			}
		case <-bounded.Done():
			t.Fatal("writer did not finish")
		}
		select {
		case err := <-freezeDone:
			if err != nil {
				t.Fatal("freeze after writer", err)
			}
		case <-bounded.Done():
			t.Fatal("freeze did not finish")
		}
		if _, err := business.ManageCreateUser(ctx, auth, ManagedUserCreate{Username: "late-writer", PasswordHash: "synthetic-only"}); !errors.Is(err, ErrSystemMaintenance) {
			t.Fatal("later instance bypassed freeze", err)
		}
		if err := owner.Abort(ctx); err != nil {
			t.Fatal(err)
		}
	})
}
