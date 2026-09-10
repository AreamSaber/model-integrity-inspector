package repository

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func TestBackupOperationReadCreatedTimeMustBeBeginAnchored(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		_, auth, ctx := managementFixture(t, s)
		old := beginTestMaintenance(t, s, ctx, auth)
		if err := old.Abort(ctx); err != nil {
			t.Fatal(err)
		}
		next := beginTestMaintenance(t, s, ctx, auth)
		if err := next.Abort(ctx); err != nil {
			t.Fatal(err)
		}
		snapshotKeyTestUnconstrained(t, s, "system_maintenance_operations")
		if err := s.db.Model(&maintenanceOperation{}).Where("id=?", old.operationID).Update("created_at_micros", old.startedAtMicros-1).Error; err != nil {
			t.Fatal(err)
		}
		got, err := s.ReadBackupOperation(ctx, auth, old.operationID)
		if !errors.Is(err, ErrMaintenanceSource) || got != (BackupOperationView{}) {
			t.Fatal("unauthenticated changed begin time returned", err)
		}
	})
}

func TestBackupOperationReadHistoricalOperationCorruptionAndBounds(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		_, auth, ctx := managementFixture(t, s)
		old := beginTestMaintenance(t, s, ctx, auth)
		if err := old.Abort(ctx); err != nil {
			t.Fatal(err)
		}
		next := beginTestMaintenance(t, s, ctx, auth)
		if err := next.Abort(ctx); err != nil {
			t.Fatal(err)
		}
		original := snapshotKeyTestUnconstrained(t, s, "system_maintenance_operations")
		reset := func() {
			for _, q := range []string{"DELETE FROM system_maintenance_operations", "INSERT INTO system_maintenance_operations SELECT * FROM " + original} {
				if err := s.db.Exec(q).Error; err != nil {
					t.Fatal(err)
				}
			}
		}
		for i, values := range []map[string]any{{"scope": "organization"}, {"mode": "normal"}, {"generation": nil}, {"generation": -1}, {"initiated_by": auth.UserID + 1}, {"session_id": auth.SessionID + 1}, {"reason_code": "backup.upgrade"}, {"status": "ready"}, {"status": "active"}, {"owner": strings.Repeat("private-owner-canary", 100000)}, {"created_at_micros": nil}, {"updated_at_micros": old.startedAtMicros - 1}, {"event_sequence": 100000}, {"event_digest": strings.Repeat("f", 64)}, {"lease_until_micros": nil}, {"deadline_micros": 1}} {
			t.Run(strconv.Itoa(i), func(t *testing.T) {
				if err := s.db.Model(&maintenanceOperation{}).Where("id=?", old.operationID).Updates(values).Error; err != nil {
					t.Fatal(err)
				}
				if i == 2 {
					// PostgreSQL DESC puts this corrupt NULL ahead of the valid
					// current generation. Preserve that SQL fact rather than
					// accepting a driver scan failure as source verification.
					var first sql.NullInt64
					if err := s.db.Raw("SELECT generation FROM system_maintenance_operations ORDER BY generation DESC LIMIT 1").Row().Scan(&first); err != nil {
						t.Fatal("nullable generation observation failed")
					}
					if first.Valid != (s.driver == "sqlite") {
						t.Fatal("unexpected NULL ordering")
					}
					if s.driver == "postgres" {
						var raw []int64
						err := s.db.Model(&maintenanceOperation{}).Select("generation").Order("generation DESC").Limit(1).Find(&raw).Error
						if err == nil || !strings.Contains(err.Error(), "converting NULL to int64") {
							t.Fatal("expected fixed scalar NULL scan failure absent")
						}
						t.Log("confirmed PostgreSQL DESC first generation is SQL NULL; []int64 scan rejects converting NULL to int64")
					}
				}
				backupOperationReadAssertZero(t, s, ctx, auth, old.operationID, ErrMaintenanceSource)
			})
			reset()
		}
		if err := s.db.Exec("INSERT INTO system_maintenance_operations SELECT * FROM "+original+" WHERE id=?", old.operationID).Error; err != nil {
			t.Fatal(err)
		}
		backupOperationReadAssertZero(t, s, ctx, auth, old.operationID, ErrMaintenanceSource)
	})
}

func TestBackupOperationReadReceiptAndLateRehashNeverReady(t *testing.T) {
	for _, mode := range []string{"missing", "duplicate", "hash", "rehash", "late-rehash"} {
		t.Run(mode, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				_, auth, ctx := managementFixture(t, s)
				lease := beginTestMaintenance(t, s, ctx, auth)
				if _, err := lease.CompleteBackup(ctx, testBackupPublication(t, lease)); err != nil {
					t.Fatal(err)
				}
				next := beginTestMaintenance(t, s, ctx, auth)
				if err := next.Abort(ctx); err != nil {
					t.Fatal(err)
				}
				reads := 0
				if err := s.db.Callback().Query().After("gorm:query").Register("backup_state_receipt_fault", func(db *gorm.DB) {
					rows, ok := db.Statement.Dest.(*[]BackupCompletionReceipt)
					if !ok || len(*rows) != 1 || (*rows)[0].BackupID != lease.operationID {
						return
					}
					reads++
					if mode == "late-rehash" && reads%2 != 0 {
						return
					}
					switch mode {
					case "missing":
						*rows = nil
						return
					case "duplicate":
						*rows = append(*rows, (*rows)[0])
						return
					}
					(*rows)[0].ArchiveSHA256 = strings.Repeat("f", 64)
					if mode == "rehash" || mode == "late-rehash" {
						digest, err := backupCompletionDigest((*rows)[0])
						if err != nil {
							_ = db.AddError(err)
							return
						}
						(*rows)[0].Digest = digest
					}
				}); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = s.db.Callback().Query().Remove("backup_state_receipt_fault") }()
				if got, err := s.ReadBackupOperation(ctx, auth, lease.operationID); err == nil || got != (BackupOperationView{}) {
					t.Fatal("unbound completion became ready", err)
				}
				if reads == 0 {
					t.Fatal("receipt fixture missed")
				}
				reads = 0
				if got, err := s.ListBackupOperations(ctx, auth, BackupOperationListRequest{Limit: 100}); err == nil || !reflect.DeepEqual(got, BackupOperationPage{}) {
					t.Fatal("unbound completion page returned", err)
				}
			})
		})
	}
}

func TestBackupOperationReadCurrentGateCannotBeCachedOrDowngraded(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, auth, ctx := managementFixture(t, s)
		old := beginTestMaintenance(t, s, ctx, auth)
		if err := old.Abort(ctx); err != nil {
			t.Fatal(err)
		}
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		if _, err := other.ReadBackupOperation(ctx, auth, old.operationID); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"reset-initial", "older-valid-normal", "restore-isolated"} {
			t.Run(mode, func(t *testing.T) {
				var original maintenanceState
				if err := s.db.Where("id=1").Take(&original).Error; err != nil {
					t.Fatal(err)
				}
				values := map[string]any{"mode": MaintenanceNormal, "version": 1, "generation": 0, "operation_id": nil, "owner": "", "lease_until_micros": 0, "deadline_micros": 0, "updated_at_micros": 0}
				want := ErrMaintenanceSource
				if mode == "older-valid-normal" {
					next := beginTestMaintenance(t, s, ctx, auth)
					if err := next.Abort(ctx); err != nil {
						t.Fatal(err)
					}
					values = map[string]any{"mode": original.Mode, "version": original.Version, "generation": original.Generation, "operation_id": original.OperationID, "owner": original.Owner, "lease_until_micros": original.LeaseUntilMicros, "deadline_micros": original.DeadlineMicros, "updated_at_micros": original.UpdatedAtMicros}
					if err := s.db.Where("id=1").Take(&original).Error; err != nil {
						t.Fatal(err)
					}
				}
				if mode == "restore-isolated" {
					values = map[string]any{"mode": MaintenanceRestoreIsolated, "owner": "", "lease_until_micros": 0, "deadline_micros": 0}
					want = ErrRestoreIsolated
				}
				if err := s.db.Model(&maintenanceState{}).Where("id=1").Updates(values).Error; err != nil {
					t.Fatal(err)
				}
				backupOperationReadAssertZero(t, other, ctx, auth, old.operationID, want)
				if err := s.db.Model(&maintenanceState{}).Where("id=1").Updates(map[string]any{"mode": original.Mode, "version": original.Version, "generation": original.Generation, "operation_id": original.OperationID, "owner": original.Owner, "lease_until_micros": original.LeaseUntilMicros, "deadline_micros": original.DeadlineMicros, "updated_at_micros": original.UpdatedAtMicros}).Error; err != nil {
					t.Fatal(err)
				}
			})
		}
	})
}

func TestBackupOperationReadAuditAndLateSQLFailureZero(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		_, auth, ctx := managementFixture(t, s)
		old := beginTestMaintenance(t, s, ctx, auth)
		if err := old.Abort(ctx); err != nil {
			t.Fatal(err)
		}
		next := beginTestMaintenance(t, s, ctx, auth)
		if err := next.Abort(ctx); err != nil {
			t.Fatal(err)
		}
		for _, stage := range []string{"operation", "latest-event", "audit"} {
			t.Run(stage, func(t *testing.T) {
				fired := false
				if err := s.db.Callback().Query().After("gorm:query").Register("backup_state_sql_fault", func(db *gorm.DB) {
					match := false
					switch value := db.Statement.Dest.(type) {
					case *[]maintenanceOperation:
						match = stage == "operation" && len(*value) > 0
					case *maintenanceEvent:
						match = stage == "latest-event" && value.OperationID == old.operationID
					case *[]audit.Event:
						match = stage == "audit" && len(*value) == 1 && strings.HasPrefix((*value)[0].ObjectID, strconv.FormatInt(old.operationID, 10)+":")
					}
					if match {
						fired = true
						_ = db.AddError(errors.New("untrusted SQL path/private-key canary"))
					}
				}); err != nil {
					t.Fatal(err)
				}
				backupOperationReadAssertZero(t, s, ctx, auth, old.operationID, ErrUnavailable)
				if err := s.db.Callback().Query().Remove("backup_state_sql_fault"); err != nil {
					t.Fatal(err)
				}
				if !fired {
					t.Fatal("fault stage missed")
				}
			})
		}
	})
}

func TestBackupOperationReadTwoInstanceBoundedGateWait(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, auth, ctx := managementFixture(t, s)
		old := beginTestMaintenance(t, s, ctx, auth)
		if err := old.Abort(ctx); err != nil {
			t.Fatal(err)
		}
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		entered, release := make(chan struct{}), make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- s.db.WithContext(ctx).Transaction(func(db *gorm.DB) error {
				if _, err := s.lockMaintenance(db, true); err != nil {
					return err
				}
				close(entered)
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
		}()
		select {
		case <-entered:
		case err := <-done:
			t.Fatal("holder", err)
		case <-time.After(2 * time.Second):
			t.Fatal("holder absent")
		}
		bounded, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		page, err := other.ListBackupOperations(bounded, auth, BackupOperationListRequest{Limit: 100})
		cancel()
		close(release)
		if holderErr := <-done; holderErr != nil {
			t.Fatal(holderErr)
		}
		if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(page, BackupOperationPage{}) {
			t.Fatal("gate wait escaped deadline", err)
		}
		if got, err := other.ReadBackupOperation(ctx, auth, old.operationID); err != nil || got.Status != BackupOperationAborted {
			t.Fatal("connection busy policy not restored", err)
		}
	})
}
