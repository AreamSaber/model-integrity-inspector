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

func TestBackupCompletionBindsOriginalBeginAfterRenewal(t *testing.T) {
	for _, mode := range []string{"changed_time", "rehashed_begin", "missing_begin", "duplicate_begin"} {
		t.Run(mode, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				_, auth, ctx := managementFixture(t, s)
				lease := beginTestMaintenance(t, s, ctx, auth)
				publication := testBackupPublication(t, lease)
				if err := lease.Renew(ctx); err != nil {
					t.Fatal(err)
				}
				if mode == "changed_time" || mode == "rehashed_begin" {
					// Active operation scalar mutation remains possible at the SQL
					// layer; its original signed begin must detect even a valid time.
					if err := s.db.Model(&maintenanceOperation{}).Where("id=?", lease.operationID).Update("created_at_micros", lease.startedAtMicros-1).Error; err != nil {
						t.Fatal(err)
					}
				}
				if mode != "changed_time" {
					if err := s.db.Callback().Query().After("gorm:query").Register("backup_completion_begin_fault", func(db *gorm.DB) {
						rows, ok := db.Statement.Dest.(*[]maintenanceEvent)
						if !ok || len(*rows) != 1 || (*rows)[0].Sequence != 1 || db.Error != nil {
							return
						}
						switch mode {
						case "missing_begin":
							*rows = nil
						case "duplicate_begin":
							*rows = append(*rows, (*rows)[0])
						case "rehashed_begin":
							(*rows)[0].ObservedAtMicros--
							digest, err := maintenanceEventDigest((*rows)[0])
							if err != nil {
								_ = db.AddError(err)
								return
							}
							(*rows)[0].Digest = digest
						}
					}); err != nil {
						t.Fatal(err)
					}
					defer func() { _ = s.db.Callback().Query().Remove("backup_completion_begin_fault") }()
				}
				got, err := lease.CompleteBackup(ctx, publication)
				if !errors.Is(err, ErrMaintenanceSource) || got != (BackupCompletionReceipt{}) {
					t.Fatal("unanchored begin authorized completion", mode, err)
				}
				var count int64
				if err := s.db.Model(&BackupCompletionReceipt{}).Count(&count).Error; err != nil || count != 0 {
					t.Fatal("invalid begin left receipt", err)
				}
			})
		})
	}
}

func TestBackupCompletionAuthorityExpiryAtFinalCommit(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		_, auth, ctx := managementFixture(t, s)
		lease := beginTestMaintenance(t, s, ctx, auth)
		expires := time.Now().UTC().Add(300 * time.Millisecond)
		if err := s.db.Model(&Session{}).Where("id=?", auth.SessionID).Update("expires_at", expires).Error; err != nil {
			t.Fatal(err)
		}
		entered := false
		if err := s.db.Callback().Create().After("gorm:create").Register("backup_completion_expire", func(db *gorm.DB) {
			e, ok := db.Statement.Dest.(*audit.Event)
			if !ok || e.Action != "system.maintenance.complete" || db.Error != nil {
				return
			}
			entered = true
			if !time.Now().Before(expires) {
				_ = db.AddError(errors.New("fixture entered after authority expiry"))
				return
			}
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
		defer func() { _ = s.db.Callback().Create().Remove("backup_completion_expire") }()
		got, err := lease.CompleteBackup(ctx, testBackupPublication(t, lease))
		if !entered || !errors.Is(err, ErrManagementSession) || got != (BackupCompletionReceipt{}) {
			t.Fatal("naturally expired authority completed", entered, err)
		}
		var count int64
		if err := s.db.Model(&BackupCompletionReceipt{}).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("expired completion left receipt", err)
		}
		state, err := s.ReadMaintenanceState(ctx)
		if err != nil || state.Mode != MaintenanceBackupFreeze || state.Version != 2 {
			t.Fatal("expired authority reopened gate", err)
		}
	})
}

func TestBackupCompletionRejectsInFlightThenAllowsActualSettlement(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, s, 1)
		_, q, samples := executionStart(t, tenant, plan, policy)
		job := mustClaim(t, q)
		auth := tenant.ctx.Value(controlAuthorityKey{}).(controlAuthority).identity
		freeze := beginTestMaintenance(t, s, tenant.ctx, auth)
		p := testBackupPublication(t, freeze)
		for _, withAttempt := range []bool{false, true} {
			if withAttempt {
				_ = reserveTestAttempt(t, tenant, q, job, samples[0])
			}
			if got, err := freeze.CompleteBackup(tenant.ctx, p); !errors.Is(err, ErrBackupNotDrained) || got != (BackupCompletionReceipt{}) {
				t.Fatal("in-flight completed", withAttempt, err)
			}
		}
		var attempt AttemptRecord
		if err := s.db.Where("organization_id=? AND logical_sample_id=? AND status='DISPATCHED'", tenant.orgID, samples[0].ID).Take(&attempt).Error; err != nil {
			t.Fatal(err)
		}
		if err := q.CompleteWith(t.Context(), job, func(tx *TenantTransaction) error {
			return tx.FinishAttempt(samples[0].ID, attempt.ID, successOutcome(), 0)
		}); err != nil {
			t.Fatal("actual original lease settlement", err)
		}
		if _, err := freeze.CompleteBackup(tenant.ctx, p); err != nil {
			t.Fatal("settled backup still blocked", err)
		}
	})
}

func TestBackupCompletionReceiptTamperingAndResealingFailsAuditBinding(t *testing.T) {
	for _, mode := range []string{"hash", "rehash", "missing", "duplicate", "late_rehash"} {
		t.Run(mode, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				_, auth, ctx := managementFixture(t, s)
				lease := beginTestMaintenance(t, s, ctx, auth)
				p := testBackupPublication(t, lease)
				if _, err := lease.CompleteBackup(ctx, p); err != nil {
					t.Fatal(err)
				}
				// Move the current gate to a later genuine operation so lookup counts
				// reflect only this historical receipt's authentication and return read.
				next := beginTestMaintenance(t, s, ctx, auth)
				if err := next.Abort(ctx); err != nil {
					t.Fatal(err)
				}
				reads := 0
				if err := s.db.Callback().Query().After("gorm:query").Register("backup_completion_tamper", func(db *gorm.DB) {
					rows, ok := db.Statement.Dest.(*[]BackupCompletionReceipt)
					if !ok || len(*rows) != 1 || (*rows)[0].BackupID != p.BackupID || db.Error != nil {
						return
					}
					reads++
					if mode == "late_rehash" && reads != 2 {
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
					if mode == "rehash" || mode == "late_rehash" {
						sum, err := backupCompletionDigest((*rows)[0])
						if err != nil {
							_ = db.AddError(err)
							return
						}
						(*rows)[0].Digest = sum
					}
				}); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = s.db.Callback().Query().Remove("backup_completion_tamper") }()
				got, err := s.ReadBackupCompletion(ctx, auth, p.BackupID)
				if reads == 0 || err == nil || !reflect.DeepEqual(got, BackupCompletionReceipt{}) {
					t.Fatal("unanchored completion returned", mode, reads, err)
				}
				if mode == "late_rehash" && reads != 2 {
					t.Fatal("late read fixture missed")
				}
			})
		})
	}
}
