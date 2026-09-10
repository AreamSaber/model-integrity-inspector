package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func TestBackupDrainExecutionActualSuppressedUpdatesRollback(t *testing.T) {
	for _, fault := range []struct{ name, table, predicate string }{
		{"job", "integrity_jobs", "OLD.status='pending' AND NEW.status='failed'"},
		{"attempt", "integrity_sample_attempts", "OLD.status='DISPATCHED' AND NEW.status='UNCERTAIN'"},
		{"sample", "integrity_logical_samples", "OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL"},
		{"budget", "integrity_runs", "NEW.token_count<>OLD.token_count"},
		{"probe", "integrity_probe_instances", "NEW.status='COMPLETED'"},
		{"head", "integrity_audit_chain_heads", "NEW.event_count>OLD.event_count"},
	} {
		t.Run(fault.name, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
				tenant, freeze, candidate, _, _, _ := backupDrainExecutionFixture(t, s, "pending", true)
				source, err := freeze.LoadBackupExecutionSource(tenant.ctx, candidate)
				if err != nil {
					t.Fatal(err)
				}
				before := reconciliationAtomicRows(t, s)
				statements := []string{"CREATE TRIGGER backup_execution_ignore BEFORE UPDATE ON " + fault.table + " WHEN " + fault.predicate + " BEGIN SELECT RAISE(IGNORE); END"}
				if cfg.Driver == "postgres" {
					statements = []string{"CREATE FUNCTION backup_execution_ignore_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$", "CREATE TRIGGER backup_execution_ignore BEFORE UPDATE ON " + fault.table + " FOR EACH ROW WHEN (" + fault.predicate + ") EXECUTE FUNCTION backup_execution_ignore_update()"}
				}
				for _, query := range statements {
					if err := s.db.Exec(query).Error; err != nil {
						t.Fatal("install fixed fault", err)
					}
				}
				got, err := freeze.ApplyBackupExecutionSource(tenant.ctx, source, nil)
				if err == nil || got != "" {
					t.Fatal("suppressed update falsely committed", got, err)
				}
				if !reflect.DeepEqual(before, reconciliationAtomicRows(t, s)) {
					t.Fatal("fault left partial job/domain/audit")
				}
				drop := "DROP TRIGGER backup_execution_ignore"
				if cfg.Driver == "postgres" {
					drop += " ON " + fault.table
				}
				if err := s.db.Exec(drop).Error; err != nil {
					t.Fatal(err)
				}
				if cfg.Driver == "postgres" {
					if err := s.db.Exec("DROP FUNCTION backup_execution_ignore_update()").Error; err != nil {
						t.Fatal(err)
					}
				}
				if got, err := freeze.ApplyBackupExecutionSource(tenant.ctx, source, nil); err != nil || got != ReconciliationApplied {
					t.Fatal("actual source could not apply after rollback", got, err)
				}
			})
		})
	}
}

func TestBackupDrainExecutionBoundedMetadataBeforeTypedRead(t *testing.T) {
	for _, field := range []struct{ table, column string }{
		{"integrity_runs", "error_summary"}, {"integrity_logical_samples", "failure_code"}, {"integrity_sample_attempts", "tokenizer_quality"},
	} {
		t.Run(field.table, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				tenant, freeze, candidate, _, run, samples := backupDrainExecutionFixture(t, s, "pending", true)
				id := run.ID
				if field.table == "integrity_logical_samples" {
					id = samples[0].ID
				}
				if field.table == "integrity_sample_attempts" {
					var ids []int64
					if err := s.db.Table(field.table).Select("id").Find(&ids).Error; err != nil || len(ids) != 1 {
						t.Fatal("actual attempt", err)
					}
					id = ids[0]
				}
				if err := s.db.Table(field.table).Where("id=?", id).Update(field.column, strings.Repeat("private-metadata-canary", 50000)).Error; err != nil {
					t.Fatal(err)
				}
				read := false
				callback := "backup_execution_bound_before_typed"
				if err := s.db.Callback().Query().Before("gorm:query").Register(callback, func(db *gorm.DB) {
					switch db.Statement.Dest.(type) {
					case *RunRecord, *LogicalSampleRecord, *[]AttemptRecord:
						read = true
					}
				}); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = s.db.Callback().Query().Remove(callback) }()
				got, err := freeze.LoadBackupExecutionSource(tenant.ctx, candidate)
				if !errors.Is(err, ErrBackupDrainUnsupported) || got != nil || read {
					t.Fatal("metadata crossed typed reader before bound", read, err)
				}
			})
		})
	}
}

func TestBackupDrainExecutionLateAuditFailureAndCancellationRollback(t *testing.T) {
	for _, mode := range []string{"audit", "cancel", "session"} {
		t.Run(mode, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				tenant, freeze, candidate, _, _, _ := backupDrainExecutionFixture(t, s, "expired", true)
				source, err := freeze.LoadBackupExecutionSource(tenant.ctx, candidate)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(tenant.ctx)
				defer cancel()
				expires := time.Now().UTC().Add(350 * time.Millisecond)
				if mode == "session" {
					if err := s.db.Model(&Session{}).Where("id=?", freeze.auth.SessionID).Update("expires_at", expires).Error; err != nil {
						t.Fatal(err)
					}
				}
				before := reconciliationAtomicRows(t, s)
				entered := false
				callback := "backup_execution_late_audit"
				if err := s.db.Callback().Create().After("gorm:create").Register(callback, func(db *gorm.DB) {
					event, ok := db.Statement.Dest.(*audit.Event)
					if !ok || !strings.HasPrefix(event.Action, "system.backup.drain.execution.") || db.Error != nil {
						return
					}
					entered = true
					switch mode {
					case "audit":
						_ = db.AddError(errors.New("private-late-canary"))
					case "cancel":
						cancel()
					case "session":
						if !time.Now().Before(expires) {
							_ = db.AddError(errors.New("failed to enter original window"))
							return
						}
						timer := time.NewTimer(time.Until(expires) + 20*time.Millisecond)
						defer timer.Stop()
						select {
						case <-timer.C:
						case <-db.Statement.Context.Done():
							_ = db.AddError(db.Statement.Context.Err())
						}
					}
				}); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = s.db.Callback().Create().Remove(callback) }()
				got, err := freeze.ApplyBackupExecutionSource(ctx, source, nil)
				want := ErrUnavailable
				if mode == "cancel" {
					want = context.Canceled
				}
				if mode == "session" {
					want = ErrManagementSession
				}
				if !entered || !errors.Is(err, want) || got != "" {
					t.Fatal("late failure committed", entered, got, err)
				}
				if !reflect.DeepEqual(before, reconciliationAtomicRows(t, s)) {
					t.Fatal("late failure left partial facts")
				}
			})
		})
	}
}

func TestBackupDrainExecutionActualAuthorityRevokedAfterLoad(t *testing.T) {
	for _, mode := range []string{"session", "admin", "user"} {
		t.Run(mode, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
				tenant, freeze, candidate, _, _, _ := backupDrainExecutionFixture(t, s, "pending", true)
				source, err := freeze.LoadBackupExecutionSource(tenant.ctx, candidate)
				if err != nil {
					t.Fatal(err)
				}
				other, err := Open(t.Context(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = other.Close() }()
				want := ErrManagementSession
				switch mode {
				case "session":
					err = other.db.Model(&Session{}).Where("id=?", freeze.auth.SessionID).UpdateColumn("revoked_at", time.Now().UTC()).Error
				case "admin":
					err = other.db.Model(&User{}).Where("id=?", freeze.auth.UserID).UpdateColumn("is_system_admin", false).Error
					want = ErrManagementPermission
				case "user":
					err = other.db.Model(&User{}).Where("id=?", freeze.auth.UserID).UpdateColumn("status", "disabled").Error
				}
				if err != nil {
					t.Fatal(err)
				}
				before := reconciliationAtomicRows(t, s)
				if got, err := freeze.ApplyBackupExecutionSource(tenant.ctx, source, nil); got != "" || !errors.Is(err, want) {
					t.Fatal("stale captured authorization accepted", got, err)
				}
				if !reflect.DeepEqual(before, reconciliationAtomicRows(t, s)) {
					t.Fatal("revoked authority changed facts")
				}
			})
		})
	}
}

func TestBackupDrainExecutionSourceOwnershipMutationAndStale(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, freeze, candidate, _, _, _ := backupDrainExecutionFixture(t, s, "pending", true)
		source, err := freeze.LoadBackupExecutionSource(tenant.ctx, candidate)
		if err != nil {
			t.Fatal(err)
		}
		if err := source.Use(func(data ExecutionReconciliationData) error {
			data.Plan.Probes[0].Samples[0].Request.Messages[0].Content = "private-mutation-canary"
			*data.Sample.JobID = -1
			data.Attempt.RequestSnapshot = "private-mutation-canary"
			*data.Attempt.StartedAt = time.Time{}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := source.Use(func(data ExecutionReconciliationData) error {
			if *data.Sample.JobID <= 0 || data.Attempt.StartedAt.IsZero() || strings.Contains(data.Attempt.RequestSnapshot, "canary") || data.Plan.Probes[0].Samples[0].Request.Messages[0].Content == "private-mutation-canary" {
				t.Fatal("borrow mutated owned source")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		for _, verb := range []string{"%v", "%+v", "%#v", "%q"} {
			if strings.Contains(fmt.Sprintf(verb, source), source.source.owner) {
				t.Fatal("source leaked")
			}
		}
		if _, err := json.Marshal(source); err == nil {
			t.Fatal("source serialized")
		}
		foreign := *source
		foreign.source.operationID++
		if got, err := freeze.ApplyBackupExecutionSource(tenant.ctx, &foreign, nil); !errors.Is(err, ErrBackupDrainSource) || got != "" {
			t.Fatal("foreign operation", err)
		}
		if err := s.db.Model(&Job{}).Where("id=?", source.data.Job.ID).Update("last_error_code", "JOB_CHANGED").Error; err != nil {
			t.Fatal(err)
		}
		before := reconciliationAtomicRows(t, s)
		if got, err := freeze.ApplyBackupExecutionSource(tenant.ctx, source, nil); !errors.Is(err, ErrBackupDrainStale) || got != "" {
			t.Fatal("stale original job", err)
		}
		if !reflect.DeepEqual(before, reconciliationAtomicRows(t, s)) {
			t.Fatal("stale source wrote")
		}
	})
}
