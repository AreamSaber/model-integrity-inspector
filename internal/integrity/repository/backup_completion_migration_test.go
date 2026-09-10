package repository

import (
	"errors"
	"reflect"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/migrations"
)

func TestBackupCompletionMigration22PreservesPopulatedHistoryAndRollback(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		list, err := migrations.ForDialect(cfg.Driver)
		if err != nil || len(list) < 22 || list[21].Name != "backup_completion" {
			t.Fatal("migration22 missing", err)
		}
		if err := s.migrate(t.Context(), list[:21]); err != nil {
			t.Fatal(err)
		}
		initial := requireInitialize(t, s)
		auth := managementSession(t, s, initial.User)
		ctx := testActorContext(t, initial.User.ID)
		first := beginTestMaintenance(t, s, ctx, auth)
		if err := first.Abort(ctx); err != nil {
			t.Fatal(err)
		}
		active := beginTestMaintenance(t, s, ctx, auth)
		type history struct {
			Versions   []SchemaVersion
			Operations []maintenanceOperation
			Events     []maintenanceEvent
			Audits     []audit.Event
			State      maintenanceState
		}
		read := func() history {
			var got history
			for _, entry := range []struct {
				table, order string
				dest         any
			}{{"schema_migrations", "version", &got.Versions}, {"system_maintenance_operations", "id", &got.Operations}, {"system_maintenance_events", "operation_id,sequence", &got.Events}, {"integrity_audit_logs", "id", &got.Audits}, {"system_maintenance", "id", &got.State}} {
				q := s.db.Table(entry.table).Order(entry.order)
				if entry.table == "schema_migrations" {
					q = q.Where("version<=21")
				}
				if err := q.Find(entry.dest).Error; err != nil {
					t.Fatal("history read", entry.table, err)
				}
			}
			return got
		}
		before := read()
		broken := append([]migrations.Migration(nil), list[:22]...)
		broken[21].SQL += "\nSELECT * FROM backup_completion_forced_missing_table;"
		if err := s.migrate(t.Context(), broken); !errors.Is(err, ErrMigrationFailed) {
			t.Fatal("broken migration committed", err)
		}
		if s.db.Migrator().HasTable("system_backup_receipts") {
			t.Fatal("failed migration left receipt table")
		}
		if got := read(); !reflect.DeepEqual(before, got) {
			t.Fatal("migration rollback changed historical facts")
		}
		if _, err := active.Observe(ctx); err != nil {
			t.Fatal("rollback broke original active capability", err)
		}
		if err := s.migrate(t.Context(), list[:22]); err != nil {
			t.Fatal("real populated upgrade", err)
		}
		if got := read(); !reflect.DeepEqual(before, got) {
			t.Fatal("upgrade rewrote original checksums, events, audit or singleton")
		}
		for _, op := range before.Operations {
			if _, err := s.verifyMaintenanceOperation(s.db, op); err != nil {
				t.Fatal("historical event failed authentication", err)
			}
		}
		if cfg.Driver == "sqlite" {
			var violations []struct {
				Table  string
				Rowid  int64
				Parent string
				Fkid   int64
			}
			if err := s.db.Raw("PRAGMA foreign_key_check").Scan(&violations).Error; err != nil || len(violations) != 0 {
				t.Fatal("rebuilt foreign keys invalid", err)
			}
		}
		got, err := active.CompleteBackup(ctx, testBackupPublication(t, active))
		if err != nil {
			t.Fatal("pre-upgrade lease cannot complete after upgrade", err)
		}
		invalid := got
		invalid.BackupID++
		invalid.ObjectID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
		if err := s.db.Create(&invalid).Error; err == nil {
			t.Fatal("receipt foreign key lost during rebuild")
		}
		if err := s.db.Model(&maintenanceOperation{}).Where("id=?", first.operationID).Update("status", "active").Error; err == nil {
			t.Fatal("old terminal guard lost")
		}
		if err := s.VerifyAllAudit(ctx, true); err != nil {
			t.Fatal("post-upgrade full audit failed", err)
		}
	})
}
