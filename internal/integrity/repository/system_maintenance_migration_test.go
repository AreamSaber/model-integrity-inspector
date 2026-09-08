package repository

import (
	"errors"
	"reflect"
	"testing"

	"model-integrity-inspector.local/mii/migrations"
)

func TestSystemMaintenanceMigration21RollbackAndHistoricalChecksums(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		list, err := migrations.ForDialect(cfg.Driver)
		if err != nil || len(list) < 21 || list[20].Name != "system_maintenance" {
			t.Fatal("migration21 absent", err)
		}
		if err := s.migrate(t.Context(), list[:20]); err != nil {
			t.Fatal(err)
		}
		var before []SchemaVersion
		if err := s.db.Table("schema_migrations").Order("version").Find(&before).Error; err != nil || len(before) != 20 {
			t.Fatal("read original migration history", err)
		}
		broken := append([]migrations.Migration(nil), list[:21]...)
		broken[20].SQL += "\nSELECT * FROM maintenance_migration_forced_missing_table;"
		if err := s.migrate(t.Context(), broken); !errors.Is(err, ErrMigrationFailed) {
			t.Fatal("broken migration21 committed", err)
		}
		for _, table := range []string{"system_maintenance", "system_maintenance_operations", "system_maintenance_events"} {
			if s.db.Migrator().HasTable(table) {
				t.Fatal("failed migration21 left partial table", table)
			}
		}
		var after []SchemaVersion
		if err := s.db.Table("schema_migrations").Order("version").Find(&after).Error; err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("failed migration21 modified original twenty ledger rows", err)
		}
		if err := s.migrate(t.Context(), list[:21]); err != nil {
			t.Fatal("actual migration21 retry", err)
		}
		var original []SchemaVersion
		if err := s.db.Table("schema_migrations").Where("version<=20").Order("version").Find(&original).Error; err != nil || !reflect.DeepEqual(before, original) {
			t.Fatal("successful migration21 modified historical checksums", err)
		}
		assertMaintenanceNoOperation(t, s, t.Context())
		for _, index := range []string{"system_maintenance_operation_generation", "system_maintenance_operation_history"} {
			if !s.db.Migrator().HasIndex(&maintenanceOperation{}, index) {
				t.Fatal("missing bounded maintenance source index", index)
			}
		}
		if !s.db.Migrator().HasIndex("integrity_audit_logs", "system_maintenance_audit_source") {
			t.Fatal("missing bounded authenticated-audit lookup index")
		}
	})
}
