package repository

import (
	"errors"
	"reflect"
	"testing"

	"model-integrity-inspector.local/mii/migrations"
)

func TestDisplayEvidenceMigrationExpandsExistingHistoryAndRollsBackFailedDDL(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		set, err := migrations.ForDialect(store.driver)
		if err != nil || len(set) < 16 || set[15].Name != "evidence_display" {
			t.Fatal("missing display migration")
		}
		if err := store.migrate(t.Context(), set[:15]); err != nil {
			t.Fatal("apply existing migrations")
		}
		var before []SchemaVersion
		if err := store.db.Table("schema_migrations").Order("version").Find(&before).Error; err != nil || len(before) != 15 {
			t.Fatal("read prior migration history")
		}
		if store.db.Migrator().HasTable("integrity_display_evidence") {
			t.Fatal("display table existed in legacy migration prefix")
		}
		// Inject after the real migration's DDL, so rollback must undo the new
		// table/indexes and preserve the existing 15 immutable ledger rows.
		bad := append([]migrations.Migration(nil), set[:16]...)
		bad[15].SQL += "\nINSERT INTO missing_display_upgrade_fixture (id) VALUES (1);\n"
		if err := store.migrate(t.Context(), bad); !errors.Is(err, ErrMigrationFailed) {
			t.Fatal("failed display upgrade accepted")
		}
		if store.db.Migrator().HasTable("integrity_display_evidence") {
			t.Fatal("display DDL survived failed upgrade")
		}
		var after []SchemaVersion
		if err := store.db.Table("schema_migrations").Order("version").Find(&after).Error; err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("failed display upgrade rewrote old migration history")
		}
		if err := store.Migrate(t.Context()); err != nil {
			t.Fatal("retry actual immutable migration", err)
		}
		if err := store.CheckSchema(t.Context()); err != nil {
			t.Fatal("upgraded schema not ready")
		}
		var current []SchemaVersion
		if err := store.db.Table("schema_migrations").Where("version <= 15").Order("version").Find(&current).Error; err != nil || !reflect.DeepEqual(before, current) {
			t.Fatal("display upgrade changed earlier migrations")
		}
		var count int64
		if err := store.db.Model(&DisplayEvidenceRecord{}).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("migration invented display rows")
		}
		for _, index := range []string{"integrity_display_evidence_expiry", "integrity_display_evidence_run"} {
			if !store.db.Migrator().HasIndex(&DisplayEvidenceRecord{}, index) {
				t.Fatal("missing bounded display lookup/expiry index")
			}
		}
	})
}
