package repository

import (
	"errors"
	"reflect"
	"testing"

	"model-integrity-inspector.local/mii/migrations"
)

func TestEvidenceDisplayReadMigrationPreservesHistoryAndRollsBackDDL(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, config Config) {
		list, err := migrations.ForDialect(config.Driver)
		if err != nil || len(list) < 19 {
			t.Fatal("migration19 absent", err)
		}
		list = list[:19]
		if err := store.migrate(t.Context(), list[:18]); err != nil {
			t.Fatal(err)
		}
		orgID := derivedUpgradeLegacyRows(t, store)
		var beforeDisplay []DisplayEvidenceRecord
		var beforeRaw []ResponseEvidenceRecord
		if err := store.db.Where("organization_id=?", orgID).Order("attempt_id").Find(&beforeDisplay).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.db.Where("organization_id=?", orgID).Order("attempt_id").Find(&beforeRaw).Error; err != nil {
			t.Fatal(err)
		}
		broken := append([]migrations.Migration(nil), list...)
		broken[18].SQL += "\nSELECT * FROM display_migration_forced_missing_table;"
		if err := store.migrate(t.Context(), broken); !errors.Is(err, ErrMigrationFailed) {
			t.Fatal("failed migration19 accepted", err)
		}
		if store.db.Migrator().HasTable("integrity_evidence_disclosures") {
			t.Fatal("failed migration19 left receipt table")
		}
		var count int64
		if err := store.db.Table("schema_migrations").Count(&count).Error; err != nil || count != 18 {
			t.Fatal("failed migration19 advanced ledger", err)
		}
		if config.Driver == "postgres" {
			if err := store.db.Raw("SELECT COUNT(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=current_schema() AND p.proname='integrity_evidence_disclosure_immutable_guard'").Scan(&count).Error; err != nil || count != 0 {
				t.Fatal("failed migration19 left function", err)
			}
		} else {
			if err := store.db.Raw("SELECT COUNT(*) FROM sqlite_master WHERE name IN ('integrity_evidence_disclosure_immutable','integrity_evidence_disclosure_no_delete')").Scan(&count).Error; err != nil || count != 0 {
				t.Fatal("failed migration19 left triggers", err)
			}
		}
		if err := store.migrate(t.Context(), list); err != nil {
			t.Fatal("retry migration19", err)
		}
		var afterDisplay []DisplayEvidenceRecord
		var afterRaw []ResponseEvidenceRecord
		if err := store.db.Where("organization_id=?", orgID).Order("attempt_id").Find(&afterDisplay).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.db.Where("organization_id=?", orgID).Order("attempt_id").Find(&afterRaw).Error; err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(beforeDisplay, afterDisplay) || !reflect.DeepEqual(beforeRaw, afterRaw) {
			t.Fatal("migration19 rewrote historical envelope")
		}
		if err := store.db.Model(&evidenceDisclosureReceipt{}).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("migration invented past disclosure", err)
		}
	})
}
