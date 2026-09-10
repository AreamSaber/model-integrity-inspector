package repository

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/migrations"
)

func TestResponseRetentionMigrationPreservesExistingSettingsAndDDLIsAtomic(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		set, err := migrations.ForDialect(s.driver)
		if err != nil || len(set) < 17 || set[16].Name != "response_retention" {
			t.Fatal("retention migration not registered")
		}
		if err := s.migrate(t.Context(), set[:16]); err != nil {
			t.Fatal("apply existing 16-version history")
		}
		stamp := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		for i, days := range []int{0, 7} {
			if err := s.db.Exec("INSERT INTO organizations (id,name,status,timezone,quota_json,created_at,updated_at,full_response_retention_days,version) VALUES (?,?,?,?,?,?,?,?,?)", i+1, "synthetic legacy retention", "active", "UTC", "{}", stamp, stamp, days, 3).Error; err != nil {
				t.Fatal("create prior-schema settings")
			}
		}
		type oldOrganization struct {
			ID                                 int64
			Name, Status, Timezone, QuotaJSON  string
			CreatedAt, UpdatedAt               time.Time
			FullResponseRetentionDays, Version int
		}
		var oldRows []oldOrganization
		// Freeze the legacy projection across additive DDL: a prepared SELECT *
		// changes PostgreSQL's result shape and fails before comparing any data.
		const oldColumns = "id,name,status,timezone,quota_json,created_at,updated_at,full_response_retention_days,version"
		if err := s.db.Table("organizations").Select(oldColumns).Order("id").Find(&oldRows).Error; err != nil {
			t.Fatal(err)
		}
		var before []SchemaVersion
		if err := s.db.Table("schema_migrations").Order("version").Find(&before).Error; err != nil || len(before) != 16 {
			t.Fatal("read old migration history")
		}
		bad := append([]migrations.Migration(nil), set[:17]...)
		bad[16].SQL += "\nINSERT INTO absent_retention_migration_fixture (id) VALUES (1);\n"
		if err := s.migrate(t.Context(), bad); !errors.Is(err, ErrMigrationFailed) {
			t.Fatal("bad retention upgrade succeeded")
		}
		if s.db.Migrator().HasColumn(&Organization{}, "response_evidence_not_before_micros") {
			t.Fatal("failed upgrade left cutoff column")
		}
		var guards int64
		query := "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name='integrity_response_retention_monotonic'"
		if s.driver == "postgres" {
			query = "SELECT count(*) FROM pg_proc WHERE proname='integrity_response_retention_monotonic_guard' AND pronamespace=current_schema()::regnamespace"
		}
		if err := s.db.Raw(query).Scan(&guards).Error; err != nil || guards != 0 {
			t.Fatal("failed upgrade left policy trigger/function")
		}
		var after []SchemaVersion
		if err := s.db.Table("schema_migrations").Order("version").Find(&after).Error; err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("failed upgrade rewrote schema history")
		}
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal("retry actual retention migration", err)
		}
		if err := s.CheckSchema(t.Context()); err != nil {
			t.Fatal(err)
		}
		var newRows []oldOrganization
		if err := s.db.Table("organizations").Select(oldColumns).Order("id").Find(&newRows).Error; err != nil || !reflect.DeepEqual(oldRows, newRows) {
			t.Fatal("retention expansion changed old organization data")
		}
		var orgs []Organization
		if err := s.db.Order("id").Find(&orgs).Error; err != nil || len(orgs) != 2 {
			t.Fatal("read upgraded organizations")
		}
		for _, org := range orgs {
			if org.ResponseEvidenceNotBeforeMicros != 0 {
				t.Fatal("migration invented a historical cutoff")
			}
		}
		var current []SchemaVersion
		if err := s.db.Table("schema_migrations").Where("version<=16").Order("version").Find(&current).Error; err != nil || !reflect.DeepEqual(before, current) {
			t.Fatal("successful expansion altered old checksum/status/time")
		}
		if err := s.db.Raw(query).Scan(&guards).Error; err != nil || guards != 1 {
			t.Fatal("monotonic database guard missing after upgrade")
		}
	})
}
