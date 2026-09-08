package repository

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/migrations"
)

// Build real rows on schema 17, without asking current-model helpers to create
// newer columns. Ciphertext is structural fixture data, never re-encrypted.
func derivedUpgradeLegacyRows(t *testing.T, store *Store) int64 {
	t.Helper()
	initial, err := store.Initialize(testActorContext(t, 0), initialState())
	if err != nil {
		t.Fatal("initialize old schema", err)
	}
	auth := managementSession(t, store, initial.User)
	ctx := bindTargetTestSession(t, store, testActorContext(t, initial.User.ID), auth.SessionID, initial.Organization.ID)
	tenant, err := store.WithOrganization(ctx, initial.Organization.ID)
	if err != nil {
		t.Fatal(err)
	}
	target := mustCreateTarget(t, tenant)
	stamp := time.Date(2026, 9, 1, 0, 0, 0, 123000, time.UTC)
	org := initial.Organization.ID
	for _, id := range []int64{1, 6} {
		status := "ANALYZING"
		if id == 6 {
			status = "QUEUED"
		}
		row := map[string]any{"id": id, "organization_id": org, "target_id": target.Target.ID, "package": "custom", "status": status, "config_snapshot": "{\"legacy_fixture\":true}", "manifest_hash": strings.Repeat("a", 64), "rule_bundle_version": "1", "template_bundle_version": "1", "scoring_version": "1", "tokenizer_bundle_version": "1", "request_budget": 50, "token_budget": 1000, "created_by": initial.User.ID, "created_at": stamp}
		if id == 1 {
			row["started_at"], row["execution_closed_at"] = stamp, stamp
		}
		if err := store.db.Table("integrity_runs").Create(row).Error; err != nil {
			t.Fatal("seed legacy run", err)
		}
	}
	if err := store.db.Table("integrity_probe_instances").Create(map[string]any{"id": 2, "organization_id": org, "run_id": 1, "probe_type": "contract", "template_id": "fixture", "template_version": "1", "category": "format", "variant": "en", "planned_samples": 1, "status": "COMPLETED", "parameters_json": "{}", "created_at": stamp}).Error; err != nil {
		t.Fatal("seed legacy probe", err)
	}
	if err := store.db.Table("integrity_logical_samples").Create(map[string]any{"id": 3, "organization_id": org, "run_id": 1, "probe_instance_id": 2, "ordinal": 0, "idempotency_key": "legacy-fixture", "request_plan": "{}", "validity": "INVALID_RETRYABLE", "attempt_count": 2, "created_at": stamp, "completed_at": stamp}).Error; err != nil {
		t.Fatal("seed legacy sample", err)
	}
	for i, id := range []int64{4, 5} {
		if err := store.db.Table("integrity_sample_attempts").Create(map[string]any{"id": id, "organization_id": org, "run_id": 1, "logical_sample_id": 3, "attempt_no": i + 1, "status": "COMPLETED", "validity": "INVALID_RETRYABLE", "request_snapshot": "{}", "request_hash": strings.Repeat("b", 64), "error_code": "MI_TIMEOUT", "started_at": stamp, "finished_at": stamp}).Error; err != nil {
			t.Fatal("seed legacy attempt", err)
		}
	}
	if err := store.db.Table("integrity_logical_samples").Where("id = 3").Update("final_attempt_id", 5).Error; err != nil {
		t.Fatal(err)
	}
	raw := ResponseEvidenceRecord{OrganizationID: org, RunID: 1, LogicalSampleID: 3, AttemptID: 4, RequestHash: strings.Repeat("b", 64), KeyVersion: "legacy", Nonce: bytes.Repeat([]byte{1}, 12), Ciphertext: bytes.Repeat([]byte{2}, 48), PlaintextBytes: 32, ContentHash: strings.Repeat("c", 64), CreatedAt: stamp, ExpiresAt: stamp.Add(30 * 24 * time.Hour)}
	if err := store.db.Create(&raw).Error; err != nil {
		t.Fatal("seed old raw envelope", err)
	}
	display := DisplayEvidenceRecord{OrganizationID: org, RunID: 1, LogicalSampleID: 3, AttemptID: 4, RequestHash: raw.RequestHash, Policy: DisplayEvidencePolicy, State: DisplayCaptured, SourceHash: strings.Repeat("d", 64), Version: 1, KeyVersion: "legacy", Nonce: bytes.Repeat([]byte{3}, 12), Ciphertext: bytes.Repeat([]byte{4}, 48), PlaintextBytes: 32, PayloadHash: strings.Repeat("e", 64), CapturedAtMicros: stamp.UnixMicro(), ExpiresAtMicros: stamp.Add(30 * 24 * time.Hour).UnixMicro(), CreatedAt: stamp}
	if err := store.db.Create(&display).Error; err != nil {
		t.Fatal("seed old display envelope", err)
	}
	unavailable := DisplayEvidenceRecord{OrganizationID: org, RunID: 1, LogicalSampleID: 3, AttemptID: 5, RequestHash: raw.RequestHash, Policy: DisplayEvidencePolicy, State: DisplayUnavailableSeal, CreatedAt: stamp}
	if err := store.db.Create(&unavailable).Error; err != nil {
		t.Fatal("seed old unavailable display", err)
	}
	return org
}

func TestDerivedExecutionMigrationPreservesLegacyBodiesAndRollsBackDDL(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		set, err := migrations.ForDialect(store.driver)
		if err != nil || len(set) < 18 || set[17].Name != "derived_attempt_source" {
			t.Fatal("missing derived migration")
		}
		if err := store.migrate(t.Context(), set[:17]); err != nil {
			t.Fatal("migrate old schema", err)
		}
		org := derivedUpgradeLegacyRows(t, store)
		var oldDisplay []DisplayEvidenceRecord
		var oldRaw []ResponseEvidenceRecord
		var oldHistory []SchemaVersion
		if err := store.db.Order("attempt_id").Find(&oldDisplay).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.db.Order("attempt_id").Find(&oldRaw).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.db.Table("schema_migrations").Order("version").Find(&oldHistory).Error; err != nil || len(oldHistory) != 17 {
			t.Fatal("read old ledger", err)
		}
		checkBodies := func() {
			var display []DisplayEvidenceRecord
			var raw []ResponseEvidenceRecord
			if err := store.db.Order("attempt_id").Find(&display).Error; err != nil || !reflect.DeepEqual(oldDisplay, display) {
				t.Fatal("upgrade rewrote display envelope/AAD/state", err)
			}
			if err := store.db.Order("attempt_id").Find(&raw).Error; err != nil || !reflect.DeepEqual(oldRaw, raw) {
				t.Fatal("upgrade rewrote raw envelope", err)
			}
		}
		bad := append([]migrations.Migration(nil), set[:18]...)
		bad[17].SQL += "\nINSERT INTO absent_derived_upgrade_fixture (id) VALUES (1);\n"
		if err := store.migrate(t.Context(), bad); !errors.Is(err, ErrMigrationFailed) {
			t.Fatal("invalid derived upgrade succeeded")
		}
		checkBodies()
		if store.db.Migrator().HasColumn(&RunRecord{}, "analysis_source_version") || store.db.Migrator().HasTable(&AttemptDerivedRecord{}) || store.db.Migrator().HasTable("integrity_display_evidence_v16") {
			t.Fatal("failed upgrade retained partial schema")
		}
		var failedHistory []SchemaVersion
		if err := store.db.Table("schema_migrations").Order("version").Find(&failedHistory).Error; err != nil || !reflect.DeepEqual(oldHistory, failedHistory) {
			t.Fatal("failed upgrade changed old history")
		}
		var guards int64
		query := "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name IN ('integrity_run_source_immutable','integrity_derived_insert_guard','integrity_attempt_derived_insert','integrity_attempt_derived_update','integrity_attempt_source_update')"
		if store.driver == "postgres" {
			query = "SELECT count(*) FROM pg_proc WHERE pronamespace=current_schema()::regnamespace AND proname IN ('integrity_run_source_guard','integrity_derived_insert_guard_fn','integrity_attempt_derived_guard','integrity_attempt_source_update_guard')"
		}
		if err := store.db.Raw(query).Scan(&guards).Error; err != nil || guards != 0 {
			t.Fatal("failed upgrade left derived guards")
		}
		sevenDayExpiry := oldDisplay[0].CapturedAtMicros + 7*responseRetentionDayMicros
		if err := store.db.Model(&DisplayEvidenceRecord{}).Where("organization_id = ? AND attempt_id = 4", org).Update("expires_at_micros", sevenDayExpiry).Error; err == nil {
			t.Fatal("failed upgrade removed old 30-day guard")
		}
		if err := store.Migrate(t.Context()); err != nil {
			t.Fatal("retry valid derived upgrade", err)
		}
		if err := store.CheckSchema(t.Context()); err != nil {
			t.Fatal(err)
		}
		checkBodies()
		var currentHistory []SchemaVersion
		if err := store.db.Table("schema_migrations").Where("version <= 17").Order("version").Find(&currentHistory).Error; err != nil || !reflect.DeepEqual(oldHistory, currentHistory) {
			t.Fatal("upgrade changed immutable history")
		}
		var runs []RunRecord
		var attempts []AttemptRecord
		if err := store.db.Order("id").Find(&runs).Error; err != nil || len(runs) != 2 {
			t.Fatal("read legacy mode", err)
		}
		for _, run := range runs {
			if run.AnalysisSourceVersion != AnalysisSourceLegacyV1 || run.ConfigSnapshot != "{\"legacy_fixture\":true}" || run.ManifestHash != strings.Repeat("a", 64) {
				t.Fatal("migration upgraded or re-signed old run")
			}
		}
		if err := store.db.Order("id").Find(&attempts).Error; err != nil || len(attempts) != 2 {
			t.Fatal(err)
		}
		for _, attempt := range attempts {
			if attempt.DerivedReceipt != DerivedLegacy || attempt.ResponseBodyReceipt != DerivedLegacy {
				t.Fatal("migration invented old attempt proof")
			}
		}
		if err := store.db.Model(&AttemptRecord{}).Where("id = 4").Updates(map[string]any{"status": "DISPATCHED", "derived_receipt": DerivedPending}).Error; err == nil {
			t.Fatal("legacy Run accepted derived pending via UPDATE")
		}
		var count int64
		if err := store.db.Model(&AttemptDerivedRecord{}).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("migration backfilled fake S1")
		}
		for _, name := range []string{"integrity_display_evidence_expiry", "integrity_display_evidence_run"} {
			if !store.db.Migrator().HasIndex(&DisplayEvidenceRecord{}, name) {
				t.Fatal("display index lost")
			}
		}
		if err := store.db.Model(&DisplayEvidenceRecord{}).Where("organization_id = ? AND attempt_id = 4", org).Update("expires_at_micros", sevenDayExpiry).Error; err != nil {
			t.Fatal("new integer-day display guard rejected 7 days", err)
		}
		if err := store.db.Model(&DisplayEvidenceRecord{}).Where("organization_id = ? AND attempt_id = 4", org).Update("expires_at_micros", sevenDayExpiry+1).Error; err == nil {
			t.Fatal("fractional day guard weakened")
		}
		if err := store.db.Model(&DisplayEvidenceRecord{}).Where("organization_id = ? AND attempt_id = 4", org).Update("request_hash", strings.Repeat("f", 64)).Error; err == nil {
			t.Fatal("display request FK lost in table replacement")
		}
	})
}

func TestDerivedExecutionMigrationRejectsAmbiguousPostgresDisplayConstraint(t *testing.T) {
	for _, scenario := range []string{"missing", "duplicate"} {
		t.Run(scenario, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, cfg Config) {
				if cfg.Driver != "postgres" {
					t.Skip("PostgreSQL named CHECK replacement")
				}
				set, err := migrations.ForDialect(store.driver)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.migrate(t.Context(), set[:17]); err != nil {
					t.Fatal(err)
				}
				statement := "ALTER TABLE integrity_display_evidence ADD CONSTRAINT duplicate_old_duration CHECK (state <> 'captured' OR expires_at_micros - captured_at_micros = 2592000000000)"
				if scenario == "missing" {
					statement = "DO $$DECLARE n text; BEGIN SELECT conname::text INTO n FROM pg_constraint WHERE conrelid = 'integrity_display_evidence'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%2592000000000%'; EXECUTE format('ALTER TABLE integrity_display_evidence DROP CONSTRAINT %I',n); END;$$;"
				}
				if err := store.db.Exec(statement).Error; err != nil {
					t.Fatal("install altered old display schema")
				}
				if err := store.Migrate(t.Context()); !errors.Is(err, ErrMigrationFailed) {
					t.Fatal("migration accepted absent/ambiguous prior CHECK", err)
				}
				if store.db.Migrator().HasColumn(&RunRecord{}, "analysis_source_version") || store.db.Migrator().HasTable(&AttemptDerivedRecord{}) {
					t.Fatal("bad old CHECK left partial derived schema")
				}
				var count int64
				if err := store.db.Table("schema_migrations").Count(&count).Error; err != nil || count != 17 {
					t.Fatal("bad CHECK advanced migration ledger")
				}
			})
		})
	}
}
