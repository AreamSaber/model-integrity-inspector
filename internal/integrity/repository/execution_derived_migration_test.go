package repository

import (
	"bytes"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/migrations"
)

// Fixed schema17 initialization seed, not an alternate production admission
// path. The migration fixtures have no bootstrap bundle configuration. Keep the
// original identities, grants, setup settings and signed initialization fact.
func derivedUpgradeLegacyInitialization(t *testing.T, store *Store) InitializationResult {
	t.Helper()
	if store.bootstrap != nil {
		t.Fatal("historical fixture requires no bootstrap bundle configuration")
	}
	const org, user, member int64 = 7001, 7002, 7003
	stamp := time.Date(2026, 9, 1, 0, 0, 0, 123000, time.UTC)
	ctx := testActorContext(t, 0)
	if err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, seed := range []struct {
			table string
			row   map[string]any
		}{
			{"organizations", map[string]any{"id": org, "name": "Example", "status": "active", "timezone": "UTC", "quota_json": "{}", "created_at": stamp, "updated_at": stamp}},
			{"users", map[string]any{"id": user, "username": "Admin", "username_normalized": "admin", "password_hash": "test-only-argon2-placeholder", "status": "active", "is_system_admin": true, "password_changed_at": stamp, "created_at": stamp, "updated_at": stamp}},
			{"organization_members", map[string]any{"id": member, "organization_id": org, "user_id": user, "status": "active", "created_at": stamp, "updated_at": stamp}},
			{"roles", map[string]any{"id": int64(7010), "organization_id": org, "name": "administrator", "description": "", "is_builtin": true, "created_at": stamp}},
			{"roles", map[string]any{"id": int64(7011), "organization_id": org, "name": "viewer", "description": "", "is_builtin": true, "created_at": stamp}},
		} {
			if err := tx.Table(seed.table).Create(seed.row).Error; err != nil {
				return err
			}
		}
		for _, permission := range []string{"target.read", "target.write", "run.create"} {
			if err := tx.Exec("INSERT INTO permissions (code, description) VALUES (?, '')", permission).Error; err != nil {
				return err
			}
			if err := tx.Exec("INSERT INTO role_permissions (organization_id, role_id, permission_code) VALUES (?, ?, ?)", org, 7010, permission).Error; err != nil {
				return err
			}
		}
		if err := tx.Exec("INSERT INTO role_permissions (organization_id, role_id, permission_code) VALUES (?, ?, ?)", org, 7011, "target.read").Error; err != nil {
			return err
		}
		if err := tx.Exec("INSERT INTO member_roles (organization_id, member_id, role_id) VALUES (?, ?, ?)", org, member, 7010).Error; err != nil {
			return err
		}
		for key, value := range map[string]string{"initialized": "true", "initial_organization_id": strconv.FormatInt(org, 10)} {
			if err := tx.Exec("INSERT INTO system_settings (setting_key, value_json, version, updated_at) VALUES (?, ?, 1, ?)", key, value, stamp).Error; err != nil {
				return err
			}
		}
		actor := user
		return store.appendAudit(ctx, tx, org, auditObject("system.initialize", "organization", org), &actor)
	}); err != nil {
		t.Fatal("seed historical initialization", err)
	}
	var result InitializationResult
	if err := store.db.Where("id=?", org).Take(&result.Organization).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.db.Where("id=?", user).Take(&result.User).Error; err != nil {
		t.Fatal(err)
	}
	return result
}

// Build real rows on schema 17, without asking current-model helpers to create
// newer columns. Ciphertext is structural fixture data, never re-encrypted.
func derivedUpgradeLegacyRows(t *testing.T, store *Store) int64 {
	t.Helper()
	initial := derivedUpgradeLegacyInitialization(t, store)
	auth := managementSession(t, store, initial.User)
	ctx := bindTargetTestSession(t, store, testActorContext(t, initial.User.ID), auth.SessionID, initial.Organization.ID)
	stamp := time.Date(2026, 9, 1, 0, 0, 0, 123000, time.UTC)
	org := initial.Organization.ID
	// This is deliberately a schema17 historical fixture. Current business
	// CRUD requires migration21's admission gate and must reject its absence.
	// Seed only the old column set in a test-owned short transaction, preserving
	// the original structural ciphertext and both signed creation audit facts.
	credential := encryptedFixture(t, org)
	targetID, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		secretRow := map[string]any{"id": credential.ID, "organization_id": org, "encrypted_data_key": credential.EncryptedDataKey, "ciphertext": credential.Ciphertext, "nonce": credential.Nonce, "key_version": credential.KeyVersion, "payload_key_version": credential.PayloadKeyVersion, "secret_version": credential.SecretVersion, "fingerprint": credential.Fingerprint, "last_four": credential.LastFour, "created_at": stamp}
		if err := tx.Table("integrity_secrets").Create(secretRow).Error; err != nil {
			return err
		}
		targetRow := map[string]any{"id": targetID, "organization_id": org, "name": "target", "endpoint": "https://upstream.example/v1", "endpoint_fingerprint": strings.Repeat("b", 64), "protocol": "openai_chat", "model": "served-model", "auth_type": "bearer", "status": "active", "tags_json": "[]", "options_json": `{"tls_verify":true}`, "secret_id": credential.ID, "version": 1, "created_by": initial.User.ID, "updated_by": initial.User.ID, "created_at": stamp, "updated_at": stamp}
		if err := tx.Table("integrity_targets").Create(targetRow).Error; err != nil {
			return err
		}
		if err := store.appendAudit(ctx, tx, org, auditObject("secret.create", "secret", credential.ID), nil); err != nil {
			return err
		}
		return store.appendAudit(ctx, tx, org, auditObject("target.create", "target", targetID), nil)
	}); err != nil {
		t.Fatal("seed old-schema target and signed audit", err)
	}
	for _, id := range []int64{1, 6} {
		status := "ANALYZING"
		if id == 6 {
			status = "QUEUED"
		}
		row := map[string]any{"id": id, "organization_id": org, "target_id": targetID, "package": "custom", "status": status, "config_snapshot": "{\"legacy_fixture\":true}", "manifest_hash": strings.Repeat("a", 64), "rule_bundle_version": "1", "template_bundle_version": "1", "scoring_version": "1", "tokenizer_bundle_version": "1", "request_budget": 50, "token_budget": 1000, "created_by": initial.User.ID, "created_at": stamp}
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
