package repository

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/migrations"
)

func TestSnapshotArtifactReferencesNativeLegacyBaselineRevision(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		set, err := migrations.ForDialect(s.driver)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.migrate(t.Context(), set[:11]); err != nil {
			t.Fatal(err)
		}
		initial := derivedUpgradeLegacyInitialization(t, s)
		org, user := initial.Organization.ID, initial.User.ID
		stamp := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		credential := encryptedFixture(t, org)
		if err := s.db.Create(&credential).Error; err != nil {
			t.Fatal(err)
		}
		snapshotJobTestInsert(t, s, "integrity_targets", map[string]any{"id": 100, "organization_id": org, "name": "legacy", "endpoint": "https://legacy.example/v1", "endpoint_fingerprint": strings.Repeat("a", 64), "protocol": "openai_chat", "model": "legacy", "auth_type": "bearer", "status": "disabled", "tags_json": "[]", "options_json": "{}", "secret_id": credential.ID, "version": 1, "created_by": user, "updated_by": user, "created_at": stamp, "updated_at": stamp})
		snapshotJobTestInsert(t, s, "integrity_runs", map[string]any{"id": 101, "organization_id": org, "target_id": 100, "package": "custom", "status": "COMPLETED", "config_snapshot": `{"legacy_fixture":true}`, "manifest_hash": strings.Repeat("a", 64), "rule_bundle_version": "1", "template_bundle_version": "1", "scoring_version": "1", "tokenizer_bundle_version": "1", "request_budget": 50, "token_budget": 1000, "created_by": user, "created_at": stamp})
		revisions := []int64{1, 2147483647}
		if s.driver == "sqlite" {
			revisions = append(revisions, 2147483648, 9223372036854775807)
		}
		for i, revision := range revisions {
			snapshotJobTestInsert(t, s, "integrity_run_results", map[string]any{"organization_id": org, "run_id": 101, "analysis_revision": revision, "confidence": 0, "risk_level": "insufficient", "evidence_grade": "D", "completeness": "INSUFFICIENT", "conclusion_json": "{}", "is_published": false, "created_at": stamp})
			snapshotJobTestInsert(t, s, "integrity_baselines", map[string]any{"id": 200 + i, "organization_id": org, "run_id": 101, "analysis_revision": revision, "name": "legacy", "model": "legacy", "protocol": "openai_chat", "status": "approved", "applicable_scope_json": "{}", "created_at": stamp, "expires_at": stamp})
		}
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal("actual schema11 expansion", err)
		}
		var before []map[string]any
		if err := s.db.Table("integrity_baselines").Order("id").Find(&before).Error; err != nil {
			t.Fatal(err)
		}
		got := snapshotReferenceTestObserve(t, s, cfg, nil)
		if got.observed != [3]int64{1, 0, int64(len(revisions))} || got.legacy != [3]int64{1, 0, int64(len(revisions))} || got.classification != snapshotReferenceLegacyIncomplete || len(got.references) != 4 {
			t.Fatal("native retained revision lost or unsigned legacy promoted")
		}
		var after []map[string]any
		if err := s.db.Table("integrity_baselines").Order("id").Find(&after).Error; err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("read-only history observation rewrote original fields", err)
		}
		var retained []int64
		if err := s.db.Table("integrity_baselines").Order("id").Pluck("analysis_revision", &retained).Error; err != nil || !reflect.DeepEqual(retained, revisions) {
			t.Fatal("native revision was truncated", err)
		}
	})
}

func TestSnapshotArtifactReferencesNativeModernBaselineRevision(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, run, _, baselines := snapshotReferenceTestFixture(t, s, nil)
		maximum := int64(2147483647)
		if s.driver == "sqlite" {
			maximum = 9223372036854775807
		}
		// Storage-only retained scope, not a claim that the baseline service
		// authenticated this fixture's MAC or analyzer emitted this revision.
		var result RunResultRecord
		if err := s.db.Where("organization_id=? AND run_id=?", tenant.orgID, run.ID).Take(&result).Error; err != nil {
			t.Fatal(err)
		}
		result.AnalysisRevision = int(maximum)
		if err := s.db.Create(&result).Error; err != nil {
			t.Fatal(err)
		}
		for _, baseline := range baselines {
			var scope BaselineScope
			if err := json.Unmarshal([]byte(baseline.SnapshotJSON), &scope); err != nil {
				t.Fatal(err)
			}
			scope.AnalysisRevision = int(maximum)
			raw, err := baselineJSON(scope)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.db.Model(&BaselineRecord{}).Where("id=?", baseline.ID).Updates(map[string]any{"analysis_revision": maximum, "snapshot_json": raw, "snapshot_hash": baselineHash([]byte(raw))}).Error; err != nil {
				t.Fatal(err)
			}
		}
		got := snapshotReferenceTestObserve(t, s, cfg, nil)
		if got.observed != [3]int64{1, 1, 4} || got.legacy != [3]int64{} || len(got.references) != 5 {
			t.Fatal("modern retained source lost native revision")
		}
		// A different physically present revision must not satisfy the original
		// canonical scope's revision just because both values are now in range.
		if err := s.db.Model(&BaselineRecord{}).Where("id=?", baselines[0].ID).UpdateColumn("analysis_revision", 1).Error; err != nil {
			t.Fatal(err)
		}
		snapshotReferenceTestObserve(t, s, cfg, errSnapshotReferenceInvalid)
	})
}
