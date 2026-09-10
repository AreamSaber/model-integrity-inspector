package repository

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/migrations"
)

func TestSnapshotResultReferencesOfflineResultCorruptionZero(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, run, _, _ := snapshotResultTestFixture(t, s)
		original := snapshotKeyTestUnconstrained(t, s, "integrity_run_results")
		reset := func() {
			for _, q := range []string{"DELETE FROM integrity_run_results", "INSERT INTO integrity_run_results SELECT * FROM " + original} {
				if err := s.db.Exec(q).Error; err != nil {
					t.Fatal(err)
				}
			}
		}
		faults := []map[string]any{{"organization_id": nil}, {"organization_id": -1}, {"organization_id": tenant.orgID + 1}, {"run_id": nil}, {"run_id": run.ID + 1}, {"analysis_revision": nil}, {"analysis_revision": 0}, {"analysis_revision": -1}, {"is_published": nil}, {"conclusion_json": nil}, {"conclusion_json": ""}, {"conclusion_json": strings.Repeat("private-body-", 400000)}, {"conclusion_json": `{"schema_version":"mii.analysis.v1","features":null}`}}
		if s.driver == "sqlite" {
			faults = append(faults, map[string]any{"analysis_revision": "not-integer"}, map[string]any{"analysis_revision": 1.5}, map[string]any{"is_published": 2}, map[string]any{"conclusion_json": []byte(`{}`)})
		}
		for i, values := range faults {
			t.Run(strconv.Itoa(i), func(t *testing.T) {
				if err := s.db.Table("integrity_run_results").Where("1=1").Updates(values).Error; err != nil {
					t.Fatal(err)
				}
				snapshotResultTestObserve(t, s, cfg, snapshotReferenceLimit, errSnapshotResultReferenceInvalid)
			})
			reset()
		}
		if err := s.db.Exec("INSERT INTO integrity_run_results SELECT * FROM " + original).Error; err != nil {
			t.Fatal(err)
		}
		snapshotResultTestObserve(t, s, cfg, snapshotReferenceLimit, errSnapshotResultReferenceInvalid)
		reset()
		if err := s.db.Table("integrity_run_results").Where("1=1").Update("conclusion_json", `[]`).Error; err != nil {
			t.Fatal(err)
		}
		snapshotResultTestObserve(t, s, cfg, snapshotReferenceLimit, errSnapshotResultReferenceUnsupported)
	})
}

func TestSnapshotResultReferencesPhysicalSampleAndProbeCorruptionZero(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, run, samples, _ := snapshotResultTestFixture(t, s)
		for _, table := range []string{"integrity_logical_samples", "integrity_probe_instances"} {
			t.Run(table, func(t *testing.T) {
				original := snapshotKeyTestUnconstrained(t, s, table)
				reset := func() {
					for _, q := range []string{"DELETE FROM " + table, "INSERT INTO " + table + " SELECT * FROM " + original} {
						if err := s.db.Exec(q).Error; err != nil {
							t.Fatal(err)
						}
					}
				}
				faults := []map[string]any{{"id": nil}, {"id": -1}, {"organization_id": nil}, {"organization_id": run.OrganizationID + 1}, {"run_id": nil}, {"run_id": run.ID + 1}}
				if table == "integrity_logical_samples" {
					faults = append(faults, map[string]any{"probe_instance_id": nil}, map[string]any{"probe_instance_id": samples[0].ProbeInstanceID + 1}, map[string]any{"ordinal": nil}, map[string]any{"ordinal": -1}, map[string]any{"execution_ordinal": nil}, map[string]any{"execution_ordinal": 1})
				} else {
					faults = append(faults, map[string]any{"template_id": nil}, map[string]any{"template_id": "other-member"}, map[string]any{"template_version": "other-version"}, map[string]any{"template_id": strings.Repeat("private-member", 1000)})
				}
				for i, values := range faults {
					t.Run(strconv.Itoa(i), func(t *testing.T) {
						if err := s.db.Table(table).Where("1=1").Updates(values).Error; err != nil {
							t.Fatal(err)
						}
						snapshotResultTestObserve(t, s, cfg, snapshotReferenceLimit, errSnapshotResultReferenceInvalid)
					})
					reset()
				}
				if err := s.db.Exec("INSERT INTO " + table + " SELECT * FROM " + original).Error; err != nil {
					t.Fatal(err)
				}
				snapshotResultTestObserve(t, s, cfg, snapshotReferenceLimit, errSnapshotResultReferenceInvalid)
			})
		}
	})
}

func TestSnapshotResultReferences101SamplesAndLateCorruption(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, run, samples, body := snapshotResultTestFixture(t, s, 101)
		got := snapshotResultTestObserve(t, s, cfg, snapshotReferenceLimit, nil)
		if got.rows != 1 || got.incomplete != 0 || len(samples) != 101 {
			t.Fatal("101 physical samples not observed")
		}
		body["features"].(map[string]any)["samples"].([]any)[100].(map[string]any)["sample_id"] = strconv.FormatInt(samples[100].ID+1, 10)
		if err := s.db.Table("integrity_run_results").Where("run_id=?", run.ID).Update("conclusion_json", string(snapshotReferenceTestJSON(t, body))).Error; err != nil {
			t.Fatal(err)
		}
		snapshotResultTestObserve(t, s, cfg, snapshotReferenceLimit, errSnapshotResultReferenceInvalid)
	})
}

func TestSnapshotResultReferencesLateResultAndCancelNeverPrefix(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, run, _, body := snapshotResultTestFixture(t, s)
		for revision := 2; revision <= 101; revision++ {
			result := RunResultRecord{OrganizationID: run.OrganizationID, RunID: run.ID, AnalysisRevision: revision, RiskLevel: "insufficient", EvidenceGrade: "D", Completeness: "INSUFFICIENT", ConclusionJSON: string(snapshotReferenceTestJSON(t, body)), CreatedAt: time.Now().UTC()}
			if err := s.db.Create(&result).Error; err != nil {
				t.Fatal(err)
			}
		}
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		canceled, cancel := context.WithCancel(ctx)
		fired := false
		if err := tx.Callback().Query().After("gorm:query").Register("result_late_cancel", func(db *gorm.DB) {
			if rows, ok := db.Statement.Dest.(*[]snapshotResultReferenceRow); ok && len(*rows) > 0 && (*rows)[0].Revision == 101 {
				fired = true
				cancel()
			}
		}); err != nil {
			t.Fatal(err)
		}
		got, err := s.snapshotResultReferences(canceled, tx)
		if removeErr := tx.Callback().Query().Remove("result_late_cancel"); removeErr != nil {
			t.Fatal(removeErr)
		}
		cancel()
		closeView()
		if !fired || !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, snapshotResultReferences{}) {
			t.Fatal("late cancellation returned prefix", err)
		}
		if err := s.db.Table("integrity_run_results").Where("analysis_revision=101").Update("conclusion_json", `{"schema_version":"mii.analysis.v1","scores":{"RulesHash":null}}`).Error; err != nil {
			t.Fatal(err)
		}
		snapshotResultTestObserve(t, s, cfg, snapshotReferenceLimit, errSnapshotResultReferenceInvalid)
	})
}

func TestSnapshotResultReferencesRealSchema17HistoryRetained(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		set, err := migrations.ForDialect(s.driver)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.migrate(t.Context(), set[:17]); err != nil {
			t.Fatal(err)
		}
		org := derivedUpgradeLegacyRows(t, s)
		maximum := int64(2147483647)
		if s.driver == "sqlite" {
			maximum = 9223372036854775807
		}
		for _, revision := range []int64{1, maximum} {
			if err := s.db.Table("integrity_run_results").Create(map[string]any{"organization_id": org, "run_id": 1, "analysis_revision": revision, "confidence": 0, "risk_level": "insufficient", "evidence_grade": "D", "completeness": "INSUFFICIENT", "conclusion_json": `{"legacy_schema17_result":"retained-original"}`, "created_at": time.Now().UTC()}).Error; err != nil {
				t.Fatal("original revision range", err)
			}
		}
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		got := snapshotResultTestObserve(t, s, cfg, snapshotReferenceLimit, nil)
		if got.rows != 2 || got.unpublished != 2 || got.incomplete != 2 || got.unknown != 2 || len(got.references) != 0 {
			t.Fatal("old result replaced/lost/promoted")
		}
		var bodies []string
		if err := s.db.Table("integrity_run_results").Pluck("conclusion_json", &bodies).Error; err != nil {
			t.Fatal(err)
		}
		for _, body := range bodies {
			if body != `{"legacy_schema17_result":"retained-original"}` {
				t.Fatal("original bytes rewritten")
			}
		}
	})
}

func TestSnapshotResultReferencesCrossTenantResultSample(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, run, _, body := snapshotResultTestFixture(t, s)
		// An independent real tenant/run/sample exists. A positive ID is not
		// enough to bind a historical result to that foreign physical sample.
		const org, runID, sampleID int64 = 8101, 8103, 8106
		stamp := time.Now().UTC().Truncate(time.Microsecond)
		snapshotJobTestInsert(t, s, "organizations", map[string]any{"id": org, "name": "other result tenant", "status": "disabled", "timezone": "UTC", "quota_json": "{}", "created_at": stamp, "updated_at": stamp})
		snapshotJobTestInsert(t, s, "organization_members", map[string]any{"id": 8104, "organization_id": org, "user_id": run.CreatedBy, "status": "disabled", "created_at": stamp, "updated_at": stamp})
		credential := encryptedFixture(t, org)
		if err := s.db.Create(&credential).Error; err != nil {
			t.Fatal(err)
		}
		snapshotJobTestInsert(t, s, "integrity_targets", map[string]any{"id": 8102, "organization_id": org, "name": "other target", "endpoint": "https://other.example/v1", "endpoint_fingerprint": strings.Repeat("a", 64), "protocol": "openai_chat", "model": "other", "auth_type": "bearer", "status": "disabled", "tags_json": "[]", "options_json": "{}", "secret_id": credential.ID, "version": 1, "created_by": run.CreatedBy, "updated_by": run.CreatedBy, "created_at": stamp, "updated_at": stamp})
		snapshotJobTestInsert(t, s, "integrity_runs", map[string]any{"id": runID, "organization_id": org, "target_id": 8102, "package": "custom", "status": "COMPLETED", "config_snapshot": `{"legacy_fixture":true}`, "manifest_hash": strings.Repeat("a", 64), "rule_bundle_version": "1", "template_bundle_version": "1", "scoring_version": "1", "tokenizer_bundle_version": "1", "request_budget": 50, "token_budget": 1000, "created_by": run.CreatedBy, "created_at": stamp})
		snapshotJobTestInsert(t, s, "integrity_probe_instances", map[string]any{"id": 8105, "organization_id": org, "run_id": runID, "probe_type": "contract", "template_id": "contract-basic", "template_version": "1", "category": "format", "variant": "en", "planned_samples": 1, "status": "COMPLETED", "parameters_json": "{}", "created_at": stamp})
		snapshotJobTestInsert(t, s, "integrity_logical_samples", map[string]any{"id": sampleID, "organization_id": org, "run_id": runID, "probe_instance_id": 8105, "ordinal": 0, "idempotency_key": "foreign-original", "request_plan": "{}", "validity": "NOT_APPLICABLE", "created_at": stamp})
		body["features"].(map[string]any)["samples"].([]any)[0].(map[string]any)["sample_id"] = strconv.FormatInt(sampleID, 10)
		if err := s.db.Table("integrity_run_results").Where("run_id=?", run.ID).Update("conclusion_json", string(snapshotReferenceTestJSON(t, body))).Error; err != nil {
			t.Fatal(err)
		}
		snapshotResultTestObserve(t, s, cfg, snapshotReferenceLimit, errSnapshotResultReferenceInvalid)
	})
}

func TestSnapshotResultReferencesSQLBoundsAndFinalCount(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, run, _, _ := snapshotResultTestFixture(t, s)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		omitted := false
		if err := tx.Callback().Query().After("gorm:query").Register("result_omit_row", func(db *gorm.DB) {
			if rows, ok := db.Statement.Dest.(*[]snapshotResultReferenceRow); ok && len(*rows) > 0 {
				*rows = nil
				omitted = true
			}
		}); err != nil {
			t.Fatal(err)
		}
		got, err := s.snapshotResultReferences(ctx, tx)
		if removeErr := tx.Callback().Query().Remove("result_omit_row"); removeErr != nil {
			t.Fatal(removeErr)
		}
		closeView()
		if !omitted || !errors.Is(err, errSnapshotResultReferenceInvalid) || !reflect.DeepEqual(got, snapshotResultReferences{}) {
			t.Fatal("count mismatch not closed", err)
		}
		if err := s.db.Table("integrity_run_results").Where("1=1").Update("conclusion_json", strings.Repeat("private-oversized", 300000)).Error; err != nil {
			t.Fatal(err)
		}
		ctx, tx, closeView = auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		raw, err := snapshotResultReferenceBody(ctx, tx, snapshotResultReferenceRow{OrganizationID: run.OrganizationID, RunID: run.ID, Revision: 1})
		if !errors.Is(err, errSnapshotResultReferenceInvalid) || raw != nil {
			t.Fatal("oversized body crossed SQL projection", err)
		}
	})
}

func TestSnapshotResultReferencesKnownCodecLegacyPhysicalOrdinal(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, run, samples, body := snapshotResultTestFixture(t, s)
		var frozen executionSnapshot
		if json.Unmarshal([]byte(run.ConfigSnapshot), &frozen) != nil {
			t.Fatal("fixture")
		}
		frozen.Plan.Manifest = nil
		if err := s.db.Table("integrity_runs").Where("id=?", run.ID).Update("config_snapshot", string(snapshotReferenceTestJSON(t, frozen))).Error; err != nil {
			t.Fatal(err)
		}
		maximum := int64(2147483647)
		if s.driver == "sqlite" {
			maximum = 9223372036854775807
		}
		if err := s.db.Table("integrity_logical_samples").Where("id=?", samples[0].ID).Update("ordinal", maximum).Error; err != nil {
			t.Fatal(err)
		}
		got := snapshotResultTestObserve(t, s, cfg, snapshotReferenceLimit, nil)
		if got.incomplete != 1 {
			t.Fatal("legacy locally numbered source not classified")
		}
		body["features"].(map[string]any)["samples"].([]any)[0].(map[string]any)["ordinal"] = maximum
		if err := s.db.Table("integrity_run_results").Where("run_id=?", run.ID).Update("conclusion_json", string(snapshotReferenceTestJSON(t, body))).Error; err != nil {
			t.Fatal(err)
		}
		snapshotResultTestObserve(t, s, cfg, snapshotReferenceLimit, errSnapshotResultReferenceInvalid)
	})
}
