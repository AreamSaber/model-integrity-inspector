package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestSnapshotArtifactReferencesOfflineCorruptionNeverPartial(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, _, _, _ := snapshotReferenceTestFixture(t, s, nil)
		for _, source := range snapshotReferenceSources() {
			t.Run(source.kind, func(t *testing.T) {
				original := snapshotKeyTestUnconstrained(t, s, source.table)
				reset := func() {
					for _, query := range []string{"DELETE FROM " + source.table, "INSERT INTO " + source.table + " SELECT * FROM " + original} {
						if err := s.db.Exec(query).Error; err != nil {
							t.Fatal("restore test-owned copy", err)
						}
					}
				}
				faults := []map[string]any{
					{"id": nil}, {"id": 0}, {"id": -1}, {"organization_id": nil}, {"organization_id": -1}, {"organization_id": tenant.orgID + 1},
					{source.body: nil}, {source.body: ""}, {source.body: strings.Repeat("x", source.maxBytes+1)},
				}
				if source.kind == "baseline" {
					faults = append(faults, map[string]any{"run_id": nil}, map[string]any{"run_id": tenant.orgID + 1}, map[string]any{"analysis_revision": 0}, map[string]any{"source_manifest_hash": nil}, map[string]any{"source_result_hash": strings.Repeat("x", 1<<20)}, map[string]any{"snapshot_hash": strings.Repeat("a", 64)}, map[string]any{"parameters_hash": strings.Repeat("d", 64)}, map[string]any{"approval_mac": nil}, map[string]any{"approval_key_version": nil}, map[string]any{"snapshot_json": "{}"})
				} else {
					faults = append(faults, map[string]any{"target_id": nil}, map[string]any{"target_id": tenant.orgID + 1}, map[string]any{"manifest_hash": nil}, map[string]any{"manifest_hash": strings.Repeat("a", 65)}, map[string]any{"manifest_hash": strings.Repeat("a", 64)}, map[string]any{source.body: `{"plan":null}`})
					if source.kind == "run" {
						faults = append(faults, map[string]any{"rule_bundle_version": nil}, map[string]any{"template_bundle_version": strings.Repeat("v", 129)}, map[string]any{"tokenizer_bundle_version": "wrong"}, map[string]any{"scoring_version": "wrong"}, map[string]any{"analysis_source_version": nil})
					} else {
						faults = append(faults, map[string]any{source.body: `{"legacy_fixture":true}`})
					}
				}
				if s.driver == "sqlite" {
					faults = append(faults, map[string]any{"id": "not-an-integer"}, map[string]any{source.body: []byte("{}")})
				}
				for i, values := range faults {
					t.Run(strconv.Itoa(i), func(t *testing.T) {
						if err := s.db.Table(source.table).Where("1=1").Updates(values).Error; err != nil {
							t.Fatal("offline test mutation", err)
						}
						snapshotReferenceTestObserve(t, s, cfg, errSnapshotReferenceInvalid)
					})
					reset()
				}
				if err := s.db.Exec("INSERT INTO " + source.table + " SELECT * FROM " + original).Error; err != nil {
					t.Fatal(err)
				}
				snapshotReferenceTestObserve(t, s, cfg, errSnapshotReferenceInvalid)
			})
		}
	})
}

func TestSnapshotArtifactReferencesBaselineSourceAndUnsigned(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, run, _, baselines := snapshotReferenceTestFixture(t, s, nil)
		original := snapshotKeyTestUnconstrained(t, s, "integrity_run_results")
		if err := s.db.Table("integrity_run_results").Where("run_id=?", run.ID).Update("conclusion_json", `{"different":"source"}`).Error; err != nil {
			t.Fatal(err)
		}
		snapshotReferenceTestObserve(t, s, cfg, errSnapshotReferenceInvalid)
		for _, query := range []string{"DELETE FROM integrity_run_results", "INSERT INTO integrity_run_results SELECT * FROM " + original} {
			if err := s.db.Exec(query).Error; err != nil {
				t.Fatal(err)
			}
		}
		if err := s.db.Exec("INSERT INTO integrity_run_results SELECT * FROM " + original).Error; err != nil {
			t.Fatal(err)
		}
		snapshotReferenceTestObserve(t, s, cfg, errSnapshotReferenceInvalid)
		for _, query := range []string{"DELETE FROM integrity_run_results", "INSERT INTO integrity_run_results SELECT * FROM " + original} {
			if err := s.db.Exec(query).Error; err != nil {
				t.Fatal(err)
			}
		}
		if err := s.db.Table("integrity_baselines").Where("id=?", baselines[0].ID).Updates(map[string]any{"approval_key_version": nil, "approval_mac": nil}).Error; err != nil {
			t.Fatal(err)
		}
		got := snapshotReferenceTestObserve(t, s, cfg, nil)
		if got.legacy != [3]int64{0, 0, 1} || got.classification != snapshotReferenceLegacyIncomplete || got.observed[2] != 4 {
			t.Fatal("unsigned full scope lost or silently trusted")
		}
	})
}

func TestSnapshotArtifactReferencesBaselineOriginalTargetMetadata(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, _, _, baselines := snapshotReferenceTestFixture(t, s, nil)
		var scope BaselineScope
		if json.Unmarshal([]byte(baselines[0].SnapshotJSON), &scope) != nil {
			t.Fatal("scope")
		}
		scope.Model = "different-from-frozen-Run"
		raw := snapshotReferenceTestJSON(t, scope)
		if err := s.db.Table("integrity_baselines").Where("id=?", baselines[0].ID).Updates(map[string]any{"model": scope.Model, "snapshot_json": string(raw), "snapshot_hash": baselineHash(raw)}).Error; err != nil {
			t.Fatal(err)
		}
		snapshotReferenceTestObserve(t, s, cfg, errSnapshotReferenceInvalid)
	})
}

func TestSnapshotArtifactReferencesBoundedBeforeTransferAndClosingCount(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		snapshotReferenceTestFixture(t, s, nil)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		// A late page omission (e.g. an offline invalid/NULL key) cannot turn a
		// declared source count into a silently smaller successful inventory.
		omitted := false
		if err := tx.Callback().Query().After("gorm:query").Register("reference_test_omit", func(db *gorm.DB) {
			if rows, ok := db.Statement.Dest.(*[]snapshotReferenceRow); ok && strings.Contains(db.Statement.SQL.String(), "integrity_baselines") && len(*rows) > 0 && !omitted {
				*rows = (*rows)[:len(*rows)-1]
				omitted = true
			}
		}); err != nil {
			t.Fatal(err)
		}
		got, err := s.snapshotArtifactReferences(ctx, tx)
		if err := tx.Callback().Query().Remove("reference_test_omit"); err != nil {
			t.Fatal(err)
		}
		if !omitted || !errors.Is(err, errSnapshotReferenceInvalid) || !reflect.DeepEqual(got, snapshotArtifactReferences{}) {
			t.Fatal("closing count failed", err)
		}
		// The SQL CASE projections themselves, not a later Go len check, refuse
		// the oversized S2 body and do not transfer it into the body destination.
		closeView()
		if err := s.db.Table("integrity_runs").Where("1=1").Update("config_snapshot", strings.Repeat("private-oversized-body-", 400000)).Error; err != nil {
			t.Fatal(err)
		}
		bodyCtx, bodyTx, bodyClose := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer bodyClose()
		var row RunRecord
		if err := s.db.Select("id,organization_id").Take(&row).Error; err != nil {
			t.Fatal(err)
		}
		body, err := snapshotReferenceBody(bodyCtx, bodyTx, snapshotReferenceSources()[0], row.OrganizationID, row.ID)
		if !errors.Is(err, errSnapshotReferenceInvalid) || body != nil {
			t.Fatal("oversized body crossed SQL bound", err)
		}
	})
}

func TestSnapshotArtifactReferencesSameVersionOtherTenantOriginalHash(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, run, _, _ := snapshotReferenceTestFixture(t, s, nil)
		const org, targetID, runID int64 = 8101, 8102, 8103
		stamp := time.Now().UTC().Truncate(time.Microsecond)
		snapshotJobTestInsert(t, s, "organizations", map[string]any{"id": org, "name": "other original parameters", "status": "disabled", "timezone": "UTC", "quota_json": "{}", "created_at": stamp, "updated_at": stamp})
		snapshotJobTestInsert(t, s, "organization_members", map[string]any{"id": 8104, "organization_id": org, "user_id": run.CreatedBy, "status": "disabled", "created_at": stamp, "updated_at": stamp})
		credential := encryptedFixture(t, org)
		if err := s.db.Create(&credential).Error; err != nil {
			t.Fatal(err)
		}
		var originalTarget TargetRecord
		if err := s.db.Where("id=?", run.TargetID).Take(&originalTarget).Error; err != nil {
			t.Fatal(err)
		}
		originalTarget.ID, originalTarget.OrganizationID, originalTarget.SecretID = targetID, org, credential.ID
		if err := s.db.Create(&originalTarget).Error; err != nil {
			t.Fatal(err)
		}
		var frozen executionSnapshot
		if json.Unmarshal([]byte(run.ConfigSnapshot), &frozen) != nil {
			t.Fatal("snapshot")
		}
		frozen.Plan.Target.ID, frozen.Plan.Target.SecretID = targetID, credential.ID
		frozen.Plan = snapshotReferenceTestAttachManifest(t, org, frozen.Plan)
		var m map[string]any
		if json.Unmarshal(frozen.Plan.Manifest, &m) != nil {
			t.Fatal("manifest")
		}
		m["template_hash"] = strings.Repeat("d", 64)
		frozen.Plan.Manifest = snapshotReferenceTestJSON(t, m)
		frozen.Plan.ManifestHash = baselineHash(frozen.Plan.Manifest)
		other := run
		other.ID, other.OrganizationID, other.TargetID, other.PlanJobID, other.RequestKey = runID, org, targetID, nil, "other-original"
		other.ConfigSnapshot, other.ManifestHash = string(snapshotReferenceTestJSON(t, frozen)), frozen.Plan.ManifestHash
		if err := s.db.Create(&other).Error; err != nil {
			t.Fatal(err)
		}
		got := snapshotReferenceTestObserve(t, s, cfg, nil)
		var initialHash, otherHash string
		for _, ref := range got.references {
			if ref.category == "template" {
				if ref.organizationID == tenant.orgID {
					initialHash = ref.sha256
				}
				if ref.organizationID == org {
					otherHash = ref.sha256
				}
			}
		}
		if initialHash == "" || otherHash == "" || initialHash == otherHash || got.observed[0] != 2 {
			t.Fatal("cross-tenant same version flattened")
		}
		// A real foreign target exists, so existence alone must not satisfy the
		// original organization relationship in an unconstrained offline copy.
		t.Run("foreign-target", func(t *testing.T) {
			snapshotKeyTestUnconstrained(t, s, "integrity_runs")
			if err := s.db.Table("integrity_runs").Where("id=?", run.ID).Update("target_id", targetID).Error; err != nil {
				t.Fatal(err)
			}
			snapshotReferenceTestObserve(t, s, cfg, errSnapshotReferenceInvalid)
		})
	})
}

func TestSnapshotArtifactReferencesReadWriteTransactionsRejected(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		if s.driver == "postgres" {
			ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, &sql.TxOptions{ReadOnly: false, Isolation: sql.LevelRepeatableRead}, false)
			defer closeView()
			if got, err := s.snapshotArtifactReferences(ctx, tx); !errors.Is(err, ErrConfiguration) || !reflect.DeepEqual(got, snapshotArtifactReferences{}) {
				t.Fatal("read-write transaction accepted", err)
			}
		}
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if got, err := s.snapshotArtifactReferences(canceled, tx); !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, snapshotArtifactReferences{}) {
			t.Fatal("canceled transaction input", err)
		}
	})
}
