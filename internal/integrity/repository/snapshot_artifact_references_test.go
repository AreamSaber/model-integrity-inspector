package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/migrations"
)

func snapshotReferenceTestObserve(t *testing.T, s *Store, cfg Config, want error) snapshotArtifactReferences {
	t.Helper()
	ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
	defer closeView()
	got, err := (&Store{driver: s.driver}).snapshotArtifactReferences(ctx, tx)
	if !errors.Is(err, want) || want != nil && !reflect.DeepEqual(got, snapshotArtifactReferences{}) {
		t.Fatal("closed observation", err)
	}
	return got
}

func snapshotReferenceTestAttachManifest(t *testing.T, org int64, plan domain.ExecutionPlan) domain.ExecutionPlan {
	t.Helper()
	raw, _ := snapshotKeyTestManifest(t, org, "retained-reference-key")
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		t.Fatal("fixture")
	}
	m["options"] = map[string]any{"organization_id": strconv.FormatInt(org, 10), "rule_version": plan.Versions.Rule, "scoring_version": plan.Versions.Scoring, "target": plan.Target}
	m["template_version"], m["tokenizer_version"] = plan.Versions.Template, plan.Versions.Tokenizer
	var samples []any
	for _, probe := range plan.Probes {
		for _, sample := range probe.Samples {
			samples = append(samples, map[string]any{"ordinal": sample.Ordinal, "template_id": probe.TemplateID, "template_version": probe.TemplateVersion})
		}
	}
	m["samples"] = samples
	plan.Manifest = snapshotReferenceTestJSON(t, m)
	plan.ManifestHash = baselineHash(plan.Manifest)
	return plan
}

func snapshotReferenceTestFixture(t *testing.T, s *Store, compile func(int64, TargetState) domain.ExecutionPlan) (*Tenant, RunRecord, RunEstimateRecord, []BaselineRecord) {
	t.Helper()
	tenant, target, plan, policy := executionFixture(t, s, 2)
	if compile == nil {
		var err error
		plan, _, err = policy.Apply(plan)
		if err != nil {
			t.Fatal("freeze policy before manifest", err)
		}
		plan = snapshotReferenceTestAttachManifest(t, tenant.orgID, plan)
	} else {
		plan = compile(tenant.orgID, target)
	}
	estimate, err := tenant.SaveRunEstimate(plan, policy)
	if err != nil {
		t.Fatal("actual estimate writer", err)
	}
	run, err := tenant.CreateRun(plan, policy, "reference-current-original")
	if err != nil {
		t.Fatal("actual Run writer", err)
	}
	stamp := time.Now().UTC().Truncate(time.Microsecond)
	// A retained result is deliberately structural, not a claimed analyzer or
	// authenticated baseline service execution. This unit only checks its hash.
	resultBody := `{"retained_result":"original-reference-fixture"}`
	result := RunResultRecord{OrganizationID: tenant.orgID, RunID: run.ID, AnalysisRevision: 1, Confidence: 0, RiskLevel: "insufficient", EvidenceGrade: "D", Completeness: "INSUFFICIENT", ConclusionJSON: resultBody, CreatedAt: stamp}
	if err := s.db.Create(&result).Error; err != nil {
		t.Fatal(err)
	}
	var m struct {
		TemplateHash  string `json:"template_hash"`
		TokenizerHash string `json:"tokenizer_hash"`
	}
	if json.Unmarshal(plan.Manifest, &m) != nil {
		t.Fatal("manifest metadata")
	}
	scope := BaselineScope{SchemaVersion: "baseline.scope.v1", OrganizationID: tenant.orgID, RunID: run.ID, TargetID: run.TargetID, AnalysisRevision: 1, Model: plan.Target.Model, Protocol: plan.Target.Protocol, MaxOutputParameter: plan.Target.MaxOutputParameter, Versions: plan.Versions, TemplateHash: m.TemplateHash, TokenizerHash: m.TokenizerHash, ParametersHash: strings.Repeat("c", 64), ManifestHash: plan.ManifestHash, ResultHash: baselineHash([]byte(resultBody)), Completeness: "INSUFFICIENT", SampledAt: stamp, Samples: []BaselineSampleScope{}}
	for _, probe := range plan.Probes {
		for range probe.Samples {
			scope.Samples = append(scope.Samples, BaselineSampleScope{TemplateID: probe.TemplateID, TemplateVersion: probe.TemplateVersion, VariablesHash: strings.Repeat("e", 64)})
		}
	}
	scope.ExpectedSamples = len(scope.Samples)
	scopeRaw, err := baselineJSON(scope)
	if err != nil {
		t.Fatal(err)
	}
	key, mac := "baseline-reference-key", strings.Repeat("f", 64)
	var baselines []BaselineRecord
	for _, state := range []string{"draft", "approved", "retired", "expired"} {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		baseline := BaselineRecord{ID: id, OrganizationID: tenant.orgID, RunID: run.ID, AnalysisRevision: 1, Name: "retained baseline", Model: scope.Model, Protocol: scope.Protocol, Status: state, ApplicableScopeJSON: `{"schema_version":"baseline.scope.v1"}`, CreatedAt: stamp, UpdatedAt: stamp, ExpiresAt: stamp.Add(-time.Hour), Version: 1, Source: "historical", SourceManifestHash: scope.ManifestHash, SourceResultHash: scope.ResultHash, ParametersHash: scope.ParametersHash, SnapshotJSON: scopeRaw, SnapshotHash: baselineHash([]byte(scopeRaw)), ApprovalKeyVersion: &key, ApprovalMAC: &mac}
		if err := s.db.Create(&baseline).Error; err != nil {
			t.Fatal(err)
		}
		baselines = append(baselines, baseline)
	}
	if err := s.db.Model(&RunEstimateRecord{}).Where("id=?", estimate.ID).Update("expires_at", stamp.Add(-time.Hour)).Error; err != nil {
		t.Fatal(err)
	}
	return tenant, run, estimate, baselines
}

func TestSnapshotArtifactReferencesAllSourcesAndSameView(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, run, _, _ := snapshotReferenceTestFixture(t, s, nil)
		if err := s.db.Table("organizations").Where("id=?", tenant.orgID).Update("status", "disabled").Error; err != nil {
			t.Fatal(err)
		}
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		first, err := (&Store{driver: s.driver}).snapshotArtifactReferences(ctx, tx.Where("1=0").Limit(1))
		if err != nil || first.observed != [3]int64{1, 1, 4} || first.legacy != [3]int64{} || first.inputIncomplete != [3]int64{1, 1, 4} || first.classification != snapshotReferenceLegacyIncomplete || len(first.references) != 5 {
			t.Fatal("all sources/disabled/expiry or NewDB scope", err)
		}
		// Commit an original byte change from the separate live connection. Both
		// logical sources are still valid, but the old view must not drift.
		changed := " " + run.ConfigSnapshot
		if err := s.db.Model(&RunRecord{}).Where("id=?", run.ID).Update("config_snapshot", changed).Error; err != nil {
			t.Fatal("independent writer", err)
		}
		second, err := (&Store{driver: s.driver}).snapshotArtifactReferences(ctx, tx)
		if err != nil || !reflect.DeepEqual(first, second) {
			t.Fatal("snapshot drift through Store pool", err)
		}
		closeView()
		fresh := snapshotReferenceTestObserve(t, s, cfg, nil)
		if fresh.sourceSHA256[0] == first.sourceSHA256[0] || !reflect.DeepEqual(fresh.references, first.references) {
			t.Fatal("raw original bytes normalized or references altered")
		}
	})
}

func TestSnapshotArtifactReferencesPagesAllOrganizationsAndLateFailure(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, run, _, _ := snapshotReferenceTestFixture(t, s, nil)
		// Exactly 101 real organizations/Run rows; the added records model
		// historical retained metadata, not execution/approval authorization.
		for i := int64(1); i <= 100; i++ {
			org := int64(10000) + i
			stamp := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
			snapshotJobTestInsert(t, s, "organizations", map[string]any{"id": org, "name": fmt.Sprintf("history-%d", i), "status": "disabled", "timezone": "UTC", "quota_json": "{}", "created_at": stamp, "updated_at": stamp})
			snapshotJobTestInsert(t, s, "organization_members", map[string]any{"id": 20000 + i, "organization_id": org, "user_id": run.CreatedBy, "status": "disabled", "created_at": stamp, "updated_at": stamp})
			credential := encryptedFixture(t, org)
			if err := s.db.Create(&credential).Error; err != nil {
				t.Fatal(err)
			}
			snapshotJobTestInsert(t, s, "integrity_targets", map[string]any{"id": 30000 + i, "organization_id": org, "name": "retained", "endpoint": "https://retained.example/v1", "endpoint_fingerprint": strings.Repeat("a", 64), "protocol": "openai_chat", "model": "retained", "auth_type": "bearer", "status": "disabled", "tags_json": "[]", "options_json": "{}", "secret_id": credential.ID, "version": 1, "created_by": run.CreatedBy, "updated_by": run.CreatedBy, "created_at": stamp, "updated_at": stamp})
			snapshotJobTestInsert(t, s, "integrity_runs", map[string]any{"id": 40000 + i, "organization_id": org, "target_id": 30000 + i, "package": "custom", "status": []string{"QUEUED", "COMPLETED", "FAILED", "CANCELLED", "PARTIAL"}[i%5], "config_snapshot": `{"legacy_fixture":true}`, "manifest_hash": strings.Repeat("a", 64), "rule_bundle_version": "1", "template_bundle_version": "1", "scoring_version": "1", "tokenizer_bundle_version": "1", "request_budget": 50, "token_budget": 1000, "created_by": run.CreatedBy, "created_at": stamp})
		}
		got := snapshotReferenceTestObserve(t, s, cfg, nil)
		if got.observed != [3]int64{101, 1, 4} || got.legacy[0] != 100 || len(got.references) != 405 {
			t.Fatal("pagination/all organization union")
		}
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		limited, err := s.snapshotArtifactReferencesLimited(ctx, tx, len(got.references))
		if err != nil || !reflect.DeepEqual(limited, got) {
			t.Fatal("exact union budget", err)
		}
		failed, err := s.snapshotArtifactReferencesLimited(ctx, tx, len(got.references)-1)
		if !errors.Is(err, errSnapshotReferenceLimit) || !reflect.DeepEqual(failed, snapshotArtifactReferences{}) {
			t.Fatal("union limit prefix returned", err)
		}
		closeView()
		// The real initial org sorts after 100 low historical IDs: damage its
		// final modern row after a complete first page has been observed.
		if err := s.db.Table("integrity_runs").Where("organization_id=? AND id=?", tenant.orgID, run.ID).Update("manifest_hash", strings.Repeat("f", 64)).Error; err != nil {
			t.Fatal(err)
		}
		snapshotReferenceTestObserve(t, s, cfg, errSnapshotReferenceInvalid)
	})
}

func TestSnapshotArtifactReferencesActualLegacyMigrations(t *testing.T) {
	var digest [3]string
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		all, err := migrations.ForDialect(s.driver)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.migrate(t.Context(), all[:11]); err != nil {
			t.Fatal(err)
		}
		initial := derivedUpgradeLegacyInitialization(t, s)
		stamp := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		credential := encryptedFixture(t, initial.Organization.ID)
		if err := s.db.Create(&credential).Error; err != nil {
			t.Fatal(err)
		}
		snapshotJobTestInsert(t, s, "integrity_targets", map[string]any{"id": 100, "organization_id": initial.Organization.ID, "name": "legacy", "endpoint": "https://legacy.example/v1", "endpoint_fingerprint": strings.Repeat("a", 64), "protocol": "openai_chat", "model": "legacy", "auth_type": "bearer", "status": "disabled", "tags_json": "[]", "options_json": "{}", "secret_id": credential.ID, "version": 1, "created_by": initial.User.ID, "updated_by": initial.User.ID, "created_at": stamp, "updated_at": stamp})
		snapshotJobTestInsert(t, s, "integrity_runs", map[string]any{"id": 101, "organization_id": initial.Organization.ID, "target_id": 100, "package": "custom", "status": "COMPLETED", "config_snapshot": `{"legacy_fixture":true}`, "manifest_hash": strings.Repeat("a", 64), "rule_bundle_version": "1", "template_bundle_version": "1", "scoring_version": "1", "tokenizer_bundle_version": "1", "request_budget": 50, "token_budget": 1000, "created_by": initial.User.ID, "created_at": stamp})
		snapshotJobTestInsert(t, s, "integrity_run_results", map[string]any{"organization_id": initial.Organization.ID, "run_id": 101, "analysis_revision": 1, "confidence": 0, "risk_level": "insufficient", "evidence_grade": "D", "completeness": "INSUFFICIENT", "conclusion_json": "{}", "is_published": false, "created_at": stamp})
		snapshotJobTestInsert(t, s, "integrity_baselines", map[string]any{"id": 102, "organization_id": initial.Organization.ID, "run_id": 101, "analysis_revision": 1, "name": "legacy", "model": "legacy", "protocol": "openai_chat", "status": "approved", "applicable_scope_json": "{}", "created_at": stamp, "expires_at": stamp})
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal("real expand migration", err)
		}
		got := snapshotReferenceTestObserve(t, s, cfg, nil)
		if got.classification != snapshotReferenceLegacyIncomplete || got.observed != [3]int64{1, 0, 1} || got.legacy != [3]int64{1, 0, 1} || len(got.references) != 4 {
			t.Fatal("legacy data lost or upgraded")
		}
		if digest != [3]string{} && digest != got.sourceSHA256 {
			t.Fatal("same original logical sources differ by driver")
		}
		digest = got.sourceSHA256
		var run RunRecord
		var baseline BaselineRecord
		if err := s.db.Where("id=101").Take(&run).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Where("id=102").Take(&baseline).Error; err != nil {
			t.Fatal(err)
		}
		if run.ConfigSnapshot != `{"legacy_fixture":true}` || baseline.SnapshotJSON != "{}" || baseline.SnapshotHash != "" || baseline.ApprovalMAC != nil || baseline.ApprovalKeyVersion != nil || baseline.Status != "approved" {
			t.Fatal("original migration data modified")
		}
	})
}

func TestSnapshotArtifactReferencesRealTransactionAndLateCancellation(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		snapshotReferenceTestFixture(t, s, nil)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		for _, args := range []struct {
			ctx   context.Context
			db    *gorm.DB
			limit int
		}{{nil, tx, 1}, {context.Background(), tx, 1}, {ctx, s.db, 1}, {ctx, tx, 0}, {ctx, tx, snapshotReferenceLimit + 1}} {
			if got, err := s.snapshotArtifactReferencesLimited(args.ctx, args.db, args.limit); !errors.Is(err, ErrConfiguration) || !reflect.DeepEqual(got, snapshotArtifactReferences{}) {
				t.Fatal("actual transaction/deadline requirement", err)
			}
		}
		canceled, cancel := context.WithCancel(ctx)
		fired := false
		if err := tx.Callback().Query().After("gorm:query").Register("snapshot_reference_late_cancel", func(db *gorm.DB) {
			if _, ok := db.Statement.Dest.(*[]snapshotReferenceRow); ok && strings.Contains(db.Statement.SQL.String(), "integrity_baselines") && !fired {
				fired = true
				cancel()
			}
		}); err != nil {
			t.Fatal(err)
		}
		got, err := s.snapshotArtifactReferences(canceled, tx)
		if err := tx.Callback().Query().Remove("snapshot_reference_late_cancel"); err != nil {
			t.Fatal(err)
		}
		cancel()
		if !fired || !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, snapshotArtifactReferences{}) {
			t.Fatal("late cancellation returned prefix", err)
		}
		closeView()
		// Actual rollback failure cannot return the previous successful prefix.
		live, liveTx, liveClose := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer liveClose()
		rolled := false
		if err := liveTx.Callback().Query().After("gorm:query").Register("snapshot_reference_late_rollback", func(db *gorm.DB) {
			if _, ok := db.Statement.Dest.(*[]snapshotReferenceRow); ok && strings.Contains(db.Statement.SQL.String(), "integrity_baselines") && !rolled {
				rolled = true
				_ = db.Statement.ConnPool.(*sql.Tx).Rollback()
			}
		}); err != nil {
			t.Fatal(err)
		}
		got, err = s.snapshotArtifactReferences(live, liveTx)
		if err := liveTx.Callback().Query().Remove("snapshot_reference_late_rollback"); err != nil {
			t.Fatal(err)
		}
		if !rolled || !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, snapshotArtifactReferences{}) {
			t.Fatal("late SQL failure returned prefix", err)
		}
	})
}

func SnapshotArtifactReferencesActualSourcesBridge(t *testing.T, compile func(int64, TargetState) domain.ExecutionPlan) {
	t.Helper()
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, run, estimate, _ := snapshotReferenceTestFixture(t, s, compile)
		got := snapshotReferenceTestObserve(t, s, cfg, nil)
		if got.observed != [3]int64{1, 1, 4} || got.classification != snapshotReferenceObserved || run.ManifestHash != estimate.ManifestHash {
			t.Fatal("actual generated source writer")
		}
		var current RunRecord
		if err := s.db.Where("id=?", run.ID).Take(&current).Error; err != nil {
			t.Fatal(err)
		}
		if current.ConfigSnapshot != run.ConfigSnapshot {
			t.Fatal("rewrote authenticated original Run")
		}
	})
}
