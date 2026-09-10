package repository

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func SnapshotReferenceModelCompatibilityPureBridge(t *testing.T, plan domain.ExecutionPlan, org int64) {
	t.Helper()
	if !validateExecutionPlan(plan) {
		t.Fatal("real compiler output not accepted by actual repository validator")
	}
	raw := snapshotReferenceTestJSON(t, executionSnapshot{Plan: plan})
	source := AnalysisSourceLegacyV1
	if plan.AnalysisSourceVersion != "" {
		source = plan.AnalysisSourceVersion
	}
	row := snapshotReferenceRow{OrganizationID: org, ID: 23, TargetID: plan.Target.ID, ManifestHash: plan.ManifestHash, AnalysisSource: source, Rule: plan.Versions.Rule, Template: plan.Versions.Template, Scoring: plan.Versions.Scoring, Tokenizer: plan.Versions.Tokenizer}
	got, err := snapshotReferencePlan(t.Context(), row, raw, false)
	if err != nil || got.legacy || got.targetModel != plan.Target.Model {
		t.Fatal("actual compiler model byte identity rejected or changed", err)
	}
	row.Rule, row.Template, row.Scoring, row.Tokenizer, row.AnalysisSource = "", "", "", "", ""
	estimate, err := snapshotReferencePlan(t.Context(), row, raw, true)
	if err != nil || !reflect.DeepEqual(got, estimate) {
		t.Fatal("actual compiler estimate model rejected or changed", err)
	}
}

func TestSnapshotReferenceModelCompatibilityPureRepositoryBounds(t *testing.T) {
	// The service's 128-rune bound, generator's 256-byte bound, and repository's
	// 512-byte historical bound are distinct. Inventory must not flatten them.
	for _, model := range []string{strings.Repeat("a", 129), strings.Repeat("模", 43), strings.Repeat("é", 128), strings.Repeat("x", 512), strings.Repeat("𠀀", 128)} {
		t.Run(fmt.Sprintf("bytes_%d_runes_%d", len(model), utf8.RuneCountInString(model)), func(t *testing.T) {
			target := targetRecordFixture()
			target.Model = model
			if !validTargetRecord(target, 17) || !utf8.ValidString(model) {
				t.Fatal("fixture exceeds actual low-level target writer")
			}
			row, raw := snapshotReferenceTestPlan(t)
			raw = snapshotReferenceTestMutation(t, raw, &row, func(plan, manifest map[string]any) {
				plan["target"].(map[string]any)["model"] = model
				manifest["options"].(map[string]any)["target"].(map[string]any)["model"] = model
			})
			// Structural retained manifest only: no claim of a valid current MAC
			// or current compiler support for models above 256 bytes.
			got, err := snapshotReferencePlan(t.Context(), row, raw, false)
			if err != nil || got.targetModel != model {
				t.Fatal("bounded original model was rejected", err)
			}
		})
	}
	row, raw := snapshotReferenceTestPlan(t)
	raw = snapshotReferenceTestMutation(t, raw, &row, func(plan, manifest map[string]any) {
		plan["target"].(map[string]any)["model"] = strings.Repeat("x", 513)
		manifest["options"].(map[string]any)["target"].(map[string]any)["model"] = strings.Repeat("x", 513)
	})
	got, err := snapshotReferencePlan(t.Context(), row, raw, false)
	if !errors.Is(err, errSnapshotReferenceInvalid) || !reflect.DeepEqual(got, snapshotReferenceObservation{}) {
		t.Fatal("model overflow returned a candidate", err)
	}
	row, raw = snapshotReferenceTestPlan(t)
	raw = snapshotReferenceTestMutation(t, raw, &row, func(plan, manifest map[string]any) {
		plan["target"].(map[string]any)["model"] = strings.Repeat("a", 256)
		manifest["options"].(map[string]any)["target"].(map[string]any)["model"] = strings.Repeat("b", 256)
	})
	got, err = snapshotReferencePlan(t.Context(), row, raw, false)
	if !errors.Is(err, errSnapshotReferenceInvalid) || !reflect.DeepEqual(got, snapshotReferenceObservation{}) {
		t.Fatal("long model identity mismatch returned a candidate", err)
	}
}

// Target/Estimate/Run use their actual authorized writers. The unsigned baseline
// row is only a structural persistence fixture using actual baselineJSON; it is
// not an analyzer run, MAC-authenticated baseline service call or approval.
func SnapshotReferenceModelCompatibilityDatabaseBridge(t *testing.T, model string, compile func(int64, TargetState) domain.ExecutionPlan) {
	t.Helper()
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, target, plan, policy := executionFixture(t, s, 1)
		replacement := target.Target
		replacement.Model = model
		target, err := tenant.UpdateTarget(target.Target.ID, target.Target.Version, replacement)
		if err != nil || target.Target.Model != model {
			t.Fatal("actual target writer lost bounded original model", err)
		}
		if compile != nil {
			plan = compile(tenant.orgID, target)
		} else {
			plan.Target.Version, plan.Target.Model = target.Target.Version, model
			for i := range plan.Probes {
				for j := range plan.Probes[i].Samples {
					plan.Probes[i].Samples[j].Request.Model = model
				}
			}
			plan, _, err = policy.Apply(plan)
			if err != nil {
				t.Fatal(err)
			}
			// Retained low-level writer history, not current generator/MAC proof.
			plan = snapshotReferenceTestAttachManifest(t, tenant.orgID, plan)
		}
		estimate, err := tenant.SaveRunEstimate(plan, policy)
		if err != nil {
			t.Fatal("actual estimate writer", err)
		}
		run, err := tenant.CreateRun(plan, policy, "model-byte-compatibility")
		if err != nil {
			t.Fatal("actual Run writer", err)
		}
		stamp := time.Now().UTC().Truncate(time.Microsecond)
		resultBody := `{"retained_result":"model-byte-compatibility"}`
		result := RunResultRecord{OrganizationID: tenant.orgID, RunID: run.ID, AnalysisRevision: 1, RiskLevel: "insufficient", EvidenceGrade: "D", Completeness: "INSUFFICIENT", ConclusionJSON: resultBody, CreatedAt: stamp}
		if err := s.db.Create(&result).Error; err != nil {
			t.Fatal(err)
		}
		manifest, _ := snapshotKeyObject(plan.Manifest)
		templateHash, _ := snapshotKeyJSONString(manifest["template_hash"])
		tokenizerHash, _ := snapshotKeyJSONString(manifest["tokenizer_hash"])
		scope := BaselineScope{SchemaVersion: "baseline.scope.v1", OrganizationID: tenant.orgID, RunID: run.ID, TargetID: run.TargetID, AnalysisRevision: 1, Model: model, Protocol: plan.Target.Protocol, MaxOutputParameter: plan.Target.MaxOutputParameter, Versions: plan.Versions, TemplateHash: templateHash, TokenizerHash: tokenizerHash, ParametersHash: strings.Repeat("c", 64), ManifestHash: plan.ManifestHash, ResultHash: baselineHash([]byte(resultBody)), Completeness: "INSUFFICIENT", SampledAt: stamp, Samples: []BaselineSampleScope{}}
		for _, probe := range plan.Probes {
			for range probe.Samples {
				scope.Samples = append(scope.Samples, BaselineSampleScope{TemplateID: probe.TemplateID, TemplateVersion: probe.TemplateVersion, VariablesHash: strings.Repeat("e", 64)})
			}
		}
		scope.ExpectedSamples = len(scope.Samples)
		raw, err := baselineJSON(scope)
		if err != nil {
			t.Fatal(err)
		}
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		baseline := BaselineRecord{ID: id, OrganizationID: tenant.orgID, RunID: run.ID, AnalysisRevision: 1, Name: "model compatibility", Model: model, Protocol: scope.Protocol, Status: "draft", ApplicableScopeJSON: `{"schema_version":"baseline.scope.v1"}`, CreatedAt: stamp, UpdatedAt: stamp, ExpiresAt: stamp.Add(time.Hour), Version: 1, Source: "historical", SourceManifestHash: scope.ManifestHash, SourceResultHash: scope.ResultHash, ParametersHash: scope.ParametersHash, SnapshotJSON: raw, SnapshotHash: baselineHash([]byte(raw))}
		if err := s.db.Create(&baseline).Error; err != nil {
			t.Fatal(err)
		}
		got := snapshotReferenceTestObserve(t, s, cfg, nil)
		if got.observed != [3]int64{1, 1, 1} || got.legacy != [3]int64{0, 0, 1} || got.classification != snapshotReferenceLegacyIncomplete || len(got.references) < 5 {
			t.Fatal("retained models rejected or unsigned baseline upgraded")
		}
		// Examine the bounded SQL projection and strict scope separately so an
		// accidental observation-only success cannot hide truncated model bytes.
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		var rows []snapshotReferenceRow
		if err := tx.Table("integrity_baselines r").Select(snapshotReferenceColumns(tx, snapshotReferenceSources()[2])).Find(&rows).Error; err != nil {
			closeView()
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Valid != 1 || rows[0].Model != model {
			closeView()
			t.Fatal("SQL model projection changed byte identity")
		}
		observedScope, legacy, err := snapshotReferenceBaselineScope(ctx, rows[0], []byte(raw))
		closeView()
		if err != nil || !legacy || observedScope.Model != model {
			t.Fatal("original scope model changed or trust upgraded", err)
		}
		var currentRun RunRecord
		var currentEstimate RunEstimateRecord
		var currentBaseline BaselineRecord
		if s.db.Where("id=?", run.ID).Take(&currentRun).Error != nil || s.db.Where("id=?", estimate.ID).Take(&currentEstimate).Error != nil || s.db.Where("id=?", baseline.ID).Take(&currentBaseline).Error != nil || currentRun.ConfigSnapshot != run.ConfigSnapshot || currentEstimate.SnapshotJSON != estimate.SnapshotJSON || currentBaseline.SnapshotJSON != raw || currentBaseline.Model != model {
			t.Fatal("observation rewrote retained original source")
		}
		// Overlength is rejected by SQL before the Model string enters Go.
		if err := s.db.Table("integrity_baselines").Where("id=?", baseline.ID).Update("model", strings.Repeat("x", 513)).Error; err != nil {
			t.Fatal(err)
		}
		invalidCtx, invalidTx, invalidClose := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer invalidClose()
		rows = nil
		if err := invalidTx.Table("integrity_baselines r").Select(snapshotReferenceColumns(invalidTx, snapshotReferenceSources()[2])).Find(&rows).Error; err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Valid != 0 || rows[0].Model != "" {
			t.Fatal("overlength baseline model crossed SQL pre-bound")
		}
		failed, err := s.snapshotArtifactReferences(invalidCtx, invalidTx)
		if !errors.Is(err, errSnapshotReferenceInvalid) || !reflect.DeepEqual(failed, snapshotArtifactReferences{}) {
			t.Fatal("overlength baseline returned a successful prefix", err)
		}
	})
}

func TestSnapshotReferenceModelCompatibilityRepositoryHistory(t *testing.T) {
	for _, model := range []string{strings.Repeat("x", 512), strings.Repeat("𠀀", 128)} {
		t.Run(fmt.Sprintf("bytes_%d_runes_%d", len(model), utf8.RuneCountInString(model)), func(t *testing.T) {
			SnapshotReferenceModelCompatibilityDatabaseBridge(t, model, nil)
		})
	}
}
