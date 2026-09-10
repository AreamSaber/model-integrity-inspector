package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

// These are deliberately minimal structural wires, not forged authentication.
// The external-package tests additionally use the real signed compiler output.
func snapshotReferenceTestPlan(t *testing.T) (snapshotReferenceRow, []byte) {
	t.Helper()
	row := snapshotReferenceRow{OrganizationID: 17, ID: 23, TargetID: 31, Valid: 1, Rule: "rule-1", Template: "template-1", Scoring: "score-1", Tokenizer: "token-1", AnalysisSource: AnalysisSourceLegacyV1}
	manifest, _ := snapshotKeyTestManifest(t, row.OrganizationID, "key-1")
	var m map[string]any
	if json.Unmarshal(manifest, &m) != nil {
		t.Fatal("fixture")
	}
	m["options"].(map[string]any)["rule_version"] = row.Rule
	m["options"].(map[string]any)["scoring_version"] = row.Scoring
	m["options"].(map[string]any)["target"] = map[string]any{"id": row.TargetID}
	m["template_version"], m["tokenizer_version"] = row.Template, row.Tokenizer
	m["samples"] = []any{map[string]any{"ordinal": 0, "template_id": "member-1", "template_version": "2.1.0"}}
	manifest = snapshotReferenceTestJSON(t, m)
	row.ManifestHash = baselineHash(manifest)
	raw := snapshotReferenceTestJSON(t, map[string]any{"plan": map[string]any{
		"target":   map[string]any{"id": row.TargetID},
		"versions": domain.BundleVersions{Rule: row.Rule, Template: row.Template, Scoring: row.Scoring, Tokenizer: row.Tokenizer},
		"manifest": json.RawMessage(manifest), "manifest_hash": row.ManifestHash,
		"probes": []any{map[string]any{"template_id": "member-1", "template_version": "2.1.0", "samples": []any{map[string]any{"ordinal": 0}}}},
	}})
	return row, raw
}

func snapshotReferenceTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func snapshotReferenceTestMutation(t *testing.T, raw []byte, row *snapshotReferenceRow, mutate func(map[string]any, map[string]any)) []byte {
	t.Helper()
	var outer map[string]any
	if json.Unmarshal(raw, &outer) != nil {
		t.Fatal("fixture")
	}
	plan := outer["plan"].(map[string]any)
	manifest := plan["manifest"].(map[string]any)
	mutate(plan, manifest)
	encoded := snapshotReferenceTestJSON(t, manifest)
	row.ManifestHash, plan["manifest_hash"] = baselineHash(encoded), baselineHash(encoded)
	return snapshotReferenceTestJSON(t, outer)
}

func TestSnapshotArtifactReferencesPureOriginalBindings(t *testing.T) {
	row, raw := snapshotReferenceTestPlan(t)
	before := bytes.Clone(raw)
	got, err := snapshotReferencePlan(t.Context(), row, raw, false)
	if err != nil || got.legacy || got.versions.Rule != row.Rule || got.templateHash != strings.Repeat("a", 64) || len(got.members) != 1 || got.members[0].Version == row.Template {
		t.Fatal("original distinct member/bundle references", err)
	}
	if !bytes.Equal(raw, before) {
		t.Fatal("rewrote original source")
	}
	estimate := row
	estimate.Rule, estimate.Template, estimate.Scoring, estimate.Tokenizer, estimate.AnalysisSource = "", "", "", "", ""
	other, err := snapshotReferencePlan(t.Context(), estimate, raw, true)
	if err != nil || !reflect.DeepEqual(other, got) {
		t.Fatal("estimate lost original references", err)
	}
	legacy, err := snapshotReferencePlan(t.Context(), row, []byte(`{"legacy_fixture":true}`), false)
	if err != nil || !legacy.legacy || legacy.versions.Rule != row.Rule || legacy.templateHash != "" {
		t.Fatal("legacy metadata upgraded/discarded", err)
	}
	for _, estimate := range []bool{false, true} {
		derived := row
		derived.AnalysisSource = domain.AnalysisSourceDerivedV1
		if got, err := snapshotReferencePlan(t.Context(), derived, []byte(`{"legacy_fixture":true}`), estimate); !errors.Is(err, errSnapshotReferenceInvalid) || !reflect.DeepEqual(got, snapshotReferenceObservation{}) {
			t.Fatal("modern missing manifest silently downgraded")
		}
	}
}

func TestSnapshotArtifactReferencesPureLegacyProbeLocalOrdinals(t *testing.T) {
	row, raw := snapshotReferenceTestPlan(t)
	var object map[string]any
	if json.Unmarshal(raw, &object) != nil {
		t.Fatal("fixture")
	}
	plan := object["plan"].(map[string]any)
	delete(plan, "manifest")
	probe := plan["probes"].([]any)[0].(map[string]any)
	probe["samples"].([]any)[0].(map[string]any)["ordinal"] = 97
	plan["probes"] = []any{probe, probe}
	got, err := snapshotReferencePlan(t.Context(), row, snapshotReferenceTestJSON(t, object), false)
	if err != nil || !got.legacy || len(got.members) != 2 {
		t.Fatal("legacy writer permits per-probe ordinals, not globally consecutive", err)
	}
}

func TestSnapshotArtifactReferencesPurePlanFaults(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]any, map[string]any)
		want   error
	}{
		{"missing-versions", func(p, _ map[string]any) { delete(p, "versions") }, errSnapshotReferenceInvalid},
		{"null-versions", func(p, _ map[string]any) { p["versions"] = nil }, errSnapshotReferenceInvalid},
		{"case-versions", func(p, _ map[string]any) { p["Versions"] = p["versions"]; delete(p, "versions") }, errSnapshotReferenceInvalid},
		{"missing-template", func(p, _ map[string]any) { delete(p["versions"].(map[string]any), "template") }, errSnapshotReferenceInvalid},
		{"version-mismatch", func(p, _ map[string]any) { p["versions"].(map[string]any)["rule"] = "different" }, errSnapshotReferenceInvalid},
		{"case-version-key", func(p, _ map[string]any) {
			v := p["versions"].(map[string]any)
			v["Rule"] = v["rule"]
			delete(v, "rule")
		}, errSnapshotReferenceInvalid},
		{"version-overlength", func(p, _ map[string]any) { p["versions"].(map[string]any)["tokenizer"] = strings.Repeat("v", 129) }, errSnapshotReferenceInvalid},
		{"missing-target", func(p, _ map[string]any) { delete(p, "target") }, errSnapshotReferenceInvalid},
		{"null-target", func(p, _ map[string]any) { p["target"] = nil }, errSnapshotReferenceInvalid},
		{"wrong-target", func(p, _ map[string]any) { p["target"].(map[string]any)["id"] = 32 }, errSnapshotReferenceInvalid},
		{"target-case", func(p, _ map[string]any) {
			p["target"].(map[string]any)["ID"] = 31
			delete(p["target"].(map[string]any), "id")
		}, errSnapshotReferenceInvalid},
		{"target-string", func(p, _ map[string]any) { p["target"].(map[string]any)["id"] = "31" }, errSnapshotReferenceInvalid},
		{"manifest-target", func(_, m map[string]any) { m["options"].(map[string]any)["target"].(map[string]any)["id"] = 32 }, errSnapshotReferenceInvalid},
		{"foreign-org", func(_, m map[string]any) { m["options"].(map[string]any)["organization_id"] = "18" }, errSnapshotReferenceInvalid},
		{"rule-option", func(_, m map[string]any) { m["options"].(map[string]any)["rule_version"] = "different" }, errSnapshotReferenceInvalid},
		{"scoring-option", func(_, m map[string]any) { m["options"].(map[string]any)["scoring_version"] = "different" }, errSnapshotReferenceInvalid},
		{"template-hash", func(_, m map[string]any) { m["template_hash"] = strings.Repeat("A", 64) }, errSnapshotReferenceInvalid},
		{"tokenizer-hash", func(_, m map[string]any) { m["tokenizer_hash"] = "carrier-hash-is-not-config-hash" }, errSnapshotReferenceInvalid},
		{"source-downgrade", func(p, _ map[string]any) { p["analysis_source_version"] = domain.AnalysisSourceDerivedV1 }, errSnapshotReferenceInvalid},
		{"empty-probes", func(p, _ map[string]any) { p["probes"] = []any{} }, errSnapshotReferenceInvalid},
		{"null-probes", func(p, _ map[string]any) { p["probes"] = nil }, errSnapshotReferenceInvalid},
		{"member-mismatch", func(p, _ map[string]any) { p["probes"].([]any)[0].(map[string]any)["template_version"] = "3.0.0" }, errSnapshotReferenceInvalid},
		{"missing-ordinal", func(p, _ map[string]any) {
			delete(p["probes"].([]any)[0].(map[string]any)["samples"].([]any)[0].(map[string]any), "ordinal")
		}, errSnapshotReferenceInvalid},
		{"ordinal-gap", func(p, _ map[string]any) {
			p["probes"].([]any)[0].(map[string]any)["samples"].([]any)[0].(map[string]any)["ordinal"] = 2
		}, errSnapshotReferenceInvalid},
		{"duplicate-ordinal", func(p, _ map[string]any) { p["probes"] = append(p["probes"].([]any), p["probes"].([]any)[0]) }, errSnapshotReferenceInvalid},
		{"missing-manifest-ordinal", func(_, m map[string]any) { delete(m["samples"].([]any)[0].(map[string]any), "ordinal") }, errSnapshotReferenceInvalid},
		{"manifest-order", func(_, m map[string]any) { m["samples"].([]any)[0].(map[string]any)["ordinal"] = 1 }, errSnapshotReferenceInvalid},
		{"unknown-generator", func(_, m map[string]any) { m["generator_version"] = "9.9.9" }, errSnapshotReferenceUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			row, raw := snapshotReferenceTestPlan(t)
			raw = snapshotReferenceTestMutation(t, raw, &row, test.mutate)
			got, err := snapshotReferencePlan(t.Context(), row, raw, false)
			if !errors.Is(err, test.want) || !reflect.DeepEqual(got, snapshotReferenceObservation{}) {
				t.Fatal("not closed", err)
			}
		})
	}
	row, raw := snapshotReferenceTestPlan(t)
	for _, bad := range [][]byte{append(bytes.Clone(raw), 'x'), bytes.Replace(raw, []byte(`"versions":`), []byte(`"versions":null,"Versions":`), 1), []byte(`{"legacy_fixture":true,"nested":{"s":1,"ſ":2}}`), []byte(`{"legacy_fixture":true,"nested":{"k":1,"K":2}}`), []byte(`{"Plan":{}}`), []byte(`{"plan":null}`)} {
		if got, err := snapshotReferencePlan(t.Context(), row, bad, false); !errors.Is(err, errSnapshotReferenceInvalid) || !reflect.DeepEqual(got, snapshotReferenceObservation{}) {
			t.Fatal("strict JSON alias/trailing accepted", err)
		}
	}
	row.ManifestHash = strings.Repeat("f", 64)
	if _, err := snapshotReferencePlan(t.Context(), row, raw, false); !errors.Is(err, errSnapshotReferenceInvalid) {
		t.Fatal("original hash mismatch")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := snapshotReferencePlan(ctx, row, raw, false); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cancellation", err)
	}
}

func snapshotReferenceTestScope(t *testing.T) (snapshotReferenceRow, BaselineScope, []byte) {
	t.Helper()
	row := snapshotReferenceRow{OrganizationID: 17, ID: 27, RunID: 23, Revision: 1, Valid: 1, Model: "model", Protocol: "openai_chat", ManifestHash: strings.Repeat("a", 64), ResultHash: strings.Repeat("b", 64), ParametersHash: strings.Repeat("c", 64)}
	scope := BaselineScope{SchemaVersion: "baseline.scope.v1", OrganizationID: 17, RunID: 23, TargetID: 31, AnalysisRevision: 1, Model: row.Model, Protocol: row.Protocol, Versions: domain.BundleVersions{Rule: "r", Template: "t", Scoring: "historical-scoring-not-current", Tokenizer: "tok"}, ManifestHash: row.ManifestHash, ResultHash: row.ResultHash, ParametersHash: row.ParametersHash, TemplateHash: strings.Repeat("d", 64), TokenizerHash: strings.Repeat("e", 64), ExpectedSamples: 1, ValidSamples: 0, Completeness: "INSUFFICIENT", SampledAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), Samples: []BaselineSampleScope{{TemplateID: "member", TemplateVersion: "1.1.0", VariablesHash: strings.Repeat("f", 64)}}}
	raw := snapshotReferenceTestJSON(t, scope)
	row.SnapshotHash = baselineHash(raw)
	return row, scope, raw
}

func TestSnapshotArtifactReferencesPureBaselineScope(t *testing.T) {
	row, scope, raw := snapshotReferenceTestScope(t)
	got, legacy, err := snapshotReferenceBaselineScope(t.Context(), row, raw)
	if err != nil || legacy || !reflect.DeepEqual(got, scope) {
		t.Fatal("current scope rejected using today's scoring version", err)
	}
	row.Unsigned = 1
	if _, legacy, err := snapshotReferenceBaselineScope(t.Context(), row, raw); err != nil || !legacy {
		t.Fatal("complete unsigned observation upgraded", err)
	}
	for _, change := range []func(*BaselineScope){
		func(s *BaselineScope) { s.OrganizationID++ }, func(s *BaselineScope) { s.RunID++ }, func(s *BaselineScope) { s.AnalysisRevision++ },
		func(s *BaselineScope) { s.Model = "other" }, func(s *BaselineScope) { s.ParametersHash = strings.Repeat("d", 64) },
		func(s *BaselineScope) { s.TemplateHash = "bad" }, func(s *BaselineScope) { s.Samples[0].VariablesHash = "bad" },
		func(s *BaselineScope) { s.Versions.Rule = "" }, func(s *BaselineScope) { s.ExpectedSamples++ },
	} {
		row, scope, _ := snapshotReferenceTestScope(t)
		change(&scope)
		bad := snapshotReferenceTestJSON(t, scope)
		row.SnapshotHash = baselineHash(bad)
		if got, _, err := snapshotReferenceBaselineScope(t.Context(), row, bad); !errors.Is(err, errSnapshotReferenceInvalid) || !reflect.DeepEqual(got, BaselineScope{}) {
			t.Fatal("scope binding not closed", err)
		}
	}
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"OrganizationID":`), []byte(`"organizationID":`), 1), append(bytes.Clone(raw), ' '), bytes.Replace(raw, []byte(`"TemplateHash":`), []byte(`"TemplateHash":"ignored","templatehash":`), 1)} {
		row.SnapshotHash = baselineHash(bad)
		if _, _, err := snapshotReferenceBaselineScope(t.Context(), row, bad); !errors.Is(err, errSnapshotReferenceInvalid) {
			t.Fatal("non-original current canonical scope", err)
		}
	}
	legacyRow := snapshotReferenceRow{Unsigned: 1}
	if _, legacy, err := snapshotReferenceBaselineScope(t.Context(), legacyRow, []byte("{ }")); err != nil || !legacy {
		t.Fatal("old empty original object lost", err)
	}
	legacyRow.ResultHash = strings.Repeat("b", 64)
	if _, _, err := snapshotReferenceBaselineScope(t.Context(), legacyRow, []byte("{}")); !errors.Is(err, errSnapshotReferenceInvalid) {
		t.Fatal("partial legacy default accepted")
	}
}

func TestSnapshotArtifactReferencesPureUnionAndRepresentation(t *testing.T) {
	row, raw := snapshotReferenceTestPlan(t)
	observation, err := snapshotReferencePlan(t.Context(), row, raw, false)
	if err != nil {
		t.Fatal(err)
	}
	refs := make(map[snapshotArtifactReference]struct{})
	if err := snapshotReferenceAccumulate(refs, 17, observation, 5); err != nil || len(refs) != 5 {
		t.Fatal("exact distinct limit", err)
	}
	if err := snapshotReferenceAccumulate(refs, 17, observation, 5); err != nil {
		t.Fatal("duplicate roots consume budget", err)
	}
	if err := snapshotReferenceAccumulate(refs, 18, observation, 5); !errors.Is(err, errSnapshotReferenceLimit) {
		t.Fatal("foreign identity incorrectly deduped")
	}
	if err := snapshotReferenceAccumulate(refs, 18, observation, 10); err != nil || len(refs) != 10 {
		t.Fatal("same versions different tenant", err)
	}
	observation.templateHash = strings.Repeat("f", 64)
	if err := snapshotReferenceAccumulate(refs, 17, observation, 12); err != nil || len(refs) != 12 {
		t.Fatal("same label different original template hash flattened", err)
	}
	canary := "private-reference-canary"
	for _, value := range []any{snapshotArtifactReferences{sourceSHA256: [3]string{canary}}, snapshotArtifactReference{version: canary}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(verb, value), canary) {
				t.Fatal("fmt reference disclosure")
			}
		}
		var output bytes.Buffer
		slog.New(slog.NewJSONHandler(&output, nil)).Info("fixture", "value", value)
		if strings.Contains(output.String(), canary) {
			t.Fatal("slog reference disclosure")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit JSON allowed")
		}
		if _, err := yaml.Marshal(value); err == nil {
			t.Fatal("implicit YAML allowed")
		}
	}
	digest := func(value any) string {
		h := sha256.New()
		snapshotReferenceFrame(h, value)
		return hex.EncodeToString(h.Sum(nil))
	}
	if digest([]string{"ab", "c"}) == digest([]string{"a", "bc"}) || digest([]string{"1"}) == digest([]int{1}) {
		t.Fatal("ambiguous observation framing")
	}
}

// External test packages can supply genuine compiler output without creating
// a production repository -> generator -> secret -> repository import cycle.
func SnapshotArtifactReferencesPureCompilerBridge(t *testing.T, plan domain.ExecutionPlan, org int64) {
	t.Helper()
	raw := snapshotReferenceTestJSON(t, executionSnapshot{Plan: plan})
	source := AnalysisSourceLegacyV1
	if plan.AnalysisSourceVersion != "" {
		source = plan.AnalysisSourceVersion
	}
	row := snapshotReferenceRow{OrganizationID: org, ID: 23, TargetID: plan.Target.ID, ManifestHash: plan.ManifestHash, AnalysisSource: source, Rule: plan.Versions.Rule, Template: plan.Versions.Template, Scoring: plan.Versions.Scoring, Tokenizer: plan.Versions.Tokenizer}
	got, err := snapshotReferencePlan(t.Context(), row, raw, false)
	if err != nil || got.legacy || len(got.members) == 0 {
		t.Fatal("real compiler references", err)
	}
}
