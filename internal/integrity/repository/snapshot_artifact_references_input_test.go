package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func snapshotReferenceInputAssert(t *testing.T, refs []snapshotArtifactReference, plan domain.ExecutionPlan, org int64, implementation, encoding string) {
	t.Helper()
	var manifest struct {
		TokenizerVersion string `json:"tokenizer_version"`
		TokenizerHash    string `json:"tokenizer_hash"`
	}
	if err := json.Unmarshal(plan.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	want := snapshotArtifactReference{org, "input_tokenizer_implementation", implementation, manifest.TokenizerHash, manifest.TokenizerVersion, encoding}
	for _, ref := range refs {
		if ref == want {
			return
		}
	}
	t.Fatal("actual compiler input tokenizer identity was not observed")
}

func SnapshotArtifactReferencesInputCompilerBridge(t *testing.T, plan domain.ExecutionPlan, org int64, implementation, encoding string) {
	t.Helper()
	source := AnalysisSourceLegacyV1
	if plan.AnalysisSourceVersion != "" {
		source = plan.AnalysisSourceVersion
	}
	row := snapshotReferenceRow{OrganizationID: org, ID: 23, TargetID: plan.Target.ID, ManifestHash: plan.ManifestHash, AnalysisSource: source, Rule: plan.Versions.Rule, Template: plan.Versions.Template, Scoring: plan.Versions.Scoring, Tokenizer: plan.Versions.Tokenizer}
	got, err := snapshotReferencePlan(t.Context(), row, snapshotReferenceTestJSON(t, executionSnapshot{Plan: plan}), false)
	if err != nil {
		t.Fatal(err)
	}
	refs := make(map[snapshotArtifactReference]struct{})
	if err := snapshotReferenceAccumulate(refs, org, got, 1000); err != nil {
		t.Fatal(err)
	}
	values := make([]snapshotArtifactReference, 0, len(refs))
	for ref := range refs {
		values = append(values, ref)
	}
	snapshotReferenceInputAssert(t, values, plan, org, implementation, encoding)
}

func SnapshotArtifactReferencesInputSourcesBridge(t *testing.T, compile func(int64, TargetState) domain.ExecutionPlan, implementation, encoding string) {
	t.Helper()
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, run, _, _ := snapshotReferenceTestFixture(t, s, compile)
		got := snapshotReferenceTestObserve(t, s, cfg, nil)
		if got.inputIncomplete != [3]int64{} || got.classification != snapshotReferenceObserved {
			t.Fatal("actual input identity incorrectly marked incomplete")
		}
		var snapshot executionSnapshot
		if err := json.Unmarshal([]byte(run.ConfigSnapshot), &snapshot); err != nil {
			t.Fatal(err)
		}
		snapshotReferenceInputAssert(t, got.references, snapshot.Plan, tenant.orgID, implementation, encoding)
	})
}

func snapshotReferenceInputTestValue() map[string]any {
	return map[string]any{"bundle_version": "token-1", "bundle_hash": strings.Repeat("b", 64), "tokenizer_version": snapshotReferenceInputBPE, "tokenizer_id": "cl100k_base", "quality": "compatible"}
}

func snapshotReferenceInputTestPlan(t *testing.T, value any, present bool) (snapshotReferenceRow, []byte) {
	t.Helper()
	row, raw := snapshotReferenceTestPlan(t)
	if present {
		raw = snapshotReferenceTestMutation(t, raw, &row, func(_, m map[string]any) {
			m["samples"].([]any)[0].(map[string]any)["input_estimate"] = value
		})
	}
	return row, raw
}

func TestSnapshotArtifactReferencesInputPureIdentityAndHistory(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutate  func(map[string]any)
		partial bool
	}{
		{"bpe", func(map[string]any) {}, false},
		{"o200k", func(v map[string]any) { v["tokenizer_id"] = "o200k_base" }, false},
		{"heuristic", func(v map[string]any) {
			v["quality"] = "heuristic"
			v["tokenizer_id"] = "unicode-byte-heuristic"
			v["tokenizer_version"] = "unicode-byte-v1"
		}, false},
		{"unknown-encoding", func(v map[string]any) { v["tokenizer_id"] = "未解析的历史编码" }, true},
		{"unknown-implementation", func(v map[string]any) { v["tokenizer_version"] = "历史算法+库@版本" }, true},
		{"unicode-bound", func(v map[string]any) { v["tokenizer_version"] = strings.Repeat("𐐀", 32) }, true},
		{"unknown-quality", func(v map[string]any) { v["quality"] = "历史质量" }, true},
		{"exact-is-not-current-input-producer", func(v map[string]any) { v["quality"] = "exact" }, true},
		{"unavailable", func(v map[string]any) { v["quality"] = "unavailable"; v["tokenizer_id"] = "" }, true},
		{"missing-configuration", func(v map[string]any) { delete(v, "bundle_version"); delete(v, "bundle_hash") }, true},
		{"missing-implementation", func(v map[string]any) { delete(v, "tokenizer_version") }, true},
		{"missing-encoding", func(v map[string]any) { delete(v, "tokenizer_id") }, true},
		{"missing-quality", func(v map[string]any) { delete(v, "quality") }, true},
		{"empty-object", func(v map[string]any) { clear(v) }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := snapshotReferenceInputTestValue()
			test.mutate(value)
			row, raw := snapshotReferenceInputTestPlan(t, value, true)
			original := bytes.Clone(raw)
			for _, estimate := range []bool{false, true} {
				got, err := snapshotReferencePlan(t.Context(), row, raw, estimate)
				if err != nil || got.legacy || got.inputIncomplete != test.partial {
					t.Fatal("original input metadata classification", err)
				}
				if len(value) > 0 {
					if len(got.inputTokenizers) != 1 {
						t.Fatal("lost partial/unknown identity")
					}
					input := got.inputTokenizers[0]
					if v, ok := value["tokenizer_version"]; ok && input.implementation != v {
						t.Fatal("implementation normalized/substituted")
					}
					if v, ok := value["tokenizer_id"]; ok && input.encoding != v {
						t.Fatal("encoding normalized/substituted")
					}
					if input.configurationVersion != row.Tokenizer || input.configurationHash != strings.Repeat("b", 64) {
						t.Fatal("lost same original container context")
					}
				}
			}
			if !bytes.Equal(raw, original) {
				t.Fatal("original body changed")
			}
		})
	}
	row, raw := snapshotReferenceInputTestPlan(t, nil, false)
	got, err := snapshotReferencePlan(t.Context(), row, raw, false)
	if err != nil || got.legacy || !got.inputIncomplete || len(got.inputTokenizers) != 0 {
		t.Fatal("missing storage-only input gained identity", err)
	}
	got, err = snapshotReferencePlan(t.Context(), row, []byte(`{"legacy_fixture":true}`), false)
	if err != nil || !got.legacy || !got.inputIncomplete {
		t.Fatal("original legacy classification changed", err)
	}
}

func TestSnapshotArtifactReferencesInputPureFaults(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
	}{
		{"null", nil}, {"array", []any{}}, {"string", "private-canary"}, {"number", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			row, raw := snapshotReferenceInputTestPlan(t, test.value, true)
			snapshotReferenceInputExpectInvalid(t, row, raw)
		})
	}
	for _, key := range []string{"bundle_version", "bundle_hash", "tokenizer_version", "tokenizer_id", "quality"} {
		for _, mode := range []string{"null", "number", "case", "overlength", "newline", "nul"} {
			t.Run(key+"/"+mode, func(t *testing.T) {
				value := snapshotReferenceInputTestValue()
				switch mode {
				case "null":
					value[key] = nil
				case "number":
					value[key] = 1
				case "case":
					value[strings.ToUpper(key)] = value[key]
					delete(value, key)
				case "overlength":
					value[key] = strings.Repeat("𐐀", 33)
				case "newline":
					value[key] = "private\ncanary"
				case "nul":
					value[key] = "private\x00canary"
				}
				row, raw := snapshotReferenceInputTestPlan(t, value, true)
				snapshotReferenceInputExpectInvalid(t, row, raw)
			})
		}
	}
	for _, changes := range []map[string]any{
		{"bundle_version": "other"}, {"bundle_hash": strings.Repeat("c", 64)}, {"bundle_hash": strings.Repeat("B", 64)},
		{"tokenizer_id": "unicode-byte-heuristic"}, {"tokenizer_version": "unicode-byte-v1"}, {"quality": "heuristic"}, //nolint:gosec // G101: public tokenizer implementation/encoding identifiers, not credentials.
		{"quality": "compatible", "tokenizer_version": "unicode-byte-v1", "tokenizer_id": "unicode-byte-heuristic"}, //nolint:gosec // G101: public tokenizer implementation/encoding identifiers, not credentials.
	} {
		value := snapshotReferenceInputTestValue()
		for key, v := range changes {
			value[key] = v
		}
		row, raw := snapshotReferenceInputTestPlan(t, value, true)
		snapshotReferenceInputExpectInvalid(t, row, raw)
	}
	row, raw := snapshotReferenceInputTestPlan(t, snapshotReferenceInputTestValue(), true)
	caseRow := row
	caseRaw := snapshotReferenceTestMutation(t, raw, &caseRow, func(_, manifest map[string]any) {
		sample := manifest["samples"].([]any)[0].(map[string]any)
		sample["Input_Estimate"] = sample["input_estimate"]
		delete(sample, "input_estimate")
	})
	// Rehash the case-only fixture so rejection cannot merely be stale SHA.
	snapshotReferenceInputExpectInvalid(t, caseRow, caseRaw)
	for _, pair := range [][2]string{{`"quality":`, `"QUALITY":"compatible","quality":`}, {`"quality":`, `"nested":{"s":1,"ſ":2},"quality":`}, {`"quality":`, `"nested":{"k":1,"K":2},"quality":`}} {
		snapshotReferenceInputExpectInvalid(t, row, bytes.Replace(raw, []byte(pair[0]), []byte(pair[1]), 1))
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := snapshotReferencePlan(ctx, row, raw, false); !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, snapshotReferenceObservation{}) {
		t.Fatal("cancellation returned input identity", err)
	}
}

func snapshotReferenceInputExpectInvalid(t *testing.T, row snapshotReferenceRow, raw []byte) {
	t.Helper()
	for _, estimate := range []bool{false, true} {
		if got, err := snapshotReferencePlan(t.Context(), row, raw, estimate); !errors.Is(err, errSnapshotReferenceInvalid) || !reflect.DeepEqual(got, snapshotReferenceObservation{}) {
			t.Fatal("invalid input returned observation", err)
		}
	}
}

func TestSnapshotArtifactReferencesInputPureUnionAndClosedRepresentation(t *testing.T) {
	row, raw := snapshotReferenceInputTestPlan(t, snapshotReferenceInputTestValue(), true)
	got, err := snapshotReferencePlan(t.Context(), row, raw, false)
	if err != nil {
		t.Fatal(err)
	}
	refs := map[snapshotArtifactReference]struct{}{}
	if err := snapshotReferenceAccumulate(refs, 17, got, 6); err != nil || len(refs) != 6 {
		t.Fatal("exact input union", err)
	}
	if err := snapshotReferenceAccumulate(refs, 17, got, 6); err != nil {
		t.Fatal("duplicate consumed union", err)
	}
	if err := snapshotReferenceAccumulate(refs, 18, got, 6); !errors.Is(err, errSnapshotReferenceLimit) {
		t.Fatal("tenant incorrectly flattened", err)
	}
	canary := "private-input-canary"
	value := snapshotReferenceInputTokenizer{canary, canary, canary, canary}
	for _, format := range []string{"%v", "%+v", "%#v", "%q", "%s"} {
		if strings.Contains(fmt.Sprintf(format, value), canary) {
			t.Fatal("format leak")
		}
	}
	if _, err := json.Marshal(value); err == nil {
		t.Fatal("implicit json")
	}
	if _, err := yaml.Marshal(value); err == nil {
		t.Fatal("implicit yaml")
	}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("observation", "value", value)
	if strings.Contains(logs.String(), canary) {
		t.Fatal("log leak")
	}
}

// Alter only test-owned, original-byte-preserving structural wires. The
// fixture's changed SHA does not assert a genuine compiler MAC or admission.
func snapshotReferenceInputEstimateWire(t *testing.T, raw string, encoding string) (string, string) {
	t.Helper()
	decode := func(raw []byte) map[string]json.RawMessage {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatal(err)
		}
		return object
	}
	outer := decode([]byte(raw))
	plan := decode(outer["plan"])
	manifest := decode(plan["manifest"])
	var samples []map[string]json.RawMessage
	if err := json.Unmarshal(manifest["samples"], &samples); err != nil {
		t.Fatal(err)
	}
	for _, sample := range samples {
		// RawMessage preserves CSPRNG int64 identifiers without float conversion.
		sample["input_estimate"] = snapshotReferenceTestJSON(t, map[string]json.RawMessage{
			"bundle_version": manifest["tokenizer_version"], "bundle_hash": manifest["tokenizer_hash"],
			"tokenizer_version": snapshotReferenceTestJSON(t, snapshotReferenceInputBPE),
			"tokenizer_id":      snapshotReferenceTestJSON(t, encoding), "quality": json.RawMessage(`"compatible"`),
		})
	}
	manifest["samples"] = snapshotReferenceTestJSON(t, samples)
	plan["manifest"] = snapshotReferenceTestJSON(t, manifest)
	hash := baselineHash(plan["manifest"])
	plan["manifest_hash"] = snapshotReferenceTestJSON(t, hash)
	outer["plan"] = snapshotReferenceTestJSON(t, plan)
	return string(snapshotReferenceTestJSON(t, outer)), hash
}

func TestSnapshotArtifactReferencesInputStoredHistorySameViewAndFaults(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, _, estimate, _ := snapshotReferenceTestFixture(t, s, nil)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		first, err := (&Store{driver: s.driver}).snapshotArtifactReferences(ctx, tx)
		if err != nil || first.inputIncomplete != [3]int64{1, 1, 4} {
			t.Fatal("original missing input classification", err)
		}
		update := func(encoding string) {
			raw, hash := snapshotReferenceInputEstimateWire(t, estimate.SnapshotJSON, encoding)
			if err := s.db.Model(&RunEstimateRecord{}).Where("organization_id=? AND id=?", tenant.orgID, estimate.ID).Updates(map[string]any{"snapshot_json": raw, "manifest_hash": hash}).Error; err != nil {
				t.Fatal("independent original estimate update", err)
			}
		}
		update("cl100k_base")
		second, err := (&Store{driver: s.driver}).snapshotArtifactReferences(ctx, tx)
		if err != nil || !reflect.DeepEqual(first, second) {
			t.Fatal("input observation escaped original physical snapshot", err)
		}
		closeView()
		fresh := snapshotReferenceTestObserve(t, s, cfg, nil)
		if fresh.inputIncomplete != [3]int64{1, 0, 4} || fresh.sourceSHA256[1] == first.sourceSHA256[1] || len(fresh.references) != len(first.references)+1 {
			t.Fatal("new view lost original input evidence or conflated baseline structural legacy")
		}
		update("合法未知历史编码")
		unknown := snapshotReferenceTestObserve(t, s, cfg, nil)
		if unknown.inputIncomplete != [3]int64{1, 1, 4} || unknown.legacy != [3]int64{} {
			t.Fatal("unknown input changed original structural legacy")
		}
		found := false
		for _, reference := range unknown.references {
			found = found || reference.category == "input_tokenizer_implementation" && reference.memberID == "合法未知历史编码"
		}
		if !found {
			t.Fatal("unknown original encoding dropped or defaulted")
		}
		// Estimate is scanned after Run. A supplied known-pair conflict must
		// reject the whole observation, not return the already valid Run prefix.
		update("unicode-byte-heuristic")
		snapshotReferenceTestObserve(t, s, cfg, errSnapshotReferenceInvalid)
	})
}
