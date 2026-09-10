package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func snapshotResultTestWire(t *testing.T) (snapshotResultReferenceRow, snapshotReferenceRow, snapshotReferenceObservation, map[string]any) {
	t.Helper()
	run, raw := snapshotReferenceTestPlan(t)
	source, err := snapshotReferencePlan(t.Context(), run, raw, false)
	if err != nil {
		t.Fatal(err)
	}
	row := snapshotResultReferenceRow{OrganizationID: run.OrganizationID, RunID: run.ID, Revision: 1, Published: 1, Valid: 1}
	body := map[string]any{"schema_version": "mii.analysis.v1",
		"features": map[string]any{"version": "features-original", "organization_id": strconv.FormatInt(row.OrganizationID, 10), "run_id": strconv.FormatInt(row.RunID, 10), "manifest_hash": run.ManifestHash, "samples": []any{map[string]any{"sample_id": "57", "ordinal": 0, "template_id": "member-1", "template_version": "2.1.0", "structure": map[string]any{"version": "structure-original"}, "local": map[string]any{"bundle_version": run.Tokenizer, "bundle_hash": source.tokenizerHash, "tokenizer_id": "encoding-original", "tokenizer_version": "implementation-original"}}}},
		"scores":   map[string]any{"Version": run.Scoring, "RulesHash": strings.Repeat("c", 64), "TokenRulesHash": strings.Repeat("d", 64)},
		"tokens":   map[string]any{"Version": "tokenrisk-original-not-tokenizer", "RulesHash": strings.Repeat("d", 64), "Series": []any{map[string]any{"TokenizerID": "encoding-original", "TokenizerVersion": "implementation-original"}}},
		"behavior": map[string]any{"version": "behavior-original", "samples": []any{map[string]any{"version": "behavior-original", "sample_id": "57"}}, "auxiliary_samples": []any{}},
	}
	return row, run, source, body
}

func TestSnapshotResultReferencesPureOriginalRoles(t *testing.T) {
	row, run, source, body := snapshotResultTestWire(t)
	raw := snapshotReferenceTestJSON(t, body)
	before := bytes.Clone(raw)
	got, err := snapshotResultReferenceDocument(t.Context(), row, run, source, raw, snapshotReferenceLimit)
	if err != nil || got.incomplete || got.unknown || !bytes.Equal(raw, before) {
		t.Fatal("complete original observation", err)
	}
	want := map[string]string{"scoring_parameters": strings.Repeat("c", 64), "tokenrisk_parameters": strings.Repeat("d", 64), "scoring_tokenrisk_binding": strings.Repeat("d", 64), "tokenizer_configuration": source.tokenizerHash, "template_member": "", "feature_implementation": "", "structure_implementation": "", "behavior_implementation": "", "tokenizer_implementation": ""}
	if len(got.refs) != len(want) {
		t.Fatal("missing or confused reference roles", len(got.refs))
	}
	for ref := range got.refs {
		hash, found := want[ref.role]
		if !found || ref.sha256 != hash || ref.organizationID != row.OrganizationID || ref.versions != source.versions {
			t.Fatal("reference role/source lost")
		}
		if ref.role == "tokenrisk_parameters" && ref.version == run.Tokenizer {
			t.Fatal("tokenrisk confused with tokenizer bundle")
		}
	}
	clear(raw)
	for ref := range got.refs {
		if ref.version == "" {
			t.Fatal("reference aliases original mutable bytes")
		}
	}
	if _, err := snapshotResultReferenceDocument(t.Context(), row, run, source, before, len(want)); err != nil {
		t.Fatal("exact distinct bound", err)
	}
	got, err = snapshotResultReferenceDocument(t.Context(), row, run, source, before, len(want)-1)
	if !errors.Is(err, errSnapshotResultReferenceLimit) || !reflect.DeepEqual(got, snapshotResultObservation{}) {
		t.Fatal("limit not closed", err)
	}
}

func TestSnapshotResultReferencesPureInvalidSuppliedFields(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"org", func(b map[string]any) { b["features"].(map[string]any)["organization_id"] = "18" }},
		{"run-number", func(b map[string]any) { b["features"].(map[string]any)["run_id"] = 23 }},
		{"run-leading-zero", func(b map[string]any) { b["features"].(map[string]any)["run_id"] = "023" }},
		{"manifest", func(b map[string]any) { b["features"].(map[string]any)["manifest_hash"] = strings.Repeat("a", 64) }},
		{"score-version", func(b map[string]any) { b["scores"].(map[string]any)["Version"] = "another" }},
		{"score-null", func(b map[string]any) { b["scores"].(map[string]any)["RulesHash"] = nil }},
		{"score-case", func(b map[string]any) { b["scores"].(map[string]any)["version"] = "score-1" }},
		{"hash-uppercase", func(b map[string]any) { b["tokens"].(map[string]any)["RulesHash"] = strings.Repeat("D", 64) }},
		{"hash-conflict", func(b map[string]any) { b["tokens"].(map[string]any)["RulesHash"] = strings.Repeat("e", 64) }},
		{"version-overlong", func(b map[string]any) { b["tokens"].(map[string]any)["Version"] = strings.Repeat("x", 129) }},
		{"tokens-null", func(b map[string]any) { b["tokens"] = nil }},
		{"samples-null", func(b map[string]any) { b["features"].(map[string]any)["samples"] = nil }},
		{"member-conflict", func(b map[string]any) {
			b["features"].(map[string]any)["samples"].([]any)[0].(map[string]any)["template_id"] = "another"
		}},
		{"ordinal-null", func(b map[string]any) {
			b["features"].(map[string]any)["samples"].([]any)[0].(map[string]any)["ordinal"] = nil
		}},
		{"ordinal-conflict", func(b map[string]any) {
			b["features"].(map[string]any)["samples"].([]any)[0].(map[string]any)["ordinal"] = 1
		}},
		{"nested-id", func(b map[string]any) {
			b["behavior"].(map[string]any)["samples"].([]any)[0].(map[string]any)["sample_id"] = "58"
		}},
		{"nested-version", func(b map[string]any) {
			b["behavior"].(map[string]any)["samples"].([]any)[0].(map[string]any)["version"] = "other"
		}},
		{"local-bundle", func(b map[string]any) {
			b["features"].(map[string]any)["samples"].([]any)[0].(map[string]any)["local"].(map[string]any)["bundle_version"] = "other"
		}},
		{"local-hash", func(b map[string]any) {
			b["features"].(map[string]any)["samples"].([]any)[0].(map[string]any)["local"].(map[string]any)["bundle_hash"] = strings.Repeat("f", 64)
		}},
		{"series-empty-id", func(b map[string]any) {
			b["tokens"].(map[string]any)["Series"].([]any)[0].(map[string]any)["TokenizerID"] = ""
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row, run, source, body := snapshotResultTestWire(t)
			tc.change(body)
			got, err := snapshotResultReferenceDocument(t.Context(), row, run, source, snapshotReferenceTestJSON(t, body), snapshotReferenceLimit)
			if !errors.Is(err, errSnapshotResultReferenceInvalid) || !reflect.DeepEqual(got, snapshotResultObservation{}) {
				t.Fatal("invalid not closed", err)
			}
		})
	}
}

func TestSnapshotResultReferencesPureMissingUnknownAndCancellation(t *testing.T) {
	row, run, source, body := snapshotResultTestWire(t)
	for _, analysisSource := range []string{AnalysisSourceLegacyV1, "attempt_derived_v1"} {
		run.AnalysisSource = analysisSource
		delete(body["scores"].(map[string]any), "RulesHash")
		got, err := snapshotResultReferenceDocument(t.Context(), row, run, source, snapshotReferenceTestJSON(t, body), snapshotReferenceLimit)
		if err != nil || !got.incomplete || got.unknown {
			t.Fatal("writer-allowed missing metadata lost", err)
		}
	}
	for _, raw := range []string{`{}`, `{"schema_version":"future.2","features":{"organization_id":null},"scores":{"RulesHash":"not-today"}}`} {
		got, err := snapshotResultReferenceDocument(t.Context(), row, run, source, []byte(raw), snapshotReferenceLimit)
		if err != nil || !got.incomplete || !got.unknown || len(got.refs) != 0 {
			t.Fatal("unknown codec guessed", err)
		}
	}
	if got, err := snapshotResultReferenceDocument(t.Context(), row, run, source, []byte(`[]`), snapshotReferenceLimit); !errors.Is(err, errSnapshotResultReferenceUnsupported) || !reflect.DeepEqual(got, snapshotResultObservation{}) {
		t.Fatal("non-object codec", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := snapshotResultReferenceDocument(ctx, row, run, source, []byte(`{}`), snapshotReferenceLimit); !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, snapshotResultObservation{}) {
		t.Fatal("canceled", err)
	}
	legacy := source
	legacy.legacy = true
	member, partial, err := snapshotResultMember(map[string]json.RawMessage{"ordinal": json.RawMessage(`9223372036854775807`), "sample_id": json.RawMessage(`"9223372036854775807"`), "template_id": json.RawMessage(`"member-1"`), "template_version": json.RawMessage(`"2.1.0"`)}, legacy)
	if err != nil || partial || member.ordinal != 9223372036854775807 {
		t.Fatal("native historical ordinal truncated", err)
	}
}

func TestSnapshotResultReferencesPureJSONAndFormattingClosed(t *testing.T) {
	for _, raw := range []string{`{"scores":{"Version":1,"version":2}}`, `{"outer":{"s":1,"\u017f":2}}`, `{"outer":{"k":1,"\u212a":2}}`, `{} {}`, `{"x":`, `{"x":"` + string([]byte{255}) + `"}`} {
		if err := snapshotResultStrictJSON(t.Context(), []byte(raw)); !errors.Is(err, errSnapshotResultReferenceInvalid) {
			t.Fatal("strict JSON accepted", err)
		}
	}
	for _, raw := range []string{strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66), `{"` + strings.Repeat("k", 129) + `":1}`} {
		if err := snapshotResultStrictJSON(t.Context(), []byte(raw)); !errors.Is(err, errSnapshotResultReferenceLimit) {
			t.Fatal("structural limit", err)
		}
	}
	marker := "private-result-reference-marker"
	for _, v := range []any{snapshotResultReference{version: marker}, snapshotResultReferences{sourceSHA256: marker}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(verb, v), marker) {
				t.Fatal("fmt leak")
			}
		}
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("JSON exposed")
		}
		if _, err := yaml.Marshal(v); err == nil {
			t.Fatal("YAML exposed")
		}
		var log bytes.Buffer
		slog.New(slog.NewJSONHandler(&log, nil)).Info("result", "value", v)
		if strings.Contains(log.String(), marker) {
			t.Fatal("log exposed")
		}
	}
}
