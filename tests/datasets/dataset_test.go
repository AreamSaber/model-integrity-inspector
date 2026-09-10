package datasets

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func exampleInput(id, content string) Input {
	return Input{SchemaVersion: SchemaVersion, CaseID: id, Samples: []Sample{{
		SampleID: "sample-01", ProbeFamily: "format_contract", Language: "en-US",
		Request:   RequestSnapshot{Model: "test-model", Messages: []Message{{Role: "user", Content: "Return only OK"}}, MaxOutputTokens: 64},
		Response:  ResponseSnapshot{HTTPStatus: 200, Content: content, ModelReported: "test-model", FinishReason: "stop", DurationMS: 10},
		Tokenizer: Tokenizer{Quality: "unavailable"},
	}}}
}

func makeManifest(t *testing.T, inputs ...Input) Manifest {
	t.Helper()
	manifest := Manifest{SchemaVersion: SchemaVersion, DatasetVersion: "example-1"}
	for index, input := range inputs {
		fingerprint, err := Fingerprint(input)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Cases = append(manifest.Cases, CaseRef{CaseID: input.CaseID, Split: Development, LineageID: "lineage-" + strconv.Itoa(index), InputSHA256: fingerprint, Coverage: []string{"normal"}})
	}
	return manifest
}

func TestStrictDetectorBoundary(t *testing.T) {
	input := exampleInput("c-001", "OK")
	encoded, _ := json.Marshal(input)
	if _, err := DecodeInput(bytes.NewReader(encoded)); err != nil {
		t.Fatal(err)
	}
	for _, payload := range []string{
		strings.Replace(string(encoded), `"case_id":"c-001"`, `"case_id":"c-001","labels":["normal"]`, 1),
		strings.Replace(string(encoded), `"model":"test-model"`, `"model":"test-model","scenario":"fixed_cap"`, 1),
		strings.Replace(string(encoded), `"http_status":200`, `"http_status":200,"expected_risk":90`, 1),
		strings.Replace(string(encoded), `"quality":"unavailable"`, `"quality":"unavailable","ground_truth":true`, 1),
		string(encoded) + ` {"label":"normal"}`,
	} {
		if _, err := DecodeInput(strings.NewReader(payload)); err == nil {
			t.Fatalf("accepted oracle payload: %s", payload)
		}
	}
}

func TestPartitionAndLabelIsolation(t *testing.T) {
	a, b := exampleInput("c-001", "OK"), exampleInput("c-002", "NOTICE OK")
	manifest := makeManifest(t, a, b)
	manifest.Cases[1].Split = Blind
	if err := ValidatePartition(manifest, Development, []Input{a}); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePartition(manifest, Blind, []Input{b}); err != nil {
		t.Fatal(err)
	}
	if ValidatePartition(manifest, Development, []Input{b}) == nil {
		t.Fatal("cross-split input accepted")
	}
	if ValidatePartition(manifest, Development, []Input{a, b}) == nil {
		t.Fatal("extra input accepted")
	}
	if ValidateLabels(manifest, Development, []Label{{CaseID: b.CaseID, Conditions: []string{"hidden_instruction"}, Rationale: "synthetic"}}) == nil {
		t.Fatal("blind label entered development partition")
	}
	if err := ValidateLabels(manifest, Development, []Label{{CaseID: a.CaseID, Conditions: []string{"normal"}, Rationale: "synthetic no mutation"}}); err != nil {
		t.Fatal(err)
	}
	a.Samples[0].Response.Content = "modified"
	if ValidatePartition(manifest, Development, []Input{a}) == nil {
		t.Fatal("changed input accepted")
	}
}

func TestCloneAndLineageIsolation(t *testing.T) {
	a := exampleInput("c-001", "OK")
	b := exampleInput("c-002", "OK")
	b.Samples[0].SampleID = "renamed"
	manifest := makeManifest(t, a, b)
	manifest.Cases[1].Split = Calibration
	if ValidateManifest(manifest) == nil {
		t.Fatal("renamed duplicate crossed partitions")
	}
	b.Samples[0].Response.Content = "Okay"
	manifest = makeManifest(t, a, b)
	manifest.Cases[1].Split = Calibration
	manifest.Cases[1].LineageID = manifest.Cases[0].LineageID
	if ValidateManifest(manifest) == nil {
		t.Fatal("related variants crossed partitions")
	}
}

func TestIncompleteDatasetCannotClaimReleaseReadiness(t *testing.T) {
	manifest := makeManifest(t, exampleInput("c-001", "OK"))
	if ValidateCoverage(manifest, Development) == nil {
		t.Fatal("one example claimed full coverage")
	}
	manifest.Cases[0].Coverage = append([]string(nil), RequiredCoverage...)
	if err := ValidateCoverage(manifest, Development); err != nil {
		t.Fatal(err)
	}
	if ValidateCoverage(manifest, Blind) == nil {
		t.Fatal("empty blind split claimed full coverage")
	}
	manifest.FrozenAt = "not-a-date"
	if ValidateManifest(manifest) == nil {
		t.Fatal("invalid freeze timestamp accepted")
	}
}

func TestUnknownTokenizerAndReasoningRemainObservation(t *testing.T) {
	input := exampleInput("c-001", "OK")
	count := int64(20)
	input.Samples[0].Tokenizer.LocalTokenCount = &count
	if ValidateInput(input) == nil {
		t.Fatal("unavailable tokenizer claimed local token count")
	}
	input.Samples[0].Tokenizer = Tokenizer{ID: "fixture", Version: "1", Quality: "heuristic", LocalTokenCount: &count}
	input.Samples[0].Response.ReasoningTokens = &count
	if err := ValidateInput(input); err != nil {
		t.Fatal(err)
	}
	count = -1
	if ValidateInput(input) == nil {
		t.Fatal("negative usage accepted")
	}
}

func TestContradictoryLabelsRejected(t *testing.T) {
	manifest := makeManifest(t, exampleInput("c-001", "OK"))
	for _, conditions := range [][]string{{"normal", "fixed_cap"}, {"unknown"}, {"normal", "normal"}} {
		if ValidateLabels(manifest, Development, []Label{{CaseID: "c-001", Conditions: conditions, Rationale: "test"}}) == nil {
			t.Fatal("bad label accepted")
		}
	}
}

func TestPublicDevelopmentExample(t *testing.T) {
	file, err := os.Open(filepath.Join("examples", "c-001.input.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	input, err := DecodeInput(file)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := Fingerprint(input)
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, err := os.ReadFile(filepath.Join("examples", "manifest.development.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Cases) != 1 || manifest.Cases[0].InputSHA256 != hash || manifest.FrozenAt != "" {
		t.Fatal("development example manifest drifted or incorrectly claims freeze")
	}
	if err := ValidatePartition(manifest, Development, []Input{input}); err != nil {
		t.Fatal(err)
	}
	labelsJSON, err := os.ReadFile(filepath.Join("examples", "labels.development.json"))
	if err != nil {
		t.Fatal(err)
	}
	var labels []Label
	if err := json.Unmarshal(labelsJSON, &labels); err != nil {
		t.Fatal(err)
	}
	if err := ValidateLabels(manifest, Development, labels); err != nil {
		t.Fatal(err)
	}
	schemaRoot, err := os.OpenRoot("schemas")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = schemaRoot.Close() }()
	for _, schema := range []string{"detector-input.schema.json", "manifest.schema.json", "labels.schema.json"} {
		encoded, err := schemaRoot.ReadFile(schema)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if err := json.Unmarshal(encoded, &document); err != nil {
			t.Fatalf("schema %s: %v", schema, err)
		}
		if document["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
			t.Fatalf("schema dialect missing: %s", schema)
		}
	}
}

// Production packages may not import controller fixtures or labels. A future
// standalone evaluator belongs in tests or a dedicated test-only command.
func TestProductionDoesNotImportTestOracle(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, directory := range []string{"internal", filepath.Join("cmd", "mii")} {
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(node ast.Node) bool {
				if spec, ok := node.(*ast.ImportSpec); ok {
					value, unquoteErr := strconv.Unquote(spec.Path.Value)
					if unquoteErr != nil {
						t.Error(unquoteErr)
						return false
					}
					if strings.Contains(value, "/tests/datasets") || strings.Contains(value, "/tests/mock-upstream") {
						t.Errorf("production oracle dependency: %s imports %s", path, value)
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
