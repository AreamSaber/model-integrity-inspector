package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func csvFixture(t *testing.T) (*Snapshot, *CSVArtifact) {
	t.Helper()
	scope, in := fixture()
	snapshot, err := NewDevelopmentSnapshot(scope, in)
	if err != nil {
		t.Fatal(err)
	}
	a, err := GenerateCSV(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, a
}

func csvReadRows(t *testing.T, data []byte) [][]string {
	t.Helper()
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = 4
	rows, err := reader.ReadAll()
	if err != nil || len(rows) < 2 || !reflect.DeepEqual(rows[0], []string{"csv_schema", "path", "value_type", "json_value"}) {
		t.Fatalf("CSV reader/header failure: %v", err)
	}
	return rows[1:]
}

// This independent test reader reconstructs containers from parent pointers,
// not from renderer traversal or Snapshot fields. Scalar bytes stay lexical;
// no float conversion or production canonical() is used in reconstruction.
type csvTestNode struct {
	kind, scalar string
	object       map[string]*csvTestNode
	array        []*csvTestNode
}

func csvRebuild(t *testing.T, rows [][]string) *csvTestNode {
	t.Helper()
	nodes := map[string]*csvTestNode{}
	for _, row := range rows {
		if row[0] != CSVSchemaVersion || nodes[row[1]] != nil || !json.Valid([]byte(row[3])) {
			t.Fatal("schema, duplicate node, or invalid JSON cell")
		}
		node := &csvTestNode{kind: row[2], scalar: row[3]}
		decoder := json.NewDecoder(strings.NewReader(row[3]))
		decoder.UseNumber()
		var decoded any
		if err := decoder.Decode(&decoded); err != nil {
			t.Fatal(err)
		}
		switch row[2] {
		case "object":
			if row[3] != "{}" {
				t.Fatal("object marker was not empty")
			}
			node.object = map[string]*csvTestNode{}
		case "array":
			if row[3] != "[]" {
				t.Fatal("array marker was not empty")
			}
		case "string":
			if _, ok := decoded.(string); !ok {
				t.Fatal("string cell type mismatch")
			}
		case "number":
			if _, ok := decoded.(json.Number); !ok {
				t.Fatal("number cell type mismatch")
			}
		case "boolean":
			if _, ok := decoded.(bool); !ok {
				t.Fatal("boolean cell type mismatch")
			}
		case "null":
			if decoded != nil {
				t.Fatal("null cell type mismatch")
			}
		default:
			t.Fatal("unknown cell type")
		}
		nodes[row[1]] = node
		if row[1] == "" {
			continue
		}
		separator := strings.LastIndexByte(row[1], '/')
		if separator < 0 || nodes[row[1][:separator]] == nil {
			t.Fatal("node missing preceding parent")
		}
		parent := nodes[row[1][:separator]]
		key := strings.ReplaceAll(strings.ReplaceAll(row[1][separator+1:], "~1", "/"), "~0", "~")
		switch parent.kind {
		case "object":
			if parent.object[key] != nil {
				t.Fatal("duplicate object key")
			}
			parent.object[key] = node
		case "array":
			if key != strconv.Itoa(len(parent.array)) {
				t.Fatal("noncontiguous or unordered array index")
			}
			parent.array = append(parent.array, node)
		default:
			t.Fatal("scalar node has children")
		}
	}
	if nodes[""] == nil {
		t.Fatal("missing document root")
	}
	return nodes[""]
}

func csvRebuiltJSON(t *testing.T, node *csvTestNode) []byte {
	t.Helper()
	var output bytes.Buffer
	switch node.kind {
	case "object":
		output.WriteByte('{')
		keys := make([]string, 0, len(node.object))
		for key := range node.object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for i, key := range keys {
			if i > 0 {
				output.WriteByte(',')
			}
			encoded, err := json.Marshal(key)
			if err != nil {
				t.Fatal(err)
			}
			output.Write(encoded)
			output.WriteByte(':')
			output.Write(csvRebuiltJSON(t, node.object[key]))
		}
		output.WriteByte('}')
	case "array":
		output.WriteByte('[')
		for i, child := range node.array {
			if i > 0 {
				output.WriteByte(',')
			}
			output.Write(csvRebuiltJSON(t, child))
		}
		output.WriteByte(']')
	default:
		output.WriteString(node.scalar)
	}
	return output.Bytes()
}

func csvTestHash(data []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(data)) }

func TestCSVFullDocumentReconstructionAndHashes(t *testing.T) {
	snapshot, exported := csvFixture(t)
	existing, err := Generate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	rows := csvReadRows(t, exported.Bytes())
	rebuilt := csvRebuild(t, rows)
	if !bytes.Equal(csvRebuiltJSON(t, rebuilt), existing.JSON()) {
		t.Fatal("CSV did not reconstruct the complete final JSON byte-for-byte")
	}
	if exported.ContentHash() != existing.ContentHash() || exported.FileHash() != csvTestHash(exported.Bytes()) || exported.FileHash() == exported.ContentHash() || exported.SchemaVersion() != CSVSchemaVersion {
		t.Fatal("CSV artifact metadata mismatch")
	}
	delete(rebuilt.object, "content_hash")
	if csvTestHash(csvRebuiltJSON(t, rebuilt)) != exported.ContentHash() {
		t.Fatal("independently reconstructed content hash mismatch")
	}
	values := map[string]string{}
	for _, row := range rows {
		values[row[1]] = row[2] + ":" + row[3]
	}
	disclaimer, err := json.Marshal(Disclaimer)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		"/disclaimer": "string:" + string(disclaimer),
		"/review":     "null:null", "/review_state": `string:"not_included"`,
		"/report_id": `string:"9007199254742999"`, "/organization_id": `string:"9007199254741999"`,
		"/run/target_id": `string:"9007199254743999"`, "/run/estimated_cost_micros": "null:null",
		"/samples/0/attempts/0/error_code": `string:"MI_TIMEOUT"`, "/samples/0/attempts/1/error_code": "null:null",
		"/result/token_statistics/plateaus/0/lower": "number:0", "/result/behavior_statistics/differences/1/p_value": "null:null",
		"/findings/0/statistics/1/actual": "null:null", "/samples/12/auxiliary_only": "boolean:true",
	} {
		if values[path] != want {
			t.Fatalf("missing or lossy node %s: %s", path, values[path])
		}
	}
	// A new CSV call must not mutate even one byte of the established exports.
	if _, err := GenerateCSV(snapshot); err != nil {
		t.Fatal(err)
	}
	again, err := Generate(snapshot)
	if err != nil || !bytes.Equal(existing.JSON(), again.JSON()) || !bytes.Equal(existing.HTML(), again.HTML()) {
		t.Fatal("CSV changed existing JSON/HTML")
	}
}

func TestCSVProfileGoldenAndPointerEscaping(t *testing.T) {
	input := []byte(`{"":[],"a":"=1+2","a/b":{},"m~n":[null,false,-1.25,1e-07],"~1":""}`)
	got, err := renderCSV(input)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"csv_schema,path,value_type,json_value",
		"mii.report.csv.v1,,object,{}",
		"mii.report.csv.v1,/,array,[]",
		`mii.report.csv.v1,/a,string,"""=1+2"""`,
		"mii.report.csv.v1,/a~1b,object,{}",
		"mii.report.csv.v1,/m~0n,array,[]",
		"mii.report.csv.v1,/m~0n/0,null,null",
		"mii.report.csv.v1,/m~0n/1,boolean,false",
		"mii.report.csv.v1,/m~0n/2,number,-1.25",
		"mii.report.csv.v1,/m~0n/3,number,1e-07",
		`mii.report.csv.v1,/~01,string,""""""`, "",
	}, "\r\n")
	if string(got) != want {
		t.Fatalf("CSV v1 bytes changed:\n%s", got)
	}
	if !bytes.Equal(csvRebuiltJSON(t, csvRebuild(t, csvReadRows(t, got))), input) {
		t.Fatal("pointer escaping conflated empty key, slash, or tilde")
	}
}

func TestCSVEmptyNullAndMaximumStringID(t *testing.T) {
	scope, in := fixture()
	scope.ReportID = "9223372036854775807"
	in.Findings, in.Result.Token, in.Result.Behavior = nil, nil, nil
	in.Samples[0].Attempts, in.Samples[0].FinalAttemptID = nil, nil
	in.Samples[0].TokenizerQuality, in.Samples[0].TokenizerID, in.Samples[0].LocalCompletionTokens = "unavailable", "", nil
	snapshot, err := NewDevelopmentSnapshot(scope, in)
	if err != nil {
		t.Fatal(err)
	}
	exported, err := GenerateCSV(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	rows := csvReadRows(t, exported.Bytes())
	values := map[string]string{}
	for _, row := range rows {
		values[row[1]] = row[2] + ":" + row[3]
	}
	for path, want := range map[string]string{
		"/report_id": `string:"9223372036854775807"`, "/findings": "array:[]",
		"/result/token_statistics": "null:null", "/result/behavior_statistics": "null:null",
		"/samples/0/attempts": "array:[]", "/samples/0/tokenizer_id": `string:""`,
		"/samples/0/local_completion_tokens": "null:null",
	} {
		if values[path] != want {
			t.Fatalf("empty/null/ID lost at %s", path)
		}
	}
	existing, err := Generate(snapshot)
	if err != nil || !bytes.Equal(csvRebuiltJSON(t, csvRebuild(t, rows)), existing.JSON()) {
		t.Fatal("empty/null report did not round trip")
	}
}

func TestCSVDeterminismOwnershipAndConcurrentReads(t *testing.T) {
	scope, in := fixture()
	snapshot, err := NewDevelopmentSnapshot(scope, in)
	if err != nil {
		t.Fatal(err)
	}
	original, err := GenerateCSV(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(in.Samples)
	slices.Reverse(in.Findings)
	slices.Reverse(in.Result.Token.Tiers)
	slices.Reverse(in.Result.Behavior.Patterns)
	permuted, err := NewDevelopmentSnapshot(scope, in)
	if err != nil {
		t.Fatal(err)
	}
	same, err := GenerateCSV(permuted)
	if err != nil || !bytes.Equal(same.Bytes(), original.Bytes()) {
		t.Fatal("set permutation changed CSV")
	}
	*in.Result.OverallRisk = 99
	in.Samples[0].Attempts[0].ID = "S1_INPUT_MUTATION_CANARY"
	in.Result.Token.Tiers[0].Median = 999
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			got, err := GenerateCSV(snapshot)
			if err != nil || !bytes.Equal(got.Bytes(), original.Bytes()) || got.FileHash() != original.FileHash() {
				t.Error("concurrent immutable generation changed")
				return
			}
			owned := got.Bytes()
			owned[0] = '!'
			if got.Bytes()[0] != 'c' {
				t.Error("artifact getter exposed backing array")
			}
		})
	}
	group.Wait()
}
