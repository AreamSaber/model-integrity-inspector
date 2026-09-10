package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestCSVNilZeroAndVersionFailClosed(t *testing.T) {
	for _, snapshot := range []*Snapshot{nil, {}, {doc: document{SchemaVersion: "future", CanonicalVersion: CanonicalVersion}}, {doc: document{SchemaVersion: SchemaVersion, CanonicalVersion: "future"}}} {
		if a, err := GenerateCSV(snapshot); a != nil || !errors.Is(err, ErrInput) {
			t.Fatal("unconstructed or incompatible snapshot accepted")
		}
	}
	for _, a := range []*CSVArtifact{nil, {}} {
		if a.Bytes() != nil || a.ContentHash() != "" || a.FileHash() != "" || a.SchemaVersion() != "" {
			t.Fatal("empty artifact implied a generated report")
		}
	}
	for _, field := range reflect.VisibleFields(reflect.TypeFor[CSVArtifact]()) {
		if field.IsExported() {
			t.Fatal("artifact exposes mutable public state")
		}
	}
}

func TestCSVStringCellsKeepJSONQuotesAndControls(t *testing.T) {
	canaries := []string{
		`=HYPERLINK("https://csv.invalid","S2_CANARY")`, "+SUM(1,2)", "-1+S2_CANARY", "@SUM(1,2)",
		"\t=1+2", "\r=1+2", "\n=1+2", " \t=1+2", "\x00=1+2", "\u2028=1+2", "\u2029@S2_CANARY",
		"comma,quote\"CR\rLF\nTab\t", `</script><img src="https://csv.invalid">&`, "中文 😀", "", "9223372036854775807",
	}
	for i, value := range canaries {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			// Renderer-only defense in depth, as in the existing HTML test:
			// arbitrary strings are NOT newly accepted by the S1 constructor.
			input, err := canonical(map[string]any{"cell": value})
			if err != nil {
				t.Fatal(err)
			}
			output, err := renderCSV(input)
			if err != nil {
				t.Fatal(err)
			}
			rows := csvReadRows(t, output)
			if len(rows) != 2 || rows[1][2] != "string" || len(rows[1][3]) < 2 || rows[1][3][0] != '"' || strings.ContainsAny(rows[1][3], "\x00\r\n\t") {
				t.Fatal("decoded string cell lost JSON quoting or escaped controls")
			}
			var decoded string
			if err := json.Unmarshal([]byte(rows[1][3]), &decoded); err != nil || decoded != value {
				t.Fatal("formula defense changed the original string")
			}
			if !bytes.Equal(csvRebuiltJSON(t, csvRebuild(t, rows)), input) {
				t.Fatal("malicious string could not be losslessly reconstructed")
			}
			scope, in := fixture()
			in.Samples[0].Family = value
			if snapshot, err := NewDevelopmentSnapshot(scope, in); snapshot != nil || !errors.Is(err, ErrInput) {
				t.Fatal("CSV work weakened the closed S1 string boundary")
			}
		})
	}
}

func TestCSVNumbersAreOnlyCanonicalFiniteLexemes(t *testing.T) {
	for _, valid := range []string{"0", "-1", "-0.5", "1e-07", "-1e-07", "9.007199254740991e+15", "-9.007199254740991e+15"} {
		kind, encoded, err := csvNodeValue(json.Number(valid))
		if err != nil || kind != "number" || encoded != valid || !json.Valid([]byte(encoded)) {
			t.Fatalf("canonical numeric lexeme rejected: %s", valid)
		}
	}
	for _, invalid := range []any{
		json.Number("-1+S2_CANARY"), json.Number("=1+1"), json.Number("+1"), json.Number("01"),
		json.Number("1e-7"), json.Number("-0"), json.Number("1.0"), json.Number("1\t"), json.Number("NaN"),
		json.Number("Inf"), json.Number("0x1p0"), json.Number("1e309"), json.Number("9007199254740992"),
		math.NaN(), float64(1), int64(1), make(chan int), json.Delim('}'), json.Delim(']'), string([]byte{0xff}),
	} {
		kind, value, err := csvNodeValue(invalid)
		if kind != "" || value != "" || !errors.Is(err, ErrInput) || strings.Contains(err.Error(), "CANARY") {
			t.Fatal("noncanonical numeric/value type not rejected with a closed error")
		}
	}
}

func TestCSVPrivateRendererRejectsAmbiguousDocuments(t *testing.T) {
	for _, raw := range []string{
		"", "{", "[", `{"a":`, `{"a":1`, `[1,`, `{"a":1,"a":2}`, `{"b":1,"a":2}`,
		`{"a":1} {"b":2}`, `{"a":1]`, `{"a":-1+S2_CANARY}`, `{"a":1e-7}`, `{"a":-0}`,
		`{"\rkey":1}`, `{"\nkey":1}`, `{"\tkey":1}`, `{"\u0000key":1}`, string([]byte{0xff}),
	} {
		if output, err := renderCSV([]byte(raw)); output != nil || !errors.Is(err, ErrInput) || strings.Contains(err.Error(), "CANARY") {
			t.Fatal("ambiguous document did not fail closed")
		}
	}
	for _, raw := range []string{
		strings.Repeat("[", 26) + "null" + strings.Repeat("]", 26),
		`{"` + strings.Repeat("x", 4096) + `":null}`,
		strings.Repeat("x", MaxOutputBytes+1),
	} {
		if output, err := renderCSV([]byte(raw)); output != nil || !errors.Is(err, ErrLimit) {
			t.Fatal("private parser resource bound did not fail closed")
		}
	}
	if !errors.Is(csvRenderError(errors.New("S2_CANARY")), ErrRender) {
		t.Fatal("unrecognized writer failure did not close error text")
	}
}

func TestCSVRealOutputBoundaryAndExpansionFailure(t *testing.T) {
	// The actual production renderer and 16 MiB writer, not a lowered test cap.
	empty, err := renderCSV([]byte(`""`))
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.Repeat("x", MaxOutputBytes-len(empty))
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	exact, err := renderCSV(raw)
	if err != nil || len(exact) != MaxOutputBytes {
		t.Fatal("exact 16 MiB CSV limit rejected")
	}
	tooLarge, err := json.Marshal(payload + "x")
	if err != nil || len(tooLarge) >= MaxOutputBytes {
		t.Fatal("test must reach output limit, not input byte limit")
	}
	if output, err := renderCSV(tooLarge); output != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("one-byte-over-limit CSV escaped buffered write/flush failure")
	}
	// Bypass only private frozen content to exercise GenerateCSV's real output
	// expansion failure. Public S1 preflight remains unchanged and stricter.
	snapshot, _ := csvFixture(t)
	snapshot.doc.Recommendations = []string{strings.Repeat(`"`, MaxOutputBytes/3)}
	content, err := canonical(snapshot.doc)
	if err != nil || len(content) >= MaxOutputBytes {
		t.Fatal("expansion test must have a bounded canonical input")
	}
	if output, err := GenerateCSV(snapshot); output != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("CSV quote expansion published partial artifact")
	}
	snapshot.doc.Recommendations = []string{strings.Repeat("x", MaxOutputBytes)}
	if output, err := GenerateCSV(snapshot); output != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("canonical pre-render bound did not propagate")
	}
}

func TestCSVMaximumSampleCount(t *testing.T) {
	scope, in := fixture()
	base := in.Samples[1]
	in.Samples = nil
	for i := range MaxSamples {
		sample := base
		sample.ID, sample.ProbeInstanceID, sample.Ordinal = strconv.Itoa(1000+i), strconv.Itoa(2000+i), i
		sample.FinalAttemptID = ptr(strconv.Itoa(3000 + i))
		sample.Attempts = []Attempt{base.Attempts[0]}
		sample.Attempts[0].ID = *sample.FinalAttemptID
		in.Samples = append(in.Samples, sample)
	}
	in.Result.ExpectedSamples, in.Result.ValidSamples, in.Run.RequestCount = MaxSamples, MaxSamples, MaxSamples
	in.Result.Token, in.Result.Behavior, in.Findings = nil, nil, nil
	snapshot, err := NewDevelopmentSnapshot(scope, in)
	if err != nil {
		t.Fatal(err)
	}
	exported, err := GenerateCSV(snapshot)
	if err != nil || len(exported.Bytes()) > MaxOutputBytes {
		t.Fatal("maximum supported samples failed bounded CSV generation")
	}
	existing, err := Generate(snapshot)
	if err != nil || !bytes.Equal(csvRebuiltJSON(t, csvRebuild(t, csvReadRows(t, exported.Bytes()))), existing.JSON()) {
		t.Fatal("maximum sample report did not fully reconstruct")
	}
}
