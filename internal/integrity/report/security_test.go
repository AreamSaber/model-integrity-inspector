package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"html"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEveryStringLeafRejectsRawContentCanary(t *testing.T) {
	scope, in := fixture()
	canary := `<script>alert("S2_CANARY_not_a_real_secret")</script>https://private.invalid/`
	count := 0
	var walk func(reflect.Value)
	walk = func(v reflect.Value) {
		if v.Type() == reflect.TypeFor[time.Time]() {
			return
		}
		switch v.Kind() {
		case reflect.Pointer:
			if !v.IsNil() {
				walk(v.Elem())
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				walk(v.Field(i))
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i))
			}
		case reflect.String:
			original := v.String()
			v.SetString(canary)
			snapshot, err := NewDevelopmentSnapshot(scope, in)
			if snapshot != nil || err == nil || strings.Contains(err.Error(), "CANARY") || !errors.Is(err, ErrInput) && !errors.Is(err, ErrLimit) {
				t.Fatal("raw input escaped the closed string boundary")
			}
			v.SetString(original)
			count++
		}
	}
	walk(reflect.ValueOf(&scope).Elem())
	walk(reflect.ValueOf(&in).Elem())
	if count < 200 {
		t.Fatalf("insufficient leaf coverage: %d", count)
	}
	a := makeArtifacts(t, scope, in)
	if bytes.Contains(a.JSON(), []byte("CANARY")) || bytes.Contains(a.HTML(), []byte("CANARY")) {
		t.Fatal("raw canary retained after rejection")
	}
}

func TestHTMLDefenseInDepthEscapesAllContexts(t *testing.T) {
	scope, in := fixture()
	snapshot, err := NewDevelopmentSnapshot(scope, in)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately bypass the public constructor only inside this renderer
	// regression. A future display string must not turn into active markup.
	canary := `</title><script>alert('CANARY')</script><img src="https://private.invalid" onerror="alert(1)"><svg onload=alert(1)>`
	doc := snapshot.doc
	doc.ReportID = canary
	doc.Result.Limitations = []string{canary}
	doc.Findings[0].RuleID = canary
	doc.Samples[0].ID = canary
	doc.Samples[0].Attempts[0].ErrorCode = &canary
	rendered, err := renderHTML(doc, canary, []byte(canary))
	if err != nil {
		t.Fatal(err)
	}
	output := string(rendered)
	for _, forbidden := range []string{"<script", "<img", "<svg", "<iframe", "<object", "<link", "<style", "<form", "<a ", "<base"} {
		if strings.Contains(strings.ToLower(output), forbidden) {
			t.Fatalf("active HTML produced: %s", forbidden)
		}
	}
	if !strings.Contains(output, "&lt;script&gt;") || !strings.Contains(html.UnescapeString(output), canary) || !strings.Contains(output, "default-src 'none'") {
		t.Fatal("text escaping/CSP not retained")
	}
}

func TestCanonicalProfileGolden(t *testing.T) {
	in := map[string]any{"z": math.Copysign(0, -1), "a": []any{3, 2, 1}, "nested": map[string]any{"é": "\u2028<>&", "a": 1e-7}, "absent": nil}
	want := `{"a":[3,2,1],"absent":null,"nested":{"a":1e-07,"é":"\u2028\u003c\u003e\u0026"},"z":0}`
	got, err := canonical(in)
	if err != nil || string(got) != want {
		t.Fatalf("canonical-json.v1 changed: %s (%v)", got, err)
	}
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(got))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	again, err := canonical(decoded)
	if err != nil || !bytes.Equal(got, again) {
		t.Fatal("canonical profile not idempotent")
	}
	for _, v := range []any{math.NaN(), math.Inf(1), 9007199254740992, make(chan int)} {
		if result, err := canonical(v); result != nil || !errors.Is(err, ErrInput) {
			t.Fatal("noncanonical value not rejected")
		}
	}
}

func TestOutputAndPreflightBounds(t *testing.T) {
	var writer boundedWriter
	chunk := bytes.Repeat([]byte("x"), MaxOutputBytes)
	if n, err := writer.Write(chunk); n != MaxOutputBytes || err != nil {
		t.Fatal("exact output limit rejected")
	}
	if n, err := io.WriteString(&writer, "y"); n != 0 || !errors.Is(err, ErrLimit) || writer.buffer.Len() != MaxOutputBytes {
		t.Fatal("io.StringWriter bypassed bounded output")
	}
	if v, err := canonical(strings.Repeat("x", MaxOutputBytes)); v != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("canonical output limit ignored")
	}
	scope, in := fixture()
	snapshot, err := NewDevelopmentSnapshot(scope, in)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := renderHTML(snapshot.doc, "hash", chunk); v != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("HTML output limit ignored")
	}
	// Individually bounded slices/strings still exceed the total preflight.
	in.Findings = make([]Finding, MaxFindings)
	for i := range in.Findings {
		in.Findings[i].Alternatives = make([]string, 128)
		for j := range in.Findings[i].Alternatives {
			in.Findings[i].Alternatives[j] = strings.Repeat("x", 128)
		}
	}
	if s, err := NewDevelopmentSnapshot(scope, in); s != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("total input resource bound not enforced before JSON copy")
	}
}

func TestProtocolWarningsClosedAndSuccessErrorNull(t *testing.T) {
	scope, in := fixture()
	known := strings.Fields(protocolCodes)
	in.Samples[0].Limitations = known
	a := makeArtifacts(t, scope, in)
	for _, code := range known {
		if !bytes.Contains(a.JSON(), []byte(code)) {
			t.Fatalf("public protocol warning lost: %s", code)
		}
	}
	if !bytes.Contains(a.JSON(), []byte(`"error_code":null`)) {
		t.Fatal("successful attempts must not invent execution errors")
	}
	in.Samples[0].Limitations = append(known, "MI_PROTOCOL_S2_CANARY")
	if _, err := NewDevelopmentSnapshot(scope, in); !errors.Is(err, ErrInput) {
		t.Fatal("MI_ prefix was treated as a generic safe string")
	}
	in.Samples[0].Limitations = nil
	in.Samples[0].Attempts[0].ErrorCode = ptr("")
	if _, err := NewDevelopmentSnapshot(scope, in); !errors.Is(err, ErrInput) {
		t.Fatal("adapter must map absent success code to null, not empty or fabricated error")
	}
}

func TestMaximumSampleCountRemainsBounded(t *testing.T) {
	scope, in := fixture()
	base := in.Samples[1]
	in.Samples = nil
	for i := range MaxSamples {
		s := base
		s.ID, s.ProbeInstanceID, s.Ordinal = strconv.Itoa(1000+i), strconv.Itoa(2000+i), i
		s.FinalAttemptID = ptr(strconv.Itoa(3000 + i))
		s.Attempts = []Attempt{base.Attempts[0]}
		s.Attempts[0].ID = *s.FinalAttemptID
		in.Samples = append(in.Samples, s)
	}
	in.Result.ExpectedSamples, in.Result.ValidSamples = MaxSamples, MaxSamples
	in.Result.Token, in.Result.Behavior, in.Findings = nil, nil, nil
	in.Run.RequestCount = MaxSamples
	a := makeArtifacts(t, scope, in)
	if len(a.JSON()) > MaxOutputBytes || len(a.HTML()) > MaxOutputBytes {
		t.Fatal("maximum supported sample input exceeds artifact limit")
	}
	in.Result.ExpectedSamples++
	in.Samples = append(in.Samples, base)
	if _, err := NewDevelopmentSnapshot(scope, in); !errors.Is(err, ErrInput) {
		t.Fatal("sample count limit not enforced")
	}
}

func FuzzCanonicalClosedNumbers(f *testing.F) {
	f.Add(0.0)
	f.Add(.125)
	f.Add(-1.25)
	f.Add(math.Inf(1))
	f.Fuzz(func(t *testing.T, v float64) {
		result, err := canonical(map[string]float64{"number": v})
		if !number(v, -9007199254740991, 9007199254740991) {
			if err == nil || result != nil {
				t.Fatal("invalid finite/safe number accepted")
			}
			return
		}
		if err != nil || !json.Valid(result) {
			t.Fatal("safe finite number failed canonicalization")
		}
	})
}
