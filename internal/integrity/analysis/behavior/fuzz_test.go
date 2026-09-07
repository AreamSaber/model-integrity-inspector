package behavior

import (
	"encoding/json"
	"errors"
	"testing"
	"unicode/utf8"
)

func FuzzAnalyzeBoundedText(f *testing.F) {
	e := testEngine(f)
	for _, seed := range []string{testMarker, "Sure! " + testMarker, "\xff", `{"field_12345678":"` + testMarker + `"}`, `{"field_12345678":null}`, "抱歉，我无法执行。", `{"outer":{"field_12345678":"` + testMarker + `"}}`} {
		f.Add(seed, true)
		f.Add(seed, false)
	}
	f.Fuzz(func(t *testing.T, text string, jsonContract bool) {
		sample := sampleFor(1, "format.en-us.1", text)
		if jsonContract {
			sample.Template.ID = "format.en-us.3"
			sample.Contract = Contract{Kind: JSONField, Key: "field_12345678", Expected: testMarker}
		}
		out, err := e.Analyze(sample)
		if len(text) > MaxTextBytes {
			if !errors.Is(err, ErrLimit) {
				t.Fatal("oversize not rejected")
			}
			return
		}
		if !utf8.ValidString(text) {
			if !errors.Is(err, ErrInput) {
				t.Fatal("invalid UTF8 not rejected")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, evidence := range out.Evidence {
			if evidence.StartByte < 0 || evidence.EndByte > len(text) || evidence.StartByte >= evidence.EndByte || !utf8.ValidString(text[evidence.StartByte:evidence.EndByte]) {
				t.Fatal("invalid evidence offsets")
			}
		}
		if _, err := json.Marshal(out); err != nil {
			t.Fatal("output is not valid JSON")
		}
	})
}
