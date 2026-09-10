package api

import "testing"

func TestStrictJSONRejectsIsolatedSurrogateEscapes(t *testing.T) {
	for _, value := range []string{`\ud800`, `\udfff`, `\ud800a`, `\ud800\n\udc00`, `\ud800\ud800`, `\udc00\ud800`, `\ud800\\udc00`, `\ud800\u0000`, `\ud800\uDC0X`} {
		var out struct {
			Text string `json:"text"`
		}
		if strictJSON([]byte(`{"text":"`+value+`"}`), &out) == nil {
			t.Fatal("isolated surrogate was silently rewritten")
		}
	}
	for _, test := range []struct{ raw, want string }{
		{`{"text":"\ud83d\ude00"}`, "😀"},
		{`{"text":"\\ud800"}`, `\ud800`},
		{`{"text":"\"\u4e2d\ud83d\ude00"}`, "\"中😀"},
		{`{"text":"�"}`, "�"},
		{`{"text":"😀"}`, "😀"},
	} {
		var out struct {
			Text string `json:"text"`
		}
		if strictJSON([]byte(test.raw), &out) != nil || out.Text != test.want {
			t.Fatal("valid scalar Unicode did not round-trip")
		}
	}
	var fields map[string]string
	if strictJSON([]byte(`{"\ud800":"key"}`), &fields) == nil {
		t.Fatal("invalid surrogate key rewritten")
	}
}

func FuzzJSONSurrogateValidation(f *testing.F) {
	for _, seed := range []string{`{"text":"ok"}`, `{"text":"\ud83d\ude00"}`, `{"text":"\ud800"}`, `"\\ud800"`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 64<<10 {
			t.Skip()
		}
		_ = validJSONSurrogates([]byte(raw))
	})
}
