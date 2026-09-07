package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStrictJSONContractRejectsAmbiguity(t *testing.T) {
	type body struct {
		targetFields
		Auth targetAuth `json:"auth"`
	}
	for _, raw := range []string{
		`{"name":"one","name":"two"}`, `{"Name":"alias"}`,
		`{"auth":{"api_key":"one","api_key":"two"}}`,
		`{"auth":{"API_KEY":"alias"}}`, `{"options":{"tls_verify":null}}`,
		`{"options":{"TLS_VERIFY":false}}`, `{"options":{"rpm":null}}`,
		`{"auth":{"headers":{"x-test":"one","x-test":"two"}}}`,
		`{"name":null}`, `{"tags":[null]}`, `{"tags":null}`, `null`,
		`{} {}`, `{"name":"` + string([]byte{0xff}) + `"}`,
	} {
		var out body
		if strictJSON([]byte(raw), &out) == nil {
			t.Fatalf("accepted ambiguous contract: %q", raw)
		}
	}
	var out body
	if err := strictJSON([]byte(`{"name":"valid","provider_id":null,"model_profile_id":null,"auth":{"headers":{"x-test":"ok"}},"options":{"tls_verify":true}}`), &out); err != nil {
		t.Fatal(err)
	}
	var patch map[string]json.RawMessage
	if strictJSON([]byte(`{"options":{"rpm":1,"rpm":2}}`), &patch) == nil {
		t.Fatal("duplicate nested patch field accepted")
	}
	if strictJSON([]byte(`{"value":`+strings.Repeat("[", 34)+`1`+strings.Repeat("]", 34)+`}`), &patch) == nil {
		t.Fatal("unbounded nesting accepted")
	}
}

func FuzzStrictJSONNoPanic(f *testing.F) {
	f.Add([]byte(`{"name":"ok","provider_id":null}`))
	f.Add([]byte(`{"auth":{"api_key":"one","api_key":"two"}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			t.Skip()
		}
		var body targetFields
		_ = strictJSON(raw, &body)
	})
}
