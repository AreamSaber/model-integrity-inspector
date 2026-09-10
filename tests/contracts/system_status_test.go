package contracts

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestSystemStatusReadScopeAndHonestCoverageContract(t *testing.T) {
	raw, err := os.ReadFile("../../docs/api/openapi-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	methods := contractObject(t, contractObject(t, spec["paths"])["/system/health"])
	if len(methods) != 1 {
		t.Fatal("diagnostics must not gain write methods")
	}
	op := contractObject(t, methods["get"])
	if op["requestBody"] != nil || op["x-permission-mode"] != "all" || !reflect.DeepEqual(op["x-permission"], []any{"system.read", "run.read", "audit.read"}) || !reflect.DeepEqual(op["security"], []any{map[string]any{"SessionCookie": []any{}}}) {
		t.Fatal("system role must not replace organization/session authorization")
	}
	parameters, ok := op["parameters"].([]any)
	if !ok || len(parameters) != 1 {
		t.Fatal("system diagnostics require exactly the organization header")
	}
	parameter := contractObject(t, parameters[0])
	if parameter["name"] != "X-Organization-ID" || parameter["in"] != "header" || parameter["required"] != true || contractObject(t, parameter["schema"])["$ref"] != "#/components/schemas/ID" || op["x-unknown-query-parameters"] != "reject" {
		t.Fatal("diagnostic scope/header drift")
	}
	for name, want := range map[string]float64{"x-request-deadline-ms": 2000, "x-max-response-bytes": 32768, "x-max-active-jobs": 10000, "x-max-tail-events": 2, "x-process-concurrency": 2, "x-organization-concurrency": 1} {
		if op[name] != want {
			t.Fatal("diagnostic resource limit drift", name)
		}
	}
	responses := contractObject(t, op["responses"])
	for _, code := range []string{"200", "400", "401", "403", "405", "409", "429", "503"} {
		if responses[code] == nil {
			t.Fatal("missing diagnostic response", code)
		}
	}
	success := contractObject(t, responses["200"])
	if contractObject(t, contractObject(t, contractObject(t, success["headers"])["Cache-Control"])["schema"])["const"] != "no-store" {
		t.Fatal("system diagnostics became cacheable")
	}
	schemas := contractObject(t, contractObject(t, spec["components"])["schemas"])
	properties := func(name string) map[string]any {
		return contractObject(t, contractObject(t, schemas[name])["properties"])
	}
	status := properties("SystemStatus")
	if contractObject(t, status["coverage"])["const"] != "partial" || !reflect.DeepEqual(contractObject(t, status["observed_state"])["enum"], []any{"ok", "degraded"}) {
		t.Fatal("partial observed checks misrepresented as global readiness")
	}
	for _, name := range []string{"SystemCheck", "SystemSchema", "SystemJobs", "SystemAudit", "SystemRetention"} {
		states := contractObject(t, properties(name)["state"])["enum"]
		if !reflect.DeepEqual(states, []any{"ok", "error", "unavailable", "startup_verified", "not_applicable"}) {
			t.Fatal("unknown/startup/not-applicable collapsed into health", name)
		}
	}
	for _, name := range []string{"SystemStatus", "SystemBuild", "SystemCheck", "SystemJobs", "SystemAudit"} {
		for _, forbidden := range []string{"ready", "dsn", "endpoint", "master_key_file", "key_version", "event_hmac", "event_body", "ciphertext", "report_directory", "secret_id"} {
			if properties(name)[forbidden] != nil {
				t.Fatal("private or misleading diagnostic field", name, forbidden)
			}
		}
	}
	for _, name := range []string{"total_active_jobs", "pending_ready", "pending_delayed", "running_leased", "running_expired"} {
		choices, ok := contractObject(t, properties("SystemJobs")[name])["anyOf"].([]any)
		if !ok || len(choices) != 2 || contractObject(t, choices[0])["maximum"] != float64(10000) || contractObject(t, choices[1])["type"] != "null" {
			t.Fatal("unavailable queue observations must not be encoded as zero")
		}
	}
	if contractObject(t, properties("SystemRetention")["current_write_policy_days"])["const"] != float64(30) {
		t.Fatal("retention status must match actual current write policy")
	}
}
