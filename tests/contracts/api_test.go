package contracts

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestAPIContract(t *testing.T) {
	raw, err := os.ReadFile("../../docs/api/openapi-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	if spec["openapi"] != "3.1.0" {
		t.Fatal("unexpected OpenAPI dialect")
	}
	components := spec["components"].(map[string]any)
	schemas := components["schemas"].(map[string]any)
	var checkRefs func(any)
	checkRefs = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			if r, ok := v["$ref"].(string); ok {
				const prefix = "#/components/schemas/"
				if !strings.HasPrefix(r, prefix) || schemas[strings.TrimPrefix(r, prefix)] == nil {
					t.Errorf("unresolved schema reference: %s", r)
				}
			}
			for _, child := range v {
				checkRefs(child)
			}
		case []any:
			for _, child := range v {
				checkRefs(child)
			}
		}
	}
	checkRefs(spec)
	paths := spec["paths"].(map[string]any)
	for _, path := range []string{"/setup/status", "/setup/initialize", "/auth/login", "/auth/logout", "/auth/me", "/auth/change-password", "/users", "/organizations", "/organizations/{id}/members", "/roles", "/providers", "/model-profiles", "/targets", "/targets/{id}/precheck", "/targets/{id}/rotate-secret", "/runs", "/runs/estimate", "/runs/{id}/events", "/runs/{id}/retry-probes", "/runs/{id}/result", "/runs/{id}/findings", "/runs/{id}/samples/{sampleId}", "/runs/{id}/reviews", "/runs/{id}/reports", "/reports/{reportId}/download", "/baselines", "/baselines/{id}/approve", "/rule-bundles/{id}/publish", "/audit-logs", "/system/health", "/system/backups"} {
		if paths[path] == nil {
			t.Errorf("missing P0 API path: %s", path)
		}
	}
	operationIDs := map[string]bool{}
	for path, methods := range paths {
		for method, value := range methods.(map[string]any) {
			op := value.(map[string]any)
			id, ok := op["operationId"].(string)
			if !ok || id == "" || operationIDs[id] {
				t.Errorf("duplicate/missing operationId %s %s", method, path)
			}
			operationIDs[id] = true
			if op["x-permission"] == nil || op["security"] == nil {
				t.Errorf("missing permission model: %s", id)
			}
			for _, fragment := range strings.Split(path, "/") {
				if !strings.HasPrefix(fragment, "{") {
					continue
				}
				name := strings.Trim(fragment, "{}")
				found := false
				for _, param := range op["parameters"].([]any) {
					p := param.(map[string]any)
					if p["name"] == name && p["in"] == "path" && p["required"] == true {
						found = true
					}
				}
				if !found {
					t.Errorf("undeclared path parameter %s: %s", name, id)
				}
			}
			responses := op["responses"].(map[string]any)
			if responses["403"] == nil || responses["429"] == nil {
				t.Errorf("missing failure contract: %s", id)
			}
		}
	}
	credentials := schemas["Credentials"].(map[string]any)["properties"].(map[string]any)
	for _, name := range []string{"api_key", "headers"} {
		if credentials[name].(map[string]any)["writeOnly"] != true {
			t.Errorf("credential not write-only: %s", name)
		}
	}
	target := schemas["Target"].(map[string]any)["properties"].(map[string]any)
	for _, name := range []string{"auth", "api_key", "headers", "ciphertext", "encrypted_data_key"} {
		if target[name] != nil {
			t.Errorf("target read model exposes secret: %s", name)
		}
	}
	if schemas["ID"].(map[string]any)["type"] != "string" {
		t.Fatal("IDs must not lose JavaScript integer precision")
	}
}

func TestPrototypeCoverage(t *testing.T) {
	raw, err := os.ReadFile("../../docs/design/m0-05-prototype.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, page := range []string{"setup", "login", "overview", "targets", "run-new", "run", "result", "evidence", "baselines", "rules", "review", "audit", "system"} {
		if !strings.Contains(string(raw), `id="`+page+`"`) || !strings.Contains(string(raw), `href="#`+page+`"`) {
			t.Errorf("missing prototype page/navigation: %s", page)
		}
	}
	if !strings.Contains(string(raw), "非运行产品") {
		t.Fatal("prototype must not claim working product")
	}
}
