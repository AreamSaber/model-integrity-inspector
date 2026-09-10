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
	for _, path := range []string{"/setup/status", "/setup/initialize", "/auth/login", "/auth/logout", "/auth/me", "/auth/change-password", "/users", "/organizations", "/organizations/{id}/members", "/roles", "/providers", "/model-profiles", "/targets", "/targets/{id}/precheck", "/targets/{id}/rotate-secret", "/runs", "/runs/trends", "/runs/estimate", "/runs/{id}/events", "/runs/{id}/retry-probes", "/runs/{id}/result", "/runs/{id}/findings", "/runs/{id}/samples/{sampleId}", "/runs/{id}/reviews", "/runs/{id}/reports", "/reports/{reportId}/download", "/baselines", "/baselines/{id}/approve", "/rule-bundles/{id}/publish", "/audit-logs", "/system/health", "/system/backups"} {
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

func TestRunQuoteConfirmationAndEffectivePermissionsContract(t *testing.T) {
	raw, err := os.ReadFile("../../docs/api/openapi-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if json.Unmarshal(raw, &spec) != nil {
		t.Fatal("invalid contract")
	}
	paths := spec["paths"].(map[string]any)
	schemas := spec["components"].(map[string]any)["schemas"].(map[string]any)
	confirm := paths["/runs"].(map[string]any)["post"].(map[string]any)
	request := confirm["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	if request["$ref"] != "#/components/schemas/ConfirmRunInput" {
		t.Fatal("confirmation accepts a mutable plan")
	}
	fields := schemas["ConfirmRunInput"].(map[string]any)["properties"].(map[string]any)
	if len(fields) != 3 || fields["estimate_id"] == nil || fields["manifest_hash"] == nil || fields["confirm_cost"].(map[string]any)["const"] != true {
		t.Fatal("confirmation lost explicit fixed quote identity")
	}
	for _, name := range []string{"RunQuote", "EffectivePermissions", "Run"} {
		object := schemas[name].(map[string]any)
		properties := object["properties"].(map[string]any)
		for _, forbidden := range []string{"manifest", "nonce", "seed", "messages", "snapshot_json", "secret_id", "ciphertext"} {
			if properties[forbidden] != nil {
				t.Fatal("S2 contract projection", name, forbidden)
			}
		}
	}
	permission := paths["/auth/permissions"].(map[string]any)["get"].(map[string]any)
	params := permission["parameters"].([]any)
	if len(params) != 1 || params[0].(map[string]any)["name"] != "X-Organization-ID" || params[0].(map[string]any)["required"] != true {
		t.Fatal("permissions not organization scoped")
	}
	run := schemas["Run"].(map[string]any)["properties"].(map[string]any)
	for _, name := range []string{"started_at", "finished_at", "execution_closed_at"} {
		types, ok := run[name].(map[string]any)["type"].([]any)
		if !ok || len(types) != 2 || types[1] != "null" {
			t.Fatal("queued run date is not nullable", name)
		}
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

func TestImplementedManagementTargetContractGuards(t *testing.T) {
	raw, err := os.ReadFile("../../docs/api/openapi-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Parameters []struct {
				Name     string `json:"name"`
				In       string `json:"in"`
				Required bool   `json:"required"`
			} `json:"parameters"`
			RequestBody struct {
				Content map[string]struct {
					Schema struct {
						Ref string `json:"$ref"`
					} `json:"schema"`
				} `json:"content"`
			} `json:"requestBody"`
		} `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]json.RawMessage `json:"properties"`
				Required   []string                   `json:"required"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if json.Unmarshal(raw, &spec) != nil {
		t.Fatal("invalid API contract")
	}
	for _, name := range []string{"UserPatch", "OrganizationPatch", "MemberPatch", "TargetPatch", "TargetSecretRotation", "VersionedRequest", "UserPasswordReset"} {
		found := false
		for _, required := range spec.Components.Schemas[name].Required {
			if required == "version" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s lost required CAS version", name)
		}
	}
	for _, path := range []string{"/organizations/{id}", "/organizations/{id}/members", "/organizations/{id}/members/{memberId}"} {
		for method, op := range spec.Paths[path] {
			found := false
			for _, param := range op.Parameters {
				if param.Name == "X-Organization-ID" && param.In == "header" && param.Required {
					found = true
				}
			}
			if !found {
				t.Errorf("%s %s lost organization scope", method, path)
			}
		}
	}
	for path, want := range map[string]string{"/users/{id}/unlock": "VersionedRequest", "/users/{id}/reset-password": "UserPasswordReset", "/targets/{id}/rotate-secret": "TargetSecretRotation", "/targets/{id}/precheck": "VersionedRequest"} {
		if spec.Paths[path]["post"].RequestBody.Content["application/json"].Schema.Ref != "#/components/schemas/"+want {
			t.Errorf("%s body drifted", path)
		}
	}
	for schema, fields := range map[string][]string{"Member": {"org_id", "version"}, "User": {"must_change_password", "version"}, "Precheck": {"id", "job_id", "target_id", "target_version", "request_count"}} {
		for _, field := range fields {
			if spec.Components.Schemas[schema].Properties[field] == nil {
				t.Errorf("%s missing %s", schema, field)
			}
		}
	}
	if spec.Paths["/targets/{id}/prechecks/{precheckId}"] == nil {
		t.Fatal("missing precise precheck polling route")
	}
}
