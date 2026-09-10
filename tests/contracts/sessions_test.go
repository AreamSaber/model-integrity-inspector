package contracts

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestLogoutAllSelfServiceContract(t *testing.T) {
	raw, err := os.ReadFile("../../docs/api/openapi-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	methods := contractObject(t, contractObject(t, spec["paths"])["/auth/logout-all"])
	if len(methods) != 1 {
		t.Fatal("logout-all must have exactly one write method")
	}
	op := contractObject(t, methods["post"])
	if op["operationId"] != "logoutAllSessions" || op["x-permission"] != "authenticated" || op["x-forced-password-allowed"] != true || op["x-request-deadline-ms"] != float64(2000) || op["x-unknown-query-parameters"] != "reject" || !reflect.DeepEqual(op["security"], []any{map[string]any{"SessionCookie": []any{}}}) {
		t.Fatal("self-service/session deadline contract changed")
	}
	parameters, ok := op["parameters"].([]any)
	if !ok || len(parameters) != 2 {
		t.Fatal("logout-all must not accept a caller-selected user/organization")
	}
	for i, name := range []string{"Origin", "X-CSRF-Token"} {
		parameter := contractObject(t, parameters[i])
		if parameter["name"] != name || parameter["in"] != "header" || parameter["required"] != true {
			t.Fatal("write security header missing")
		}
	}
	body := contractObject(t, op["requestBody"])
	schema := contractObject(t, contractObject(t, contractObject(t, body["content"])["application/json"])["schema"])
	if body["required"] != true || schema["type"] != "object" || schema["additionalProperties"] != false || schema["maxProperties"] != float64(0) || len(contractObject(t, schema["properties"])) != 0 {
		t.Fatal("logout-all accepts request fields")
	}
	responses := contractObject(t, op["responses"])
	for _, status := range []string{"200", "400", "401", "403", "409", "413", "503"} {
		if responses[status] == nil {
			t.Fatal("missing logout-all response", status)
		}
	}
	success := contractObject(t, responses["200"])
	headers := contractObject(t, success["headers"])
	if contractObject(t, contractObject(t, headers["Cache-Control"])["schema"])["const"] != "no-store" || headers["Set-Cookie"] == nil {
		t.Fatal("logout-all lost cookie/cache policy")
	}
	envelope := contractObject(t, contractObject(t, contractObject(t, success["content"])["application/json"])["schema"])
	if contractObject(t, contractObject(t, envelope["properties"])["data"])["$ref"] != "#/components/schemas/Acknowledged" {
		t.Fatal("logout-all must not return session material")
	}
}
