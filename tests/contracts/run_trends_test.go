package contracts

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func trendContract(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile("../../docs/api/openapi-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	paths := contractObject(t, spec["paths"])
	methods := contractObject(t, paths["/runs/trends"])
	if len(methods) != 1 {
		t.Fatal("trends must expose only the implemented GET operation")
	}
	return contractObject(t, methods["get"]), contractObject(t, contractObject(t, spec["components"])["schemas"])
}

func contractObject(t *testing.T, value any) map[string]any {
	t.Helper()
	out, ok := value.(map[string]any)
	if !ok {
		t.Fatal("missing or unstructured contract object")
	}
	return out
}

func closedContractFields(t *testing.T, value map[string]any, fields ...string) map[string]any {
	t.Helper()
	properties := contractObject(t, value["properties"])
	if value["type"] != "object" || value["additionalProperties"] != false || len(properties) != len(fields) {
		t.Fatal("contract fields not closed")
	}
	required, ok := value["required"].([]any)
	if !ok || len(required) != len(fields) {
		t.Fatal("required field set drifted")
	}
	for _, field := range fields {
		if properties[field] == nil || !slices.Contains(required, any(field)) {
			t.Fatal("missing required field", field)
		}
	}
	return properties
}

func trendResponseData(t *testing.T, op map[string]any) map[string]any {
	t.Helper()
	response := contractObject(t, contractObject(t, op["responses"])["200"])
	content := contractObject(t, contractObject(t, response["content"])["application/json"])
	envelope := closedContractFields(t, contractObject(t, content["schema"]), "data", "request_id")
	return closedContractFields(t, contractObject(t, envelope["data"]), "items", "next_cursor", "scope", "analysis_revision", "success_rate_basis", "latency_basis", "development", "calibrated")
}

func TestRunTrendsOperationParametersAndErrorsContract(t *testing.T) {
	op, schemas := trendContract(t)
	if op["operationId"] != "listRunTrends" || op["x-permission"] != "run.read" || op["x-development-status"] != "implemented-database-backed" || op["requestBody"] != nil {
		t.Fatal("trend operation/permission drift")
	}
	security := []any{map[string]any{"SessionCookie": []any{}}}
	if !reflect.DeepEqual(op["security"], security) {
		t.Fatal("trends lost authenticated cookie transport")
	}
	parameters, ok := op["parameters"].([]any)
	if !ok || len(parameters) != 12 {
		t.Fatal("trend query/header whitelist drift")
	}
	want := []string{"X-Organization-ID", "target_id", "limit", "cursor", "q", "status", "package", "model", "channel_id", "risk_level", "date_from", "date_to"}
	byName := map[string]map[string]any{}
	for _, value := range parameters {
		p := contractObject(t, value)
		name, ok := p["name"].(string)
		if !ok || !slices.Contains(want, name) || byName[name] != nil {
			t.Fatal("unknown or repeated parameter")
		}
		byName[name] = p
		location := "query"
		if name == "X-Organization-ID" {
			location = "header"
		}
		if p["in"] != location {
			t.Fatal("parameter location drift", name)
		}
		if (p["required"] == true) != (name == "target_id" || name == "X-Organization-ID") {
			t.Fatal("mandatory target/scope drift", name)
		}
	}
	for _, name := range []string{"target_id", "X-Organization-ID"} {
		if contractObject(t, byName[name]["schema"])["$ref"] != "#/components/schemas/ID" {
			t.Fatal("target/scope lost decimal-string ID")
		}
	}
	limit := contractObject(t, byName["limit"]["schema"])
	if limit["type"] != "integer" || limit["minimum"] != float64(1) || limit["maximum"] != float64(100) || limit["default"] != float64(25) {
		t.Fatal("page limits drifted")
	}
	cursor := contractObject(t, byName["cursor"]["schema"])
	if cursor["type"] != "string" || cursor["maxLength"] != float64(1024) {
		t.Fatal("cursor bound drift")
	}
	for _, name := range []string{"q", "model", "channel_id"} {
		p := contractObject(t, byName[name]["schema"])
		if p["type"] != "string" || p["maxLength"] != float64(128) || p["x-max-utf8-bytes"] != float64(128) {
			t.Fatal("filter UTF-8 byte bound lost", name)
		}
	}
	for _, name := range []string{"date_from", "date_to"} {
		if contractObject(t, byName[name]["schema"])["format"] != "date-time" {
			t.Fatal("date filter format lost")
		}
	}
	risk := contractObject(t, byName["risk_level"]["schema"])
	if !reflect.DeepEqual(risk["enum"], []any{"low", "watch", "medium", "high", "critical", "insufficient"}) {
		t.Fatal("HTTP risk vocabulary drift")
	}
	responses := contractObject(t, op["responses"])
	expectedErrors := map[string][]any{"400": {"MI_INVALID_REQUEST"}, "401": {"MI_SESSION_REQUIRED"}, "403": {"MI_PERMISSION_DENIED", "MI_PASSWORD_CHANGE_REQUIRED"}, "409": {"MI_SETUP_REQUIRED"}, "429": {"MI_RATE_LIMITED"}, "500": {"MI_SERVICE_UNAVAILABLE"}, "503": {"MI_ANALYSIS_RESULT_INVALID", "MI_SERVICE_UNAVAILABLE"}}
	if len(responses) != len(expectedErrors)+1 {
		t.Fatal("unknown response; missing target is empty page, not 404")
	}
	errorFields := contractObject(t, contractObject(t, schemas["ErrorEnvelope"])["properties"])
	errorCodes := contractObject(t, contractObject(t, contractObject(t, errorFields["error"])["properties"])["code"])["enum"].([]any)
	for status, codes := range expectedErrors {
		response := contractObject(t, responses[status])
		if !reflect.DeepEqual(response["x-error-codes"], codes) {
			t.Fatal("closed error codes drifted", status)
		}
		body := contractObject(t, contractObject(t, response["content"])["application/json"])
		if contractObject(t, body["schema"])["$ref"] != "#/components/schemas/ErrorEnvelope" {
			t.Fatal("raw error response allowed", status)
		}
		for _, code := range codes {
			if !slices.Contains(errorCodes, code) {
				t.Fatal("implemented error absent from common enum", code)
			}
		}
	}
	if !strings.Contains(contractObject(t, responses["429"])["description"].(string), "does not implement") {
		t.Fatal("reserved 429 falsely claims implemented per-route limiter")
	}
}

func TestRunTrendsClosedPageAndNullableDenominatorsContract(t *testing.T) {
	op, schemas := trendContract(t)
	data := trendResponseData(t, op)
	items := contractObject(t, data["items"])
	if items["type"] != "array" || items["maxItems"] != float64(100) || contractObject(t, items["items"])["$ref"] != "#/components/schemas/RunTrendItem" {
		t.Fatal("unbounded/untyped trend page")
	}
	next := contractObject(t, data["next_cursor"])
	if !reflect.DeepEqual(next["type"], []any{"string", "null"}) || next["maxLength"] != float64(1024) {
		t.Fatal("nullable cursor drift")
	}
	for field, want := range map[string]any{"scope": "run_page", "analysis_revision": float64(1), "success_rate_basis": "confirmed_successes_over_all_dispatches_percent", "latency_basis": "completed_attempts_with_observed_duration", "development": true, "calibrated": false} {
		if contractObject(t, data[field])["const"] != want {
			t.Fatal("scope/method/development declaration drift", field)
		}
	}
	row := closedContractFields(t, contractObject(t, schemas["RunTrendItem"]), "run", "attempts")
	if contractObject(t, row["run"])["$ref"] != "#/components/schemas/RunHistoryItem" || contractObject(t, row["attempts"])["$ref"] != "#/components/schemas/AttemptTrend" {
		t.Fatal("trend row no longer uses actual DTOs")
	}
	stats := closedContractFields(t, contractObject(t, schemas["AttemptTrend"]), "dispatched", "logical_samples", "retry_attempts", "succeeded", "failed", "uncertain", "in_flight", "success_rate_percent", "success_rate_denominator", "latency_samples", "latency_mean_ms", "latency_min_ms", "latency_max_ms")
	for _, field := range []string{"dispatched", "logical_samples", "retry_attempts", "succeeded", "failed", "uncertain", "in_flight", "success_rate_denominator", "latency_samples"} {
		value := contractObject(t, stats[field])
		maximum := float64(3000)
		if field == "logical_samples" {
			maximum = 1000
		}
		if value["type"] != "integer" || value["minimum"] != float64(0) || value["maximum"] != maximum {
			t.Fatal("attempt count bound drift", field)
		}
	}
	for _, field := range []string{"success_rate_percent", "latency_mean_ms", "latency_min_ms", "latency_max_ms"} {
		value := contractObject(t, stats[field])
		choices, ok := value["anyOf"].([]any)
		if !ok || len(choices) != 2 || contractObject(t, choices[1])["type"] != "null" {
			t.Fatal("missing observation became zero/omission", field)
		}
		number := contractObject(t, choices[0])
		kind, max := "number", float64(86400000)
		if field == "success_rate_percent" {
			max = 100
		}
		if field == "latency_min_ms" || field == "latency_max_ms" {
			kind = "integer"
		}
		if number["type"] != kind || number["minimum"] != float64(0) || number["maximum"] != max {
			t.Fatal("latency/percentage bounds drift", field)
		}
	}
	// Follow every referenced success DTO. A new field must neither bypass
	// the closed reflection check nor smuggle raw request/response material.
	seen := map[string]bool{}
	var walk func(map[string]any)
	walk = func(value map[string]any) {
		if ref, ok := value["$ref"].(string); ok {
			if seen[ref] {
				return
			}
			seen[ref] = true
			walk(contractObject(t, schemas[strings.TrimPrefix(ref, "#/components/schemas/")]))
		}
		if props, ok := value["properties"].(map[string]any); ok {
			if value["additionalProperties"] != false {
				t.Fatal("unstructured public response object")
			}
			for field, child := range props {
				if slices.Contains([]string{"body", "content", "messages", "nonce", "seed", "manifest", "request_snapshot", "request_plan", "config_snapshot", "response_meta", "response_content", "conclusion_json", "ciphertext", "api_key", "headers", "secret_id"}, field) {
					t.Fatal("S2 field in success contract", field)
				}
				walk(contractObject(t, child))
			}
		}
		for _, key := range []string{"anyOf", "oneOf", "allOf"} {
			if choices, ok := value[key].([]any); ok {
				for _, child := range choices {
					walk(contractObject(t, child))
				}
			}
		}
		if child, ok := value["items"].(map[string]any); ok {
			walk(child)
		}
	}
	walk(map[string]any{"$ref": "#/components/schemas/RunTrendItem"})
}

func contractSource(t *testing.T, path string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func contractLiteral(expr ast.Expr) any {
	switch value := expr.(type) {
	case *ast.BasicLit:
		if value.Kind == token.STRING {
			out, _ := strconv.Unquote(value.Value)
			return out
		}
		if value.Kind == token.INT {
			out, _ := strconv.ParseFloat(value.Value, 64)
			return out
		}
	case *ast.Ident:
		if value.Name == "true" {
			return true
		}
		if value.Name == "false" {
			return false
		}
	}
	return nil
}

func TestRunTrendsContractMatchesActualRouteAndScopeConstants(t *testing.T) {
	op, _ := trendContract(t)
	data := trendResponseData(t, op)
	routes := contractSource(t, "../../internal/integrity/api/run_results.go")
	registered := 0
	ast.Inspect(routes, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 || contractLiteral(call.Args[0]) != "GET /api/v1/runs/trends" {
			return true
		}
		method, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || method.Sel.Name != "HandleFunc" {
			t.Fatal("trend registration changed")
		}
		handler, ok := call.Args[1].(*ast.SelectorExpr)
		if !ok || handler.Sel.Name != "listRunTrends" {
			t.Fatal("documented operation no longer binds real handler")
		}
		registered++
		return true
	})
	if registered != 1 {
		t.Fatal("missing or duplicate real trend route")
	}
	source := contractSource(t, "../../internal/integrity/api/run_trends.go")
	calls, constants := map[string]bool{}, map[string]any{}
	targetGuard := false
	ast.Inspect(source, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.CallExpr:
			name := ""
			switch fun := value.Fun.(type) {
			case *ast.Ident:
				name = fun.Name
			case *ast.SelectorExpr:
				name = fun.Sel.Name
			}
			calls[name] = true
			if name == "authorizeOrganization" && (len(value.Args) != 3 || contractLiteral(value.Args[2]) != op["x-permission"]) {
				t.Fatal("actual permission differs from contract")
			}
			if name == "resultScope" && (len(value.Args) != 3 || contractLiteral(value.Args[2]) != "run-trends/revision:1") {
				t.Fatal("signed resource/revision scope drift")
			}
		case *ast.AssignStmt:
			if len(value.Lhs) != 1 || len(value.Rhs) != 1 {
				break
			}
			index, ok := value.Lhs[0].(*ast.IndexExpr)
			if !ok {
				break
			}
			ident, ok := index.X.(*ast.Ident)
			if !ok || ident.Name != "data" {
				break
			}
			key, ok := contractLiteral(index.Index).(string)
			if ok {
				constants[key] = contractLiteral(value.Rhs[0])
			}
		case *ast.BinaryExpr:
			field, ok := value.X.(*ast.SelectorExpr)
			if ok && field.Sel.Name == "TargetID" && value.Op == token.LEQ && contractLiteral(value.Y) == float64(0) {
				targetGuard = true
			}
		}
		return true
	})
	for _, name := range []string{"authorizeOrganization", "resultScope", "runHistoryRequest", "parsePage", "Trends", "pageResult"} {
		if !calls[name] {
			t.Fatal("actual request/response path diverged", name)
		}
	}
	if !targetGuard || len(constants) != 6 {
		t.Fatal("mandatory target or scope metadata changed")
	}
	for field, value := range constants {
		if contractObject(t, data[field])["const"] != value {
			t.Fatal("handler constant differs from public schema", field)
		}
	}
}
