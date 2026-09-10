package contracts

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func overviewContract(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile("../../docs/api/openapi-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if json.Unmarshal(raw, &spec) != nil {
		t.Fatal("invalid OpenAPI document")
	}
	methods := contractObject(t, contractObject(t, spec["paths"])["/overview"])
	if len(methods) != 1 {
		t.Fatal("overview must not expose write operations")
	}
	return contractObject(t, methods["get"]), contractObject(t, contractObject(t, spec["components"])["schemas"])
}

func TestOverviewAuthorizationAndBoundedReadContract(t *testing.T) {
	op, schemas := overviewContract(t)
	if op["operationId"] != "getOverview" || op["requestBody"] != nil || op["x-permission-mode"] != "all" || !reflect.DeepEqual(op["x-permission"], []any{"run.read", "target.read"}) || !reflect.DeepEqual(op["security"], []any{map[string]any{"SessionCookie": []any{}}}) {
		t.Fatal("overview authority or read-only operation drift")
	}
	for key, want := range map[string]float64{"x-max-response-bytes": 262144, "x-request-deadline-ms": 2000, "x-max-window-runs": 10000, "x-max-current-targets": 10000, "x-max-risk-cohorts": 16} {
		if op[key] != want {
			t.Fatal("overview resource guard contract drift", key)
		}
	}
	parameters, ok := op["parameters"].([]any)
	if !ok || len(parameters) != 2 {
		t.Fatal("overview query/header whitelist drift")
	}
	header := contractObject(t, parameters[0])
	if header["name"] != "X-Organization-ID" || header["in"] != "header" || header["required"] != true || contractObject(t, header["schema"])["$ref"] != "#/components/schemas/ID" {
		t.Fatal("overview organization scope drift")
	}
	query := contractObject(t, parameters[1])
	days := contractObject(t, query["schema"])
	if query["name"] != "days" || query["in"] != "query" || query["required"] != false || days["type"] != "integer" || days["default"] != float64(7) || !reflect.DeepEqual(days["enum"], []any{float64(7), float64(30)}) {
		t.Fatal("overview window selection drift")
	}
	responses := contractObject(t, op["responses"])
	if len(responses) != 8 {
		t.Fatal("overview error response set drift")
	}
	for _, status := range []string{"200", "400", "401", "403", "409", "429", "500", "503"} {
		if responses[status] == nil {
			t.Fatal("missing overview response", status)
		}
	}
	success := contractObject(t, responses["200"])
	headers := contractObject(t, success["headers"])
	if contractObject(t, contractObject(t, headers["Cache-Control"])["schema"])["const"] != "no-store" {
		t.Fatal("overview must not be cached")
	}
	body := contractObject(t, contractObject(t, success["content"])["application/json"])
	envelope := closedContractFields(t, contractObject(t, body["schema"]), "data", "request_id")
	if contractObject(t, envelope["data"])["$ref"] != "#/components/schemas/Overview" {
		t.Fatal("overview response lost its typed projection")
	}
	busy := contractObject(t, contractObject(t, contractObject(t, responses["429"])["headers"])["Retry-After"])
	if contractObject(t, busy["schema"])["const"] != "2" {
		t.Fatal("overview busy Retry-After drift")
	}
	fields := closedContractFields(t, contractObject(t, schemas["Overview"]), "schema_version", "scope", "organization_id", "analysis_revision", "development", "calibrated", "window", "targets", "runs", "costs", "risk_cohorts", "daily")
	for key, want := range map[string]any{"schema_version": "overview-v1", "scope": "organization_window", "analysis_revision": float64(1), "development": true, "calibrated": false} {
		if contractObject(t, fields[key])["const"] != want {
			t.Fatal("overview observational scope drift", key)
		}
	}
	if contractObject(t, fields["risk_cohorts"])["maxItems"] != float64(16) || contractObject(t, fields["daily"])["maxItems"] != float64(30) {
		t.Fatal("overview aggregate array bounds drift")
	}
}

func TestOverviewUnknownCostsAndSeparateDenominatorsContract(t *testing.T) {
	_, schemas := overviewContract(t)
	closedContractFields(t, contractObject(t, schemas["OverviewTargets"]), "total", "active", "disabled")
	closedContractFields(t, contractObject(t, schemas["OverviewRuns"]), "total", "by_status", "unpublished_runs", "published_runs", "scored_runs", "unscored_runs")
	closedContractFields(t, contractObject(t, schemas["OverviewStatuses"]), "DRAFT", "PRECHECKING", "QUEUED", "RUNNING", "ANALYZING", "COMPLETED", "PARTIAL", "FAILED", "REVIEW_REQUIRED", "CANCELLING", "CANCELLED")
	costs := closedContractFields(t, contractObject(t, schemas["OverviewCosts"]), "currency", "basis", "known_runs", "unknown_runs", "known_subtotal_micros", "complete_total_micros")
	if contractObject(t, costs["currency"])["const"] != "USD" || contractObject(t, costs["basis"])["const"] != "persisted_run_estimate" {
		t.Fatal("estimated cost confused with provider billing")
	}
	for _, name := range []string{"known_subtotal_micros", "complete_total_micros"} {
		choices := contractObject(t, costs[name])["anyOf"].([]any)
		integer := contractObject(t, choices[0])
		if len(choices) != 2 || contractObject(t, choices[1])["type"] != "null" || integer["type"] != "integer" || integer["maximum"] != float64(9007199254740991) || integer["minimum"] != float64(0) {
			t.Fatal("unknown estimate lost null or integer precision boundary")
		}
	}
	distribution := closedContractFields(t, contractObject(t, schemas["OverviewDistribution"]), "low", "watch", "medium", "high", "critical", "insufficient")
	for _, value := range distribution {
		count := contractObject(t, value)
		if count["type"] != "integer" || count["minimum"] != float64(0) || count["maximum"] != float64(10000) {
			t.Fatal("risk distribution changed from finite descriptive counts")
		}
	}
	cohort := closedContractFields(t, contractObject(t, schemas["OverviewCohort"]), "id", "package", "versions", "published_runs", "scored_runs", "unscored_runs", "distribution")
	if contractObject(t, cohort["id"])["pattern"] != "^c([1-9]|1[0-6])$" || contractObject(t, cohort["versions"])["$ref"] != "#/components/schemas/Versions" {
		t.Fatal("cohort scope/version binding lost")
	}
	closedContractFields(t, contractObject(t, schemas["OverviewDailyCohort"]), "cohort_id", "published_runs", "scored_runs", "unscored_runs", "distribution")
	day := closedContractFields(t, contractObject(t, schemas["OverviewDay"]), "local_date", "start_utc", "end_utc", "partial", "run_count", "risk_cohorts")
	if contractObject(t, day["local_date"])["format"] != "date" || contractObject(t, day["partial"])["type"] != "boolean" || contractObject(t, day["risk_cohorts"])["maxItems"] != float64(16) {
		t.Fatal("daily partial/window metadata lost")
	}
}
