package contracts

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func reportCSVAt(value any, keys ...string) any {
	for _, key := range keys {
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = object[key]
	}
	return value
}

func validReportCSVContract(spec map[string]any) bool {
	schemas := reportCSVAt(spec, "components", "schemas")
	for _, name := range []string{"ReportRequest", "Report"} {
		if reportCSVAt(schemas, name, "additionalProperties") != false ||
			!reflect.DeepEqual(reportCSVAt(schemas, name, "properties", "format", "enum"), []any{"json", "html", "csv"}) ||
			reportCSVAt(schemas, name, "properties", "analysis_revision", "const") != float64(1) {
			return false
		}
	}
	request, ok := reportCSVAt(schemas, "ReportRequest", "properties").(map[string]any)
	if !ok || len(request) != 3 || reportCSVAt(request, "include_restricted_content", "const") != false ||
		reportCSVAt(schemas, "Report", "properties", "file_size", "maximum") != float64(16<<20) {
		return false
	}
	for _, name := range []string{"Report", "ReportDocument", "ReportDocumentContent"} {
		if reportCSVAt(schemas, name, "properties", "schema_version", "const") != "mii.report.v1" ||
			reportCSVAt(schemas, name, "properties", "review_state", "const") != "not_included" {
			return false
		}
	}
	paths := reportCSVAt(spec, "paths")
	for _, endpoint := range [][2]string{{"/runs/{id}/reports", "post"}, {"/runs/{id}/reports", "get"}, {"/reports/{reportId}", "get"}, {"/reports/{reportId}/download", "get"}} {
		op := reportCSVAt(paths, endpoint[0], endpoint[1])
		if reportCSVAt(op, "x-permission") != "report.export" || !reflect.DeepEqual(reportCSVAt(op, "security"), []any{map[string]any{"SessionCookie": []any{}}}) {
			return false
		}
		parameters, ok := reportCSVAt(op, "parameters").([]any)
		if !ok {
			return false
		}
		required := map[string]bool{"X-Organization-ID": false}
		if endpoint[1] == "post" {
			required["X-CSRF-Token"], required["Idempotency-Key"] = false, false
		}
		for _, parameter := range parameters {
			name, ok := reportCSVAt(parameter, "name").(string)
			if !ok {
				return false
			}
			if _, wanted := required[name]; wanted {
				required[name] = reportCSVAt(parameter, "in") == "header" && reportCSVAt(parameter, "required") == true
			}
			// A download always serves its immutable stored format; no query
			// selector may silently convert an older report into CSV.
			if endpoint[0] == "/reports/{reportId}/download" && reportCSVAt(parameter, "in") == "query" {
				return false
			}
		}
		for _, present := range required {
			if !present {
				return false
			}
		}
	}
	response := reportCSVAt(paths, "/reports/{reportId}/download", "get", "responses", "200")
	media, ok := reportCSVAt(response, "content").(map[string]any)
	if !ok || len(media) != 3 || reportCSVAt(media, "application/json", "schema", "$ref") != "#/components/schemas/ReportDocument" ||
		reportCSVAt(media, "text/html", "schema", "type") != "string" || reportCSVAt(media, "text/csv", "schema", "type") != "string" ||
		reportCSVAt(media, "text/csv", "schema", "x-csv-profile") != "mii.report.csv.v1" {
		return false
	}
	description, _ := reportCSVAt(media, "text/csv", "schema", "description").(string)
	if !strings.Contains(description, "text/csv; charset=utf-8") || !strings.Contains(description, "csv_schema,path,value_type,json_value") {
		return false
	}
	for _, name := range []string{"X-Report-Content-Hash", "X-Report-File-Hash"} {
		if reportCSVAt(response, "headers", name, "schema", "pattern") != "^sha256:[a-f0-9]{64}$" {
			return false
		}
	}
	return reportCSVAt(response, "headers", "X-Content-Type-Options", "schema", "const") == "nosniff" &&
		reportCSVAt(response, "headers", "Content-Disposition", "schema", "type") == "string"
}

func reportCSVSpec(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../docs/api/openapi-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestReportCSVClosedTransportContract(t *testing.T) {
	if !validReportCSVContract(reportCSVSpec(t)) {
		t.Fatal("CSV transport lost its closed formats, document/profile separation, immutable download or authorization contract")
	}
}

func TestReportCSVContractRejectsBoundaryDrift(t *testing.T) {
	for _, mode := range []string{"missing_csv", "pdf_enabled", "profile_as_document", "profile_missing", "wrong_mime", "charset_missing", "restricted", "scope", "csrf", "permission", "download_conversion", "file_hash"} {
		t.Run(mode, func(t *testing.T) {
			spec := reportCSVSpec(t)
			object := func(keys ...string) map[string]any { return reportCSVAt(spec, keys...).(map[string]any) }
			switch mode {
			case "missing_csv":
				object("components", "schemas", "ReportRequest", "properties", "format")["enum"] = []any{"json", "html"}
			case "pdf_enabled":
				object("components", "schemas", "Report", "properties", "format")["enum"] = []any{"json", "html", "csv", "pdf"}
			case "profile_as_document":
				object("components", "schemas", "Report", "properties", "schema_version")["const"] = "mii.report.csv.v1"
			case "profile_missing":
				delete(object("paths", "/reports/{reportId}/download", "get", "responses", "200", "content", "text/csv", "schema"), "x-csv-profile")
			case "wrong_mime":
				content := object("paths", "/reports/{reportId}/download", "get", "responses", "200", "content")
				content["text/plain"] = content["text/csv"]
				delete(content, "text/csv")
			case "charset_missing":
				object("paths", "/reports/{reportId}/download", "get", "responses", "200", "content", "text/csv", "schema")["description"] = "csv_schema,path,value_type,json_value"
			case "restricted":
				object("components", "schemas", "ReportRequest", "properties", "include_restricted_content")["const"] = true
			case "scope", "csrf":
				op := object("paths", "/runs/{id}/reports", "post")
				name := "X-Organization-ID"
				if mode == "csrf" {
					name = "X-CSRF-Token"
				}
				for _, parameter := range op["parameters"].([]any) {
					if parameter.(map[string]any)["name"] == name {
						parameter.(map[string]any)["required"] = false
					}
				}
			case "permission":
				object("paths", "/reports/{reportId}/download", "get")["x-permission"] = "run.read"
			case "download_conversion":
				op := object("paths", "/reports/{reportId}/download", "get")
				op["parameters"] = append(op["parameters"].([]any), map[string]any{"name": "format", "in": "query"})
			case "file_hash":
				delete(object("paths", "/reports/{reportId}/download", "get", "responses", "200", "headers"), "X-Report-File-Hash")
			}
			if validReportCSVContract(spec) {
				t.Fatal("CSV boundary mutation escaped contract verification")
			}
		})
	}
}

func TestReportCSVSchemaGeneratorRetainsClosedFormats(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "../../scripts/read-contract-schemas.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var formats []string
	assignments := 0
	ast.Inspect(file, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			return true
		}
		index, ok := assignment.Lhs[0].(*ast.IndexExpr)
		if !ok {
			return true
		}
		key, ok := index.Index.(*ast.BasicLit)
		if !ok || key.Value != `"format"` {
			return true
		}
		assignments++
		ast.Inspect(assignment.Rhs[0], func(child ast.Node) bool {
			pair, ok := child.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			key, ok := pair.Key.(*ast.BasicLit)
			if !ok || key.Value != `"enum"` {
				return true
			}
			values, ok := pair.Value.(*ast.CompositeLit)
			if !ok {
				return false
			}
			for _, entry := range values.Elts {
				literal, ok := entry.(*ast.BasicLit)
				if !ok {
					return false
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					return false
				}
				formats = append(formats, value)
			}
			return false
		})
		return false
	})
	if assignments != 1 || !reflect.DeepEqual(formats, []string{"json", "html", "csv"}) {
		t.Fatal("schema generator can silently restore the pre-CSV format set")
	}
}
