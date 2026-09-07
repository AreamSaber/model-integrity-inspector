//go:build ignore

// Emit the structural OpenAPI schemas for the implemented read-only Run DTOs.
// This command does not write files or inspect a database. Keep closed schemas
// synchronized with the public projection types, not persistence structures.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/baseline"
	"model-integrity-inspector.local/mii/internal/integrity/report"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

type schema = map[string]any

type reportArtifact struct {
	report.Document
	ContentHash string `json:"content_hash"`
}

var names = map[reflect.Type]string{
	reflect.TypeFor[runservice.HistoryItem]():          "RunHistoryItem",
	reflect.TypeFor[runservice.ResultSummary]():        "ResultSummary",
	reflect.TypeFor[runservice.VersionsView]():         "Versions",
	reflect.TypeFor[runservice.ResultView]():           "Result",
	reflect.TypeFor[runservice.TokenAnalysisView]():    "TokenAnalysis",
	reflect.TypeFor[runservice.TokenTierView]():        "TokenTier",
	reflect.TypeFor[runservice.TokenPlateauView]():     "TokenPlateau",
	reflect.TypeFor[runservice.BehaviorAnalysisView](): "BehaviorAnalysis",
	reflect.TypeFor[runservice.PatternView]():          "BehaviorPattern",
	reflect.TypeFor[runservice.DifferenceView]():       "BehaviorDifference",
	reflect.TypeFor[runservice.StatisticView]():        "Statistic",
	reflect.TypeFor[runservice.FindingView]():          "Finding",
	reflect.TypeFor[runservice.SampleView]():           "Sample",
	reflect.TypeFor[runservice.AttemptView]():          "Attempt",
	reflect.TypeFor[runservice.SampleDetail]():         "SampleDetail",
	reflect.TypeFor[runservice.ReviewView]():           "Review",
	reflect.TypeFor[baseline.View]():                   "Baseline",
	reflect.TypeFor[runservice.ReportView]():           "Report",
	reflect.TypeFor[reportArtifact]():                  "ReportDocument",
	reflect.TypeFor[report.Document]():                 "ReportDocumentContent",
	reflect.TypeFor[report.Versions]():                 "ReportVersions",
	reflect.TypeFor[report.Run]():                      "ReportRun",
	reflect.TypeFor[report.Result]():                   "ReportResult",
	reflect.TypeFor[report.Statistic]():                "ReportStatistic",
	reflect.TypeFor[report.Finding]():                  "ReportFinding",
	reflect.TypeFor[report.Sample]():                   "ReportSample",
	reflect.TypeFor[report.Attempt]():                  "ReportAttempt",
	reflect.TypeFor[report.TokenStatistics]():          "ReportTokenStatistics",
	reflect.TypeFor[report.Tier]():                     "ReportTier",
	reflect.TypeFor[report.Plateau]():                  "ReportPlateau",
	reflect.TypeFor[report.BehaviorStatistics]():       "ReportBehaviorStatistics",
	reflect.TypeFor[report.Pattern]():                  "ReportPattern",
	reflect.TypeFor[report.Difference]():               "ReportDifference",
}

func nullable(value schema) schema {
	return schema{"anyOf": []schema{value, {"type": "null"}}}
}

func fieldSchema(t reflect.Type, key string) schema {
	if t.Kind() == reflect.Pointer {
		return nullable(fieldSchema(t.Elem(), key))
	}
	if t == reflect.TypeFor[time.Time]() {
		return schema{"type": "string", "format": "date-time", "maxLength": 64}
	}
	if name, exists := names[t]; exists {
		return schema{"$ref": "#/components/schemas/" + name}
	}
	switch t.Kind() {
	case reflect.Struct:
		if t.NumField() == 0 {
			return schema{"type": "object", "additionalProperties": false, "properties": schema{}}
		}
		panic("unregistered nested DTO: " + t.String())
	case reflect.String:
		if key == "id" || key == "run_id" || key == "target_id" || key == "created_by" || key == "approved_by" || key == "report_id" || key == "organization_id" || key == "probe_instance_id" || key == "final_attempt_id" || key == "sample_refs" {
			return schema{"$ref": "#/components/schemas/ID"}
		}
		value := schema{"type": "string", "maxLength": 4096}
		if key == "rule_bundle" || key == "template_bundle" || key == "scoring" || key == "tokenizer_bundle" || key == "rule_version" {
			value["maxLength"] = 128
			value["pattern"] = "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
		}
		choices := map[string][]string{
			"conclusion":     {"confirmed", "false_positive", "watch", "not_applicable"},
			"evidence_grade": {"C", "D"}, "risk_level": {"low", "watch", "medium", "high", "critical", "insufficient"},
			"completeness": {"full", "partial", "insufficient"}, "observation_mode": {"blackbox"},
			"package": {"quick", "standard", "deep", "custom"},
			"status":  {"DRAFT", "PRECHECKING", "QUEUED", "RUNNING", "ANALYZING", "COMPLETED", "PARTIAL", "FAILED", "REVIEW_REQUIRED", "CANCELLING", "CANCELLED"},
		}
		if values, exists := choices[key]; exists {
			value["enum"] = values
		}
		return value
	case reflect.Int, reflect.Int64:
		value := schema{"type": "integer", "minimum": 0, "maximum": 9007199254740991}
		if key == "analysis_revision" {
			value["const"] = 1
		}
		if key == "confidence" {
			value["maximum"] = 74
		}
		return value
	case reflect.Float64:
		value := schema{"type": "number"}
		if strings.HasSuffix(key, "risk") || key == "risk_score" {
			value["minimum"], value["maximum"] = 0, 100
		}
		return value
	case reflect.Bool:
		value := schema{"type": "boolean"}
		if key == "calibrated" {
			value["const"] = false
		}
		if key == "development" || key == "published" {
			value["const"] = true
		}
		return value
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			panic("binary data must not enter public read DTOs")
		}
		maximum := 1000
		switch key {
		case "patterns":
			maximum = 2048
		case "tiers", "sample_refs":
			maximum = 512
		case "attempts":
			maximum = 3
		case "differences":
			maximum = 4
		}
		return schema{"type": "array", "items": fieldSchema(t.Elem(), key), "maxItems": maximum}
	default:
		panic("unsupported public DTO field: " + t.String())
	}
}

func objectSchema(t reflect.Type) schema {
	properties := schema{}
	required := []string{}
	var add func(reflect.Type)
	add = func(t reflect.Type) {
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if field.Anonymous {
				add(field.Type)
				continue
			}
			parts := strings.Split(field.Tag.Get("json"), ",")
			if parts[0] == "" || parts[0] == "-" {
				panic("untagged public DTO field: " + field.Name)
			}
			optional := len(parts) > 1 && parts[1] == "omitempty"
			typeOf := field.Type
			if optional && typeOf.Kind() == reflect.Pointer {
				typeOf = typeOf.Elem()
			}
			properties[parts[0]] = fieldSchema(typeOf, parts[0])
			if !optional {
				required = append(required, parts[0])
			}
		}
	}
	add(t)
	return schema{"type": "object", "additionalProperties": false, "properties": properties, "required": required}
}

func main() {
	result := schema{}
	for t, name := range names {
		result[name] = objectSchema(t)
	}
	properties := func(name string) schema { return result[name].(schema)["properties"].(schema) }
	props := properties("Baseline")
	props["status"] = schema{"type": "string", "enum": []string{"draft", "approved", "expired", "retired"}}
	props["eligible_for_scoring"] = schema{"type": "boolean", "const": false}
	props["source"] = schema{"type": "string", "enum": []string{"official", "historical"}}
	props["protocol"] = schema{"type": "string", "enum": []string{"openai_chat"}}
	for _, field := range []string{"parameters_hash", "manifest_hash"} {
		props[field] = schema{"type": "string", "pattern": "^[a-f0-9]{64}$", "maxLength": 64}
	}
	props = properties("Report")
	props["status"] = schema{"type": "string", "enum": []string{"queued", "generating", "ready", "failed", "expired"}}
	props["format"] = schema{"type": "string", "enum": []string{"json", "html"}}
	props["file_size"] = schema{"type": "integer", "minimum": 1, "maximum": report.MaxOutputBytes}
	props["revision"] = schema{"type": "integer", "minimum": 1, "maximum": 2147483647}
	for _, name := range []string{"Report", "ReportDocument", "ReportDocumentContent"} {
		p := properties(name)
		p["schema_version"] = schema{"type": "string", "const": report.SchemaVersion}
		p["review_state"] = schema{"type": "string", "const": "not_included"}
		if name != "Report" {
			p["review"] = schema{"anyOf": []schema{{"type": "object", "additionalProperties": false}, {"type": "null"}}, "const": nil}
			p["canonical_version"] = schema{"type": "string", "const": report.CanonicalVersion}
			p["content_state"] = schema{"type": "string", "const": "redacted"}
			p["findings"].(schema)["maxItems"] = report.MaxFindings
			p["samples"].(schema)["maxItems"] = report.MaxSamples
		}
		for _, field := range []string{"content_hash", "file_hash"} {
			if _, exists := p[field]; exists {
				p[field] = schema{"type": "string", "pattern": "^sha256:[a-f0-9]{64}$", "maxLength": 71}
			}
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "cannot encode public DTO schemas")
		os.Exit(1)
	}
}
