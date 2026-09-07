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
	reflect.TypeFor[runservice.TrendItem]():            "RunTrendItem",
	reflect.TypeFor[runservice.AttemptTrendView]():     "AttemptTrend",
	reflect.TypeFor[runservice.OverviewView]():         "Overview",
	reflect.TypeFor[runservice.OverviewWindow]():       "OverviewWindow",
	reflect.TypeFor[runservice.OverviewTargets]():      "OverviewTargets",
	reflect.TypeFor[runservice.OverviewStatuses]():     "OverviewStatuses",
	reflect.TypeFor[runservice.OverviewRuns]():         "OverviewRuns",
	reflect.TypeFor[runservice.OverviewCosts]():        "OverviewCosts",
	reflect.TypeFor[runservice.OverviewDistribution](): "OverviewDistribution",
	reflect.TypeFor[runservice.OverviewCohort]():       "OverviewCohort",
	reflect.TypeFor[runservice.OverviewDailyCohort]():  "OverviewDailyCohort",
	reflect.TypeFor[runservice.OverviewDay]():          "OverviewDay",
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
	overviewSchemas(result)
	properties := func(name string) schema { return result[name].(schema)["properties"].(schema) }
	trend := properties("AttemptTrend")
	for _, field := range []string{"dispatched", "retry_attempts", "succeeded", "failed", "uncertain", "in_flight", "success_rate_denominator", "latency_samples"} {
		trend[field] = schema{"type": "integer", "minimum": 0, "maximum": 3000}
	}
	trend["logical_samples"] = schema{"type": "integer", "minimum": 0, "maximum": 1000}
	trend["success_rate_percent"] = nullable(schema{"type": "number", "minimum": 0, "maximum": 100})
	trend["success_rate_percent"].(schema)["description"] = "100 * succeeded / dispatched. Null only when dispatched=0. This is the confirmed-success fraction of observed dispatch records, not a future probability; uncertain and in-flight attempts remain in the denominator but are not labelled failed."
	trend["success_rate_denominator"].(schema)["description"] = "Equals dispatched, including every retry, UNCERTAIN and in-flight attempt. Never Run completed_samples, valid_sample_count or a substitute request counter."
	trend["logical_samples"].(schema)["description"] = "Distinct persisted logical sample IDs with an attempt. Retrying a sample does not create an independent statistical sample."
	trend["succeeded"].(schema)["description"] = "COMPLETED attempts with VALID or VALID_WITH_WARNING validity, HTTP 200, no error and valid start/finish timestamps. COMPLETED alone is not success."
	trend["failed"].(schema)["description"] = "Known COMPLETED attempts with non-valid final outcomes, including HTTP/protocol/safety/cancellation failures. Does not include UNCERTAIN or DISPATCHED attempts."
	trend["latency_samples"].(schema)["description"] = "COMPLETED successful or failed attempts with a non-null observed duration_ms in [0,86400000]. Missing duration, in-flight attempts and UNCERTAIN recovery zero placeholders are excluded."
	trend["latency_mean_ms"] = nullable(schema{"type": "number", "minimum": 0, "maximum": 86400000})
	for _, field := range []string{"latency_min_ms", "latency_max_ms"} {
		trend[field] = nullable(schema{"type": "integer", "minimum": 0, "maximum": 86400000})
	}
	for _, field := range []string{"latency_mean_ms", "latency_min_ms", "latency_max_ms"} {
		trend[field].(schema)["description"] = "Observed client-side total duration in milliseconds; null when latency_samples=0. Real observed 0ms is retained. Not time-to-first-token, P95, server compute time or an inferred latency for missing observations."
	}
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

func overviewSchemas(result schema) {
	properties := func(name string) schema { return result[name].(schema)["properties"].(schema) }
	for _, name := range []string{"OverviewTargets", "OverviewStatuses", "OverviewRuns", "OverviewCosts", "OverviewDistribution", "OverviewCohort", "OverviewDailyCohort", "OverviewDay"} {
		for key, value := range properties(name) {
			if value.(schema)["type"] == "integer" {
				properties(name)[key] = schema{"type": "integer", "minimum": 0, "maximum": 10000}
			}
		}
	}
	p := properties("Overview")
	p["schema_version"] = schema{"type": "string", "const": "overview-v1"}
	p["scope"] = schema{"type": "string", "const": "organization_window"}
	p["analysis_revision"] = schema{"type": "integer", "const": 1}
	p["development"] = schema{"type": "boolean", "const": true}
	p["calibrated"] = schema{"type": "boolean", "const": false}
	p["risk_cohorts"].(schema)["maxItems"] = 16
	p["daily"].(schema)["minItems"] = 7
	p["daily"].(schema)["maxItems"] = 30
	p["daily"].(schema)["description"] = "Exactly window.days local calendar buckets, ordered oldest first; only the last bucket is partial. Empty days are retained."
	p = properties("OverviewWindow")
	p["days"] = schema{"type": "integer", "enum": []int{7, 30}}
	p["timezone"] = schema{"type": "string", "minLength": 1, "maxLength": 128, "description": "Current organization IANA location or UTC; Local and unknown locations fail closed. Calendar days follow this location, including DST, not fixed UTC 24-hour intervals."}
	p["as_of"].(schema)["description"] = "The fixed observation instant for this authorized read snapshot; equals end_utc."
	p["start_utc"].(schema)["description"] = "Inclusive UTC instant of local midnight window.days-1 dates before today."
	p["end_utc"].(schema)["description"] = "Exclusive UTC end, equal to as_of. Run membership uses created_at, not finished_at or Attempt timestamps."
	p = properties("OverviewCosts")
	p["currency"] = schema{"type": "string", "const": "USD"}
	p["basis"] = schema{"type": "string", "const": "persisted_run_estimate"}
	for _, key := range []string{"known_subtotal_micros", "complete_total_micros"} {
		p[key] = nullable(schema{"type": "integer", "minimum": 0, "maximum": 9007199254740991})
	}
	p["known_subtotal_micros"].(schema)["description"] = "Sum of known persisted Run estimates only, in integer USD micros, not invoices. Null when known_runs=0; an observed known zero remains 0."
	p["complete_total_micros"].(schema)["description"] = "Equal to known_subtotal_micros only when at least one Run has a known estimate and unknown_runs=0; otherwise null, including an empty window."
	id := func() schema {
		return schema{"type": "string", "pattern": "^c([1-9]|1[0-6])$", "maxLength": 3, "description": "Response-local cohort identity assigned by a deterministic package/version tuple sort. Not a persistent database ID, cross-window identity or authorization token."}
	}
	properties("OverviewCohort")["id"] = id()
	properties("OverviewDailyCohort")["cohort_id"] = id()
	p = properties("OverviewDay")
	p["local_date"] = schema{"type": "string", "format": "date", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$", "maxLength": 10}
	p["risk_cohorts"].(schema)["maxItems"] = 16
	p["partial"].(schema)["description"] = "True only for the current unfinished local day, whose exclusive end is as_of; do not compare this partial count as a complete day's improvement."
	result["OverviewTargets"].(schema)["description"] = "Current non-deleted target directory counts, including disabled targets, independent of the Run time window; not endpoint availability."
	result["OverviewStatuses"].(schema)["description"] = "Current Run statuses counted once per Run created in the window. COMPLETED is not upstream request success; no Attempt success-rate is calculated here."
	result["OverviewDistribution"].(schema)["description"] = "Counts of scored, published revision-1 results in one exact package/four-version cohort. Null scores and unpublished Runs are separate, never low risk. These are descriptive counts, not calibrated probabilities, causal anomalies or a new threshold."
}
