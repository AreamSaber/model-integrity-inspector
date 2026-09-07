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

	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

type schema = map[string]any

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
	case reflect.String:
		if key == "id" || key == "run_id" || key == "target_id" || key == "created_by" || key == "probe_instance_id" || key == "final_attempt_id" || key == "sample_refs" {
			return schema{"$ref": "#/components/schemas/ID"}
		}
		value := schema{"type": "string", "maxLength": 4096}
		if key == "rule_bundle" || key == "template_bundle" || key == "scoring" || key == "tokenizer_bundle" || key == "rule_version" {
			value["maxLength"] = 128
			value["pattern"] = "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
		}
		choices := map[string][]string{
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
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "cannot encode public DTO schemas")
		os.Exit(1)
	}
}
