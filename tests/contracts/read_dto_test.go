package contracts

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/identity"
	"model-integrity-inspector.local/mii/internal/integrity/baseline"
	"model-integrity-inspector.local/mii/internal/integrity/report"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

func TestPublicRunReadSchemasMatchActualClosedDTOs(t *testing.T) {
	raw, err := os.ReadFile("../../docs/api/openapi-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	types := map[string]reflect.Type{
		"SystemStatus": reflect.TypeFor[identity.SystemStatus](), "SystemCheck": reflect.TypeFor[identity.SystemCheck](), "SystemBuild": reflect.TypeFor[identity.SystemBuild](),
		"SystemSchema": reflect.TypeFor[identity.SystemSchema](), "SystemJobs": reflect.TypeFor[identity.SystemJobs](), "SystemAudit": reflect.TypeFor[identity.SystemAudit](), "SystemRetention": reflect.TypeFor[identity.SystemRetention](),
		"RunHistoryItem": reflect.TypeFor[runservice.HistoryItem](), "ResultSummary": reflect.TypeFor[runservice.ResultSummary](),
		"RunTrendItem": reflect.TypeFor[runservice.TrendItem](), "AttemptTrend": reflect.TypeFor[runservice.AttemptTrendView](),
		"Overview": reflect.TypeFor[runservice.OverviewView](), "OverviewWindow": reflect.TypeFor[runservice.OverviewWindow](),
		"OverviewTargets": reflect.TypeFor[runservice.OverviewTargets](), "OverviewStatuses": reflect.TypeFor[runservice.OverviewStatuses](),
		"OverviewRuns": reflect.TypeFor[runservice.OverviewRuns](), "OverviewCosts": reflect.TypeFor[runservice.OverviewCosts](),
		"OverviewDistribution": reflect.TypeFor[runservice.OverviewDistribution](), "OverviewCohort": reflect.TypeFor[runservice.OverviewCohort](),
		"OverviewDailyCohort": reflect.TypeFor[runservice.OverviewDailyCohort](), "OverviewDay": reflect.TypeFor[runservice.OverviewDay](),
		"Versions": reflect.TypeFor[runservice.VersionsView](), "Result": reflect.TypeFor[runservice.ResultView](),
		"TokenAnalysis": reflect.TypeFor[runservice.TokenAnalysisView](), "TokenTier": reflect.TypeFor[runservice.TokenTierView](), "TokenPlateau": reflect.TypeFor[runservice.TokenPlateauView](),
		"BehaviorAnalysis": reflect.TypeFor[runservice.BehaviorAnalysisView](), "BehaviorPattern": reflect.TypeFor[runservice.PatternView](), "BehaviorDifference": reflect.TypeFor[runservice.DifferenceView](),
		"Statistic": reflect.TypeFor[runservice.StatisticView](), "Finding": reflect.TypeFor[runservice.FindingView](), "Sample": reflect.TypeFor[runservice.SampleView](), "Attempt": reflect.TypeFor[runservice.AttemptView](), "SampleDetail": reflect.TypeFor[runservice.SampleDetail](),
		"Review":   reflect.TypeFor[runservice.ReviewView](),
		"Baseline": reflect.TypeFor[baseline.View](), "Report": reflect.TypeFor[runservice.ReportView](),
		"ReportDocumentContent": reflect.TypeFor[report.Document](),
		"ReportDocument": reflect.TypeFor[struct {
			report.Document
			ContentHash string `json:"content_hash"`
		}](),
		"ReportVersions": reflect.TypeFor[report.Versions](), "ReportRun": reflect.TypeFor[report.Run](), "ReportResult": reflect.TypeFor[report.Result](),
		"ReportStatistic": reflect.TypeFor[report.Statistic](), "ReportFinding": reflect.TypeFor[report.Finding](), "ReportSample": reflect.TypeFor[report.Sample](), "ReportAttempt": reflect.TypeFor[report.Attempt](),
		"ReportTokenStatistics": reflect.TypeFor[report.TokenStatistics](), "ReportTier": reflect.TypeFor[report.Tier](), "ReportPlateau": reflect.TypeFor[report.Plateau](),
		"ReportBehaviorStatistics": reflect.TypeFor[report.BehaviorStatistics](), "ReportPattern": reflect.TypeFor[report.Pattern](), "ReportDifference": reflect.TypeFor[report.Difference](),
	}
	for name, typeOf := range types {
		t.Run(name, func(t *testing.T) {
			schema := spec.Components.Schemas[name]
			if schema == nil || schema["type"] != "object" || schema["additionalProperties"] != false {
				t.Fatal("public DTO schema missing or not closed")
			}
			properties := schema["properties"].(map[string]any)
			required := map[string]bool{}
			for _, field := range schema["required"].([]any) {
				required[field.(string)] = true
			}
			fields := map[string]reflect.StructField{}
			var collect func(reflect.Type)
			collect = func(typ reflect.Type) {
				for i := 0; i < typ.NumField(); i++ {
					field := typ.Field(i)
					if field.Anonymous {
						collect(field.Type)
						continue
					}
					key := strings.Split(field.Tag.Get("json"), ",")[0]
					if key == "" || key == "-" {
						t.Fatal("untagged public projection field")
					}
					fields[key] = field
				}
			}
			collect(typeOf)
			if len(properties) != len(fields) {
				t.Fatalf("DTO schema drift: %d declared fields vs %d actual; regenerate read-contract-schemas.go", len(properties), len(fields))
			}
			for key, field := range fields {
				property, ok := properties[key].(map[string]any)
				if !ok {
					t.Fatalf("DTO field %s missing from contract", key)
				}
				optional := strings.Contains(field.Tag.Get("json"), ",omitempty")
				if required[key] == optional {
					t.Errorf("required/omitempty mismatch for %s", key)
				}
				checkPublicFieldType(t, spec.Components.Schemas, property, field.Type, !optional, key)
			}
		})
	}
}

func checkPublicFieldType(t *testing.T, schemas map[string]map[string]any, property map[string]any, typeOf reflect.Type, required bool, key string) {
	t.Helper()
	if typeOf.Kind() == reflect.Pointer {
		if required {
			choices, ok := property["anyOf"].([]any)
			if !ok || len(choices) != 2 || choices[1].(map[string]any)["type"] != "null" {
				t.Errorf("nullable DTO field %s cannot be omitted/converted to zero", key)
				return
			}
			property = choices[0].(map[string]any)
		}
		checkPublicFieldType(t, schemas, property, typeOf.Elem(), true, key)
		return
	}
	if ref, ok := property["$ref"].(string); ok {
		property = schemas[strings.TrimPrefix(ref, "#/components/schemas/")]
	}
	want := ""
	switch typeOf.Kind() {
	case reflect.String:
		want = "string"
	case reflect.Int, reflect.Int64:
		want = "integer"
	case reflect.Float64:
		want = "number"
	case reflect.Bool:
		want = "boolean"
	case reflect.Struct:
		want = "object"
		if typeOf == reflect.TypeFor[time.Time]() {
			want = "string"
			if property["format"] != "date-time" {
				t.Errorf("timestamp %s lost RFC3339 format", key)
			}
		}
	case reflect.Slice:
		want = "array"
		items, ok := property["items"].(map[string]any)
		if !ok {
			t.Fatalf("untyped array %s", key)
		}
		maximum, ok := property["maxItems"].(float64)
		if !ok || maximum < 1 || maximum > 4096 {
			t.Errorf("unbounded public array %s", key)
		}
		checkPublicFieldType(t, schemas, items, typeOf.Elem(), true, key)
	default:
		t.Fatalf("unsupported unstructured public field %s", key)
	}
	if property["type"] != want {
		t.Errorf("field %s: declared type %v, actual %s", key, property["type"], want)
	}
}
