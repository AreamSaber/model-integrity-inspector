package app

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/report"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

// All three real artifact types must survive response cleanup. Only an explicit
// browser hold may create additional independent reports, and every extra row
// is captured and compared afterwards rather than filtering it out.
func validPipelineReportInventory(rows []runservice.ReportView, runID string, allowExtra bool) bool {
	if len(rows) < 3 || len(rows) >= 100 || !allowExtra && len(rows) != 3 {
		return false
	}
	formats, ids := map[string]bool{}, map[string]bool{}
	for _, row := range rows {
		if row.ID == "" || ids[row.ID] || row.RunID != runID || row.AnalysisRevision != 1 || row.SchemaVersion != report.SchemaVersion || row.Status != "ready" || row.Revision < 1 {
			return false
		}
		switch row.Format {
		case "json", "html", "csv":
			formats[row.Format], ids[row.ID] = true, true
		default:
			return false
		}
	}
	return len(formats) == 3
}

func checkPipelineCSV(t *testing.T, data []byte, view runservice.ReportView, orgID string, expectedSamples int) {
	t.Helper()
	if bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) || !bytes.HasSuffix(data, []byte("\r\n")) {
		t.Fatal("actual pipeline CSV encoding changed")
	}
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = 4
	rows, err := reader.ReadAll()
	if err != nil || len(rows) < 2 || !reflect.DeepEqual(rows[0], []string{"csv_schema", "path", "value_type", "json_value"}) {
		t.Fatal("actual pipeline did not produce CSV")
	}
	nodes := map[string][]string{}
	samples := map[string]bool{}
	for _, row := range rows[1:] {
		if row[0] != report.CSVSchemaVersion || nodes[row[1]] != nil || !json.Valid([]byte(row[3])) {
			t.Fatal("CSV full-node profile damaged in the actual application")
		}
		nodes[row[1]] = row
		if index, ok := strings.CutPrefix(row[1], "/samples/"); ok && !strings.Contains(index, "/") {
			if row[2] != "object" {
				t.Fatal("CSV sample node is not an object")
			}
			samples[index] = true
		}
	}
	for path, value := range map[string]any{
		"/schema_version": report.SchemaVersion, "/organization_id": orgID,
		"/report_id": view.ID, "/run_id": view.RunID, "/content_hash": *view.ContentHash,
		"/review": nil, "/review_state": "not_included", "/development": true,
		"/calibrated": false, "/disclaimer": report.Disclaimer,
	} {
		encoded, err := json.Marshal(value)
		if err != nil || nodes[path] == nil || nodes[path][3] != string(encoded) {
			t.Fatal("actual CSV lost fixed source or truthful review boundary", path)
		}
	}
	if len(samples) != expectedSamples {
		t.Fatal("actual CSV omitted logical samples")
	}
	for i := range expectedSamples {
		if !samples[strconv.Itoa(i)] {
			t.Fatal("actual CSV sample indexes are not complete")
		}
	}
}

func TestPipelineReportInventoryRequiresAllFormatsAndPreservesBrowserExtras(t *testing.T) {
	var rows []runservice.ReportView
	for i, format := range []string{"json", "html", "csv"} {
		rows = append(rows, runservice.ReportView{ID: strconv.Itoa(i + 1), RunID: "7", AnalysisRevision: 1, Revision: 1, SchemaVersion: report.SchemaVersion, Format: format, Status: "ready"})
	}
	for _, extra := range []bool{false, true} {
		if !validPipelineReportInventory(rows, "7", extra) {
			t.Fatal("complete inventory refused")
		}
		for _, mutation := range []string{"missing", "duplicate_id", "missing_format", "unknown_format", "unready", "foreign_run", "profile_as_schema"} {
			changed := append([]runservice.ReportView(nil), rows...)
			switch mutation {
			case "missing":
				changed = changed[:2]
			case "duplicate_id":
				changed[2].ID = changed[0].ID
			case "missing_format":
				changed[2].Format = "json"
			case "unknown_format":
				changed[2].Format = "pdf"
			case "unready":
				changed[2].Status = "generating"
			case "foreign_run":
				changed[2].RunID = "8"
			case "profile_as_schema":
				changed[2].SchemaVersion = report.CSVSchemaVersion
			}
			if validPipelineReportInventory(changed, "7", extra) {
				t.Fatal("invalid inventory accepted", mutation)
			}
		}
	}
	additional := rows[2]
	additional.ID, additional.Revision = "4", 2
	rows = append(rows, additional)
	if validPipelineReportInventory(rows, "7", false) || !validPipelineReportInventory(rows, "7", true) {
		t.Fatal("only explicit browser workflow may create additional immutable reports")
	}
}
