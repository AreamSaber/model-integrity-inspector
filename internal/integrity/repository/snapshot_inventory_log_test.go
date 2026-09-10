package repository

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"time"
)

// Exercise the real structured handler, retaining a timestamp containing the
// numeric fixture canaries. Only the private attribute represents the object;
// searching the complete line incorrectly treats timestamp digits as leaked IDs.
func snapshotInventoryLogText(t *testing.T, value any) string {
	t.Helper()
	stamp := time.Date(2026, 9, 10, 12, 34, 0, 123456789, time.UTC)
	record := slog.NewRecord(stamp, slog.LevelInfo, "snapshot", 0)
	record.Add("value", value)
	var out bytes.Buffer
	if err := slog.NewJSONHandler(&out, nil).Handle(t.Context(), record); err != nil {
		t.Fatal("real snapshot JSON log handler failed", err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(out.Bytes(), &fields) != nil || len(fields) != 4 {
		t.Fatal("snapshot log envelope changed or exposed additional fields")
	}
	for key, want := range map[string]string{"time": stamp.Format(time.RFC3339Nano), "level": "INFO", "msg": "snapshot"} {
		var actual string
		if json.Unmarshal(fields[key], &actual) != nil || actual != want {
			t.Fatal("snapshot log metadata changed")
		}
	}
	var text string
	raw := fields["value"]
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &text) != nil {
		t.Fatal("private snapshot log value is not a fixed string projection")
	}
	return text
}

func TestSnapshotInventoryLogExtractionPreservesActualLeaks(t *testing.T) {
	for _, raw := range []string{"private-canary 1234", "[private snapshot report entry] 123456789 987654321"} {
		// Extraction must not redact the payload merely to make its assertions
		// pass. Deliberately leaked attributes remain visible to the old canaries.
		if got := snapshotInventoryLogText(t, slog.StringValue(raw)); got != raw {
			t.Fatal("test helper hid a real leaked attribute")
		}
	}
}
