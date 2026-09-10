package run

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestReviewViewDiagnosticsRedactButAuthorizedJSONPreservesProse(t *testing.T) {
	const note = "synthetic-human-review-canary"
	view := ReviewView{Explanation: note}
	for _, pattern := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		if strings.Contains(fmt.Sprintf(pattern, view), note) || strings.Contains(fmt.Sprintf(pattern, &view), note) {
			t.Fatal("human note exposed by diagnostic formatting")
		}
	}
	for _, asJSON := range []bool{false, true} {
		var output bytes.Buffer
		var handler slog.Handler = slog.NewTextHandler(&output, nil)
		if asJSON {
			handler = slog.NewJSONHandler(&output, nil)
		}
		slog.New(handler).Info("review", "value", view, "pointer", &view)
		if strings.Contains(output.String(), note) {
			t.Fatal("human note exposed by structured diagnostics")
		}
	}
	raw, err := json.Marshal(view)
	if err != nil || !bytes.Contains(raw, []byte(note)) {
		t.Fatal("authorized HTTP projection lost human note")
	}
}
