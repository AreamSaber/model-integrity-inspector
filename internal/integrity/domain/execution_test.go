package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestExecutionPlanRedactsFormattingAndStructuredLogsButPersists(t *testing.T) {
	const canary = "S2-execution-prompt-and-nonce-canary"
	plan := ExecutionPlan{Manifest: json.RawMessage(`{"nonce":"` + canary + `"}`), Probes: []ProbePlan{{Samples: []SamplePlan{{Nonce: canary, Request: NormalizedRequest{Messages: []NormalizedMessage{{Role: "user", Content: canary}}}}}}}}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, plan), canary) {
			t.Fatal("formatted execution plan leaked S2")
		}
	}
	var output bytes.Buffer
	for _, handler := range []slog.Handler{slog.NewJSONHandler(&output, nil), slog.NewTextHandler(&output, nil)} {
		slog.New(handler).Info("safe", "plan", plan, "pointer", &plan, slog.Group("nested", "plan", plan))
	}
	if strings.Contains(output.String(), canary) || !strings.Contains(output.String(), "redacted execution plan") {
		t.Fatal("structured logger bypassed execution redaction")
	}
	encoded, err := json.Marshal(plan)
	if err != nil || !bytes.Contains(encoded, []byte(canary)) {
		t.Fatal("explicit S2 persistence unexpectedly disabled")
	}
}
