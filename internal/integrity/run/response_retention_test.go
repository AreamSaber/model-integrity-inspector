package run

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func TestResponseRetentionViewClosedSafeObservation(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	deleted := now.Add(-time.Second)
	row := repository.ResponseRetentionSummary{ObservedAt: now, PolicyDays: 30, PolicyVersion: 2, AttemptCount: 4, RawDeletedCount: 2, DisplayDeletedCount: 1, DisplayExpiredCount: 1, DisplayRetainedCount: 2, LastDeletedAt: &deleted}
	view, err := responseRetentionView(9007199254740993, row)
	if err != nil || view.RunID != "9007199254740993" || view.AnalysisRevision != 1 || view.Version != responseRetentionSummaryVersion {
		t.Fatal("valid summary lost exact historical scope")
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	expected := []string{"version", "run_id", "analysis_revision", "observed_at", "policy_days", "policy_version", "attempt_count", "raw_deleted_count", "display_deleted_count", "display_expired_count", "display_retained_count", "last_deleted_at"}
	if json.Unmarshal(encoded, &fields) != nil || len(fields) != len(expected) {
		t.Fatal("summary is not the closed S1 projection")
	}
	for _, name := range expected {
		if _, ok := fields[name]; !ok {
			t.Fatal("summary omitted its explicit observation field")
		}
	}
	// Empty storage is an actual successful observation, not a failed read
	// represented as zeros. The optional deletion time is explicitly null.
	empty, err := responseRetentionView(1, repository.ResponseRetentionSummary{ObservedAt: now, PolicyVersion: 1})
	if err != nil || empty.LastDeletedAt != nil {
		t.Fatal("valid zero-day empty observation rejected")
	}
}

func TestResponseRetentionViewRejectsContradictions(t *testing.T) {
	now := time.Now().UTC()
	for _, change := range []func(*repository.ResponseRetentionSummary){
		func(r *repository.ResponseRetentionSummary) { r.ObservedAt = time.Time{} },
		func(r *repository.ResponseRetentionSummary) { r.PolicyDays = -1 },
		func(r *repository.ResponseRetentionSummary) { r.PolicyDays = 181 },
		func(r *repository.ResponseRetentionSummary) { r.PolicyVersion = 0 },
		func(r *repository.ResponseRetentionSummary) { r.AttemptCount = 1537 },
		func(r *repository.ResponseRetentionSummary) { r.RawDeletedCount = -1 },
		func(r *repository.ResponseRetentionSummary) { r.DisplayExpiredCount = 3 },
		func(r *repository.ResponseRetentionSummary) { r.DisplayRetainedCount = 2; r.DisplayExpiredCount = 1 },
		func(r *repository.ResponseRetentionSummary) { r.DisplayDeletedCount = 1 },
		func(r *repository.ResponseRetentionSummary) { r.LastDeletedAt = &now },
		func(r *repository.ResponseRetentionSummary) {
			future := now.Add(time.Second)
			r.LastDeletedAt = &future
			r.RawDeletedCount = 1
		},
	} {
		row := repository.ResponseRetentionSummary{ObservedAt: now, PolicyDays: 30, PolicyVersion: 1, AttemptCount: 2}
		change(&row)
		if view, err := responseRetentionView(1, row); !errors.Is(err, repository.ErrRetentionSource) || view.Version != "" {
			t.Fatal("invalid storage observation became an apparently valid summary")
		}
	}
}
