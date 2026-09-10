package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func analysisReadyFixture(t *testing.T, store *Store, count int) (*Tenant, *JobQueue, RunRecord, []LogicalSampleRecord, JobLease) {
	t.Helper()
	tenant, _, plan, policy := executionFixture(t, store, count)
	run, queue, samples := executionStart(t, tenant, plan, policy)
	for _, sample := range samples {
		lease, err := queue.Claim(context.Background())
		if err != nil || lease == nil {
			t.Fatal("sample lease", err)
		}
		attempt := reserveTestAttempt(t, tenant, queue, *lease, sample)
		body := responseFixtureBody(t, tenant, queue, *lease, sample, attempt)
		if err := queue.CompleteWith(context.Background(), *lease, func(tx *TenantTransaction) error {
			return tx.FinishLegacyAttemptWithCapture(sample.ID, attempt.ID, successOutcome(), 0, body)
		}); err != nil {
			t.Fatal(err)
		}
	}
	lease, err := queue.Claim(context.Background())
	if err != nil || lease == nil || JobType(lease.Job.Type) != JobRunAnalyze {
		t.Fatal("analysis lease", err)
	}
	run, err = tenant.GetRun(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	samples, err = tenant.ListExecutionSamples(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	return tenant, queue, run, samples, *lease
}

func TestAnalysisSourceScopedFencedAndRedacted(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, queue, run, samples, lease := analysisReadyFixture(t, store, 2)
		source, err := queue.LoadRunAnalysis(context.Background(), lease)
		if err != nil {
			t.Fatal("load", err)
		}
		if err := source.Use(func(data AnalysisData) error {
			if data.Run.ID != run.ID || data.Run.OrganizationID != tenant.orgID || len(data.Samples) != 2 || len(data.Attempts) != 2 || len(data.Evidence) != 2 {
				t.Fatal("source lost scoped rows")
			}
			for _, a := range data.Attempts {
				if a.ResponseMeta != "" {
					t.Fatal("loaded redundant response blob")
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		for _, mutate := range []func(*JobLease){
			func(l *JobLease) { l.Job.OrganizationID++ },
			func(l *JobLease) { l.Job.ObjectID++ },
			func(l *JobLease) { l.Generation++ },
			func(l *JobLease) { l.Job.Type = string(JobSampleExecute) },
		} {
			wrong := lease
			mutate(&wrong)
			if got, err := queue.LoadRunAnalysis(context.Background(), wrong); err == nil || got != nil {
				t.Fatal("forged fence obtained source")
			}
		}
		if err := store.db.Model(&ResponseEvidenceRecord{}).Where("organization_id = ? AND attempt_id = ?", tenant.orgID, *samples[0].FinalAttemptID).Update("expires_at", time.Now().UTC().Add(-time.Hour)).Error; err != nil {
			t.Fatal(err)
		}
		source, err = queue.LoadRunAnalysis(context.Background(), lease)
		if err != nil {
			t.Fatal(err)
		}
		if err := source.Use(func(data AnalysisData) error {
			if len(data.Evidence) != 1 || len(data.Attempts) != 2 || len(data.Samples) != 2 {
				t.Fatal("expiry should remove evidence, not historic attempts")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := queue.CompleteWith(context.Background(), lease, func(*TenantTransaction) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if got, err := queue.LoadRunAnalysis(context.Background(), lease); !errors.Is(err, ErrJobLeaseLost) || got != nil {
			t.Fatal("completed lease loaded source", err)
		}
	})
}

func TestAnalysisSourceRejectsBrokenClosedBindings(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, queue, run, samples, lease := analysisReadyFixture(t, store, 2)
		cases := []struct {
			name, table, column string
			id                  int64
			bad, good           any
		}{
			{"open", "integrity_runs", "execution_closed_at", run.ID, nil, run.ExecutionClosedAt},
			{"state", "integrity_runs", "status", run.ID, "RUNNING", "ANALYZING"},
			{"reserved", "integrity_runs", "reserved_tokens", run.ID, 1, 0},
			{"pending", "integrity_logical_samples", "completed_at", samples[0].ID, nil, samples[0].CompletedAt},
			{"count", "integrity_logical_samples", "attempt_count", samples[0].ID, 2, 1},
			{"missing-final", "integrity_logical_samples", "final_attempt_id", samples[0].ID, nil, samples[0].FinalAttemptID},
			{"unfinished-attempt", "integrity_sample_attempts", "status", *samples[0].FinalAttemptID, "DISPATCHED", "COMPLETED"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				query := store.db.Table(tc.table).Where("organization_id = ? AND id = ?", tenant.orgID, tc.id)
				if err := query.Update(tc.column, tc.bad).Error; err != nil {
					t.Fatal(err)
				}
				got, err := queue.LoadRunAnalysis(context.Background(), lease)
				if !errors.Is(err, ErrAnalysisSource) || got != nil {
					t.Fatal("broken binding accepted", err)
				}
				if err := query.Update(tc.column, tc.good).Error; err != nil {
					t.Fatal(err)
				}
			})
		}
		// Existing database constraints prevent a cross-sample final pointer even
		// before the new loader runs; do not disable those protections in a test.
		if err := store.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND id = ?", tenant.orgID, samples[0].ID).Update("final_attempt_id", samples[1].FinalAttemptID).Error; err == nil {
			t.Fatal("database allowed cross-sample final pointer")
		}
	})
}

func TestAnalysisSourceByteBudgetBeforeDecodeAndNoArbitraryJob(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, queue, run, _, lease := analysisReadyFixture(t, store, 1)
		// Multibyte text verifies byte rather than character accounting on both DBs.
		query := store.db.Model(&RunRecord{}).Where("organization_id = ? AND id = ?", tenant.orgID, run.ID)
		if err := query.Update("config_snapshot", strings.Repeat("界", (8<<20)/3+1)).Error; err != nil {
			t.Fatal(err)
		}
		if got, err := queue.LoadRunAnalysis(context.Background(), lease); !errors.Is(err, ErrAnalysisLimit) || got != nil {
			t.Fatal("oversized source decoded", err)
		}
		if err := query.Update("config_snapshot", run.ConfigSnapshot).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.db.Model(&Job{}).Where("organization_id = ? AND id = ?", tenant.orgID, lease.Job.ID).Update("idempotency_key", "unrelated-analysis").Error; err != nil {
			t.Fatal(err)
		}
		if got, err := queue.LoadRunAnalysis(context.Background(), lease); !errors.Is(err, ErrAnalysisSource) || got != nil {
			t.Fatal("arbitrary queued job accepted", err)
		}
	})
}

func TestAnalysisSourceProtectedFormatting(t *testing.T) {
	const canary = "S2-analysis-prompt-canary"
	data := AnalysisData{Run: RunRecord{ConfigSnapshot: canary}, Attempts: []AttemptRecord{{RequestSnapshot: canary}}}
	source := &AnalysisSource{data: data}
	for _, value := range []any{data, &data, source} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, value), canary) {
				t.Fatal("format leaked source")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrAnalysisSensitive) {
			t.Fatal("JSON source exported")
		}
		var output bytes.Buffer
		for _, handler := range []slog.Handler{slog.NewJSONHandler(&output, nil), slog.NewTextHandler(&output, nil)} {
			slog.New(handler).Info("safe", "source", value)
		}
		if strings.Contains(output.String(), canary) {
			t.Fatal("logger leaked source")
		}
	}
}
