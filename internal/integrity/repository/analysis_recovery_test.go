package repository

import (
	"context"
	"errors"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func TestAnalysisRecoveryDoesNotInventResultsOrCloseLiveJob(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, queue, run, _, lease := analysisReadyFixture(t, store, 1)
		if err := queue.ReconcileAnalyses(context.Background()); err != nil {
			t.Fatal(err)
		}
		live, _ := tenant.GetRun(run.ID)
		if live.Status != "ANALYZING" || live.Version != run.Version {
			t.Fatal("live analysis closed")
		}
		if err := queue.Fail(context.Background(), lease, "WORKER_HANDLER_FAILED"); err != nil {
			t.Fatal(err)
		}
		original := store.auditSigner
		broken := &switchAuditSigner{}
		broken.fail.Store(true)
		store.auditSigner = broken
		if err := queue.ReconcileAnalyses(context.Background()); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatal("audit failure ignored", err)
		}
		store.auditSigner = original
		live, _ = tenant.GetRun(run.ID)
		if live.Status != "ANALYZING" {
			t.Fatal("failure status escaped audit rollback")
		}
		if err := queue.ReconcileRunJobs(context.Background()); err != nil {
			t.Fatal(err)
		}
		failed, _ := tenant.GetRun(run.ID)
		if failed.Status != "FAILED" || failed.FinishedAt == nil || failed.ExecutionClosedAt == nil || failed.Version != run.Version+1 || failed.ErrorSummary == nil || *failed.ErrorSummary != "MI_ANALYSIS_FAILED" || failed.RequestCount != run.RequestCount {
			t.Fatal("wrong analysis failure projection")
		}
		if _, err := tenant.GetPublishedAnalysis(run.ID, 1); !errors.Is(err, ErrNotFound) {
			t.Fatal("failed analysis invented scores")
		}
		if err := queue.ReconcileAnalyses(context.Background()); err != nil {
			t.Fatal(err)
		}
		same, _ := tenant.GetRun(run.ID)
		if same.Version != failed.Version {
			t.Fatal("reconciliation repeated terminal transition")
		}
		if err := queue.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := queue.ReconcileAnalyses(context.Background()); !errors.Is(err, ErrConsumerLost) {
			t.Fatal("closed consumer recovered analysis", err)
		}
	})
}
