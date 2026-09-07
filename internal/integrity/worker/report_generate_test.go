package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/reportstorage"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func TestReportWorkerRealAnalysisToFrozenArtifactAndRetry(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		tenant, run, builder, queue, lease, _ := closedSignedAnalysisRun(t, f)
		analyze, err := NewAnalysisHandler(AnalysisConfig{Builder: builder, EvidenceKeys: f.ring})
		if err != nil {
			t.Fatal(err)
		}
		completion, err := analyze(t.Context(), Execution{queue, lease})
		if err != nil {
			t.Fatal(err)
		}
		if err := queue.CompleteWith(t.Context(), lease, completion); err != nil {
			t.Fatal(err)
		}
		for _, permission := range []string{"run.read", "evidence.read", "report.export"} {
			if _, err := f.db.ExecContext(f.ctx, "INSERT INTO permissions (code,description) VALUES ($1,'') ON CONFLICT (code) DO NOTHING", permission); err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.ExecContext(f.ctx, "INSERT INTO role_permissions (organization_id,role_id,permission_code) SELECT organization_id,id,$1 FROM roles WHERE organization_id=$2 AND name='administrator' ON CONFLICT DO NOTHING", permission, f.orgID); err != nil {
				t.Fatal(err)
			}
		}
		path := filepath.Join(t.TempDir(), "reports")
		storage, err := reportstorage.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = storage.Close() }()
		handler, err := NewReportHandler(ReportConfig{Storage: storage})
		if err != nil {
			t.Fatal(err)
		}
		for _, format := range []string{"json", "html"} {
			row, err := tenant.CreateReport(repository.ReportInput{RunID: run.ID, AnalysisRevision: 1, Format: format, IdempotencyKey: "report-worker-real-" + format})
			if err != nil {
				t.Fatal(err)
			}
			job, err := queue.Claim(context.Background())
			if err != nil || job == nil {
				t.Fatal("claim report", err)
			}
			completion, err := handler(t.Context(), Execution{queue, *job})
			if err != nil {
				t.Fatal("actual report handler", err)
			}
			before, err := tenant.GetReport(row.ID)
			if err != nil || before.Status != "generating" {
				t.Fatal("handler published outside fenced completion", err)
			}
			files, err := os.ReadDir(path)
			if err != nil || len(files) == 0 {
				t.Fatal("no real artifact", err)
			}
			// Simulate a retry after durable file write but before DB completion.
			if err := queue.Retry(t.Context(), *job, "WORKER_STORAGE_UNAVAILABLE", 0); err != nil {
				t.Fatal(err)
			}
			if err := queue.CompleteWith(t.Context(), *job, completion); !errors.Is(err, repository.ErrJobLeaseLost) {
				t.Fatal("stale generation published", err)
			}
			job, err = queue.Claim(t.Context())
			if err != nil || job == nil {
				t.Fatal(err)
			}
			completion, err = handler(t.Context(), Execution{queue, *job})
			if err != nil {
				t.Fatal("retry frozen generation", err)
			}
			if err := queue.CompleteWith(t.Context(), *job, completion); err != nil {
				t.Fatal("report publication", err)
			}
			ready, err := tenant.GetReport(row.ID)
			if err != nil || ready.Status != "ready" || !ready.CreatedAt.Equal(row.CreatedAt) {
				t.Fatal("immutable publication", err)
			}
			ref := reportstorage.Reference{OrganizationID: f.orgID, Hash: *ready.FileHash, Format: format, Size: *ready.FileSize}
			body, err := storage.Read(t.Context(), ref)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{workerCanary, "https://example.com", "\"messages\"", "\"ciphertext\"", "\"nonce\""} {
				if bytes.Contains(body, []byte(secret)) {
					t.Fatal("restricted source disclosed")
				}
			}
			if !bytes.Contains(body, []byte("not_included")) {
				t.Fatal("review omission not explicit")
			}
			if format == "json" && !bytes.Contains(body, []byte(`"calibrated":false`)) {
				t.Fatal("development flags lost")
			}
			if format == "html" && strings.Contains(string(body), "<script") {
				t.Fatal("active script")
			}
		}
	})
}
