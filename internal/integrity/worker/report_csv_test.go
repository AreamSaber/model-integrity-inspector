package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/report"
	"model-integrity-inspector.local/mii/internal/integrity/reportstorage"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

func TestReportArtifactFormatFailsClosed(t *testing.T) {
	for _, format := range []string{"", "CSV", "pdf", "text/csv", "csv\r\n", "../csv"} {
		artifact, err := generateReportArtifact(nil, format)
		if !errors.Is(err, repository.ErrReportInvalid) || len(artifact.content) != 0 || artifact.contentHash != "" || artifact.fileHash != "" {
			t.Fatal("unknown report format fell back to a successful artifact")
		}
	}
	for _, format := range []string{"json", "html", "csv"} {
		artifact, err := generateReportArtifact(nil, format)
		if !errors.Is(err, report.ErrInput) || len(artifact.content) != 0 || artifact.contentHash != "" || artifact.fileHash != "" {
			t.Fatal("invalid snapshot produced a partial artifact")
		}
	}
}

func TestReportWorkerCSVIndependentFrozenSnapshotRetryAndLegacyImmutability(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		tenant, run, storage, handler, path := prepareReportCompletionWorker(t, f)
		queue, err := f.store.OpenJobQueue(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = queue.Close(context.Background()) }()
		machineBefore, err := tenant.GetPublishedAnalysis(run.ID, 1)
		if err != nil {
			t.Fatal(err)
		}
		var legacyRows []repository.ReportRecord
		var legacyBytes [][]byte
		for _, format := range []string{"json", "html", "csv"} {
			row, err := tenant.CreateReport(repository.ReportInput{RunID: run.ID, AnalysisRevision: 1, Format: format, IdempotencyKey: "csv-independent-frozen-" + format})
			if err != nil {
				t.Fatal("create real report", err)
			}
			lease, err := queue.Claim(t.Context())
			if err != nil || lease == nil || lease.Job.ObjectID != row.ID {
				t.Fatal("claim real report job", err)
			}
			completion, err := handler(t.Context(), Execution{queue, *lease})
			if err != nil || completion == nil {
				t.Fatal("generate real report", err)
			}
			var expected *report.CSVArtifact
			if format == "csv" {
				before, err := tenant.GetReport(row.ID)
				if err != nil || before.Status != "generating" || before.FileHash != nil || before.SourceHash == nil || before.FrozenAt == nil {
					t.Fatal("CSV was not frozen before fenced publication", err)
				}
				// Load the exact CSV row's persisted source, not a different JSON
				// report ID/time. Both encoders must use this same snapshot.
				source, err := queue.LoadReportSource(t.Context(), *lease)
				if err != nil {
					t.Fatal(err)
				}
				snapshot, _, err := runservice.BuildReportSnapshot(source)
				if err != nil {
					t.Fatal(err)
				}
				expected, err = report.GenerateCSV(snapshot)
				if err != nil {
					t.Fatal(err)
				}
				jsonArtifact, err := report.Generate(snapshot)
				if err != nil || expected.ContentHash() != jsonArtifact.ContentHash() || expected.FileHash() == jsonArtifact.JSONFileHash() {
					t.Fatal("same-snapshot content hash/file hash boundary", err)
				}
				if err := queue.Retry(t.Context(), *lease, "WORKER_STORAGE_UNAVAILABLE", 0); err != nil {
					t.Fatal(err)
				}
				if err := queue.CompleteWith(t.Context(), *lease, completion); !errors.Is(err, repository.ErrJobLeaseLost) {
					t.Fatal("stale CSV generation published", err)
				}
				lease, err = queue.Claim(t.Context())
				if err != nil || lease == nil || lease.Job.ObjectID != row.ID {
					t.Fatal("claim CSV retry", err)
				}
				completion, err = handler(t.Context(), Execution{queue, *lease})
				if err != nil || completion == nil {
					t.Fatal("regenerate frozen CSV", err)
				}
				after, err := tenant.GetReport(row.ID)
				if err != nil || after.SourceHash == nil || *after.SourceHash != *before.SourceHash || after.FrozenAt == nil || !after.FrozenAt.Equal(*before.FrozenAt) {
					t.Fatal("retry changed frozen source", err)
				}
			}
			if err := queue.CompleteWith(t.Context(), *lease, completion); err != nil {
				t.Fatal("publish real report", err)
			}
			ready, err := tenant.GetReport(row.ID)
			if err != nil || ready.Status != "ready" || ready.SchemaVersion != report.SchemaVersion || ready.FormatName != format || !ready.CreatedAt.Equal(row.CreatedAt) || ready.FileHash == nil || ready.ContentHash == nil || ready.FileSize == nil {
				t.Fatal("immutable ready report metadata", err)
			}
			body, err := storage.Read(t.Context(), reportstorage.Reference{OrganizationID: f.orgID, Hash: *ready.FileHash, Format: format, Size: *ready.FileSize})
			if err != nil {
				t.Fatal(err)
			}
			if format != "csv" {
				legacyRows, legacyBytes = append(legacyRows, ready), append(legacyBytes, body)
				continue
			}
			if !bytes.Equal(body, expected.Bytes()) || *ready.ContentHash != expected.ContentHash() || "sha256:"+*ready.FileHash != expected.FileHash() {
				t.Fatal("CSV stored bytes or published hashes differ from its frozen snapshot")
			}
			for _, secret := range []string{workerCanary, "https://example.com", "messages", "ciphertext", "nonce"} {
				if bytes.Contains(body, []byte(secret)) {
					t.Fatal("CSV disclosed restricted source")
				}
			}
			if !bytes.Contains(body, []byte("not_included")) || !bytes.Contains(body, []byte(report.Disclaimer)) {
				t.Fatal("CSV lost review omission or report disclaimer")
			}
		}
		for i, old := range legacyRows {
			current, err := tenant.GetReport(old.ID)
			if err != nil || !reflect.DeepEqual(old, current) {
				t.Fatal("new CSV mutated a prior report row", err)
			}
			body, err := storage.Read(t.Context(), reportstorage.Reference{OrganizationID: f.orgID, Hash: *old.FileHash, Format: old.FormatName, Size: *old.FileSize})
			if err != nil || !bytes.Equal(body, legacyBytes[i]) {
				t.Fatal("new CSV replaced a prior artifact", err)
			}
		}
		files, err := os.ReadDir(path)
		if err != nil || len(files) != 3 {
			t.Fatal("CSV retry did not retain exactly one object per report", err)
		}
		machineAfter, err := tenant.GetPublishedAnalysis(run.ID, 1)
		if err != nil || !reflect.DeepEqual(machineBefore, machineAfter) {
			t.Fatal("CSV changed the published analysis", err)
		}
		if _, err := tenant.VerifyAuditFull(); err != nil {
			t.Fatal("CSV audit chain", err)
		}
	})
}

func TestReportWorkerCSVFailuresNeverPublishOrExposeOrphans(t *testing.T) {
	for _, fault := range []string{"storage_closed", "pre_canceled", "revoked_before_source", "revoked_completion", "publication_audit"} {
		t.Run(fault, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				tenant, run, storage, handler, _ := prepareReportCompletionWorker(t, f)
				otherCtx := reportWorkerOtherPrincipal(t, f)
				other, err := f.store.WithOrganization(otherCtx, f.orgID)
				if err != nil {
					t.Fatal(err)
				}
				before, err := tenant.GetPublishedAnalysis(run.ID, 1)
				if err != nil {
					t.Fatal(err)
				}
				row, err := tenant.CreateReport(repository.ReportInput{RunID: run.ID, AnalysisRevision: 1, Format: "csv", IdempotencyKey: "csv-failure-" + fault})
				if err != nil {
					t.Fatal(err)
				}
				queue, err := f.store.OpenJobQueue(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = queue.Close(context.Background()) }()
				lease, err := queue.Claim(t.Context())
				if err != nil || lease == nil {
					t.Fatal(err)
				}
				revoke := func() {
					if _, err := f.db.ExecContext(f.ctx, "DELETE FROM role_permissions WHERE organization_id=$1 AND permission_code='report.export'", f.orgID); err != nil {
						t.Fatal("revoke CSV creator", err)
					}
				}
				ctx := t.Context()
				want := repository.ErrUnavailable
				switch fault {
				case "storage_closed":
					if err := storage.Close(); err != nil {
						t.Fatal(err)
					}
				case "pre_canceled":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
					// The source repository intentionally closes database/context
					// errors as ErrUnavailable; no artifact capability may escape.
				case "revoked_before_source":
					revoke()
					want = repository.ErrManagementPermission
				}
				completion, err := handler(ctx, Execution{queue, *lease})
				if fault == "revoked_completion" || fault == "publication_audit" {
					if err != nil || completion == nil {
						t.Fatal("real CSV file not written before publication fault", err)
					}
					if fault == "revoked_completion" {
						revoke()
						want = repository.ErrManagementPermission
					} else if f.store.Driver() == "sqlite" {
						want = repository.ErrConflict
						if _, err := f.db.ExecContext(f.ctx, `CREATE TRIGGER fixture_csv_audit_failure BEFORE INSERT ON integrity_audit_logs WHEN NEW.action='report.publish' BEGIN SELECT RAISE(ABORT, 'synthetic CSV audit persistence failure'); END`); err != nil {
							t.Fatal("install SQLite CSV audit fault")
						}
					} else {
						if _, err := f.db.ExecContext(f.ctx, `CREATE FUNCTION fixture_csv_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='report.publish' THEN RAISE EXCEPTION 'synthetic CSV audit persistence failure'; END IF; RETURN NEW; END $$`); err != nil {
							t.Fatal("install PostgreSQL CSV audit fault function")
						}
						if _, err := f.db.ExecContext(f.ctx, `CREATE TRIGGER fixture_csv_audit_failure BEFORE INSERT ON integrity_audit_logs FOR EACH ROW EXECUTE FUNCTION fixture_csv_audit_failure()`); err != nil {
							t.Fatal("install PostgreSQL CSV audit fault trigger")
						}
					}
					err = queue.CompleteWith(t.Context(), *lease, completion)
				} else if completion != nil {
					t.Fatal("failed CSV generation returned a publication capability")
				}
				if !errors.Is(err, want) {
					t.Fatal("CSV failure was hidden or misclassified", err)
				}
				stored, err := other.GetReport(row.ID)
				if err != nil || stored.Status == "ready" || stored.ContentHash != nil || stored.FileHash != nil || stored.StoragePath != nil || stored.CompletedAt != nil {
					t.Fatal("failed CSV committed a ready or partial publication", err)
				}
				job, err := other.GetJob(*row.JobID)
				if err != nil || job.Status != "running" {
					t.Fatal("CSV publication failure falsely completed the job", err)
				}
				if fault == "revoked_before_source" || fault == "revoked_completion" {
					// Match the real runner: source rejection fails the job and
					// maintenance reconciles it; final publication rejection uses
					// the narrower atomic report/job failure capability.
					if fault == "revoked_before_source" {
						if err := queue.Fail(t.Context(), *lease, "WORKER_HANDLER_FAILED"); err != nil {
							t.Fatal("fail revoked CSV source job", err)
						}
						if err := queue.ReconcileReports(t.Context()); err != nil {
							t.Fatal("reconcile failed CSV source", err)
						}
					} else if err := queue.FailReportGeneration(t.Context(), *lease); err != nil {
						t.Fatal("terminally fail revoked CSV", err)
					}
					stored, err = other.GetReport(row.ID)
					if err != nil || stored.Status != "failed" || stored.FileHash != nil {
						t.Fatal("revoked CSV not safely terminal", err)
					}
				}
				service, err := runservice.NewReportService(runservice.ReportConfig{Store: f.store, Storage: storage})
				if err != nil {
					t.Fatal(err)
				}
				if download, err := service.PrepareDownload(otherCtx, f.orgID, row.ID); !errors.Is(err, repository.ErrReportNotReady) || download != nil {
					if download != nil {
						download.Close()
					}
					t.Fatal("authorized reader received a failed CSV orphan", err)
				}
				after, err := other.GetPublishedAnalysis(run.ID, 1)
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatal("failed CSV changed the machine result", err)
				}
				if _, err := other.VerifyAuditFull(); err != nil {
					t.Fatal("CSV failure audit chain", err)
				}
			})
		})
	}
}
