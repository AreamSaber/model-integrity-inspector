package worker

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/reportstorage"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

func grantReportWorkerPermissions(t *testing.T, f runFixture) {
	t.Helper()
	for _, permission := range []string{"run.read", "evidence.read", "report.export"} {
		if _, err := f.db.ExecContext(f.ctx, "INSERT INTO permissions (code,description) VALUES ($1,'') ON CONFLICT (code) DO NOTHING", permission); err != nil {
			t.Fatal("create report permission fixture")
		}
		if _, err := f.db.ExecContext(f.ctx, "INSERT INTO role_permissions (organization_id,role_id,permission_code) SELECT organization_id,id,$1 FROM roles WHERE organization_id=$2 AND name='administrator' ON CONFLICT DO NOTHING", permission, f.orgID); err != nil {
			t.Fatal("grant report permission fixture")
		}
	}
}

// The second principal uses an actual persisted user, membership, independent
// grants and authenticated session. It never borrows the revoked creator's
// role or bypasses the read/download authority checks.
func reportWorkerOtherPrincipal(t *testing.T, f runFixture) context.Context {
	t.Helper()
	user, err := repository.NewID()
	if err != nil {
		t.Fatal(err)
	}
	member, err := repository.NewID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	const fixtureHash = "synthetic-report-reader-password-hash"
	if _, err := f.db.ExecContext(f.ctx, "INSERT INTO users (id,username,username_normalized,password_hash,password_changed_at,created_at,updated_at) VALUES ($1,'report-reader','report-reader',$2,$3,$3,$3)", user, fixtureHash, now); err != nil {
		t.Fatal("create report reader fixture")
	}
	if _, err := f.db.ExecContext(f.ctx, "INSERT INTO organization_members (id,organization_id,user_id,created_at,updated_at) VALUES ($1,$2,$3,$4,$4)", member, f.orgID, user, now); err != nil {
		t.Fatal("create report reader membership")
	}
	for _, permission := range []string{"run.read", "evidence.read", "report.export"} {
		if _, err := f.db.ExecContext(f.ctx, "INSERT INTO member_permissions (organization_id,member_id,permission_code) VALUES ($1,$2,$3)", f.orgID, member, permission); err != nil {
			t.Fatal("grant independent report reader permission")
		}
	}
	ctx := audit.WithActor(t.Context(), audit.Actor{ActorID: user, ReasonCode: "report.test"})
	session := repository.Session{UserID: user, SessionHash: strings.Repeat("d", 64), CSRFHash: strings.Repeat("e", 64), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := f.store.CreateSessionIfPasswordCurrent(ctx, &session, fixtureHash, now); err != nil {
		t.Fatal("authenticate report reader fixture", err)
	}
	ctx, err = f.store.BindControlAuthority(ctx, session.SessionHash, f.orgID)
	if err != nil {
		t.Fatal("bind report reader authority", err)
	}
	return ctx
}

func prepareReportCompletionWorker(t *testing.T, f runFixture) (*repository.Tenant, repository.RunRecord, *reportstorage.Store, Handler, string) {
	t.Helper()
	tenant, run, builder, queue, lease, _ := closedSignedAnalysisRun(t, f)
	analyze, err := NewAnalysisHandler(AnalysisConfig{Builder: builder, EvidenceKeys: f.ring})
	if err != nil {
		t.Fatal(err)
	}
	completion, err := analyze(context.Background(), Execution{queue, lease})
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.CompleteWith(context.Background(), lease, completion); err != nil {
		t.Fatal(err)
	}
	if err := queue.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	grantReportWorkerPermissions(t, f)
	path := filepath.Join(t.TempDir(), "reports")
	storage, err := reportstorage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	handler, err := NewReportHandler(ReportConfig{Storage: storage})
	if err != nil {
		t.Fatal(err)
	}
	return tenant, run, storage, handler, path
}

func TestReportWorkerRevokedPublicationFailsOnlyThatJobAndContinues(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		tenant, run, storage, realHandler, path := prepareReportCompletionWorker(t, f)
		otherCtx := reportWorkerOtherPrincipal(t, f)
		other, err := f.store.WithOrganization(otherCtx, f.orgID)
		if err != nil {
			t.Fatal(err)
		}
		machineBefore, err := tenant.GetPublishedAnalysis(run.ID, 1)
		if err != nil {
			t.Fatal(err)
		}
		blocked, err := tenant.CreateReport(repository.ReportInput{RunID: run.ID, AnalysisRevision: 1, Format: "json", IdempotencyKey: "report-revoked-after-write"})
		if err != nil {
			t.Fatal(err)
		}
		written, release := make(chan struct{}), make(chan struct{})
		checked := make(chan error, 1)
		handler := func(ctx context.Context, execution Execution) (Completion, error) {
			completion, err := realHandler(ctx, execution)
			if err != nil || execution.Lease.Job.ObjectID != blocked.ID {
				return completion, err
			}
			close(written)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return func(tx *repository.TenantTransaction) error {
				err := completion(tx)
				checked <- err
				return err
			}, nil
		}
		var log executionLogBuffer
		runner, err := New(Config{Store: f.store, Handlers: map[repository.JobType]Handler{repository.JobReportGenerate: handler}, Logger: slog.New(slog.NewTextHandler(&log, nil)), PollInterval: 10 * time.Millisecond, HeartbeatInterval: 40 * time.Millisecond, Maintenance: func(ctx context.Context, queue *repository.JobQueue) error { return queue.ReconcileReports(ctx) }})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		var runnerErr error
		go func() { runnerErr = runner.Run(ctx); close(done) }()
		t.Cleanup(func() {
			cancel()
			select {
			case <-done:
				if runnerErr != nil {
					t.Errorf("ordinary report revocation stopped consumer: %v", runnerErr)
				}
			case <-time.After(7 * time.Second):
				t.Error("report worker did not stop")
			}
			if t.Failed() {
				t.Log(log.String())
			}
		})
		select {
		case <-written:
		case <-done:
			t.Fatal("report worker failed before file write")
		case <-time.After(5 * time.Second):
			t.Fatal("real report artifact not written")
		}
		files, err := os.ReadDir(path)
		if err != nil || len(files) != 1 {
			t.Fatal("missing durable unpublished report file")
		}
		if _, err := f.db.ExecContext(f.ctx, "DELETE FROM role_permissions WHERE organization_id=$1 AND permission_code='report.export'", f.orgID); err != nil {
			t.Fatal("revoke report creator")
		}
		following, err := other.CreateReport(repository.ReportInput{RunID: run.ID, AnalysisRevision: 1, Format: "html", IdempotencyKey: "report-other-creator-after-denial"})
		if err != nil {
			t.Fatal("create independently authorized following report", err)
		}
		close(release)
		select {
		case err := <-checked:
			if !errors.Is(err, repository.ErrManagementPermission) {
				t.Fatal("real PublishReport missed creator revocation")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("final report authority check not reached")
		}
		deadline := time.Now().Add(5 * time.Second)
		var failed, ready repository.ReportRecord
		for time.Now().Before(deadline) {
			failed, err = other.GetReport(blocked.ID)
			if err != nil {
				t.Fatal("authorized failure-state read", err)
			}
			ready, err = other.GetReport(following.ID)
			if err != nil {
				t.Fatal("authorized following-state read", err)
			}
			if failed.Status == "failed" && ready.Status == "ready" {
				break
			}
			select {
			case <-done:
				deadline = time.Time{}
			default:
				time.Sleep(10 * time.Millisecond)
			}
		}
		if failed.Status != "failed" || failed.FileHash != nil || failed.StoragePath != nil || failed.CompletedAt == nil {
			t.Error("revoked publication did not become an inaccessible terminal failure")
		}
		if ready.Status != "ready" || !runner.Ready() {
			t.Error("consumer did not continue the independently authorized report")
		}
		job, err := tenant.GetJob(*blocked.JobID)
		if err != nil || job.Status != "failed" || job.AttemptCount != 1 {
			t.Error("revoked report job was not terminally failed")
		}
		service, err := runservice.NewReportService(runservice.ReportConfig{Store: f.store, Storage: storage})
		if err != nil {
			t.Fatal(err)
		}
		if download, err := service.PrepareDownload(f.ctx, f.orgID, blocked.ID); !errors.Is(err, repository.ErrManagementPermission) || download != nil {
			if download != nil {
				download.Close()
			}
			t.Error("revoked caller received an artifact")
		}
		if download, err := service.PrepareDownload(otherCtx, f.orgID, blocked.ID); !errors.Is(err, repository.ErrReportNotReady) || download != nil {
			if download != nil {
				download.Close()
			}
			t.Error("authorized reader downloaded an unpublished orphan file")
		}
		if ready.Status == "ready" {
			download, err := service.PrepareDownload(otherCtx, f.orgID, following.ID)
			if err != nil || download == nil {
				t.Error("authorized following report not downloadable")
			} else {
				if len(download.Bytes()) == 0 {
					t.Error("following report lacks real file content")
				}
				download.Close()
			}
		}
		machineAfter, err := tenant.GetPublishedAnalysis(run.ID, 1)
		if err != nil || !reflect.DeepEqual(machineBefore, machineAfter) {
			t.Error("report failure changed the immutable machine result")
		}
		if _, err := tenant.VerifyAuditFull(); err != nil {
			t.Fatal("report failure damaged audit chain", err)
		}
	})
}

func TestReportWorkerPublicationInfrastructureFailuresStopConsumer(t *testing.T) {
	for _, fault := range []string{"publication_audit", "failure_audit", "database", "lease"} {
		t.Run(fault, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				tenant, run, storage, realHandler, _ := prepareReportCompletionWorker(t, f)
				otherCtx := reportWorkerOtherPrincipal(t, f)
				machineBefore, err := tenant.GetPublishedAnalysis(run.ID, 1)
				if err != nil {
					t.Fatal(err)
				}
				row, err := tenant.CreateReport(repository.ReportInput{RunID: run.ID, AnalysisRevision: 1, Format: "json", IdempotencyKey: "report-publication-system-fault"})
				if err != nil {
					t.Fatal(err)
				}
				written, release := make(chan struct{}), make(chan struct{})
				handler := func(ctx context.Context, execution Execution) (Completion, error) {
					completion, err := realHandler(ctx, execution)
					if err != nil {
						return nil, err
					}
					close(written)
					select {
					case <-release:
						return completion, nil
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				runner, err := New(Config{Store: f.store, Handlers: map[repository.JobType]Handler{repository.JobReportGenerate: handler}, PollInterval: 10 * time.Millisecond, HeartbeatInterval: 40 * time.Millisecond})
				if err != nil {
					t.Fatal(err)
				}
				// Register cancel-and-join before any fault installation can fail.
				// Normal assertions still observe the uncancelled Runner result;
				// cleanup also covers every early Fatal before that assertion.
				process := startReportRunnerFixture(t, runner.Run)
				select {
				case <-written:
				case <-process.done:
					t.Fatal("report worker failed before test fault", process.result)
				case <-time.After(5 * time.Second):
					t.Fatal("report file not written before fault")
				}
				want := repository.ErrUnavailable
				switch fault {
				case "publication_audit", "failure_audit":
					if fault == "failure_audit" {
						if _, err := f.db.ExecContext(f.ctx, "DELETE FROM role_permissions WHERE organization_id=$1 AND permission_code='report.export'", f.orgID); err != nil {
							t.Fatal("revoke creator before failure audit fault")
						}
					}
					// These database triggers reject the actual audit INSERT, after
					// the report status write. They exercise transaction rollback,
					// not an injected arbitrary handler error.
					if f.store.Driver() == "sqlite" {
						want = repository.ErrConflict
						if _, err := f.db.ExecContext(f.ctx, `CREATE TRIGGER fixture_report_audit_failure BEFORE INSERT ON integrity_audit_logs WHEN NEW.action IN ('report.publish','report.fail') BEGIN SELECT RAISE(ABORT, 'synthetic audit persistence failure'); END`); err != nil {
							t.Fatal("install sqlite audit fault")
						}
					} else {
						if _, err := f.db.ExecContext(f.ctx, `CREATE FUNCTION fixture_report_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('report.publish','report.fail') THEN RAISE EXCEPTION 'synthetic audit persistence failure'; END IF; RETURN NEW; END $$`); err != nil {
							t.Fatal("install postgres audit fault function")
						}
						if _, err := f.db.ExecContext(f.ctx, `CREATE TRIGGER fixture_report_audit_failure BEFORE INSERT ON integrity_audit_logs FOR EACH ROW EXECUTE FUNCTION fixture_report_audit_failure()`); err != nil {
							t.Fatal("install postgres audit fault trigger")
						}
					}
				case "database":
					if err := f.store.Close(); err != nil {
						t.Fatal("close application database")
					}
				case "lease":
					want = repository.ErrJobLeaseLost
					if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_jobs SET lease_owner='replacement-owner' WHERE organization_id=$1 AND id=$2", f.orgID, *row.JobID); err != nil {
						t.Fatal("replace report lease")
					}
				}
				close(release)
				select {
				case <-process.done:
					if !errors.Is(process.result, want) {
						t.Fatalf("systemic/fencing failure was concealed: %v", process.result)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("consumer did not stop on infrastructure/fencing failure")
				}
				if runner.Ready() {
					t.Fatal("faulted consumer reported ready")
				}
				var reportStatus, jobStatus, conclusion string
				var fileHash, storagePath sql.NullString
				if err := f.db.QueryRowContext(f.ctx, "SELECT status,file_hash,storage_path FROM integrity_reports WHERE organization_id=$1 AND id=$2", f.orgID, row.ID).Scan(&reportStatus, &fileHash, &storagePath); err != nil {
					t.Fatal("inspect publication rollback")
				}
				if err := f.db.QueryRowContext(f.ctx, "SELECT status FROM integrity_jobs WHERE organization_id=$1 AND id=$2", f.orgID, *row.JobID).Scan(&jobStatus); err != nil {
					t.Fatal("inspect job rollback")
				}
				if reportStatus != "generating" || jobStatus != "running" || fileHash.Valid || storagePath.Valid {
					t.Fatal("fault path committed a partial or unaudited terminal state")
				}
				if err := f.db.QueryRowContext(f.ctx, "SELECT conclusion_json FROM integrity_run_results WHERE organization_id=$1 AND run_id=$2 AND analysis_revision=1", f.orgID, run.ID).Scan(&conclusion); err != nil || conclusion != machineBefore.ConclusionJSON {
					t.Fatal("report fault changed the machine result")
				}
				service, err := runservice.NewReportService(runservice.ReportConfig{Store: f.store, Storage: storage})
				if err != nil {
					t.Fatal(err)
				}
				if download, err := service.PrepareDownload(otherCtx, f.orgID, row.ID); err == nil || download != nil {
					if download != nil {
						download.Close()
					}
					t.Fatal("faulted publication disclosed an orphan artifact")
				}
			})
		})
	}
}

func TestRunnerNonReportPermissionFailureIsNotDowngraded(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		tenant, run, _ := f.createRun(t, []bool{false})
		handler := func(context.Context, Execution) (Completion, error) {
			return func(*repository.TenantTransaction) error { return repository.ErrManagementPermission }, nil
		}
		runner, err := New(Config{Store: f.store, Handlers: map[repository.JobType]Handler{repository.JobRunPlan: handler}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runner.Run(ctx); !errors.Is(err, repository.ErrManagementPermission) {
			t.Fatal("report-specific permission disposition was applied to another Job", err)
		}
		stored, err := tenant.GetRun(run.ID)
		if err != nil || stored.Status != "QUEUED" || stored.StartedAt != nil || runner.Ready() {
			t.Fatal("non-report failure was concealed or changed business state")
		}
	})
}
