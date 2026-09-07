package repository

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func TestReportCompletionRevocationPreservesTypedPermission(t *testing.T) {
	for _, revoke := range []string{"run.read", "evidence.read", "report.export", "user_disabled", "password_change", "membership_disabled", "organization_disabled"} {
		t.Run(revoke, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				tenant, queue, run := reportFixture(t, store)
				row, err := tenant.CreateReport(ReportInput{run.ID, 1, "json", "report-completion-revoked"})
				if err != nil {
					t.Fatal(err)
				}
				lease := mustClaim(t, queue)
				source, err := queue.LoadReportSource(context.Background(), lease)
				if err != nil {
					t.Fatal(err)
				}
				encoded := []byte(`{"synthetic_s1":true}`)
				if err := queue.FreezeReportSource(context.Background(), lease, source, encoded); err != nil {
					t.Fatal(err)
				}
				var mutation error
				switch revoke {
				case "user_disabled":
					mutation = store.db.Model(&User{}).Where("id=?", run.CreatedBy).Update("status", "disabled").Error
				case "password_change":
					mutation = store.db.Model(&User{}).Where("id=?", run.CreatedBy).Update("must_change_password", true).Error
				case "membership_disabled":
					mutation = store.db.Model(&Membership{}).Where("organization_id=? AND user_id=?", tenant.orgID, run.CreatedBy).Update("status", "disabled").Error
				case "organization_disabled":
					mutation = store.db.Model(&Organization{}).Where("id=?", tenant.orgID).Update("status", "disabled").Error
				default:
					mutation = store.db.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code=?", tenant.orgID, revoke).Error
				}
				if mutation != nil {
					t.Fatal("fixture revocation failed")
				}
				var callbackErr error
				publication := ReportPublication{ContentHash: "sha256:" + strings.Repeat("a", 64), FileHash: strings.Repeat("b", 64), FileSize: 123}
				err = queue.CompleteWith(context.Background(), lease, func(tx *TenantTransaction) error {
					callbackErr = tx.PublishReport(source, reportDigest(encoded), publication)
					return callbackErr
				})
				if !errors.Is(callbackErr, ErrManagementPermission) {
					t.Fatal("publication did not perform its real final permission check")
				}
				if !errors.Is(err, ErrManagementPermission) {
					t.Errorf("known permission rejection became infrastructure failure: %v", err)
				}
				var stored ReportRecord
				if err := store.db.Where("organization_id=? AND id=?", tenant.orgID, row.ID).Take(&stored).Error; err != nil {
					t.Fatal("read rejected publication")
				}
				if stored.Status != "generating" || stored.ContentHash != nil || stored.FileHash != nil || stored.FileSize != nil || stored.StoragePath != nil {
					t.Fatal("permission failure published any artifact reference")
				}
				job, err := tenant.GetJob(lease.Job.ID)
				if err != nil || job.Status != "running" || job.CompletedAt != nil {
					t.Fatal("rejected callback partially completed its job")
				}
			})
		})
	}
}

func TestReportCompletionInfrastructureAndLeaseErrorsRemainClosed(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, queue, run := reportFixture(t, store)
		row, err := tenant.CreateReport(ReportInput{run.ID, 1, "json", "report-completion-faults"})
		if err != nil {
			t.Fatal(err)
		}
		lease := mustClaim(t, queue)
		source, err := queue.LoadReportSource(context.Background(), lease)
		if err != nil {
			t.Fatal(err)
		}
		encoded := []byte(`{"synthetic_s1":true}`)
		if err := queue.FreezeReportSource(context.Background(), lease, source, encoded); err != nil {
			t.Fatal(err)
		}
		publication := ReportPublication{ContentHash: "sha256:" + strings.Repeat("a", 64), FileHash: strings.Repeat("b", 64), FileSize: 123}
		publish := func(tx *TenantTransaction) error { return tx.PublishReport(source, reportDigest(encoded), publication) }
		signer := store.auditSigner
		store.auditSigner = nil
		err = queue.CompleteWith(context.Background(), lease, publish)
		store.auditSigner = signer
		if !errors.Is(err, audit.ErrUnavailable) {
			t.Fatal("actual publication audit failure was concealed")
		}
		for _, diagnostic := range []string{"synthetic-report-diagnostic-canary", ErrManagementPermission.Error()} {
			if err := queue.CompleteWith(context.Background(), lease, func(*TenantTransaction) error { return errors.New(diagnostic) }); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "canary") {
				t.Fatal("unknown callback diagnostic or matching text was disclosed or downgraded")
			}
		}
		// Neither an actual audit failure nor an unknown callback error is an
		// authorization failure, and neither may trigger a successful publication.
		before, err := tenant.GetReport(row.ID)
		if err != nil || before.Status != "generating" {
			t.Fatal("failed callback changed report state")
		}
		if err := store.db.Model(&Job{}).Where("organization_id=? AND id=?", tenant.orgID, lease.Job.ID).Update("lease_until", time.Now().UTC().Add(-time.Second)).Error; err != nil {
			t.Fatal("expire lease fixture")
		}
		if err := queue.CompleteWith(context.Background(), lease, publish); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatalf("expired owner did not return the lease rejection: %v", err)
		}
		var stored ReportRecord
		if err := store.db.Where("organization_id=? AND id=?", tenant.orgID, row.ID).Take(&stored).Error; err != nil || stored.Status != "generating" || stored.ContentHash != nil || stored.FileHash != nil {
			t.Fatal("fault path committed an artifact reference")
		}
	})
}

func TestReportCompletionLogoutDoesNotRevokePersistedJob(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, queue, run := reportFixture(t, store)
		row, err := tenant.CreateReport(ReportInput{run.ID, 1, "json", "report-completion-logout"})
		if err != nil {
			t.Fatal(err)
		}
		lease := mustClaim(t, queue)
		source, err := queue.LoadReportSource(context.Background(), lease)
		if err != nil {
			t.Fatal(err)
		}
		encoded := []byte(`{"synthetic_s1":true}`)
		if err := queue.FreezeReportSource(context.Background(), lease, source, encoded); err != nil {
			t.Fatal(err)
		}
		if err := store.db.Model(&Session{}).Where("user_id=?", run.CreatedBy).Update("revoked_at", time.Now().UTC()).Error; err != nil {
			t.Fatal("logout fixture session")
		}
		publication := ReportPublication{ContentHash: "sha256:" + strings.Repeat("a", 64), FileHash: strings.Repeat("b", 64), FileSize: 123}
		if err := queue.CompleteWith(context.Background(), lease, func(tx *TenantTransaction) error { return tx.PublishReport(source, reportDigest(encoded), publication) }); err != nil {
			t.Fatal("logout was confused with creator permission revocation", err)
		}
		job, err := tenant.GetJob(lease.Job.ID)
		if err != nil || job.Status != "completed" {
			t.Fatal("persisted report job did not complete after logout")
		}
		if _, err := tenant.GetReport(row.ID); !errors.Is(err, ErrManagementSession) {
			t.Fatal("worker completion granted the logged-out session download access")
		}
	})
}

func TestReportFailureSettlementIsFencedAtomicAndAudited(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, queue, run := reportFixture(t, store)
		row, err := tenant.CreateReport(ReportInput{run.ID, 1, "json", "report-atomic-failure"})
		if err != nil {
			t.Fatal(err)
		}
		lease := mustClaim(t, queue)
		source, err := queue.LoadReportSource(context.Background(), lease)
		if err != nil {
			t.Fatal(err)
		}
		if err := queue.FreezeReportSource(context.Background(), lease, source, []byte(`{"synthetic_s1":true}`)); err != nil {
			t.Fatal(err)
		}
		machineBefore, err := tenant.GetPublishedAnalysis(run.ID, 1)
		if err != nil {
			t.Fatal(err)
		}
		other, err := tenant.CreateReport(ReportInput{run.ID, 1, "html", "report-other-untouched"})
		if err != nil {
			t.Fatal(err)
		}
		for _, change := range []func(*JobLease){
			func(l *JobLease) { l.Job.OrganizationID++ },
			func(l *JobLease) { l.Job.ObjectID = other.ID },
			func(l *JobLease) { l.Job.Type = string(JobRunPlan) },
			func(l *JobLease) { l.Generation++ },
		} {
			wrong := lease
			change(&wrong)
			if err := queue.FailReportGeneration(context.Background(), wrong); err == nil {
				t.Fatal("unbound failure request changed a report")
			}
		}
		if err := store.db.Model(&User{}).Where("id=?", run.CreatedBy).Update("status", "disabled").Error; err != nil {
			t.Fatal("disable historical initiator fixture")
		}
		spoof := audit.WithActor(t.Context(), audit.Actor{ActorID: run.CreatedBy + 1, ReasonCode: "spoofed.failure", IPSummary: "spoofed"})
		signer := store.auditSigner
		store.auditSigner = nil
		err = queue.FailReportGeneration(spoof, lease)
		store.auditSigner = signer
		if !errors.Is(err, audit.ErrUnavailable) {
			t.Fatal("failure settlement swallowed an actual missing audit signer")
		}
		var report ReportRecord
		if err := store.db.Where("organization_id=? AND id=?", tenant.orgID, row.ID).Take(&report).Error; err != nil || report.Status != "generating" || report.CompletedAt != nil {
			t.Fatal("audit failure did not roll back report status")
		}
		job, err := tenant.GetJob(lease.Job.ID)
		if err != nil || job.Status != "running" || job.CompletedAt != nil {
			t.Fatal("audit failure did not roll back job status")
		}
		if err := queue.FailReportGeneration(spoof, lease); err != nil {
			t.Fatal("historical initiator could not be attributed to safe terminal failure", err)
		}
		if err := store.db.Where("organization_id=? AND id=?", tenant.orgID, row.ID).Take(&report).Error; err != nil || report.Status != "failed" || report.ErrorCode == nil || *report.ErrorCode != "MI_REPORT_GENERATION_FAILED" || report.CompletedAt == nil || report.FileHash != nil || report.StoragePath != nil {
			t.Fatal("failed report has incorrect terminal state or file reference")
		}
		job, err = tenant.GetJob(lease.Job.ID)
		if err != nil || job.Status != "failed" || job.LastErrorCode == nil || *job.LastErrorCode != "WORKER_REPORT_PERMISSION_DENIED" || job.CompletedAt == nil || job.LeaseOwner != nil || job.LeaseUntil != nil || job.AttemptCount != lease.Generation {
			t.Fatal("job failure did not commit with the report")
		}
		if err := queue.FailReportGeneration(spoof, lease); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("terminal failure replay bypassed its lease")
		}
		if err := queue.ReconcileReports(context.Background()); err != nil {
			t.Fatal(err)
		}
		var events []audit.Event
		if err := store.db.Where("organization_id=? AND action='report.fail' AND object_id=?", tenant.orgID, strconv.FormatInt(row.ID, 10)).Find(&events).Error; err != nil || len(events) != 1 {
			t.Fatal("failure audit missing or duplicated")
		}
		if events[0].ActorID == nil || *events[0].ActorID != run.CreatedBy || !strings.Contains(events[0].DiffSummary, "worker.report.generate") || strings.Contains(events[0].DiffSummary, "spoofed") || events[0].IPSummary != "" {
			t.Fatal("failure used forged rather than persisted actor")
		}
		machineAfter, err := tenant.GetPublishedAnalysis(run.ID, 1)
		if err != nil || !reflect.DeepEqual(machineBefore, machineAfter) {
			t.Fatal("terminal report failure changed machine result")
		}
		var untouched ReportRecord
		if err := store.db.Where("organization_id=? AND id=?", tenant.orgID, other.ID).Take(&untouched).Error; err != nil || untouched.Status != "queued" {
			t.Fatal("failure affected another report")
		}
	})
}

func TestReportFailureSettlementRejectsExpiredLeaseAndClosedDatabase(t *testing.T) {
	for _, fault := range []string{"expired_lease", "closed_database"} {
		t.Run(fault, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, cfg Config) {
				tenant, queue, run := reportFixture(t, store)
				row, err := tenant.CreateReport(ReportInput{run.ID, 1, "json", "report-failure-fault"})
				if err != nil {
					t.Fatal(err)
				}
				lease := mustClaim(t, queue)
				source, err := queue.LoadReportSource(context.Background(), lease)
				if err != nil {
					t.Fatal(err)
				}
				if err := queue.FreezeReportSource(context.Background(), lease, source, []byte(`{"synthetic_s1":true}`)); err != nil {
					t.Fatal(err)
				}
				inspection, err := Open(t.Context(), cfg)
				if err != nil {
					t.Fatal("open independent state inspection")
				}
				defer func() { _ = inspection.Close() }()
				want := ErrJobLeaseLost
				if fault == "expired_lease" {
					expireJob(t, store, lease.Job)
				} else {
					want = ErrUnavailable
					if err := store.Close(); err != nil {
						t.Fatal("close application database")
					}
				}
				if err := queue.FailReportGeneration(context.Background(), lease); !errors.Is(err, want) {
					t.Fatalf("failure settlement concealed its fault: %v", err)
				}
				var report ReportRecord
				if err := inspection.db.Where("organization_id=? AND id=?", tenant.orgID, row.ID).Take(&report).Error; err != nil || report.Status != "generating" || report.CompletedAt != nil || report.FileHash != nil {
					t.Fatal("unavailable or stale consumer changed report status")
				}
				var job Job
				if err := inspection.db.Where("organization_id=? AND id=?", tenant.orgID, lease.Job.ID).Take(&job).Error; err != nil || job.Status != "running" || job.CompletedAt != nil {
					t.Fatal("unavailable or stale consumer changed job status")
				}
			})
		})
	}
}
