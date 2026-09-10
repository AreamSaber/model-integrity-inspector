package repository

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func TestReportCSVClosedFormatAndDocumentSchema(t *testing.T) {
	creator, job := int64(7), int64(8)
	now := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	for _, format := range []string{"json", "html", "csv"} {
		input := ReportInput{RunID: 3, AnalysisRevision: 1, Format: format, IdempotencyKey: "report-format-closed-case"}
		row := ReportRecord{ID: 1, OrganizationID: 2, RunID: 3, AnalysisRevision: 1, Revision: 1, FormatName: format, SchemaVersion: reportSchema, Status: "queued", CreatedBy: &creator, JobID: &job, CreatedAt: now}
		if !validReportInput(input) || !validReportRecord(row, 2) || ReportObjectName(2, strings.Repeat("a", 64), format) != "org-2-"+strings.Repeat("a", 64)+"."+format {
			t.Fatal("supported format rejected or object identity changed", format)
		}
		row.SchemaVersion = "mii.report.csv.v1"
		if validReportRecord(row, 2) {
			t.Fatal("CSV transport profile replaced the document schema")
		}
		row.SchemaVersion = reportSchema
		for _, invalid := range []string{"", "CSV", " csv", "csv ", ".csv", "../csv", "csv/../json", "csv\x00", "csv\r\n", "pdf", "zip"} {
			input.Format, row.FormatName = invalid, invalid
			if validReportInput(input) || validReportRecord(row, 2) || ReportObjectName(2, strings.Repeat("a", 64), invalid) != "" {
				t.Fatal("format allowlist accepted noncanonical input")
			}
		}
	}
}

// Repository tests intentionally use a synthetic opaque source/publication.
// The production Worker alone constructs a validated report Snapshot and writes
// real artifact bytes; these tests exercise actual database transactions only.
func csvRepositoryPublication(row ReportRecord) ([]byte, ReportPublication) {
	encoded := []byte(`{"synthetic_s1":true}`)
	file := []byte("synthetic-report:" + row.FormatName + ":" + strconv.FormatInt(row.ID, 10))
	return encoded, ReportPublication{ContentHash: "sha256:" + reportDigest(file), FileHash: reportDigest(file), FileSize: int64(len(file))}
}

func csvRepositoryStored(t *testing.T, store *Store, org, id int64) ReportRecord {
	t.Helper()
	var row ReportRecord
	if err := store.db.Where("organization_id=? AND id=?", org, id).Take(&row).Error; err != nil {
		t.Fatal("read exact report fixture", err)
	}
	return row
}

func csvRepositoryPublish(t *testing.T, tenant *Tenant, queue *JobQueue, input ReportInput) ReportRecord {
	t.Helper()
	row, err := tenant.CreateReport(input)
	if err != nil {
		t.Fatal(err)
	}
	lease := mustClaim(t, queue)
	if lease.Job.ObjectID != row.ID || lease.Job.Type != string(JobReportGenerate) {
		t.Fatal("wrong report job claimed")
	}
	source, err := queue.LoadReportSource(t.Context(), lease)
	if err != nil {
		t.Fatal(err)
	}
	encoded, publication := csvRepositoryPublication(row)
	if err := queue.FreezeReportSource(t.Context(), lease, source, encoded); err != nil {
		t.Fatal(err)
	}
	if err := queue.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error {
		return tx.PublishReport(source, reportDigest(encoded), publication)
	}); err != nil {
		t.Fatal(err)
	}
	return csvRepositoryStored(t, tenant.store, tenant.orgID, row.ID)
}

func TestReportCSVIndependentRevisionIdempotencyAndLegacyImmutability(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, queue, run := reportFixture(t, store)
		legacy := []ReportRecord{}
		for _, format := range []string{"json", "html"} {
			legacy = append(legacy, csvRepositoryPublish(t, tenant, queue, ReportInput{RunID: run.ID, AnalysisRevision: 1, Format: format, IdempotencyKey: "report-legacy-before-csv-" + format}))
		}
		input := ReportInput{RunID: run.ID, AnalysisRevision: 1, Format: "csv", IdempotencyKey: "report-csv-independent-logical"}
		row, err := tenant.CreateReport(input)
		if err != nil || row.FormatName != "csv" || row.SchemaVersion != "mii.report.v1" || row.Status != "queued" || row.Revision != 1 || row.ContentHash != nil || row.FileHash != nil {
			t.Fatal("CSV was not an independently queued document-v1 report", err)
		}
		for _, old := range legacy {
			if row.ID == old.ID || row.JobID == nil || old.JobID == nil || *row.JobID == *old.JobID {
				t.Fatal("CSV reused a legacy report/job identity")
			}
		}
		retry, err := tenant.CreateReport(input)
		if err != nil || !reflect.DeepEqual(row, retry) {
			t.Fatal("same-key CSV retry changed metadata", err)
		}
		for _, format := range []string{"json", "html"} {
			changed := input
			changed.Format = format
			if _, err := tenant.CreateReport(changed); !errors.Is(err, ErrConflict) {
				t.Fatal("same key accepted a different format", err)
			}
		}
		ready := csvRepositoryPublish(t, tenant, queue, input)
		if ready.Status != "ready" || ready.Revision != 1 || ready.SchemaVersion != reportSchema || ready.StoragePath == nil || *ready.StoragePath != ReportObjectName(tenant.orgID, *ready.FileHash, "csv") || !ready.CreatedAt.Equal(row.CreatedAt) {
			t.Fatal("CSV publication lost fixed source/format metadata")
		}
		readyRetry, err := tenant.CreateReport(input)
		if err != nil || readyRetry.ID != ready.ID || readyRetry.Status != "ready" || *readyRetry.FileHash != *ready.FileHash {
			t.Fatal("ready CSV retry regenerated its record", err)
		}
		for _, format := range []string{"csv", "json"} {
			next, err := tenant.CreateReport(ReportInput{RunID: run.ID, AnalysisRevision: 1, Format: format, IdempotencyKey: "report-independent-second-" + format})
			if err != nil || next.ID == row.ID || next.Revision != 2 {
				t.Fatal("report revisions were not scoped to their format", err)
			}
		}
		for _, old := range append(legacy, ready) {
			if err := store.db.Model(&ReportRecord{}).Where("organization_id=? AND id=?", tenant.orgID, old.ID).Update("format", "csv").Error; err == nil {
				t.Fatal("ready format could be overwritten")
			}
			if err := store.db.Model(&ReportRecord{}).Where("organization_id=? AND id=?", tenant.orgID, old.ID).Update("file_hash", strings.Repeat("f", 64)).Error; err == nil {
				t.Fatal("ready hash could be overwritten")
			}
			if actual := csvRepositoryStored(t, store, tenant.orgID, old.ID); !reflect.DeepEqual(actual, old) {
				t.Fatal("CSV creation/publication altered an immutable report")
			}
		}
		var creates int64
		if err := store.db.Model(&audit.Event{}).Where("organization_id=? AND action='report.create' AND object_id=?", tenant.orgID, strconv.FormatInt(row.ID, 10)).Count(&creates).Error; err != nil || creates != 1 {
			t.Fatal("CSV retry emitted duplicate or missing creation audit", err)
		}
		rows, err := tenant.ListReports(run.ID, 1, ListOptions{Limit: 10})
		if err != nil || len(rows) != 5 {
			t.Fatal("mixed-format history was hidden or duplicated", err)
		}
		if err := store.VerifyAllAudit(t.Context(), true); err != nil {
			t.Fatal(err)
		}
	})
}

func TestReportCSVAuditRollbackRetryFenceAndDownloadBinding(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, queue, run := reportFixture(t, store)
		input := ReportInput{RunID: run.ID, AnalysisRevision: 1, Format: "csv", IdempotencyKey: "report-csv-audit-and-fences"}
		signer := store.auditSigner
		store.auditSigner = nil
		_, err := tenant.CreateReport(input)
		store.auditSigner = signer
		if !errors.Is(err, audit.ErrUnavailable) {
			t.Fatal("CSV create did not fail on real audit signer loss", err)
		}
		var count int64
		if err := store.db.Model(&ReportRecord{}).Where("organization_id=?", tenant.orgID).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("failed audited CSV create committed a row")
		}
		row, err := tenant.CreateReport(input)
		if err != nil {
			t.Fatal(err)
		}
		lease := mustClaim(t, queue)
		source, err := queue.LoadReportSource(t.Context(), lease)
		if err != nil {
			t.Fatal(err)
		}
		encoded, publication := csvRepositoryPublication(row)
		if err := queue.FreezeReportSource(t.Context(), lease, source, encoded); err != nil {
			t.Fatal(err)
		}
		if err := queue.FreezeReportSource(t.Context(), lease, source, []byte(`{"changed":true}`)); !errors.Is(err, ErrReportInvalid) {
			t.Fatal("frozen CSV source could be replaced", err)
		}
		if err := store.db.Model(&ReportRecord{}).Where("id=?", row.ID).Update("schema_version", "mii.report.csv.v1").Error; err == nil {
			t.Fatal("frozen document schema changed to CSV transport profile")
		}
		publish := func(tx *TenantTransaction) error { return tx.PublishReport(source, reportDigest(encoded), publication) }
		store.auditSigner = nil
		err = queue.CompleteWith(t.Context(), lease, publish)
		store.auditSigner = signer
		if !errors.Is(err, audit.ErrUnavailable) {
			t.Fatal("CSV publish concealed audit failure", err)
		}
		before := csvRepositoryStored(t, store, tenant.orgID, row.ID)
		if before.Status != "generating" || before.FileHash != nil || before.ContentHash != nil || before.StoragePath != nil {
			t.Fatal("failed CSV publication left an authorized artifact")
		}
		if err := queue.Retry(t.Context(), lease, "WORKER_STORAGE_UNAVAILABLE", 0); err != nil {
			t.Fatal(err)
		}
		if err := queue.CompleteWith(t.Context(), lease, publish); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("stale CSV lease could publish", err)
		}
		current := mustClaim(t, queue)
		frozen, err := queue.LoadReportSource(t.Context(), current)
		if err != nil || frozen.Scope() != source.Scope() {
			t.Fatal("CSV retry scope changed", err)
		}
		if err := frozen.Use(func(data PublishedRead, b []byte) error {
			if string(b) != string(encoded) || data.Run.ID != 0 {
				return ErrReportInvalid
			}
			return nil
		}); err != nil {
			t.Fatal("retry did not reuse only the frozen source", err)
		}
		if err := queue.CompleteWith(t.Context(), current, func(tx *TenantTransaction) error {
			return tx.PublishReport(frozen, reportDigest(encoded), publication)
		}); err != nil {
			t.Fatal(err)
		}
		if err := tenant.AuditReportDownload(row.ID, publication.FileHash, publication.FileSize+1); !errors.Is(err, ErrReportInvalid) {
			t.Fatal("CSV download audit accepted wrong length", err)
		}
		if err := tenant.AuditReportDownload(row.ID, strings.Repeat("f", 64), publication.FileSize); !errors.Is(err, ErrReportInvalid) {
			t.Fatal("CSV download audit accepted wrong hash", err)
		}
		if err := tenant.AuditReportDownload(row.ID, publication.FileHash, publication.FileSize); err != nil {
			t.Fatal(err)
		}
		job, err := tenant.GetJob(current.Job.ID)
		if err != nil || job.Status != "completed" {
			t.Fatal("CSV job did not complete atomically", err)
		}
		if err := store.VerifyAllAudit(t.Context(), true); err != nil {
			t.Fatal(err)
		}
	})
}

func TestReportCSVRevokedGrantsDenyReadRetryAndFinalPublication(t *testing.T) {
	for _, permission := range []string{"run.read", "evidence.read", "report.export"} {
		t.Run(permission, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				tenant, queue, run := reportFixture(t, store)
				input := ReportInput{RunID: run.ID, AnalysisRevision: 1, Format: "csv", IdempotencyKey: "report-csv-revocation"}
				row, err := tenant.CreateReport(input)
				if err != nil {
					t.Fatal(err)
				}
				lease := mustClaim(t, queue)
				source, err := queue.LoadReportSource(t.Context(), lease)
				if err != nil {
					t.Fatal(err)
				}
				encoded, publication := csvRepositoryPublication(row)
				if err := queue.FreezeReportSource(t.Context(), lease, source, encoded); err != nil {
					t.Fatal(err)
				}
				if err := store.db.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code=?", tenant.orgID, permission).Error; err != nil {
					t.Fatal(err)
				}
				if _, err := tenant.CreateReport(input); !errors.Is(err, ErrManagementPermission) {
					t.Fatal("CSV idempotency bypassed revoked grant", err)
				}
				if _, err := tenant.GetReport(row.ID); !errors.Is(err, ErrManagementPermission) {
					t.Fatal("CSV read bypassed revoked grant", err)
				}
				if _, err := queue.LoadReportSource(t.Context(), lease); !errors.Is(err, ErrManagementPermission) {
					t.Fatal("CSV worker source bypassed revoked creator grant", err)
				}
				if err := queue.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error {
					return tx.PublishReport(source, reportDigest(encoded), publication)
				}); !errors.Is(err, ErrManagementPermission) {
					t.Fatal("CSV final publication bypassed revoked creator grant", err)
				}
				stored := csvRepositoryStored(t, store, tenant.orgID, row.ID)
				if stored.Status != "generating" || stored.FileHash != nil || stored.StoragePath != nil {
					t.Fatal("revocation left a downloadable CSV")
				}
				if err := queue.FailReportGeneration(t.Context(), lease); err != nil {
					t.Fatal("revoked CSV could not settle truthful failure", err)
				}
				failed := csvRepositoryStored(t, store, tenant.orgID, row.ID)
				if failed.Status != "failed" || failed.FileHash != nil || failed.StoragePath != nil || failed.ErrorCode == nil || *failed.ErrorCode != "MI_REPORT_GENERATION_FAILED" {
					t.Fatal("CSV failure status/reference inconsistent")
				}
			})
		})
	}
}
