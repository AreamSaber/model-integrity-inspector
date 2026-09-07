package repository

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func reportFixture(t *testing.T, store *Store) (*Tenant, *JobQueue, RunRecord) {
	t.Helper()
	tenant, q, run, samples, lease := analysisReadyFixture(t, store, 2)
	readPermissions(t, tenant)
	var role int64
	if err := store.db.Table("roles").Select("id").Where("organization_id=? AND name=?", tenant.orgID, "administrator").Scan(&role).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.db.Exec("INSERT INTO permissions (code) VALUES ('report.export') ON CONFLICT (code) DO NOTHING").Error; err != nil {
		t.Fatal(err)
	}
	if err := store.db.Exec("INSERT INTO role_permissions (organization_id,role_id,permission_code) VALUES (?,?,?)", tenant.orgID, role, "report.export").Error; err != nil {
		t.Fatal(err)
	}
	source, err := q.LoadRunAnalysis(t.Context(), lease)
	if err != nil {
		t.Fatal(err)
	}
	publication := analysisPublicationFixture(t, run, samples)
	if err := q.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error { return tx.PublishRunAnalysis(source, publication) }); err != nil {
		t.Fatal(err)
	}
	return tenant, q, run
}
func TestReportTransactionalPublicationAndPrivateSource(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, q, run := reportFixture(t, store)
		input := ReportInput{RunID: run.ID, AnalysisRevision: 1, Format: "json", IdempotencyKey: "report-create-logical-1"}
		row, err := tenant.CreateReport(input)
		if err != nil {
			t.Fatal(err)
		}
		if row.Status != "queued" || row.JobID == nil || row.CreatedBy == nil || *row.CreatedBy != run.CreatedBy {
			t.Fatal("queued report missing binding")
		}
		retry, err := tenant.CreateReport(input)
		if err != nil || retry.ID != row.ID || !retry.CreatedAt.Equal(row.CreatedAt) {
			t.Fatal("retry changed report", err)
		}
		changed := input
		changed.Format = "html"
		if _, err := tenant.CreateReport(changed); !errors.Is(err, ErrConflict) {
			t.Fatal("same key accepted changed content", err)
		}
		lease := mustClaim(t, q)
		source, err := q.LoadReportSource(t.Context(), lease)
		if err != nil {
			t.Fatal(err)
		}
		if source.Scope().ReportID != row.ID || source.Scope().OrganizationID != tenant.orgID {
			t.Fatal("source scope wrong")
		}
		if err := source.Use(func(data PublishedRead, encoded []byte) error {
			if len(data.Samples) != 2 || len(data.Attempts) != 2 || len(encoded) != 0 {
				return ErrReportInvalid
			}
			return nil
		}); err != nil {
			t.Fatal("inconsistent source", err)
		}
		// Repository transaction tests use a synthetic opaque payload. Production
		// Worker can obtain its payload only through run.BuildReportSnapshot.
		encoded := []byte(`{"synthetic_s1":true}`)
		if err := q.FreezeReportSource(t.Context(), lease, source, encoded); err != nil {
			t.Fatal(err)
		}
		if err := q.FreezeReportSource(t.Context(), lease, source, encoded); err != nil {
			t.Fatal("idempotent freeze", err)
		}
		if err := q.FreezeReportSource(t.Context(), lease, source, []byte(`{"changed":true}`)); !errors.Is(err, ErrReportInvalid) {
			t.Fatal("snapshot overwrite accepted", err)
		}
		for field, value := range map[string]any{"revision": 2, "schema_version": "changed"} {
			if err := store.db.Model(&ReportRecord{}).Where("id=?", row.ID).Update(field, value).Error; err == nil {
				t.Fatal("frozen report identity changed", field)
			}
		}
		frozen, err := q.LoadReportSource(t.Context(), lease)
		if err != nil {
			t.Fatal(err)
		}
		if err := frozen.Use(func(data PublishedRead, b []byte) error {
			if string(b) != string(encoded) || data.Run.ID != 0 {
				return ErrReportInvalid
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		publication := ReportPublication{ContentHash: "sha256:" + strings.Repeat("a", 64), FileHash: strings.Repeat("b", 64), FileSize: 128}
		spoof := audit.WithActor(t.Context(), audit.Actor{ActorID: run.CreatedBy + 1, ReasonCode: "spoof"})
		signer := store.auditSigner
		store.auditSigner = nil
		err = q.CompleteWith(spoof, lease, func(tx *TenantTransaction) error { return tx.PublishReport(frozen, reportDigest(encoded), publication) })
		store.auditSigner = signer
		if !errors.Is(err, audit.ErrUnavailable) {
			t.Fatal("audit failure not closed", err)
		}
		before, err := tenant.GetReport(row.ID)
		if err != nil || before.Status != "generating" {
			t.Fatal("failed publication committed", err)
		}
		if err := q.CompleteWith(spoof, lease, func(tx *TenantTransaction) error {
			actor, err := audit.ActorFromContext(tx.ctx)
			if err != nil || actor.ActorID != run.CreatedBy || actor.ReasonCode != "worker.report.generate" {
				return ErrReportInvalid
			}
			return tx.PublishReport(frozen, reportDigest(encoded), publication)
		}); err != nil {
			t.Fatal(err)
		}
		ready, err := tenant.GetReport(row.ID)
		if err != nil || ready.Status != "ready" || *ready.FileHash != publication.FileHash || *ready.FileSize != 128 {
			t.Fatal("not published", err)
		}
		job, err := tenant.GetJob(*row.JobID)
		if err != nil || job.Status != "completed" {
			t.Fatal("job completion not atomic", err)
		}
		if err := tenant.AuditReportDownload(row.ID, publication.FileHash, 128); err != nil {
			t.Fatal(err)
		}
		if err := tenant.AuditReportDownload(row.ID, strings.Repeat("c", 64), 128); !errors.Is(err, ErrReportInvalid) {
			t.Fatal("download receipt mismatch", err)
		}
		if err := store.db.Model(&ReportRecord{}).Where("id=?", row.ID).Update("file_hash", strings.Repeat("c", 64)).Error; err == nil {
			t.Fatal("ready artifact was mutable")
		}
		if err := q.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error { return tx.PublishReport(frozen, reportDigest(encoded), publication) }); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("completed lease replay", err)
		}
	})
}

func TestReportRevocationLogoutAndFailureRecovery(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, q, run := reportFixture(t, store)
		row, err := tenant.CreateReport(ReportInput{run.ID, 1, "html", "report-revocation-logical"})
		if err != nil {
			t.Fatal(err)
		}
		lease := mustClaim(t, q)
		if err := store.db.Model(&Session{}).Where("user_id=?", run.CreatedBy).Update("revoked_at", time.Now()).Error; err != nil {
			t.Fatal(err)
		}
		source, err := q.LoadReportSource(context.Background(), lease)
		if err != nil {
			t.Fatal("logout wrongly cancelled persisted job", err)
		}
		if _, err := tenant.GetReport(row.ID); !errors.Is(err, ErrManagementSession) {
			t.Fatal("download reused logged-out session", err)
		}
		if err := store.db.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code='report.export'", tenant.orgID).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := q.LoadReportSource(t.Context(), lease); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("revoked creator obtained source", err)
		}
		if err := q.FreezeReportSource(t.Context(), lease, source, []byte(`{"s1":true}`)); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("revoked creator froze source", err)
		}
		if err := q.Fail(t.Context(), lease, "WORKER_HANDLER_FAILED"); err != nil {
			t.Fatal(err)
		}
		if err := q.ReconcileReports(t.Context()); err != nil {
			t.Fatal(err)
		}
		var stored ReportRecord
		if err := store.db.Where("id=?", row.ID).Take(&stored).Error; err != nil {
			t.Fatal(err)
		}
		if stored.Status != "failed" || stored.ErrorCode == nil || *stored.ErrorCode != "MI_REPORT_GENERATION_FAILED" {
			t.Fatal("report failure not projected")
		}
		var results int64
		if err := store.db.Model(&RunResultRecord{}).Where("organization_id=? AND run_id=? AND is_published=?", tenant.orgID, run.ID, true).Count(&results).Error; err != nil || results != 1 {
			t.Fatal("report failure lost result")
		}
		if err := q.ReconcileReports(t.Context()); err != nil {
			t.Fatal("reconcile not idempotent", err)
		}
	})
}

func TestReportCreationPermissionsAuditAndOversizedSource(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, q, run := reportFixture(t, store)
		input := ReportInput{run.ID, 1, "json", "report-permissions-logical"}
		signer := store.auditSigner
		store.auditSigner = nil
		if _, err := tenant.CreateReport(input); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatal("unaudited create", err)
		}
		store.auditSigner = signer
		row, err := tenant.CreateReport(input)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := tenant.ListReports(run.ID, 1, ListOptions{Limit: 10})
		if err != nil || len(rows) != 1 || rows[0].ID != row.ID {
			t.Fatal("list", err)
		}
		unbound, _ := store.WithOrganization(t.Context(), tenant.orgID)
		if _, err := unbound.GetReport(row.ID); !errors.Is(err, ErrManagementSession) {
			t.Fatal("unbound read", err)
		}
		foreign, _ := store.WithOrganization(tenant.ctx, tenant.orgID+1)
		if _, err := foreign.GetReport(row.ID); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("foreign org", err)
		}
		lease := mustClaim(t, q)
		if err := store.db.Model(&RunResultRecord{}).Where("organization_id=? AND run_id=?", tenant.orgID, run.ID).Update("conclusion_json", strings.Repeat("x", (4<<20)+1)).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := q.LoadReportSource(t.Context(), lease); !errors.Is(err, ErrResultDocument) {
			t.Fatal("oversize source allocated/accepted", err)
		}
		if err := store.db.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code='evidence.read'", tenant.orgID).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.CreateReport(input); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("retry bypassed revoked evidence grant", err)
		}
	})
}
