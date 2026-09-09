package app

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"slices"
	"strconv"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

type pipelineRetentionSnapshot struct {
	summary                         runservice.ResponseRetentionView
	result, derived                 []byte
	unavailable                     []byte
	raw, captured, unavailableCount int
	reports                         []runservice.ReportView
	files                           [][]byte
}

func pipelineUnavailableDisplayBytes(t *testing.T, db *sql.DB, p *pipelineHTTP, runID string) ([]byte, int) {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), "SELECT attempt_id,state,request_hash,policy,created_at,COALESCE(length(ciphertext),0),COALESCE(length(nonce),0),plaintext_bytes,version,captured_at_micros,expires_at_micros,length(source_hash),length(payload_hash),length(key_version) FROM integrity_display_evidence WHERE organization_id=$1 AND run_id=$2 AND state<>'captured' ORDER BY attempt_id", p.orgID, runID)
	if err != nil {
		t.Fatal("read bounded unavailable display metadata")
	}
	defer func() { _ = rows.Close() }()
	type item struct {
		AttemptID                  int64
		State, RequestHash, Policy string
		CreatedAt                  time.Time
	}
	items := make([]item, 0)
	for rows.Next() {
		var current item
		var sizes [9]int64
		if err := rows.Scan(&current.AttemptID, &current.State, &current.RequestHash, &current.Policy, &current.CreatedAt, &sizes[0], &sizes[1], &sizes[2], &sizes[3], &sizes[4], &sizes[5], &sizes[6], &sizes[7], &sizes[8]); err != nil || len(items) >= 1536 {
			t.Fatal("invalid bounded unavailable metadata")
		}
		if current.AttemptID <= 0 || current.CreatedAt.IsZero() || len(current.RequestHash) != 64 || current.Policy != repository.DisplayEvidencePolicy || sizes != [9]int64{} || !slices.Contains([]string{repository.DisplayUnavailablePolicy, repository.DisplayUnavailableLimit, repository.DisplayUnavailableSource, repository.DisplayUnavailableCancelled, repository.DisplayUnavailableCapture, repository.DisplayUnavailableSeal}, current.State) {
			t.Fatal("unavailable display row retained a body or invalid classification")
		}
		items = append(items, current)
	}
	if rows.Err() != nil {
		t.Fatal("complete unavailable metadata read")
	}
	encoded, err := json.Marshal(items)
	if err != nil {
		t.Fatal("encode unavailable S1 identity")
	}
	return encoded, len(items)
}

func pipelineDerivedBytes(t *testing.T, db *sql.DB, p *pipelineHTTP, runID string) []byte {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), "SELECT attempt_id,payload,mac FROM integrity_attempt_derived WHERE organization_id=$1 AND run_id=$2 ORDER BY attempt_id", p.orgID, runID)
	if err != nil {
		t.Fatal("read bounded authenticated S1 identity")
	}
	defer func() { _ = rows.Close() }()
	type record struct {
		AttemptID    int64
		Payload, MAC []byte
	}
	items := make([]record, 0, 32)
	for rows.Next() {
		var item record
		if err := rows.Scan(&item.AttemptID, &item.Payload, &item.MAC); err != nil || len(items) >= 1536 || len(item.Payload) > 32768 || len(item.MAC) != 32 {
			t.Fatal("invalid bounded S1 identity")
		}
		items = append(items, item)
	}
	if rows.Err() != nil || len(items) == 0 {
		t.Fatal("actual S1 rows unavailable")
	}
	data, err := json.Marshal(items)
	if err != nil {
		t.Fatal("encode test-owned S1 identity")
	}
	return data
}

func capturePipelineRetention(t *testing.T, db *sql.DB, p *pipelineHTTP, runID string, days int, allowExtraReports bool) pipelineRetentionSnapshot {
	t.Helper()
	var snapshot pipelineRetentionSnapshot
	path := "/api/v1/runs/" + runID
	p.request(t, "GET", path+"/response-retention?analysis_revision=1", nil, 200, &snapshot.summary)
	if snapshot.summary.Version != "mii.response-retention-summary.v1" || snapshot.summary.RunID != runID || snapshot.summary.AnalysisRevision != 1 || snapshot.summary.PolicyDays != days || snapshot.summary.AttemptCount < 1 || snapshot.summary.RawDeletedCount != 0 || snapshot.summary.DisplayDeletedCount != 0 || snapshot.summary.LastDeletedAt != nil {
		t.Fatal("actual fresh response retention observation is invalid")
	}
	if days == 0 {
		if snapshot.summary.DisplayRetainedCount != 0 || snapshot.summary.DisplayExpiredCount != 0 {
			t.Fatal("zero-day capture invented retained response copies")
		}
		return snapshot
	}
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM integrity_response_evidence WHERE organization_id=$1 AND run_id=$2", p.orgID, runID).Scan(&snapshot.raw); err != nil {
		t.Fatal("read actual raw response count")
	}
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM integrity_display_evidence WHERE organization_id=$1 AND run_id=$2 AND state='captured'", p.orgID, runID).Scan(&snapshot.captured); err != nil {
		t.Fatal("read actual captured display count")
	}
	snapshot.unavailable, snapshot.unavailableCount = pipelineUnavailableDisplayBytes(t, db, p, runID)
	// A recorded body receipt preserves raw plus either captured display or an
	// explicit S1-only failure row. Never invent a display ciphertext for it.
	if snapshot.raw != snapshot.summary.AttemptCount || snapshot.captured < 1 || snapshot.captured+snapshot.unavailableCount != snapshot.summary.AttemptCount || snapshot.summary.DisplayRetainedCount != snapshot.captured || snapshot.summary.DisplayExpiredCount != 0 {
		t.Fatalf("actual retained response counts disagree with the captured pipeline: attempts=%d retained=%d expired=%d raw_deleted=%d display_deleted=%d", snapshot.summary.AttemptCount, snapshot.summary.DisplayRetainedCount, snapshot.summary.DisplayExpiredCount, snapshot.summary.RawDeletedCount, snapshot.summary.DisplayDeletedCount)
	}
	snapshot.result = p.request(t, "GET", path+"/result?analysis_revision=1&include=statistics", nil, 200, nil)
	snapshot.derived = pipelineDerivedBytes(t, db, p, runID)
	var page struct {
		Items []runservice.ReportView `json:"items"`
	}
	p.request(t, "GET", path+"/reports?analysis_revision=1&limit=100", nil, 200, &page)
	if !validPipelineReportInventory(page.Items, runID, allowExtraReports) {
		t.Fatal("actual JSON/HTML/CSV report inventory missing, duplicated, unready or outside scope before cleanup")
	}
	for _, report := range page.Items {
		if report.Status != "ready" || report.RunID != runID {
			t.Fatal("report is not ready before cleanup")
		}
		snapshot.files = append(snapshot.files, downloadPipelineReport(t, p, report))
	}
	snapshot.reports = page.Items
	return snapshot
}

// This runs after real management HTTP disabled then reenabled retention. The
// monotonic cutoff, not a forged expiry/cipher, makes the original copies due.
// Advancing only this test-owned daily schedule avoids waiting a calendar day;
// the actual app maintenance, Job claim, fenced handler and COMMIT still run.
func finishPipelineRetention(t *testing.T, store *repository.Store, db *sql.DB, p *pipelineHTTP, runID string, before pipelineRetentionSnapshot) {
	t.Helper()
	due := time.Unix(0, 0).UTC()
	if _, err := db.ExecContext(t.Context(), "UPDATE integrity_response_retention_schedule SET next_due_at=$1,last_checked_at=$1,sweep_day=0,cursor_run_id=0 WHERE organization_id=$2 AND active_batch_id IS NULL", due, p.orgID); err != nil {
		t.Fatal("advance isolated daily schedule eligibility")
	}
	path := "/api/v1/runs/" + runID
	var observed runservice.ResponseRetentionView
	deadline, tick := time.NewTimer(30*time.Second), time.NewTicker(100*time.Millisecond)
	defer deadline.Stop()
	defer tick.Stop()
	for {
		p.request(t, "GET", path+"/response-retention?analysis_revision=1", nil, 200, &observed)
		if observed.RawDeletedCount == before.raw && observed.DisplayDeletedCount == before.captured {
			break
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("actual daily cleanup Job did not finish the original response copies")
		case <-t.Context().Done():
			t.Fatal("actual daily cleanup test canceled")
		}
	}
	if observed.DisplayRetainedCount != 0 || observed.DisplayExpiredCount != 0 || observed.LastDeletedAt == nil || observed.LastDeletedAt.Before(before.summary.ObservedAt) || observed.ObservedAt.Before(*observed.LastDeletedAt) {
		t.Fatal("deleted response observation lost its actual time or counts")
	}
	for _, object := range []struct {
		table     string
		remaining int
	}{{"integrity_response_evidence", 0}, {"integrity_display_evidence", before.unavailableCount}} {
		var count int
		if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+object.table+" WHERE organization_id=$1 AND run_id=$2", p.orgID, runID).Scan(&count); err != nil || count != object.remaining {
			t.Fatal("response expiry did not physically delete the exact Run objects")
		}
	}
	if unavailable, count := pipelineUnavailableDisplayBytes(t, db, p, runID); count != before.unavailableCount || !bytes.Equal(unavailable, before.unavailable) {
		t.Fatal("response cleanup deleted or rewrote unavailable S1 display metadata")
	}
	var completed int
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM integrity_response_retention_batches b JOIN integrity_jobs j ON j.organization_id=b.organization_id AND j.id=b.job_id WHERE b.organization_id=$1 AND b.run_id=$2 AND b.state='completed' AND j.status='completed' AND j.type='integrity.retention.delete' AND b.deleted_rows>0", p.orgID, runID).Scan(&completed); err != nil || completed < 1 {
		t.Fatal("physical deletion bypassed actual batch Job completion")
	}
	if !bytes.Equal(before.result, p.request(t, "GET", path+"/result?analysis_revision=1&include=statistics", nil, 200, nil)) || !bytes.Equal(before.derived, pipelineDerivedBytes(t, db, p, runID)) {
		t.Fatal("response cleanup changed frozen analysis or authenticated S1 bytes")
	}
	for i, original := range before.reports {
		var current runservice.ReportView
		p.request(t, "GET", "/api/v1/reports/"+original.ID, nil, 200, &current)
		if current.Status != "ready" || current.Revision != original.Revision || current.ContentHash == nil || original.ContentHash == nil || *current.ContentHash != *original.ContentHash || !bytes.Equal(before.files[i], downloadPipelineReport(t, p, current)) {
			t.Fatal("body cleanup rewrote or removed an immutable report")
		}
	}
	for _, permission := range []string{"run.read", "evidence.read"} {
		t.Run("retention_summary_without_"+permission, func(t *testing.T) {
			org, err := strconv.ParseInt(p.orgID, 10, 64)
			if err != nil {
				t.Fatal("invalid actual organization")
			}
			pipelineRemoveDisplayPermission(t, db, org, permission)
			p.request(t, "GET", path+"/response-retention?analysis_revision=1", nil, 403, nil)
		})
	}
	if err := store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal("actual cleanup or report observation damaged the audit chain")
	}
}
