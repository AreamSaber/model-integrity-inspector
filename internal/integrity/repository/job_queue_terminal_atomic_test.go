package repository

import (
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

// This is the ordinary Claim path, not a test-only domain caller or maintenance
// drain. A real precheck reserves one request; only expiry/exhaustion and the
// exact driver-level ignored UPDATE are controlled failure-fixture mutations.
func TestJobQueueTerminalUpdateSuppressionRollsBackClaim(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run("cancelled_"+strconv.FormatBool(cancelled), func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
				tenant, target, record, queue, lease := precheckFixture(t, s)
				if err := queue.WithLease(t.Context(), lease, func(tx *TenantTransaction) error {
					if _, err := tx.BeginPrecheck(record.ID, lease.Job.ID); err != nil {
						return err
					}
					return tx.ReservePrecheckRequest(record.ID, lease.Job.ID)
				}); err != nil {
					t.Fatal("actual precheck Begin/Reserve failed", err)
				}
				now, err := queueTime(s.db.WithContext(t.Context()), s.driver)
				if err != nil {
					t.Fatal(err)
				}
				changes := map[string]any{"attempt_count": lease.Job.MaxAttempts, "lease_until": now.Add(-time.Second)}
				if cancelled {
					changes["cancel_requested_at"] = now
				}
				changed := s.db.Model(&Job{}).Where("organization_id=? AND id=?", tenant.orgID, lease.Job.ID).Updates(changes)
				if changed.Error != nil || changed.RowsAffected != 1 {
					t.Fatal("failed to bound the actual expired exhausted Job", changed.Error)
				}
				if err := s.db.Model(&User{}).Where("id=?", record.CreatedBy).UpdateColumn("status", "disabled").Error; err != nil {
					t.Fatal("disable original creator without rewriting history", err)
				}
				beforeJob, err := tenant.GetJob(lease.Job.ID)
				if err != nil {
					t.Fatal(err)
				}
				beforeCheck, err := tenant.GetPrecheck(target.Target.ID, record.ID)
				if err != nil || beforeCheck.RequestCount != 1 || beforeCheck.StartedAt == nil || beforeCheck.Status != "running" {
					t.Fatal("real request reservation missing", err)
				}
				before := jobQueueTerminalRows(t, s)
				remove := jobQueueTerminalIgnore(t, s, cfg)
				t.Cleanup(remove)
				spoof := audit.WithActor(t.Context(), audit.Actor{ActorID: record.CreatedBy + 1, ReasonCode: "forged.queue", IPSummary: "forged"})
				claimed, err := queue.Claim(spoof)
				if !errors.Is(err, ErrJobLeaseLost) || claimed != nil {
					t.Fatal("ignored terminal UPDATE falsely committed ordinary Claim", err)
				}
				if !reflect.DeepEqual(before, jobQueueTerminalRows(t, s)) {
					t.Fatal("failed Claim changed Job/domain/audit/head/consumer/fairness")
				}
				remove()
				claimed, err = queue.Claim(spoof)
				if err != nil || claimed != nil {
					t.Fatal("same actual Job could not terminate after exact fault removal", err)
				}
				afterJob, err := tenant.GetJob(lease.Job.ID)
				if err != nil {
					t.Fatal(err)
				}
				afterCheck, err := tenant.GetPrecheck(target.Target.ID, record.ID)
				if err != nil {
					t.Fatal(err)
				}
				jobStatus, jobCode, checkCode := "failed", "JOB_ATTEMPTS_EXHAUSTED", "MI_UNCERTAIN_ATTEMPT"
				if cancelled {
					jobStatus, jobCode, checkCode = "cancelled", "JOB_CANCELLED", "MI_PRECHECK_CANCELLED"
				}
				if afterJob.Status != jobStatus || afterJob.LastErrorCode == nil || *afterJob.LastErrorCode != jobCode || afterJob.LeaseOwner != nil || afterJob.LeaseUntil != nil || afterJob.CompletedAt == nil || !afterJob.UpdatedAt.Equal(*afterJob.CompletedAt) || afterCheck.Status != "failed" || afterCheck.ErrorCode != checkCode || afterCheck.ResultJSON != "[]" || afterCheck.Version != beforeCheck.Version+1 || afterCheck.FinishedAt == nil || !afterCheck.FinishedAt.Equal(*afterJob.CompletedAt) || afterCheck.RequestCount != 1 {
					t.Fatal("original queue/precheck priority, time or request facts changed")
				}
				terminalJob, terminalCheck := afterJob, afterCheck
				afterJob.Status, afterJob.LastErrorCode, afterJob.LeaseOwner, afterJob.LeaseUntil, afterJob.UpdatedAt, afterJob.CompletedAt = beforeJob.Status, beforeJob.LastErrorCode, beforeJob.LeaseOwner, beforeJob.LeaseUntil, beforeJob.UpdatedAt, beforeJob.CompletedAt
				afterCheck.Status, afterCheck.ErrorCode, afterCheck.ResultJSON, afterCheck.Version, afterCheck.FinishedAt = beforeCheck.Status, beforeCheck.ErrorCode, beforeCheck.ResultJSON, beforeCheck.Version, beforeCheck.FinishedAt
				if !reflect.DeepEqual(beforeJob, afterJob) || !reflect.DeepEqual(beforeCheck, afterCheck) {
					t.Fatal("terminal projection rewrote unrelated original fields")
				}
				if claimed, err := queue.Claim(spoof); err != nil || claimed != nil {
					t.Fatal("repeated empty Claim failed", err)
				}
				actualJob, jobErr := tenant.GetJob(lease.Job.ID)
				actualCheck, checkErr := tenant.GetPrecheck(target.Target.ID, record.ID)
				if jobErr != nil || checkErr != nil || !reflect.DeepEqual(terminalJob, actualJob) || !reflect.DeepEqual(terminalCheck, actualCheck) {
					t.Fatal("repeat Claim duplicated terminal projection")
				}
				var events []audit.Event
				if err := s.db.Where("organization_id=? AND action='target.precheck.reconcile' AND object_id=?", tenant.orgID, strconv.FormatInt(record.ID, 10)).Find(&events).Error; err != nil || len(events) != 1 {
					t.Fatal("terminal recovery audit missing or duplicated", err)
				}
				var summary struct {
					ReasonCode string `json:"reason_code"`
				}
				if events[0].ActorID == nil || *events[0].ActorID != record.CreatedBy || events[0].IPSummary != "" || json.Unmarshal([]byte(events[0].DiffSummary), &summary) != nil || summary.ReasonCode != "target.precheck.reconcile" {
					t.Fatal("terminal recovery replaced original departed creator or reason")
				}
				if err := s.VerifyAllAudit(t.Context(), true); err != nil {
					t.Fatal("real terminal audit chain failed verification", err)
				}
			})
		})
	}
}

func TestJobQueueTerminalUpdateKeepsEmptyAndUnprojectedClaims(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, tenant, queue := queueFixture(t, s)
		if claimed, err := queue.Claim(t.Context()); err != nil || claimed != nil {
			t.Fatal("legitimate empty queue is not an UPDATE failure", err)
		}
		job := mustEnqueue(t, tenant, retentionJob(initial.Organization.ID, "terminal-no-precheck-projection"))
		now, err := queueTime(s.db.WithContext(t.Context()), s.driver)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.db.Model(&Job{}).Where("organization_id=? AND id=?", tenant.orgID, job.ID).UpdateColumn("cancel_requested_at", now).Error; err != nil {
			t.Fatal(err)
		}
		before := jobQueueTerminalRows(t, s)
		if claimed, err := queue.Claim(t.Context()); err != nil || claimed != nil {
			t.Fatal("unprojected terminal Job was rejected", err)
		}
		after := jobQueueTerminalRows(t, s)
		for _, table := range []string{"integrity_target_prechecks", "integrity_audit_logs", "integrity_audit_chain_heads"} {
			if !reflect.DeepEqual(before[table], after[table]) {
				t.Fatal("non-precheck terminal Job fabricated domain projection or audit")
			}
		}
		actual, err := tenant.GetJob(job.ID)
		if err != nil || actual.Status != "cancelled" || actual.AttemptCount != 0 || actual.CompletedAt == nil || actual.LastErrorCode == nil || *actual.LastErrorCode != "JOB_CANCELLED" {
			t.Fatal("pending cancellation/no-projection semantics changed", err)
		}
	})
}

func jobQueueTerminalRows(t *testing.T, s *Store) map[string][]map[string]any {
	t.Helper()
	out := map[string][]map[string]any{}
	for _, table := range []string{"integrity_jobs", "integrity_target_prechecks", "integrity_audit_logs", "integrity_audit_chain_heads", "integrity_queue_consumer_leases", "integrity_queue_fairness"} {
		order := "id"
		switch table {
		case "integrity_audit_chain_heads", "integrity_queue_fairness":
			order = "organization_id"
		case "integrity_queue_consumer_leases":
			order = "lock_name"
		}
		var rows []map[string]any
		if err := s.db.Table(table).Order(order).Find(&rows).Error; err != nil {
			t.Fatal("read fixed terminal-transaction facts", err)
		}
		out[table] = rows
	}
	return out
}

func jobQueueTerminalIgnore(t *testing.T, s *Store, cfg Config) func() {
	t.Helper()
	statements := []string{"CREATE TRIGGER job_queue_terminal_ignore BEFORE UPDATE ON integrity_jobs WHEN OLD.status='running' AND NEW.status IN ('failed','cancelled') BEGIN SELECT RAISE(IGNORE); END"}
	if cfg.Driver == "postgres" {
		statements = []string{"CREATE FUNCTION job_queue_terminal_ignore_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$", "CREATE TRIGGER job_queue_terminal_ignore BEFORE UPDATE ON integrity_jobs FOR EACH ROW WHEN (OLD.status='running' AND NEW.status IN ('failed','cancelled')) EXECUTE FUNCTION job_queue_terminal_ignore_fn()"}
	}
	for _, statement := range statements {
		if err := s.db.Exec(statement).Error; err != nil {
			t.Fatal("install exact terminal UPDATE suppression", err)
		}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			drop := "DROP TRIGGER job_queue_terminal_ignore"
			if cfg.Driver == "postgres" {
				drop += " ON integrity_jobs"
			}
			if err := s.db.Exec(drop).Error; err != nil {
				t.Error("remove exact terminal UPDATE suppression", err)
			}
			if cfg.Driver == "postgres" {
				if err := s.db.Exec("DROP FUNCTION job_queue_terminal_ignore_fn()").Error; err != nil {
					t.Error("remove exact terminal UPDATE suppression function", err)
				}
			}
		})
	}
}
