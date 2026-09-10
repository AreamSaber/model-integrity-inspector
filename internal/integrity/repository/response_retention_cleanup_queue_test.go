package repository

import (
	"testing"
	"time"
)

func TestResponseRetentionCleanupDisabledExceptionRejectsUnboundJobs(t *testing.T) {
	for _, boundary := range []string{"legacy_org_job", "ordinary_job", "batch_job_binding", "job_object_binding", "job_idempotency_binding", "batch_creator_binding", "cancel_requested", "attempts_exhausted"} {
		t.Run(boundary, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				tenant, q, selection := responseCleanupFixture(t, s, false)
				var job Job
				if boundary == "legacy_org_job" || boundary == "ordinary_job" {
					spec := JobSpec{Type: JobRetentionDelete, ObjectID: tenant.orgID, IdempotencyKey: "retention-inactive-legacy"}
					if boundary == "ordinary_job" {
						spec.Type, spec.ObjectID, spec.IdempotencyKey = JobRunAnalyze, selection.RunID, "retention-inactive-ordinary"
					}
					var err error
					job, err = tenant.Enqueue(spec)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					derivedFixtureRetention(t, tenant, 0)
					if err := q.ScheduleResponseRetention(tenant.ctx); err != nil {
						t.Fatal(err)
					}
					if err := s.db.Where("organization_id=? AND type=? AND status='pending'", tenant.orgID, string(JobRetentionDelete)).Take(&job).Error; err != nil {
						t.Fatal(err)
					}
					batch := s.db.Model(&responseRetentionBatch{}).Where("organization_id=? AND id=?", tenant.orgID, job.ObjectID)
					jobRow := s.db.Model(&Job{}).Where("organization_id=? AND id=?", tenant.orgID, job.ID)
					switch boundary {
					case "batch_job_binding":
						if err := batch.Update("job_id", nil).Error; err != nil {
							t.Fatal(err)
						}
					case "job_object_binding":
						if err := jobRow.Update("object_id", job.ObjectID-1).Error; err != nil {
							t.Fatal(err)
						}
					case "job_idempotency_binding":
						if err := jobRow.Update("idempotency_key", "retention-unbound-key").Error; err != nil {
							t.Fatal(err)
						}
					case "batch_creator_binding":
						if err := batch.Update("created_by", 1).Error; err != nil {
							t.Fatal(err)
						}
					case "cancel_requested":
						if err := jobRow.Update("cancel_requested_at", time.Now().UTC()).Error; err != nil {
							t.Fatal(err)
						}
					case "attempts_exhausted":
						if err := jobRow.Update("attempt_count", job.MaxAttempts).Error; err != nil {
							t.Fatal(err)
						}
					}
				}
				if err := s.db.Model(&Organization{}).Where("id=?", tenant.orgID).Update("status", "disabled").Error; err != nil {
					t.Fatal(err)
				}
				if claimed, err := q.Claim(tenant.ctx); err != nil || claimed != nil {
					t.Fatal("disabled exception claimed an unauthorized/terminal Job", err)
				}
				var after Job
				if err := s.db.Where("organization_id=? AND id=?", tenant.orgID, job.ID).Take(&after).Error; err != nil {
					t.Fatal(err)
				}
				wantStatus, wantCode := "cancelled", "JOB_ORGANIZATION_INACTIVE"
				if boundary == "cancel_requested" {
					wantCode = "JOB_CANCELLED"
				}
				if boundary == "attempts_exhausted" {
					wantStatus, wantCode = "failed", "JOB_ATTEMPTS_EXHAUSTED"
				}
				if after.Status != wantStatus || after.LastErrorCode == nil || *after.LastErrorCode != wantCode {
					t.Fatal("inactive reconcile changed ordinary cancellation/failure", after.Status, after.LastErrorCode)
				}
				assertCleanupRows(t, s, tenant.orgID, 1, 1, 0)
			})
		})
	}
}
