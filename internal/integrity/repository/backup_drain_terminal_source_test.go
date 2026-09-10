package repository

import (
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestBackupDrainTerminalApplyPurePriorities(t *testing.T) {
	base := backupDrainJob{ID: 3, OrganizationID: 1, ObjectID: 2, Type: string(JobTargetPrecheck), Status: "running", Expired: true, AttemptCount: 1, MaxAttempts: 3, LeaseUntil: sql.NullString{String: "original", Valid: true}}
	domain := backupDrainDomain{ID: 2, OrganizationID: 1, JobID: 3, State: "running", Count: 1}
	for _, item := range []struct {
		name                 string
		change               func(*backupDrainJob, *backupDrainDomain)
		status, code, action string
		wantErr              bool
	}{
		{"request", func(*backupDrainJob, *backupDrainDomain) {}, "failed", "JOB_BACKUP_UNCERTAIN", "precheck_uncertain", false},
		{"cancel-first", func(j *backupDrainJob, _ *backupDrainDomain) {
			j.CancelRequestedAt.Valid = true
			j.LeaseUntil.Valid = false
			j.AttemptCount = 3
			j.Inactive = true
		}, "cancelled", "JOB_CANCELLED", "terminalize", false},
		{"null-lease-before-exhausted", func(j *backupDrainJob, _ *backupDrainDomain) {
			j.LeaseUntil.Valid = false
			j.AttemptCount = 3
			j.Inactive = true
		}, "failed", "JOB_LEASE_INVALID", "terminalize", false},
		{"exhausted-before-inactive", func(j *backupDrainJob, _ *backupDrainDomain) { j.AttemptCount = 3; j.Inactive = true }, "failed", "JOB_ATTEMPTS_EXHAUSTED", "terminalize", false},
		{"inactive-before-uncertain", func(j *backupDrainJob, _ *backupDrainDomain) { j.Inactive = true }, "cancelled", "JOB_ORGANIZATION_INACTIVE", "terminalize", false},
		{"pending-not-null-lease", func(j *backupDrainJob, _ *backupDrainDomain) {
			j.Status = "pending"
			j.Expired = false
			j.LeaseUntil.Valid = false
		}, "failed", "JOB_BACKUP_UNCERTAIN", "precheck_uncertain", false},
		{"never-claimed-request", func(j *backupDrainJob, _ *backupDrainDomain) { j.AttemptCount = 0 }, "", "", "", true},
		{"no-request", func(_ *backupDrainJob, d *backupDrainDomain) { d.Count = 0 }, "", "", "", true},
		{"live", func(j *backupDrainJob, _ *backupDrainDomain) { j.Expired = false }, "", "", "", true},
		{"completed", func(j *backupDrainJob, _ *backupDrainDomain) { j.Status = "completed" }, "", "", "", true},
		{"completed-time", func(j *backupDrainJob, _ *backupDrainDomain) { j.CompletedAt.Valid = true }, "", "", "", true},
		{"dispatched", func(j *backupDrainJob, _ *backupDrainDomain) { j.Unsettled = true }, "", "", "", true},
		{"legacy-generation", func(j *backupDrainJob, _ *backupDrainDomain) { j.UnsettledLegacy = true }, "", "", "", true},
		{"legacy-pointer", func(_ *backupDrainJob, d *backupDrainDomain) { d.Legacy = true }, "", "", "", true},
		{"wrong-pointer", func(_ *backupDrainJob, d *backupDrainDomain) { d.JobID++ }, "", "", "", true},
		{"finished-precheck", func(_ *backupDrainJob, d *backupDrainDomain) { d.Completed.Valid = true }, "", "", "", true},
		{"old-cancelled", func(j *backupDrainJob, _ *backupDrainDomain) {
			j.Status = "cancelled"
			j.LastErrorCode = sql.NullString{String: "ORIGINAL_CODE", Valid: true}
		}, "cancelled", "ORIGINAL_CODE", "project_terminal", false},
		{"old-null-error", func(j *backupDrainJob, _ *backupDrainDomain) { j.Status = "failed" }, "failed", "", "project_terminal", false},
		{"unknown-type", func(j *backupDrainJob, _ *backupDrainDomain) { j.Type = "unknown" }, "", "", "", true},
	} {
		t.Run(item.name, func(t *testing.T) {
			job, d := base, domain
			item.change(&job, &d)
			got, err := backupDrainTerminalDecide(job, d)
			if item.wantErr {
				if !errors.Is(err, ErrBackupDrainUnsupported) || got != (backupDrainTerminalDecision{}) {
					t.Fatal("unsupported decision acquired authority", err)
				}
				return
			}
			if err != nil || got.status != item.status || got.code != item.code || got.action != item.action || !got.project || got.changeJob != (item.action != "project_terminal") {
				t.Fatal("original decision priority changed", got, err)
			}
		})
	}
}

func TestBackupDrainTerminalApplyOriginalJobAndDomainStale(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		f, freeze, source := backupDrainTerminalFixture(t, s, JobRunAnalyze)
		var original Job
		if err := s.db.First(&original, source.job.ID).Error; err != nil {
			t.Fatal(err)
		}
		for _, mutation := range []struct {
			name   string
			update map[string]any
		}{
			{"idempotency", map[string]any{"idempotency_key": "other-fixed-key"}},
			{"priority", map[string]any{"priority": original.Priority + 1}},
			{"attempt", map[string]any{"attempt_count": original.AttemptCount + 1}},
			{"maximum", map[string]any{"max_attempts": original.MaxAttempts + 1}},
			{"owner", map[string]any{"lease_owner": "other-original-owner"}},
			{"lease", map[string]any{"lease_until": nil}},
			{"cancel", map[string]any{"cancel_requested_at": time.Now().UTC()}},
			{"error", map[string]any{"last_error_code": "OTHER_CODE"}},
			{"completed", map[string]any{"completed_at": time.Now().UTC()}},
			{"updated", map[string]any{"updated_at": time.Unix(2, 0).UTC()}},
		} {
			t.Run(mutation.name, func(t *testing.T) {
				if err := s.db.Model(&Job{}).Where("id=?", original.ID).UpdateColumns(mutation.update).Error; err != nil {
					t.Fatal(err)
				}
				before := backupDrainTerminalRows(t, s)
				if result, err := freeze.ApplyBackupTerminalCandidate(f.tenant.ctx, source); !errors.Is(err, ErrBackupDrainStale) || result != (BackupDrainTerminalResult{}) || !reflect.DeepEqual(before, backupDrainTerminalRows(t, s)) {
					t.Fatal("changed original metadata was overwritten", err)
				}
				if err := s.db.Model(&Job{}).Where("id=?", original.ID).Select("*").Updates(&original).Error; err != nil {
					t.Fatal(err)
				}
			})
		}
		// A separately changed terminal Run is not an Applied no-op. This is an
		// explicit stale-source injection, not a normal producer transition.
		if err := s.db.Model(&RunRecord{}).Where("id=?", source.job.ObjectID).UpdateColumn("status", "FAILED").Error; err != nil {
			t.Fatal(err)
		}
		before := backupDrainTerminalRows(t, s)
		if result, err := freeze.ApplyBackupTerminalCandidate(f.tenant.ctx, source); !errors.Is(err, ErrBackupDrainStale) || result != (BackupDrainTerminalResult{}) || !reflect.DeepEqual(before, backupDrainTerminalRows(t, s)) {
			t.Fatal("no active original domain was reported Applied", err)
		}
	})
}
