package repository

import (
	"database/sql"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBackupDrainRoutingClosedDiscriminator(t *testing.T) {
	if (*BackupDrainSource)(nil).JobType() != "" || (&BackupDrainSource{}).JobType() != "" {
		t.Fatal("empty source invented a routing type")
	}
	for _, kind := range []JobType{JobRunPlan, JobSampleExecute, JobRunAnalyze, JobReportGenerate, JobTargetPrecheck, JobRetentionDelete, JobNotificationSend} {
		source := BackupDrainSource{kind: BackupDrainTerminalRequired, job: backupDrainJob{Type: string(kind)}}
		if source.JobType() != kind || source.Kind() != BackupDrainTerminalRequired {
			t.Fatal("terminal source lost its closed domain discriminator")
		}
	}
	for _, raw := range []string{"private-unknown-type", strings.ToUpper(string(JobSampleExecute)), " " + string(JobSampleExecute), string(JobSampleExecute) + "\x00"} {
		source := BackupDrainSource{job: backupDrainJob{Type: raw}}
		if source.JobType() != "" {
			t.Fatal("unknown original text escaped through routing getter")
		}
	}
}

func TestBackupDrainRoutingActualTerminalSources(t *testing.T) {
	for _, kind := range []JobType{JobRunPlan, JobSampleExecute, JobRunAnalyze, JobReportGenerate, JobTargetPrecheck, JobRetentionDelete} {
		t.Run(string(kind), func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				tenant, _, original := backupDrainRealProducer(t, s, kind)
				changed := s.db.Model(&Job{}).Where("organization_id=? AND id=?", tenant.orgID, original.Job.ID).
					UpdateColumns(map[string]any{"lease_until": time.Unix(1, 0).UTC(), "attempt_count": original.Job.MaxAttempts})
				if changed.Error != nil || changed.RowsAffected != 1 {
					t.Fatal("create controlled expired exhausted real Job", changed.Error)
				}
				freeze := beginTestMaintenance(t, s, tenant.ctx, backupDrainTestAuthority(t, s, tenant.ctx))
				source, observed, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
				if err != nil || source == nil || !observed.CandidatePresent || source.Kind() != BackupDrainTerminalRequired {
					t.Fatal("real terminal candidate was not observed", err)
				}
				before := backupDrainDomainRows(t, s)
				if source.JobType() != kind || source.job.ID != original.Job.ID {
					t.Fatal("routing did not retain the original real producer domain")
				}
				if !reflect.DeepEqual(before, backupDrainDomainRows(t, s)) {
					t.Fatal("read-only discriminator changed domain facts")
				}
			})
		})
	}
}

func TestBackupDrainRoutingLegacyRetentionTerminalIsReachable(t *testing.T) {
	base := backupDrainJob{ID: 3, OrganizationID: 1, ObjectID: 1, Type: string(JobRetentionDelete), Status: "running", Expired: true, AttemptCount: 1, MaxAttempts: 3, LeaseUntil: sql.NullString{Valid: true, String: "original"}}
	d := backupDrainDomain{Legacy: true}
	for _, item := range []struct {
		name   string
		change func(*backupDrainJob)
		want   BackupDrainKind
	}{
		{"retryable", func(*backupDrainJob) {}, BackupDrainSourceUnsupported},
		{"null-lease", func(j *backupDrainJob) { j.LeaseUntil.Valid = false }, BackupDrainTerminalRequired},
		{"cancelled", func(j *backupDrainJob) { j.CancelRequestedAt.Valid = true }, BackupDrainTerminalRequired},
		{"exhausted", func(j *backupDrainJob) { j.AttemptCount = j.MaxAttempts }, BackupDrainTerminalRequired},
		{"live-exhausted", func(j *backupDrainJob) { j.Expired = false; j.AttemptCount = j.MaxAttempts }, BackupDrainSourceUnsupported},
		{"wrong-object", func(j *backupDrainJob) { j.ObjectID++; j.LeaseUntil.Valid = false }, BackupDrainSourceUnsupported},
		{"execution-legacy", func(j *backupDrainJob) { j.Type = string(JobSampleExecute); j.LeaseUntil.Valid = false }, BackupDrainSourceUnsupported},
		{"uncertain", func(j *backupDrainJob) { j.Unsettled = true; j.LeaseUntil.Valid = false }, BackupDrainSourceUnsupported},
		{"static-terminal", func(j *backupDrainJob) { j.Status = "failed"; j.LeaseUntil.Valid = false }, BackupDrainSourceUnsupported},
	} {
		t.Run(item.name, func(t *testing.T) {
			job := base
			item.change(&job)
			if got := backupDrainClassify(job, d); got != item.want {
				t.Fatal("legacy routing does not match the exact supported terminal contract", got)
			}
		})
	}
}
