package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestBackupDrainPurePrivateProjectionAndClosedErrors(t *testing.T) {
	source := BackupDrainSource{owner: "private-owner-canary", job: backupDrainJob{IdempotencyKey: "private-job-canary", LeaseOwner: sql.NullString{String: "private-lease-canary", Valid: true}}}
	for _, value := range []any{source, &source} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(format, value), "canary") {
				t.Fatal("private source formatted")
			}
		}
		if encoded, err := json.Marshal(value); err == nil || len(encoded) != 0 {
			t.Fatal("private source serialized")
		}
	}
	if source.LogValue().String() != "[private backup drain source]" {
		t.Fatal("private log projection changed")
	}
	if value, err := source.MarshalYAML(); err == nil || value != nil {
		t.Fatal("YAML exposed source")
	}
	if (&BackupDrainSource{}).Kind() != BackupDrainSourceUnsupported || (*BackupDrainSource)(nil).Kind() != BackupDrainSourceUnsupported {
		t.Fatal("zero source invented a kind")
	}
	for _, known := range []error{ErrBackupDrainSource, ErrBackupDrainUnsupported, ErrBackupDrainStale, ErrMaintenanceLeaseLost, ErrManagementPermission, ErrManagementSession, context.Canceled, context.DeadlineExceeded} {
		if got := backupDrainError(fmt.Errorf("private-error-canary: %w", known)); !errors.Is(got, known) || got.Error() != known.Error() || strings.Contains(got.Error(), "canary") {
			t.Fatal("wrapped error not projected to closed error")
		}
	}
	if got := backupDrainError(errors.New("private-error-canary")); !errors.Is(got, ErrUnavailable) || got.Error() != ErrUnavailable.Error() {
		t.Fatal("unexpected error was not closed")
	}
	if backupDrainError(nil) != nil {
		t.Fatal("nil error changed")
	}
}

func TestBackupDrainPureClassificationNeverMakesUncertaintySafe(t *testing.T) {
	job := backupDrainJob{Type: string(JobSampleExecute), Status: "running", Expired: true, AttemptCount: 1, MaxAttempts: 3, LeaseUntil: sql.NullString{String: "old", Valid: true}, LeaseOwner: sql.NullString{String: "owner", Valid: true}}
	domain := backupDrainDomain{Safe: true}
	if backupDrainClassify(job, domain) != BackupDrainPauseSafe {
		t.Fatal("safe classification")
	}
	for _, item := range []struct {
		job    func(*backupDrainJob)
		domain func(*backupDrainDomain)
		want   BackupDrainKind
	}{
		{job: func(j *backupDrainJob) { j.Unsettled = true }, want: BackupDrainExecutionRequired},
		{job: func(j *backupDrainJob) { j.Status = "pending"; j.Unsettled = true }, want: BackupDrainExecutionRequired},
		{job: func(j *backupDrainJob) { j.PrecheckRequested = true }, want: BackupDrainPrecheckRequired},
		{job: func(j *backupDrainJob) { j.CancelRequestedAt.Valid = true }, want: BackupDrainTerminalRequired},
		{job: func(j *backupDrainJob) { j.LeaseUntil.Valid = false }, want: BackupDrainTerminalRequired},
		{job: func(j *backupDrainJob) { j.Inactive = true }, want: BackupDrainTerminalRequired},
		{job: func(j *backupDrainJob) { j.AttemptCount = j.MaxAttempts }, want: BackupDrainTerminalRequired},
		{job: func(j *backupDrainJob) { j.Type = string(JobNotificationSend) }, want: BackupDrainNotificationRequired},
		{job: func(j *backupDrainJob) { j.Expired = false }, want: BackupDrainSourceUnsupported},
		{job: func(j *backupDrainJob) { j.AttemptCount = 0 }, want: BackupDrainSourceUnsupported},
		{domain: func(d *backupDrainDomain) { d.Legacy = true }, want: BackupDrainSourceUnsupported},
		{domain: func(d *backupDrainDomain) { d.Safe = false }, want: BackupDrainSourceUnsupported},
	} {
		j, d := job, domain
		if item.job != nil {
			item.job(&j)
		}
		if item.domain != nil {
			item.domain(&d)
		}
		if got := backupDrainClassify(j, d); got != item.want {
			t.Fatal("closed classification mismatch", got, item.want)
		}
	}
}
