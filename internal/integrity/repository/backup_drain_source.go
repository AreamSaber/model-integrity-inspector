package repository

import (
	"context"
	"time"

	"gorm.io/gorm"
)

// LoadBackupDrainCandidate observes every blocker class, but reads at most one
// Job's bounded private metadata. It performs no Job/domain/audit mutation.
func (lease *MaintenanceLease) LoadBackupDrainCandidate(ctx context.Context) (*BackupDrainSource, BackupDrainObservation, error) {
	var source *BackupDrainSource
	var observation BackupDrainObservation
	err := lease.backupDrainTransaction(ctx, func(db *gorm.DB, now time.Time, _ maintenanceOperation) error {
		var err error
		observation, err = backupDrainObserve(db, now)
		if err != nil {
			return err
		}
		query := `SELECT j.id FROM integrity_jobs j JOIN organizations o ON o.id=j.organization_id WHERE ` + backupDrainCandidateSQL() + ` ORDER BY j.id LIMIT 1`
		if lease.store.driver == "postgres" {
			query += " FOR UPDATE OF j SKIP LOCKED"
		}
		var ids []int64
		if err := db.Raw(query, now).Scan(&ids).Error; err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		job, err := backupDrainReadJob(db, ids[0], now)
		if err != nil {
			return err
		}
		domain, err := backupDrainReadDomain(db, job)
		if err != nil {
			return err
		}
		source = &BackupDrainSource{store: lease.store, operationID: lease.operationID, generation: lease.generation, owner: lease.owner, job: job, domain: domain, kind: backupDrainClassify(job, domain)}
		return nil
	})
	if err != nil {
		return nil, BackupDrainObservation{}, err
	}
	return source, observation, nil
}

func backupDrainObserve(db *gorm.DB, now time.Time) (BackupDrainObservation, error) {
	var out BackupDrainObservation
	for _, query := range []string{
		// Validate global associations without imposing new textual/timestamp
		// limits on static historical rows which we never materialize. Selected
		// candidates alone must pass the bounded metadata projection below.
		snapshotJobInvalidRows("integrity_jobs j", backupDrainJobStructuralSQL(db)),
		"SELECT EXISTS(SELECT 1 FROM integrity_jobs GROUP BY id HAVING COUNT(*)<>1)",
		backupDrainDispatchedInvalidSQL(db),
		"SELECT EXISTS(SELECT 1 FROM integrity_sample_attempts WHERE status='DISPATCHED' GROUP BY organization_id,logical_sample_id HAVING COUNT(*)<>1)",
	} {
		invalid, err := backupDrainExists(db, query)
		if err != nil {
			return out, err
		}
		if invalid {
			return out, ErrBackupDrainSource
		}
	}
	queries := []struct {
		target *bool
		query  string
		args   []any
	}{
		{&out.RunningJobPresent, "SELECT EXISTS(SELECT 1 FROM integrity_jobs WHERE status='running')", nil},
		{&out.ExpiredJobPresent, "SELECT EXISTS(SELECT 1 FROM integrity_jobs WHERE status='running' AND (lease_until IS NULL OR lease_until<=?))", []any{now}},
		{&out.UnsettledAttemptPresent, "SELECT EXISTS(SELECT 1 FROM integrity_sample_attempts WHERE status='DISPATCHED')", nil},
		{&out.CandidatePresent, "SELECT EXISTS(SELECT 1 FROM integrity_jobs j JOIN organizations o ON o.id=j.organization_id WHERE " + backupDrainCandidateSQL() + ")", []any{now}},
		{&out.UnsupportedSourcePresent, `SELECT EXISTS(SELECT 1 FROM integrity_sample_attempts a WHERE a.status='DISPATCHED' AND (a.job_id IS NULL OR a.run_id IS NULL OR a.lease_generation=0 OR EXISTS(SELECT 1 FROM integrity_jobs j WHERE j.id=a.job_id AND j.status='completed')))`, nil},
	}
	for _, item := range queries {
		value, err := backupDrainExists(db, item.query, item.args...)
		if err != nil {
			return BackupDrainObservation{}, err
		}
		*item.target = value
	}
	out.ObservedAtMicros = now.UnixMicro()
	return out, nil
}

func backupDrainReadJob(db *gorm.DB, id int64, now time.Time) (backupDrainJob, error) {
	var rows []backupDrainJob
	query := `SELECT j.id,j.organization_id,j.object_id,j.priority,j.attempt_count,j.max_attempts,j.type,j.idempotency_key,j.status,
 CAST(j.available_at AS TEXT) AS available_at,CAST(j.created_at AS TEXT) AS created_at,CAST(j.updated_at AS TEXT) AS updated_at,
 j.lease_owner,CAST(j.lease_until AS TEXT) AS lease_until,j.last_error_code,CAST(j.cancel_requested_at AS TEXT) AS cancel_requested_at,CAST(j.completed_at AS TEXT) AS completed_at,
 (j.status='running' AND (j.lease_until IS NULL OR j.lease_until<=?)) AS expired,
 (o.status<>'active' AND NOT (` + retentionDisabledJobSQL + `)) AS inactive,
 (` + backupDrainDispatched + `) AS unsettled,
 EXISTS(SELECT 1 FROM integrity_sample_attempts a WHERE a.job_id=j.id AND a.status='DISPATCHED' AND (a.run_id IS NULL OR a.lease_generation=0)) AS unsettled_legacy,
 (` + backupDrainPrecheckRequested + `) AS precheck_requested
 FROM integrity_jobs j JOIN organizations o ON o.id=j.organization_id WHERE j.id=? AND ` + backupDrainJobValidSQL(db) + ` LIMIT 2`
	if db.Name() == "postgres" {
		query += " FOR UPDATE OF j"
	}
	if err := db.Raw(query, now, id).Scan(&rows).Error; err != nil {
		return backupDrainJob{}, err
	}
	if len(rows) != 1 {
		return backupDrainJob{}, ErrBackupDrainSource
	}
	return rows[0], nil
}

func backupDrainClassify(job backupDrainJob, d backupDrainDomain) BackupDrainKind {
	if d.Legacy || job.UnsettledLegacy {
		return BackupDrainSourceUnsupported
	}
	if job.Unsettled {
		return BackupDrainExecutionRequired
	}
	if job.PrecheckRequested {
		return BackupDrainPrecheckRequired
	}
	if job.Status == "pending" || job.Expired {
		if job.CancelRequestedAt.Valid || job.AttemptCount >= job.MaxAttempts || job.Inactive || (job.Status == "running" && !job.LeaseUntil.Valid) {
			return BackupDrainTerminalRequired
		}
	}
	if job.Type == string(JobNotificationSend) {
		return BackupDrainNotificationRequired
	}
	if job.Status == "failed" || job.Status == "cancelled" {
		switch JobType(job.Type) {
		case JobRunPlan, JobSampleExecute:
			return BackupDrainExecutionRequired
		case JobRunAnalyze:
			return BackupDrainAnalysisRequired
		case JobReportGenerate:
			return BackupDrainReportRequired
		case JobTargetPrecheck:
			return BackupDrainPrecheckRequired
		}
	}
	if job.Status == "running" && job.AttemptCount > 0 && job.Expired && job.LeaseUntil.Valid && job.LeaseOwner.Valid && job.LeaseOwner.String != "" && !job.CompletedAt.Valid && d.Safe {
		return BackupDrainPauseSafe
	}
	return BackupDrainSourceUnsupported
}
