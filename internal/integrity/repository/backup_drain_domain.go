package repository

import (
	"errors"
	"strconv"
	"strings"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

type backupDrainDomainSQL struct {
	from, where             string
	integers                map[string]string
	texts                   map[string]string
	times                   map[string]string
	safe, legacy, published string
}

// These fixed projections never read request_plan/config_snapshot/source_json,
// outbox content, storage paths, response data or credential values. Query joins
// include both organizations and original object identities, not just row IDs.
func backupDrainDomainProjection(job backupDrainJob) (backupDrainDomainSQL, error) {
	q := backupDrainDomainSQL{integers: map[string]string{}, texts: map[string]string{}, times: map[string]string{}, safe: "FALSE", legacy: "FALSE", published: "FALSE"}
	switch JobType(job.Type) {
	case JobRunPlan, JobRunAnalyze:
		q.from = "integrity_runs r JOIN integrity_targets t ON t.organization_id=r.organization_id AND t.id=r.target_id"
		q.where = "r.organization_id=? AND r.id=?"
		q.integers = map[string]string{"id": "r.id", "organization_id": "r.organization_id", "run_id": "r.id", "job_id": "COALESCE(r.plan_job_id,0)", "parent_id": "r.target_id", "version": "r.version", "count": "r.request_count", "reserved_tokens": "r.reserved_tokens", "reserved_cost": "r.reserved_cost_micros"}
		q.texts = map[string]string{"state": "r.status", "source_version": "r.analysis_source_version"}
		q.times = map[string]string{"started": "r.started_at", "completed": "r.execution_closed_at", "cancelled": "r.cancel_requested_at"}
		if JobType(job.Type) == JobRunPlan {
			q.where += " AND (r.plan_job_id IS NULL OR r.plan_job_id=" + strconv.FormatInt(job.ID, 10) + ")"
			q.legacy = "r.plan_job_id IS NULL"
			q.safe = "r.status='QUEUED' AND r.plan_job_id IS NOT NULL AND r.started_at IS NULL AND r.execution_closed_at IS NULL AND r.cancel_requested_at IS NULL AND r.request_count=0 AND r.reserved_tokens=0 AND r.reserved_cost_micros=0"
		} else {
			q.published = "EXISTS(SELECT 1 FROM integrity_run_results v WHERE v.organization_id=r.organization_id AND v.run_id=r.id AND v.is_published=TRUE)"
			q.safe = "r.status='ANALYZING' AND r.execution_closed_at IS NOT NULL AND r.cancel_requested_at IS NULL AND r.reserved_tokens=0 AND r.reserved_cost_micros=0 AND NOT (" + q.published + ")"
		}
	case JobSampleExecute:
		q.from = "integrity_logical_samples s JOIN integrity_runs r ON r.organization_id=s.organization_id AND r.id=s.run_id JOIN integrity_probe_instances p ON p.organization_id=s.organization_id AND p.run_id=s.run_id AND p.id=s.probe_instance_id JOIN integrity_targets t ON t.organization_id=r.organization_id AND t.id=r.target_id"
		q.where = "s.organization_id=? AND s.id=?"
		q.integers = map[string]string{"id": "s.id", "organization_id": "s.organization_id", "run_id": "s.run_id", "job_id": "COALESCE(s.job_id,0)", "parent_id": "s.probe_instance_id", "version": "r.version", "count": "s.attempt_count", "reserved_tokens": "r.reserved_tokens", "reserved_cost": "r.reserved_cost_micros"}
		q.texts = map[string]string{"state": "r.status", "source_version": "r.analysis_source_version"}
		q.times = map[string]string{"started": "r.started_at", "completed": "s.completed_at", "cancelled": "r.cancel_requested_at"}
		q.legacy = "s.job_id IS NULL"
		q.safe = "s.job_id=" + strconv.FormatInt(job.ID, 10) + " AND s.completed_at IS NULL AND s.final_attempt_id IS NULL AND s.completion_sequence IS NULL AND r.status='RUNNING' AND r.execution_closed_at IS NULL AND r.cancel_requested_at IS NULL AND r.circuit_breaker_code='' AND NOT EXISTS(SELECT 1 FROM integrity_sample_attempts a WHERE a.organization_id=s.organization_id AND a.logical_sample_id=s.id AND a.status='DISPATCHED')"
	case JobReportGenerate:
		q.from = "integrity_reports p JOIN integrity_runs r ON r.organization_id=p.organization_id AND r.id=p.run_id JOIN integrity_run_results v ON v.organization_id=p.organization_id AND v.run_id=p.run_id AND v.analysis_revision=p.analysis_revision"
		q.where = "p.organization_id=? AND p.id=? AND (p.job_id IS NULL OR p.job_id=" + strconv.FormatInt(job.ID, 10) + ")"
		q.integers = map[string]string{"id": "p.id", "organization_id": "p.organization_id", "run_id": "p.run_id", "job_id": "COALESCE(p.job_id,0)", "parent_id": "COALESCE(p.created_by,0)", "version": "p.revision", "revision": "p.analysis_revision"}
		q.texts = map[string]string{"state": "p.status", "source_version": "p.schema_version"}
		q.times = map[string]string{"started": "p.frozen_at", "completed": "p.completed_at", "commitment": "p.source_hash"}
		q.legacy = "p.job_id IS NULL OR p.created_by IS NULL"
		q.safe = "p.job_id IS NOT NULL AND p.created_by IS NOT NULL AND p.status IN ('queued','generating') AND p.completed_at IS NULL AND p.file_hash IS NULL AND p.file_size IS NULL AND p.storage_path IS NULL"
	case JobTargetPrecheck:
		q.from = "integrity_target_prechecks p JOIN integrity_targets t ON t.organization_id=p.organization_id AND t.id=p.target_id"
		q.where = "p.organization_id=? AND p.id=? AND (p.job_id IS NULL OR p.job_id=" + strconv.FormatInt(job.ID, 10) + ")"
		q.integers = map[string]string{"id": "p.id", "organization_id": "p.organization_id", "job_id": "COALESCE(p.job_id,0)", "parent_id": "p.target_id", "version": "p.version", "count": "p.request_count"}
		q.texts = map[string]string{"state": "p.status"}
		q.times = map[string]string{"started": "p.started_at", "completed": "p.finished_at"}
		q.legacy = "p.job_id IS NULL"
		q.safe = "p.job_id IS NOT NULL AND p.status IN ('queued','running') AND p.finished_at IS NULL AND p.request_count=0"
	case JobRetentionDelete:
		if job.ObjectID == job.OrganizationID {
			return q, ErrBackupDrainUnsupported
		}
		q.from = "integrity_response_retention_batches b JOIN integrity_runs r ON r.organization_id=b.organization_id AND r.id=b.run_id AND r.created_by=b.created_by"
		q.where = "b.organization_id=? AND b.id=? AND b.job_id=" + strconv.FormatInt(job.ID, 10)
		q.integers = map[string]string{"id": "b.id", "organization_id": "b.organization_id", "run_id": "b.run_id", "job_id": "COALESCE(b.job_id,0)", "parent_id": "b.created_by", "count": "b.deleted_rows", "bytes": "b.deleted_bytes", "version": "b.policy_version", "revision": "b.observed_at_micros"}
		q.texts = map[string]string{"state": "b.state"}
		q.times = map[string]string{"started": "b.created_at", "completed": "b.completed_at", "commitment": "b.receipt_hash"}
		q.safe = "b.state='planned' AND b.completed_at IS NULL AND b.deleted_rows=0 AND b.deleted_bytes=0 AND b.receipt_hash='' AND b.run_id>0 AND b.created_by>0"
	case JobNotificationSend:
		q.from = "integrity_outbox o"
		q.where = "o.organization_id=? AND o.id=?"
		q.integers = map[string]string{"id": "o.id", "organization_id": "o.organization_id", "parent_id": "o.object_id"}
		q.texts = map[string]string{"state": "o.status"}
		q.times = map[string]string{"started": "o.created_at", "completed": "o.delivered_at"}
	default:
		return q, ErrBackupDrainSource
	}
	return q, nil
}

func backupDrainReadDomain(db *gorm.DB, job backupDrainJob) (backupDrainDomain, error) {
	q, err := backupDrainDomainProjection(job)
	if errors.Is(err, ErrBackupDrainUnsupported) {
		return backupDrainDomain{ID: job.ObjectID, OrganizationID: job.OrganizationID, Legacy: true}, nil
	}
	if err != nil {
		return backupDrainDomain{}, err
	}
	columns, checks := []string{}, []string{}
	// Fixed ordering, independent of Go map iteration, also makes actual query
	// traces stable. These maps contain only the finite code-owned projections.
	for _, name := range []string{"id", "organization_id", "run_id", "job_id", "parent_id", "version", "count", "bytes", "reserved_tokens", "reserved_cost", "revision"} {
		if field, ok := q.integers[name]; ok {
			minimum := int64(0)
			if name == "id" || name == "organization_id" {
				minimum = 1
			}
			checks = append(checks, backupDrainInteger(db, field, minimum))
			columns = append(columns, field+" AS "+name)
		}
	}
	for _, name := range []string{"state", "source_version"} {
		if field, ok := q.texts[name]; ok {
			checks = append(checks, backupDrainText(db, field, 128, false))
			columns = append(columns, field+" AS "+name)
		}
	}
	for _, name := range []string{"started", "completed", "cancelled", "commitment"} {
		if field, ok := q.times[name]; ok {
			maximum := 128
			if name == "commitment" {
				maximum = 64
			}
			checks = append(checks, backupDrainText(db, field, maximum, true))
			columns = append(columns, "CAST("+field+" AS TEXT) AS "+name)
		}
	}
	columns = append(columns, "("+q.safe+") AS safe", "("+q.legacy+") AS legacy", "("+q.published+") AS published")
	query := "SELECT " + strings.Join(columns, ",") + " FROM " + q.from + " WHERE " + q.where + " AND " + strings.Join(checks, " AND ") + " LIMIT 2"
	var rows []backupDrainDomain
	if err := db.Raw(query, job.OrganizationID, job.ObjectID).Scan(&rows).Error; err != nil {
		return backupDrainDomain{}, err
	}
	if len(rows) != 1 {
		return backupDrainDomain{}, ErrBackupDrainSource
	}
	d := rows[0]
	if JobType(job.Type) == JobRunAnalyze && job.IdempotencyKey != "analyze:"+strconv.FormatInt(job.ObjectID, 10)+":1" {
		d.Safe = false
	}
	if JobType(job.Type) == JobReportGenerate && job.IdempotencyKey != "report:"+strconv.FormatInt(job.ObjectID, 10) {
		d.Safe = false
	}
	if JobType(job.Type) == JobRetentionDelete && job.IdempotencyKey != "response-retention:"+strconv.FormatInt(job.ObjectID, 10) {
		d.Safe = false
	}
	if JobType(job.Type) == JobRunPlan || JobType(job.Type) == JobSampleExecute || JobType(job.Type) == JobRunAnalyze {
		if d.SourceVersion != AnalysisSourceLegacyV1 && d.SourceVersion != domain.AnalysisSourceDerivedV1 {
			d.Safe = false
		}
	}
	return d, nil
}
