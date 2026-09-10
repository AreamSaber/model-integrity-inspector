package repository

import (
	"context"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

// workerAuditContext is called only AFTER a Job row has been locked under the
// consumer/lease fence (or selected by terminal recovery). The actor attributes
// deferred work to its persisted initiator; it does not impersonate a current
// login, grant control authority, or bypass execution/secret/cancellation checks.
// Caller-provided actor, reason, IP and user agent are always discarded.
func workerAuditContext(ctx context.Context, db *gorm.DB, job Job) (context.Context, error) {
	if job.ID <= 0 || job.OrganizationID <= 0 || job.ObjectID <= 0 {
		return nil, ErrJobInvalid
	}
	var creator int64
	var reason string
	var query *gorm.DB
	switch JobType(job.Type) {
	case JobTargetPrecheck:
		query = db.Table("integrity_target_prechecks").Select("created_by").Where("organization_id = ? AND id = ? AND job_id = ?", job.OrganizationID, job.ObjectID, job.ID)
		reason = "worker.target.precheck"
	case JobRunPlan:
		query = db.Table("integrity_runs").Select("created_by").Where("organization_id = ? AND id = ? AND plan_job_id = ?", job.OrganizationID, job.ObjectID, job.ID)
		reason = "worker.run.plan"
	case JobSampleExecute:
		query = db.Table("integrity_logical_samples AS s").Select("r.created_by").Joins("JOIN integrity_runs r ON r.organization_id = s.organization_id AND r.id = s.run_id").Where("s.organization_id = ? AND s.id = ? AND s.job_id = ?", job.OrganizationID, job.ObjectID, job.ID)
		reason = "worker.sample.execute"
	case JobRunAnalyze:
		query = db.Table("integrity_runs").Select("created_by").Where("organization_id = ? AND id = ?", job.OrganizationID, job.ObjectID)
		reason = "worker.run.analyze"
	case JobReportGenerate:
		query = db.Table("integrity_reports").Select("created_by").Where("organization_id = ? AND id = ? AND job_id = ?", job.OrganizationID, job.ObjectID, job.ID)
		reason = "worker.report.generate"
	case JobRetentionDelete:
		if job.ObjectID != job.OrganizationID {
			batch, err := retentionJobBatch(db, job)
			if err != nil {
				return nil, err
			}
			return audit.WithActor(ctx, audit.Actor{ActorID: batch.CreatedBy, ReasonCode: "response.evidence.automatic_expiry"}), nil
		}
		if err := validateJobObject(db, job.OrganizationID, JobType(job.Type), job.ObjectID); err != nil {
			return nil, err
		}
		return audit.WithActor(ctx, audit.Actor{}), nil
	case JobNotificationSend:
		// Queue-only operations (including dependency enqueue) remain usable.
		// No audited business capability exists for these handlers yet. An invalid
		// empty Actor shadows any caller Actor, so appendAudit fails closed.
		if err := validateJobObject(db, job.OrganizationID, JobType(job.Type), job.ObjectID); err != nil {
			return nil, err
		}
		return audit.WithActor(ctx, audit.Actor{}), nil
	default:
		return nil, ErrJobInvalid
	}
	result := query.Scan(&creator)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected != 1 || creator <= 0 {
		return nil, ErrJobInvalid
	}
	var count int64
	if err := db.Model(&User{}).Where("id = ?", creator).Count(&count).Error; err != nil {
		return nil, err
	}
	// A disabled/departed initiator is still the historical actor. Requiring a
	// live membership here would prevent safe cancellation/uncertain recovery.
	if count != 1 {
		return nil, ErrJobInvalid
	}
	return audit.WithActor(ctx, audit.Actor{ActorID: creator, ReasonCode: reason}), nil
}

func (q *JobQueue) leasedAuditContext(ctx context.Context, db *gorm.DB, lease JobLease) (context.Context, error) {
	var job Job
	result := db.Where("organization_id = ? AND id = ?", lease.Job.OrganizationID, lease.Job.ID).Find(&job)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected != 1 || job.Type != lease.Job.Type || job.ObjectID != lease.Job.ObjectID {
		return nil, ErrJobLeaseLost
	}
	return workerAuditContext(ctx, db, job)
}
