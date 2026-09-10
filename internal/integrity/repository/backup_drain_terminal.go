package repository

import (
	"context"
	"errors"
	"strconv"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type BackupDrainTerminalResult struct{ Applied bool }

// ApplyBackupTerminalCandidate handles only the five non-execution Job types.
// It grants no consumer, dispatch, file or deletion capability. The original
// terminal decision, required domain projection and both audits commit together
// under the current maintenance authority and its final original lease window.
func (lease *MaintenanceLease) ApplyBackupTerminalCandidate(ctx context.Context, source *BackupDrainSource) (BackupDrainTerminalResult, error) {
	if !lease.valid() || source == nil || source.store != lease.store || source.operationID != lease.operationID || source.generation != lease.generation || source.owner != lease.owner {
		return BackupDrainTerminalResult{}, ErrBackupDrainSource
	}
	if !backupDrainTerminalType(source.job.Type) {
		return BackupDrainTerminalResult{}, ErrBackupDrainUnsupported
	}
	err := lease.backupDrainTransaction(ctx, func(db *gorm.DB, now time.Time, op maintenanceOperation) error {
		job, err := backupDrainReadJob(db, source.job.ID, now)
		if errors.Is(err, ErrBackupDrainSource) {
			return ErrBackupDrainStale
		}
		if err != nil {
			return err
		}
		if job != source.job {
			return ErrBackupDrainStale
		}
		if err := backupDrainTerminalLockDomain(db, job); err != nil {
			return err
		}
		d, err := backupDrainReadDomain(db, job)
		if errors.Is(err, ErrBackupDrainSource) {
			return ErrBackupDrainStale
		}
		if err != nil {
			return err
		}
		if d != source.domain || backupDrainClassify(job, d) != source.kind {
			return ErrBackupDrainStale
		}
		decision, err := backupDrainTerminalDecide(job, d)
		if err != nil {
			return err
		}
		heads, anchor, err := backupDrainTerminalAuditHeads(lease.store, db, job.OrganizationID, decision.project, now)
		if err != nil {
			return err
		}
		if decision.changeJob {
			changed := db.Model(&Job{}).Where("organization_id=? AND id=? AND status=? AND attempt_count=?", job.OrganizationID, job.ID, job.Status, job.AttemptCount).
				Updates(map[string]any{"status": decision.status, "last_error_code": decision.code, "lease_owner": nil, "lease_until": nil, "completed_at": now, "updated_at": now})
			if changed.Error != nil {
				return changed.Error
			}
			// The complete original row is already locked/revalidated. A driver
			// suppressing this update is not successful or legitimate no-progress.
			if changed.RowsAffected != 1 {
				return ErrBackupDrainSource
			}
		}
		if decision.project {
			if err := backupDrainTerminalProject(lease.store, db, job, decision, now); err != nil {
				return err
			}
		}
		if err := backupDrainTerminalAudit(lease, db, op, anchor, job, decision.action); err != nil {
			return err
		}
		return backupDrainTerminalVerifyHeads(lease.store, db, heads)
	})
	if err != nil {
		return BackupDrainTerminalResult{}, err
	}
	return BackupDrainTerminalResult{Applied: true}, nil
}

func backupDrainTerminalType(kind string) bool {
	switch JobType(kind) {
	case JobRunAnalyze, JobReportGenerate, JobTargetPrecheck, JobRetentionDelete, JobNotificationSend:
		return true
	default:
		return false
	}
}

func backupDrainTerminalLockDomain(db *gorm.DB, job backupDrainJob) error {
	var table string
	switch JobType(job.Type) {
	case JobRunAnalyze:
		table = "integrity_runs"
	case JobReportGenerate:
		table = "integrity_reports"
	case JobTargetPrecheck:
		table = "integrity_target_prechecks"
	case JobRetentionDelete:
		if job.ObjectID == job.OrganizationID {
			return nil // Original organization sentinel has no fabricated batch.
		}
		table = "integrity_response_retention_batches"
	case JobNotificationSend:
		table = "integrity_outbox"
	default:
		return ErrBackupDrainUnsupported
	}
	var rows []int64
	query := db.Table(table).Select("id").Where("organization_id=? AND id=?", job.OrganizationID, job.ObjectID).Limit(2)
	if db.Name() == "postgres" {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	if err := query.Find(&rows).Error; err != nil {
		return err
	}
	if len(rows) != 1 {
		return ErrBackupDrainStale
	}
	return nil
}

func backupDrainTerminalProject(s *Store, db *gorm.DB, original backupDrainJob, decision backupDrainTerminalDecision, now time.Time) error {
	// The old timestamp strings remain untouched: these narrow cores consume
	// only the exact locked identity and original explicit terminal decision.
	job := Job{ID: original.ID, OrganizationID: original.OrganizationID, ObjectID: original.ObjectID, Type: original.Type, IdempotencyKey: original.IdempotencyKey, Status: decision.status}
	var result domainProjectionResult
	var err error
	switch JobType(original.Type) {
	case JobRunAnalyze:
		result, err = s.reconcileAnalysisDomain(db, job, now)
	case JobReportGenerate:
		result, err = s.reconcileReportDomain(db, job, now)
	case JobTargetPrecheck:
		job.Status = original.Status
		result, err = s.reconcilePrecheckDomain(db, job, decision.status, decision.code, now)
	default:
		return ErrBackupDrainUnsupported
	}
	if errors.Is(err, ErrAnalysisSource) || errors.Is(err, ErrReportInvalid) || errors.Is(err, ErrConflict) {
		return ErrBackupDrainSource
	}
	if err != nil {
		return err
	}
	if result == domainProjectionNone {
		return ErrBackupDrainStale
	}
	if result != domainProjectionApplied {
		return ErrBackupDrainSource
	}
	return nil
}

func backupDrainTerminalIdentity(op maintenanceOperation, job backupDrainJob) string {
	return strconv.FormatInt(op.ID, 10) + ":" + strconv.FormatInt(op.Generation, 10) + ":" + strconv.FormatInt(job.OrganizationID, 10) + ":" + strconv.FormatInt(job.ID, 10) + ":" + strconv.FormatInt(job.AttemptCount, 10)
}
