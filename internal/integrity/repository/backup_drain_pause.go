package repository

import (
	"context"
	"errors"
	"strconv"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

// PauseBackupDrainCandidate only pauses proven-safe expired work. It never
// settles an Attempt, projects a terminal domain state, or marks a backup ready.
func (lease *MaintenanceLease) PauseBackupDrainCandidate(ctx context.Context, source *BackupDrainSource) (BackupDrainPauseResult, error) {
	if !lease.valid() || source == nil || source.store != lease.store || source.operationID != lease.operationID || source.generation != lease.generation || source.owner != lease.owner {
		return BackupDrainPauseResult{}, ErrBackupDrainSource
	}
	if source.kind != BackupDrainPauseSafe {
		return BackupDrainPauseResult{}, ErrBackupDrainUnsupported
	}
	err := lease.backupDrainTransaction(ctx, func(db *gorm.DB, now time.Time, op maintenanceOperation) error {
		// Revalidate both the entire original Job metadata and the actual domain.
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
		d, err := backupDrainReadDomain(db, job)
		if err != nil {
			return err
		}
		if d != source.domain || backupDrainClassify(job, d) != BackupDrainPauseSafe {
			return ErrBackupDrainStale
		}
		changed := db.Model(&Job{}).Where("organization_id=? AND id=? AND status='running' AND attempt_count=? AND lease_until<=?", job.OrganizationID, job.ID, job.AttemptCount, now).
			Updates(map[string]any{"status": "pending", "lease_owner": nil, "lease_until": nil, "updated_at": now})
		if changed.Error != nil {
			return changed.Error
		}
		if changed.RowsAffected != 1 {
			return ErrBackupDrainStale
		}
		return backupDrainPauseAudit(lease, db, op, job)
	})
	if err != nil {
		return BackupDrainPauseResult{}, err
	}
	return BackupDrainPauseResult{Applied: true}, nil
}

func backupDrainPauseAudit(lease *MaintenanceLease, db *gorm.DB, op maintenanceOperation, job backupDrainJob) error {
	anchor, err := initialAuditOrganization(db)
	if err != nil {
		return err
	}
	actor, err := audit.ActorFromContext(db.Statement.Context)
	if err != nil {
		return err
	}
	actor.ReasonCode = op.ReasonCode
	object := strconv.FormatInt(op.ID, 10) + ":" + strconv.FormatInt(op.Generation, 10) + ":" + strconv.FormatInt(job.OrganizationID, 10) + ":" + strconv.FormatInt(job.ID, 10) + ":" + strconv.FormatInt(job.AttemptCount, 10)
	return lease.store.appendAuditWithClock(audit.WithActor(db.Statement.Context, actor), db, anchor, AuditCommand{Action: "system.backup.drain.pause_running", ObjectType: "system_backup_drain", ObjectID: object, Result: "success"}, nil, true)
}
