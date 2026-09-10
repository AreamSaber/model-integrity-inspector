package repository

import (
	"strconv"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

// Both chains are acquired in ascending organization order, including their
// first-head INSERT. Ordinary direct audit appends need not hold the gate.
func backupDrainExecutionAuditHeads(s *Store, db *gorm.DB, org int64, now time.Time) ([]int64, error) {
	anchor, err := initialAuditOrganization(db)
	if err != nil {
		return nil, err
	}
	ids := []int64{org}
	if anchor < org {
		ids = []int64{anchor, org}
	} else if anchor > org {
		ids = append(ids, anchor)
	}
	for _, id := range ids {
		if s.auditSigner == nil {
			return nil, audit.ErrUnavailable
		}
		head := auditChainHead{OrganizationID: id, KeyVersion: s.auditSigner.ActiveVersion(), UpdatedAt: now}
		if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&head).Error; err != nil {
			return nil, err
		}
		query := db.Select(auditHeadReadColumns(db)).Where("organization_id=?", id)
		if s.driver == "postgres" {
			query = query.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := query.Take(&head).Error; err != nil {
			return nil, err
		}
		if _, err := s.verifyAuditTail(db, head); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

func backupDrainExecutionVerifyHeads(s *Store, db *gorm.DB, ids []int64) error {
	for _, id := range ids {
		var head auditChainHead
		if err := db.Select(auditHeadReadColumns(db)).Where("organization_id=?", id).Take(&head).Error; err != nil {
			return err
		}
		if _, err := s.verifyAuditTail(db, head); err != nil {
			return err
		}
	}
	return nil
}

func backupDrainExecutionAudit(lease *MaintenanceLease, db *gorm.DB, op maintenanceOperation, job Job, action string) error {
	if action != "project_terminal" && action != "terminal_rule" && action != "uncertain" {
		return ErrBackupDrainSource
	}
	anchor, err := initialAuditOrganization(db)
	if err != nil {
		return err
	}
	actor, err := audit.ActorFromContext(db.Statement.Context)
	if err != nil {
		return err
	}
	actor.ReasonCode = op.ReasonCode
	object := strconv.FormatInt(op.ID, 10) + ":" + strconv.FormatInt(op.Generation, 10) + ":" + strconv.FormatInt(job.OrganizationID, 10) + ":" + strconv.FormatInt(job.ID, 10) + ":" + strconv.Itoa(job.AttemptCount)
	return lease.store.appendAuditWithClock(audit.WithActor(db.Statement.Context, actor), db, anchor, AuditCommand{Action: "system.backup.drain.execution." + action, ObjectType: "system_backup_drain", ObjectID: object, Result: "success"}, nil, true)
}
