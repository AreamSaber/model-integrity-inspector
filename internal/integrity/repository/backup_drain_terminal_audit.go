package repository

import (
	"math"
	"slices"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

type backupDrainTerminalHead struct {
	organizationID, finalCount int64
}

// Lock only actual audit participants, sorted before either domain/system audit.
// Pure multi-organization audit writers need not hold the maintenance gate.
func backupDrainTerminalAuditHeads(s *Store, db *gorm.DB, org int64, project bool, now time.Time) ([]backupDrainTerminalHead, int64, error) {
	if err := s.auditReady(db.Statement.Context); err != nil {
		return nil, 0, err
	}
	anchor, err := initialAuditOrganization(db)
	if err != nil {
		return nil, 0, err
	}
	ids := []int64{anchor}
	if project && org != anchor {
		ids = append(ids, org)
	}
	slices.Sort(ids)
	heads := make([]backupDrainTerminalHead, 0, len(ids))
	for _, id := range ids {
		head := auditChainHead{OrganizationID: id, KeyVersion: s.auditSigner.ActiveVersion(), UpdatedAt: now}
		if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&head).Error; err != nil {
			return nil, 0, err
		}
		query := db.Select(auditHeadReadColumns(db)).Where("organization_id=?", id)
		if db.Name() == "postgres" {
			query = query.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := query.First(&head).Error; err != nil {
			return nil, 0, err
		}
		if _, err := s.verifyAuditTail(db, head); err != nil {
			return nil, 0, err
		}
		added := int64(0)
		if id == anchor {
			added++
		}
		if project && id == org {
			added++
		}
		if head.EventCount > math.MaxInt64-added {
			return nil, 0, audit.ErrIntegrity
		}
		heads = append(heads, backupDrainTerminalHead{id, head.EventCount + added})
	}
	return heads, anchor, nil
}

func backupDrainTerminalAudit(lease *MaintenanceLease, db *gorm.DB, op maintenanceOperation, anchor int64, job backupDrainJob, action string) error {
	switch action {
	case "terminalize", "project_terminal", "precheck_uncertain", "notification_uncertain":
	default:
		return ErrBackupDrainSource
	}
	actor, err := audit.ActorFromContext(db.Statement.Context)
	if err != nil {
		return err
	}
	actor.ReasonCode = op.ReasonCode
	return lease.store.appendAuditWithClock(audit.WithActor(db.Statement.Context, actor), db, anchor, AuditCommand{Action: "system.backup.drain." + action, ObjectType: "system_backup_drain", ObjectID: backupDrainTerminalIdentity(op, job), Result: "success"}, nil, true)
}

func backupDrainTerminalVerifyHeads(s *Store, db *gorm.DB, expected []backupDrainTerminalHead) error {
	for _, item := range expected {
		var head auditChainHead
		if err := db.Select(auditHeadReadColumns(db)).Where("organization_id=?", item.organizationID).First(&head).Error; err != nil {
			return err
		}
		if head.EventCount != item.finalCount {
			return audit.ErrIntegrity
		}
		if _, err := s.verifyAuditTail(db, head); err != nil {
			return err
		}
	}
	return nil
}
