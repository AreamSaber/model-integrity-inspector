package repository

import (
	"errors"
	"regexp"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var maintenanceOwnerPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func validMaintenanceReason(reason string) bool {
	return reason == "backup.manual" || reason == "backup.upgrade" || reason == "backup.recovery"
}

var (
	ErrSystemMaintenance    = errors.New("MI_SYSTEM_MAINTENANCE")
	ErrRestoreIsolated      = errors.New("MI_RESTORE_ISOLATED")
	ErrMaintenanceLeaseLost = errors.New("MI_MAINTENANCE_LEASE_LOST")
	ErrMaintenanceSource    = errors.New("MI_MAINTENANCE_STATE_INVALID")
	ErrBackupNotDrained     = errors.New("MI_BACKUP_NOT_DRAINED")
)

type MaintenanceMode string

const (
	MaintenanceNormal          MaintenanceMode = "normal"
	MaintenanceBackupFreeze    MaintenanceMode = "backup_freeze"
	MaintenanceRestoreIsolated MaintenanceMode = "restore_isolated"
)

// These purposes are private, fixed at typed transaction entry points, and
// cannot be supplied through a request, public boolean or context value.
type maintenancePurpose uint8

const (
	maintenanceBusiness maintenancePurpose = iota
	maintenanceReadAudit
	maintenanceCancel
	maintenanceSettlement
	maintenanceRecovery
	maintenanceScheduled
)

type maintenanceState struct {
	ID               int
	Version          int64
	Mode             MaintenanceMode
	Generation       int64
	OperationID      *int64
	Owner            string
	LeaseUntilMicros int64
	DeadlineMicros   int64
	UpdatedAtMicros  int64
}

func (maintenanceState) TableName() string { return "system_maintenance" }

func validMaintenanceState(row maintenanceState) bool {
	if row.ID != 1 || row.Version < 1 || row.Generation < 0 || row.UpdatedAtMicros < 0 {
		return false
	}
	switch row.Mode {
	case MaintenanceNormal:
		if row.Owner != "" || row.LeaseUntilMicros != 0 || row.DeadlineMicros != 0 {
			return false
		}
		if row.OperationID == nil {
			return row.Version == 1 && row.Generation == 0 && row.UpdatedAtMicros == 0
		}
		return *row.OperationID > 0 && row.Version > 1 && row.Generation > 0 && row.UpdatedAtMicros > 0
	case MaintenanceBackupFreeze:
		return row.OperationID != nil && *row.OperationID > 0 && row.Generation > 0 && maintenanceOwnerPattern.MatchString(row.Owner) && row.LeaseUntilMicros > 0 && row.DeadlineMicros > 0 && row.LeaseUntilMicros <= row.DeadlineMicros
	case MaintenanceRestoreIsolated:
		// A restored copy never acquires a time-based right to open. The later
		// offline restore coordinator must establish provenance before activation.
		return row.Owner == "" && row.LeaseUntilMicros == 0 && row.DeadlineMicros == 0
	default:
		return false
	}
}

// lockMaintenance is always the FIRST lock in a participating transaction.
// SHARE gates admission without serializing ordinary PostgreSQL writers. A
// transition takes UPDATE, then the existing management/user/session locks.
// SQLite retains the Store's BEGIN IMMEDIATE policy across processes.
func (s *Store) lockMaintenance(db *gorm.DB, exclusive bool) (maintenanceState, error) {
	query := db.Where("id = 1")
	if s.driver == "postgres" {
		strength := "SHARE"
		if exclusive {
			strength = "UPDATE"
		}
		query = query.Clauses(clause.Locking{Strength: strength})
	}
	var row maintenanceState
	if err := query.Take(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return row, ErrMaintenanceSource
		}
		return row, err
	}
	return row, s.authenticateMaintenanceState(db, row)
}

// The normal state retains its last authenticated operation. Resetting only
// the singleton, or pointing it at an older valid operation, must not reopen
// admission while newer history remains. These indexed LIMIT 1 reads do not
// claim to detect rollback of the entire database and its audit history.
func (s *Store) authenticateMaintenanceState(db *gorm.DB, row maintenanceState) error {
	if !validMaintenanceState(row) {
		return ErrMaintenanceSource
	}
	if row.Mode == MaintenanceRestoreIsolated {
		// Isolation grants no creation, Claim, snapshot, or activation authority.
		// Its provenance belongs to the not-yet-implemented offline coordinator.
		return nil
	}
	var latest []int64
	if err := db.Model(&maintenanceOperation{}).Select("generation").Order("generation DESC").Limit(1).Find(&latest).Error; err != nil {
		return err
	}
	if row.OperationID == nil {
		if len(latest) != 0 {
			return ErrMaintenanceSource
		}
		return nil
	}
	if len(latest) != 1 || latest[0] != row.Generation {
		return ErrMaintenanceSource
	}
	_, err := s.authenticatedMaintenanceOperation(db, row)
	return err
}

// maintenanceAdmission holds its gate through commit. A false admission is a
// normal pause only for autonomous background discovery/reconciliation; all
// direct business callers receive a fixed, non-success maintenance error.
func (s *Store) maintenanceAdmission(db *gorm.DB, purpose maintenancePurpose) (bool, error) {
	row, err := s.lockMaintenance(db, false)
	if err != nil {
		return false, err
	}
	if purpose > maintenanceScheduled {
		return false, ErrMaintenanceSource
	}
	if row.Mode == MaintenanceNormal {
		return true, nil
	}
	if purpose == maintenanceReadAudit || purpose == maintenanceSettlement {
		return true, nil
	}
	if row.Mode == MaintenanceBackupFreeze {
		if purpose == maintenanceCancel || purpose == maintenanceRecovery {
			return true, nil
		}
		if purpose == maintenanceScheduled {
			return false, nil
		}
		return false, ErrSystemMaintenance
	}
	if purpose == maintenanceRecovery || purpose == maintenanceScheduled {
		return false, nil
	}
	return false, ErrRestoreIsolated
}

func maintenanceKnownError(err error) error {
	for _, known := range []error{ErrSystemMaintenance, ErrRestoreIsolated, ErrMaintenanceLeaseLost, ErrMaintenanceSource, ErrBackupNotDrained} {
		if errors.Is(err, known) {
			return known
		}
	}
	return nil
}
