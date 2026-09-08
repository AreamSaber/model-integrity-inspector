package repository

import (
	"context"
	"math"
	"time"

	"gorm.io/gorm"
)

func (lease *MaintenanceLease) valid() bool {
	return lease != nil && lease.store != nil && lease.operationID > 0 && lease.generation > 0 && maintenanceOwnerPattern.MatchString(lease.owner) && lease.auth.UserID > 0 && lease.auth.SessionID > 0
}

func (lease *MaintenanceLease) matches(row maintenanceState, now time.Time) bool {
	return row.Mode == MaintenanceBackupFreeze && row.OperationID != nil && *row.OperationID == lease.operationID && row.Owner == lease.owner && row.Generation == lease.generation && row.LeaseUntilMicros > now.UnixMicro()
}

func (lease *MaintenanceLease) Renew(ctx context.Context) error { return lease.change(ctx, false) }

// Abort only records an unsuccessful operation and reopens new admission. It
// does not mark work drained, publish a backup, or activate a restored database.
func (lease *MaintenanceLease) Abort(ctx context.Context) error { return lease.change(ctx, true) }

func (lease *MaintenanceLease) change(ctx context.Context, abort bool) error {
	if !lease.valid() || ctx == nil {
		return ErrMaintenanceLeaseLost
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	s := lease.store
	return managementError(s.maintenanceTransaction(ctx, func(db *gorm.DB) error {
		before, err := s.lockMaintenance(db, true)
		if err != nil {
			return err
		}
		session, err := s.authorizeMaintenance(ctx, db, lease.auth)
		if err != nil {
			return err
		}
		now, err := queueTime(db, s.driver)
		if err != nil {
			return err
		}
		if !lease.matches(before, now) || before.Version == math.MaxInt64 {
			return ErrMaintenanceLeaseLost
		}
		op, err := s.loadMaintenanceOperation(db, before)
		if err != nil {
			return err
		}
		after := before
		after.Version++
		after.UpdatedAtMicros = now.UnixMicro()
		action, status := "renew", "active"
		if abort {
			action, status = "abort", "aborted"
			// Preserve the terminal operation pointer as the authenticated source
			// of reopening. A nil pointer is reserved for the genuine initial DB.
			after.Mode, after.Owner, after.LeaseUntilMicros, after.DeadlineMicros = MaintenanceNormal, "", 0, 0
		} else {
			after.LeaseUntilMicros = min(now.Add(MaintenanceLeaseDuration).UnixMicro(), after.DeadlineMicros)
			if after.LeaseUntilMicros <= now.UnixMicro() {
				return ErrMaintenanceLeaseLost
			}
		}
		if err := s.transitionMaintenanceOperation(db, before, after, &op, lease.auth, action, status, now); err != nil {
			return err
		}
		if err := s.writeMaintenanceState(db, before, after); err != nil {
			return err
		}
		// Renewal cannot resurrect an old lease that expired during lock/audit
		// waits; its ORIGINAL authority window is checked immediately before commit.
		return s.finishMaintenanceAuthority(db, session, before.LeaseUntilMicros)
	}))
}

// MaintenanceObservation is a bounded blocker observation, not a snapshot
// permit. This unit deliberately issues NO ready/activation capability. Even an
// expired lease is still a running Job, never proof that upstream I/O stopped.
type MaintenanceObservation struct {
	ObservedAtMicros        int64
	RunningJobPresent       bool
	ExpiredJobPresent       bool
	UnsettledAttemptPresent bool
}

func (lease *MaintenanceLease) Observe(ctx context.Context) (MaintenanceObservation, error) {
	var out MaintenanceObservation
	if !lease.valid() || ctx == nil {
		return out, ErrMaintenanceLeaseLost
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	s := lease.store
	err := s.maintenanceTransaction(ctx, func(db *gorm.DB) error {
		row, err := s.lockMaintenance(db, false)
		if err != nil {
			return err
		}
		session, err := s.authorizeMaintenance(ctx, db, lease.auth)
		if err != nil {
			return err
		}
		now, err := queueTime(db, s.driver)
		if err != nil {
			return err
		}
		if !lease.matches(row, now) {
			return ErrMaintenanceLeaseLost
		}
		if _, err := s.loadMaintenanceOperation(db, row); err != nil {
			return err
		}
		var running, expired, unsettled []int64
		if err := db.Model(&Job{}).Select("id").Where("status='running'").Limit(1).Find(&running).Error; err != nil {
			return err
		}
		if err := db.Model(&Job{}).Select("id").Where("status='running' AND (lease_until IS NULL OR lease_until<=?)", now).Limit(1).Find(&expired).Error; err != nil {
			return err
		}
		if err := db.Model(&AttemptRecord{}).Select("id").Where("status='DISPATCHED'").Limit(1).Find(&unsettled).Error; err != nil {
			return err
		}
		out = MaintenanceObservation{ObservedAtMicros: now.UnixMicro(), RunningJobPresent: len(running) > 0, ExpiredJobPresent: len(expired) > 0, UnsettledAttemptPresent: len(unsettled) > 0}
		return s.finishMaintenanceAuthority(db, session, row.LeaseUntilMicros)
	})
	if err != nil {
		return MaintenanceObservation{}, managementError(err)
	}
	return out, nil
}
