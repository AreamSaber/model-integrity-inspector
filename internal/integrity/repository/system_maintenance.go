package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

const MaintenanceLeaseDuration = 60 * time.Second
const maxMaintenanceDuration = 24 * time.Hour

// This is infrastructure input, never directly decoded from an HTTP request.
type BackupMaintenanceRequest struct {
	ExpectedVersion int64
	ReasonCode      string
	MaxDuration     time.Duration
}

// MaintenanceLease is an opaque coordinator capability. There is deliberately
// no ready, download, restore activation, or public owner/generation setter.
type MaintenanceLease struct {
	store                   *Store
	operationID, generation int64
	owner                   string
	auth                    ManagementAuthority
}

func (MaintenanceLease) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (*MaintenanceLease) UnmarshalJSON([]byte) error  { return ErrConfiguration }
func (MaintenanceLease) String() string               { return "[private maintenance lease]" }
func (v MaintenanceLease) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }

type MaintenanceStateView struct {
	Mode                MaintenanceMode
	Version, Generation int64
}

// ReadMaintenanceState is infrastructure metadata, not a user-authorized HTTP
// endpoint. Missing/corrupt state never silently becomes normal.
func (s *Store) ReadMaintenanceState(ctx context.Context) (MaintenanceStateView, error) {
	if ctx == nil {
		return MaintenanceStateView{}, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var row maintenanceState
	// Read a consistent snapshot: a concurrent transition must not combine its
	// new event with the preceding singleton (or vice versa). No write is made.
	err := reportSnapshotTransaction(ctx, s, func(db *gorm.DB) error {
		if err := db.Where("id=1").Take(&row).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrMaintenanceSource
			}
			return err
		}
		return s.authenticateMaintenanceState(db, row)
	})
	if err != nil {
		return MaintenanceStateView{}, persistenceError(err)
	}
	return MaintenanceStateView{row.Mode, row.Version, row.Generation}, nil
}

func (s *Store) authorizeMaintenance(ctx context.Context, db *gorm.DB, auth ManagementAuthority) (Session, error) {
	if auth.UserID <= 0 || auth.SessionID <= 0 {
		return Session{}, ErrManagementSession
	}
	actor, err := audit.ActorFromContext(ctx)
	if err != nil || actor.ActorID != auth.UserID {
		return Session{}, audit.ErrActorRequired
	}
	if s.driver == "postgres" {
		if err := db.Exec("SELECT pg_advisory_xact_lock(?)", migrationLockID+100).Error; err != nil {
			return Session{}, err
		}
	}
	lock := func(q *gorm.DB) *gorm.DB {
		if s.driver == "postgres" {
			return q.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		return q
	}
	var user User
	if err := lock(db.Where("id=?", auth.UserID)).Take(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return Session{}, ErrManagementSession
		}
		return Session{}, err
	}
	var session Session
	if err := lock(db.Where("id=? AND user_id=?", auth.SessionID, auth.UserID)).Take(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return Session{}, ErrManagementSession
		}
		return Session{}, err
	}
	now, err := queueTime(db, s.driver)
	if err != nil {
		return Session{}, err
	}
	if user.Status != "active" || session.RevokedAt != nil || !session.ExpiresAt.After(now) || session.CreatedAt.Before(user.PasswordChangedAt) {
		return Session{}, ErrManagementSession
	}
	if user.MustChangePassword {
		return Session{}, ErrPasswordChangeRequired
	}
	if !user.IsSystemAdmin {
		return Session{}, ErrManagementPermission
	}
	return session, nil
}

func validBackupMaintenanceRequest(request BackupMaintenanceRequest) bool {
	return request.ExpectedVersion > 0 && request.ExpectedVersion < math.MaxInt64 && validMaintenanceReason(request.ReasonCode) && request.MaxDuration >= MaintenanceLeaseDuration && request.MaxDuration <= maxMaintenanceDuration
}

func (s *Store) BeginBackupMaintenance(ctx context.Context, auth ManagementAuthority, request BackupMaintenanceRequest) (*MaintenanceLease, error) {
	return s.beginBackupMaintenance(ctx, auth, request, false)
}

// TakeOverExpiredBackup does not unfreeze or declare the old owner stopped. It
// fences its late writes by advancing generation while keeping admission closed.
func (s *Store) TakeOverExpiredBackup(ctx context.Context, auth ManagementAuthority, request BackupMaintenanceRequest) (*MaintenanceLease, error) {
	return s.beginBackupMaintenance(ctx, auth, request, true)
}

func (s *Store) beginBackupMaintenance(ctx context.Context, auth ManagementAuthority, request BackupMaintenanceRequest, takeover bool) (*MaintenanceLease, error) {
	if ctx == nil || !validBackupMaintenanceRequest(request) {
		return nil, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := s.auditReady(ctx); err != nil {
		return nil, err
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, ErrUnavailable
	}
	owner := hex.EncodeToString(token[:])
	id, err := NewID()
	if err != nil {
		return nil, err
	}
	var result *MaintenanceLease
	err = s.maintenanceTransaction(ctx, func(db *gorm.DB) error {
		before, err := s.lockMaintenance(db, true)
		if err != nil {
			return err
		}
		session, err := s.authorizeMaintenance(ctx, db, auth)
		if err != nil {
			return err
		}
		now, err := queueTime(db, s.driver)
		if err != nil {
			return err
		}
		if before.Version != request.ExpectedVersion || before.Generation == math.MaxInt64 {
			return ErrConflict
		}
		if before.Mode == MaintenanceRestoreIsolated {
			return ErrRestoreIsolated
		}
		if !takeover && before.Mode != MaintenanceNormal {
			return ErrSystemMaintenance
		}
		if takeover && (before.Mode != MaintenanceBackupFreeze || before.LeaseUntilMicros > now.UnixMicro()) {
			return ErrMaintenanceLeaseLost
		}
		after := maintenanceState{ID: 1, Version: before.Version + 1, Mode: MaintenanceBackupFreeze, Generation: before.Generation + 1, OperationID: &id, Owner: owner, LeaseUntilMicros: now.Add(MaintenanceLeaseDuration).UnixMicro(), DeadlineMicros: now.Add(request.MaxDuration).UnixMicro(), UpdatedAtMicros: now.UnixMicro()}
		if takeover {
			old, err := s.loadMaintenanceOperation(db, before)
			if err != nil {
				return err
			}
			if err := s.transitionMaintenanceOperation(db, before, after, &old, auth, "supersede", "superseded", now); err != nil {
				return err
			}
		}
		op := maintenanceOperation{ID: id, Scope: "system", Mode: MaintenanceBackupFreeze, Generation: after.Generation, Owner: owner, InitiatedBy: auth.UserID, SessionID: auth.SessionID, ReasonCode: request.ReasonCode, Status: "active", CreatedAtMicros: now.UnixMicro(), UpdatedAtMicros: now.UnixMicro(), LeaseUntilMicros: after.LeaseUntilMicros, DeadlineMicros: after.DeadlineMicros, EventSequence: 1}
		event := makeMaintenanceEvent(before, after, op, auth, "begin", "none", now)
		op.EventDigest, err = maintenanceEventDigest(event)
		if err != nil {
			return err
		}
		if err := db.Create(&op).Error; err != nil {
			return err
		}
		if err := s.appendMaintenanceEvent(db, &event); err != nil {
			return err
		}
		if err := s.writeMaintenanceState(db, before, after); err != nil {
			return err
		}
		if err := s.finishMaintenanceAuthority(db, session, after.LeaseUntilMicros); err != nil {
			return err
		}
		result = &MaintenanceLease{store: s, operationID: id, generation: after.Generation, owner: owner, auth: auth}
		return nil
	})
	if err != nil {
		return nil, managementError(err)
	}
	return result, nil
}

func (s *Store) finishMaintenanceAuthority(db *gorm.DB, session Session, leaseUntil int64) error {
	now, err := queueTime(db, s.driver)
	if err != nil {
		return err
	}
	if !session.ExpiresAt.After(now) {
		return ErrManagementSession
	}
	if now.UnixMicro() >= leaseUntil {
		return ErrMaintenanceLeaseLost
	}
	return nil
}

func (s *Store) loadMaintenanceOperation(db *gorm.DB, state maintenanceState) (maintenanceOperation, error) {
	if state.Mode != MaintenanceBackupFreeze {
		return maintenanceOperation{}, ErrMaintenanceSource
	}
	return s.authenticatedMaintenanceOperation(db, state)
}

func (s *Store) authenticatedMaintenanceOperation(db *gorm.DB, state maintenanceState) (maintenanceOperation, error) {
	var op maintenanceOperation
	if state.OperationID == nil {
		return op, ErrMaintenanceSource
	}
	if err := db.Where("id=?", *state.OperationID).Take(&op).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return op, ErrMaintenanceSource
		}
		return op, err
	}
	if op.Generation != state.Generation {
		return op, ErrMaintenanceSource
	}
	switch state.Mode {
	case MaintenanceBackupFreeze:
		if op.Status != "active" || op.Owner != state.Owner || op.LeaseUntilMicros != state.LeaseUntilMicros || op.DeadlineMicros != state.DeadlineMicros {
			return op, ErrMaintenanceSource
		}
	case MaintenanceNormal:
		if op.Status != "aborted" {
			return op, ErrMaintenanceSource
		}
	default:
		return op, ErrMaintenanceSource
	}
	event, err := s.verifyMaintenanceOperation(db, op)
	if err != nil {
		return op, err
	}
	if event.OperationID != *state.OperationID || event.AfterMode != state.Mode || event.AfterVersion != state.Version || event.AfterGeneration != state.Generation || event.ObservedAtMicros != state.UpdatedAtMicros {
		return op, ErrMaintenanceSource
	}
	return op, nil
}

func (s *Store) writeMaintenanceState(db *gorm.DB, before, after maintenanceState) error {
	if !validMaintenanceState(after) {
		return ErrMaintenanceSource
	}
	changed := db.Model(&maintenanceState{}).Where("id=1 AND version=? AND generation=? AND mode=?", before.Version, before.Generation, before.Mode).Updates(map[string]any{"version": after.Version, "mode": after.Mode, "generation": after.Generation, "operation_id": after.OperationID, "owner": after.Owner, "lease_until_micros": after.LeaseUntilMicros, "deadline_micros": after.DeadlineMicros, "updated_at_micros": after.UpdatedAtMicros})
	if changed.Error != nil {
		return changed.Error
	}
	if changed.RowsAffected != 1 {
		return ErrMaintenanceLeaseLost
	}
	return nil
}

func makeMaintenanceEvent(before, after maintenanceState, op maintenanceOperation, auth ManagementAuthority, action, previous string, now time.Time) maintenanceEvent {
	return maintenanceEvent{OperationID: op.ID, Sequence: op.EventSequence, Scope: "system", Action: action, ActorID: auth.UserID, SessionID: auth.SessionID, ReasonCode: op.ReasonCode, BeforeMode: before.Mode, AfterMode: after.Mode, BeforeVersion: before.Version, AfterVersion: after.Version, BeforeGeneration: before.Generation, AfterGeneration: after.Generation, Generation: op.Generation, InitiatedBy: op.InitiatedBy, InitiatingSessionID: op.SessionID, PreviousStatus: previous, Status: op.Status, ObservedAtMicros: now.UnixMicro(), LeaseUntilMicros: op.LeaseUntilMicros, DeadlineMicros: op.DeadlineMicros}
}

func (s *Store) transitionMaintenanceOperation(db *gorm.DB, before, after maintenanceState, op *maintenanceOperation, auth ManagementAuthority, action, status string, now time.Time) error {
	if op.EventSequence == math.MaxInt64 {
		return ErrMaintenanceSource
	}
	previous := op.Status
	op.Status, op.UpdatedAtMicros, op.EventSequence = status, now.UnixMicro(), op.EventSequence+1
	if action == "renew" {
		op.LeaseUntilMicros = after.LeaseUntilMicros
	}
	event := makeMaintenanceEvent(before, after, *op, auth, action, previous, now)
	digest, err := maintenanceEventDigest(event)
	if err != nil {
		return err
	}
	op.EventDigest = digest
	changed := db.Model(&maintenanceOperation{}).Where("id=? AND generation=? AND owner=? AND status='active' AND event_sequence=?", op.ID, op.Generation, op.Owner, op.EventSequence-1).Updates(map[string]any{"status": op.Status, "updated_at_micros": op.UpdatedAtMicros, "lease_until_micros": op.LeaseUntilMicros, "event_sequence": op.EventSequence, "event_digest": op.EventDigest})
	if changed.Error != nil {
		return changed.Error
	}
	if changed.RowsAffected != 1 {
		return ErrMaintenanceLeaseLost
	}
	return s.appendMaintenanceEvent(db, &event)
}
