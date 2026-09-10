package repository

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type BackupOperationStatus string

const (
	BackupOperationActive     BackupOperationStatus = "active"
	BackupOperationAborted    BackupOperationStatus = "aborted"
	BackupOperationSuperseded BackupOperationStatus = "superseded"
	BackupOperationCompleted  BackupOperationStatus = "completed"
)

// BackupOperationView is safe infrastructure metadata, not an HTTP DTO or a
// download capability. Completed authenticates the durable DB receipt only;
// a download must separately reauthorize and authenticate the physical file.
// It deliberately excludes actors/sessions, owner, object ID, paths and keys.
type BackupOperationView struct {
	ID                                                                 int64
	Status                                                             BackupOperationStatus
	ReasonCode                                                         string
	CreatedAtMicros, UpdatedAtMicros, LeaseUntilMicros, DeadlineMicros int64
	Version                                                            int64  // the original authenticated operation event sequence
	ManifestVersion                                                    string // only populated for an authenticated completed receipt
}

func (BackupOperationView) String() string               { return "[backup operation state]" }
func (v BackupOperationView) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (v BackupOperationView) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (BackupOperationView) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (*BackupOperationView) UnmarshalJSON([]byte) error  { return ErrConfiguration }
func (BackupOperationView) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

// BeforeID is an exclusive descending-ID keyset cursor, never authority or SQL.
// Zero starts a new page; there are no free-form filters, SQL or cursor strings.
type BackupOperationListRequest struct {
	BeforeID int64
	Limit    int
}

type BackupOperationPage struct {
	Items        []BackupOperationView
	NextBeforeID int64
}

func (BackupOperationPage) String() string               { return "[backup operation page]" }
func (v BackupOperationPage) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (v BackupOperationPage) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (BackupOperationPage) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (*BackupOperationPage) UnmarshalJSON([]byte) error  { return ErrConfiguration }
func (BackupOperationPage) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

func validBackupOperationListRequest(request BackupOperationListRequest) bool {
	return request.BeforeID >= 0 && request.Limit >= 1 && request.Limit <= 100
}

// The authenticated singleton is always locked first, then the actual system
// administrator/user/session locks in authorizeMaintenance. An expired active
// lease remains active; it is never promoted to a ready or completed backup.
func (s *Store) readBackupOperations(ctx context.Context, auth ManagementAuthority, read func(*gorm.DB, maintenanceState) error) error {
	if s == nil || s.db == nil || s.sql == nil || ctx == nil || read == nil || (s.driver != "sqlite" && s.driver != "postgres") {
		return ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := s.maintenanceTransaction(ctx, func(db *gorm.DB) error {
		state, err := s.lockMaintenance(db, false)
		if err != nil {
			return err
		}
		if state.Mode == MaintenanceRestoreIsolated {
			return ErrRestoreIsolated
		}
		session, err := s.authorizeMaintenance(ctx, db, auth)
		if err != nil {
			return err
		}
		if err := read(db, state); err != nil {
			return err
		}
		// Session locks prevent revocation/password/admin changes while reading;
		// the final database clock also prevents natural expiry during the page.
		return s.finishMaintenanceAuthority(db, session, math.MaxInt64)
	})
	return managementError(err)
}

func (s *Store) ReadBackupOperation(ctx context.Context, auth ManagementAuthority, backupID int64) (BackupOperationView, error) {
	if backupID <= 0 {
		return BackupOperationView{}, ErrConfiguration
	}
	var out BackupOperationView
	err := s.readBackupOperations(ctx, auth, func(db *gorm.DB, state maintenanceState) error {
		var rows []maintenanceOperation
		if err := backupOperationReadQuery(db).Where("id=?", backupID).Limit(2).Find(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return ErrNotFound
		}
		if len(rows) != 1 || rows[0].ID != backupID {
			return ErrMaintenanceSource
		}
		var err error
		out, err = s.backupOperationView(db, state, rows[0])
		return err
	})
	if err != nil {
		return BackupOperationView{}, err
	}
	return out, nil
}

func (s *Store) ListBackupOperations(ctx context.Context, auth ManagementAuthority, request BackupOperationListRequest) (BackupOperationPage, error) {
	if !validBackupOperationListRequest(request) {
		return BackupOperationPage{}, ErrConfiguration
	}
	var out BackupOperationPage
	err := s.readBackupOperations(ctx, auth, func(db *gorm.DB, state maintenanceState) error {
		query := backupOperationReadQuery(db)
		if request.BeforeID > 0 {
			query = query.Where("id<?", request.BeforeID)
		}
		var rows []maintenanceOperation
		if err := query.Order("id DESC").Limit(request.Limit + 1).Find(&rows).Error; err != nil {
			return err
		}
		if len(rows) > request.Limit+1 {
			return ErrMaintenanceSource
		}
		out.Items = make([]BackupOperationView, 0, min(len(rows), request.Limit))
		var previous int64
		for i, row := range rows {
			if row.ID <= 0 || request.BeforeID > 0 && row.ID >= request.BeforeID || i > 0 && row.ID >= previous {
				return ErrMaintenanceSource
			}
			view, err := s.backupOperationView(db, state, row)
			if err != nil {
				return err
			}
			// The lookahead is authenticated as well. A corrupt final item must
			// not return a successful prefix or an unverified continuation.
			if i < request.Limit {
				out.Items = append(out.Items, view)
			}
			previous = row.ID
		}
		if len(rows) > request.Limit {
			out.NextBeforeID = out.Items[len(out.Items)-1].ID
		}
		return nil
	})
	if err != nil {
		return BackupOperationPage{}, err
	}
	return out, nil
}

func backupOperationReadQuery(db *gorm.DB) *gorm.DB {
	columns := "id,generation,initiated_by,session_id,created_at_micros,updated_at_micros,lease_until_micros,deadline_micros,event_sequence"
	for _, field := range []struct {
		name  string
		limit int
	}{{"scope", 16}, {"mode", 32}, {"owner", 64}, {"reason_code", 128}, {"status", 32}, {"event_digest", 64}} {
		columns += "," + readBoundedText(db, field.name, field.name, field.limit)
	}
	query := db.Model(&maintenanceOperation{}).Select(columns)
	if db.Name() == "postgres" {
		query = query.Clauses(clause.Locking{Strength: "SHARE"})
	}
	return query
}

func (s *Store) backupOperationView(db *gorm.DB, state maintenanceState, op maintenanceOperation) (BackupOperationView, error) {
	zero := BackupOperationView{}
	switch BackupOperationStatus(op.Status) {
	case BackupOperationActive, BackupOperationAborted, BackupOperationSuperseded, BackupOperationCompleted:
	default:
		return zero, ErrMaintenanceSource
	}
	event, err := s.verifyMaintenanceOperation(db, op)
	if err != nil {
		return zero, err
	}
	if op.Generation > state.Generation || event.AfterGeneration > state.Generation || event.AfterVersion > state.Version {
		return zero, ErrMaintenanceSource
	}
	if op.Status == string(BackupOperationActive) {
		if state.Mode != MaintenanceBackupFreeze || state.OperationID == nil || *state.OperationID != op.ID || state.Generation != op.Generation || state.Owner != op.Owner || state.LeaseUntilMicros != op.LeaseUntilMicros || state.DeadlineMicros != op.DeadlineMicros {
			return zero, ErrMaintenanceSource
		}
	}
	out := BackupOperationView{ID: op.ID, Status: BackupOperationStatus(op.Status), ReasonCode: op.ReasonCode, CreatedAtMicros: op.CreatedAtMicros, UpdatedAtMicros: op.UpdatedAtMicros, LeaseUntilMicros: op.LeaseUntilMicros, DeadlineMicros: op.DeadlineMicros, Version: op.EventSequence}
	if op.Status == string(BackupOperationCompleted) {
		receipt, err := s.loadBackupCompletion(db, op)
		if err != nil {
			return zero, err
		}
		if receipt.Digest != event.CompletionDigest {
			return zero, ErrMaintenanceSource
		}
		out.ManifestVersion = receipt.ManifestVersion
	}
	return out, nil
}
