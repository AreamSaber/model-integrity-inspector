package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"gorm.io/gorm"
)

var (
	ErrBackupDrainSource      = errors.New("MI_BACKUP_DRAIN_SOURCE_INVALID")
	ErrBackupDrainUnsupported = errors.New("MI_BACKUP_DRAIN_RECONCILIATION_REQUIRED")
	ErrBackupDrainStale       = errors.New("MI_BACKUP_DRAIN_SOURCE_STALE")
)

// BackupDrainKind is a closed classification, not permission to dispatch or settle.
type BackupDrainKind string

const (
	BackupDrainPauseSafe            BackupDrainKind = "pause_safe"
	BackupDrainTerminalRequired     BackupDrainKind = "terminal_required"
	BackupDrainExecutionRequired    BackupDrainKind = "execution_required"
	BackupDrainPrecheckRequired     BackupDrainKind = "precheck_required"
	BackupDrainAnalysisRequired     BackupDrainKind = "analysis_required"
	BackupDrainReportRequired       BackupDrainKind = "report_required"
	BackupDrainNotificationRequired BackupDrainKind = "notification_required"
	BackupDrainSourceUnsupported    BackupDrainKind = "source_unsupported"
)

// BackupDrainObservation is a bounded live observation, never snapshot/ready authority.
// CandidatePresent is independent of a SKIP LOCKED selection returning no source.
type BackupDrainObservation struct {
	ObservedAtMicros                                              int64
	RunningJobPresent, ExpiredJobPresent, UnsettledAttemptPresent bool
	CandidatePresent, UnsupportedSourcePresent                    bool
}

type BackupDrainPauseResult struct{ Applied bool }

// Every field is private and metadata-only. No body, locator, raw SQL, queue
// consumer, JobLease, arbitrary callback or cryptographic authority is retained.
type BackupDrainSource struct {
	store                   *Store
	operationID, generation int64
	owner                   string
	kind                    BackupDrainKind
	job                     backupDrainJob
	domain                  backupDrainDomain
}

func (s *BackupDrainSource) Kind() BackupDrainKind {
	if s == nil {
		return BackupDrainSourceUnsupported
	}
	switch s.kind {
	case BackupDrainPauseSafe, BackupDrainTerminalRequired, BackupDrainExecutionRequired, BackupDrainPrecheckRequired, BackupDrainAnalysisRequired, BackupDrainReportRequired, BackupDrainNotificationRequired, BackupDrainSourceUnsupported:
		return s.kind
	default:
		return BackupDrainSourceUnsupported
	}
}
func (BackupDrainSource) String() string               { return "[private backup drain source]" }
func (s BackupDrainSource) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
func (s BackupDrainSource) LogValue() slog.Value       { return slog.StringValue(s.String()) }
func (BackupDrainSource) MarshalJSON() ([]byte, error) { return nil, ErrBackupDrainSource }
func (*BackupDrainSource) UnmarshalJSON([]byte) error  { return ErrBackupDrainSource }
func (BackupDrainSource) MarshalYAML() (any, error)    { return nil, ErrBackupDrainSource }

// Raw timestamp projections preserve NULL and the stored SQLite representation.
// PostgreSQL casts its native timestamps on this transaction's connection. None
// of these strings is interpreted as a new timestamp or exposed in diagnostics.
type backupDrainJob struct {
	ID, OrganizationID, ObjectID, Priority, AttemptCount, MaxAttempts     int64
	Type, IdempotencyKey, Status                                          string
	AvailableAt, CreatedAt, UpdatedAt                                     string
	LeaseOwner, LeaseUntil, LastErrorCode, CancelRequestedAt, CompletedAt sql.NullString
	Expired, Inactive, Unsettled, UnsettledLegacy, PrecheckRequested      bool
}

// Only fixed identifiers, counters, states and NULL-preserving timestamp metadata.
// The source is not a commitment to an unread frozen JSON/body and cannot settle it.
type backupDrainDomain struct {
	ID, OrganizationID, RunID, JobID, ParentID, Version  int64
	Count, Bytes, ReservedTokens, ReservedCost, Revision int64
	State, SourceVersion                                 string
	Started, Completed, Cancelled                        sql.NullString
	Commitment                                           sql.NullString
	Safe, Legacy, Published                              bool
}

func backupDrainError(err error) error {
	for _, known := range []error{ErrBackupDrainSource, ErrBackupDrainUnsupported, ErrBackupDrainStale, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, known) {
			return known
		}
	}
	return managementError(err)
}

// backupDrainTransaction neither renews the lease nor grants a consumer. A
// normal Renew of the same operation is allowed: state.Version is not a binding.
func (lease *MaintenanceLease) backupDrainTransaction(ctx context.Context, fn func(*gorm.DB, time.Time, maintenanceOperation) error) error {
	if !lease.valid() || ctx == nil || fn == nil {
		return ErrMaintenanceLeaseLost
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	s := lease.store
	err := s.maintenanceTransaction(ctx, func(db *gorm.DB) error {
		state, err := s.lockMaintenance(db, true)
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
		if !lease.matches(state, now) {
			return ErrMaintenanceLeaseLost
		}
		op, err := s.loadMaintenanceOperation(db, state)
		if err != nil {
			return err
		}
		if err := fn(db, now, op); err != nil {
			return err
		}
		return s.finishMaintenanceAuthority(db, session, state.LeaseUntilMicros)
	})
	// Inner persistence helpers deliberately redact driver errors. At this new
	// entry point the coordinator's own cancellation/deadline is still known;
	// preserve it without exposing the wrapped SQL diagnostic. Never reinterpret
	// a successfully committed operation merely because cancellation arrived late.
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return backupDrainError(err)
}
