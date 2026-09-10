package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/pgbackup"
)

var (
	errPostgresSnapshotClosed   = errors.New("POSTGRES_SNAPSHOT_CLOSED")
	errPostgresSnapshotCanceled = errors.New("POSTGRES_SNAPSHOT_CANCELED")
)

type postgresSnapshotMetadata struct {
	ServerVersion              int
	TransactionStartedAtMicros int64
}

// postgresSnapshot is private infrastructure, not a backup authorization or
// arbitrary-SQL business API. The trusted coordinator must retain maintenance
// authority and synchronously finish inventory AND pg_dump within use. It must
// not retain the transaction/token or detach a callback. PostgreSQL invalidates
// the export when the owning transaction ends; an imported transaction may
// continue independently and remains the importing coordinator's responsibility.
type postgresSnapshot struct {
	mu       sync.Mutex
	ctx      context.Context
	tx       *gorm.DB
	id       string
	metadata postgresSnapshotMetadata
	active   bool
	failure  error
}

func (*postgresSnapshot) String() string { return "[private PostgreSQL snapshot]" }
func (s *postgresSnapshot) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, s.String())
}
func (*postgresSnapshot) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (*postgresSnapshot) MarshalYAML() (any, error)    { return nil, ErrConfiguration }
func (s *postgresSnapshot) LogValue() slog.Value       { return slog.StringValue(s.String()) }

func (s *postgresSnapshot) use(read func(*gorm.DB, string, postgresSnapshotMetadata) error) error {
	if s == nil {
		return errPostgresSnapshotClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active || s.tx == nil {
		return errPostgresSnapshotClosed
	}
	if s.failure != nil {
		return s.failure
	}
	if read == nil {
		s.failure = ErrConfiguration
	} else if s.ctx.Err() != nil {
		s.failure = errPostgresSnapshotCanceled
	} else {
		s.failure = postgresSnapshotError(s.ctx, read(s.tx, s.id, s.metadata))
	}
	return s.failure
}

// This owns a real RR READ ONLY transaction. No migration, business mutation,
// dump process, schema selection, or publication is performed here. The outer
// caller may publish only after THIS method, including Commit, succeeds.
func (s *Store) withPostgresSnapshot(ctx context.Context, consume func(*postgresSnapshot) error) error {
	if err := validatePostgresSnapshotRequest(ctx, s, consume); err != nil {
		return err
	}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) (finalErr error) {
		remaining, _ := ctx.Deadline()
		milliseconds := max(int64(1), time.Until(remaining).Milliseconds())
		// Transaction-local, finite timeouts complement context cancellation;
		// no persistent connection/database configuration is changed.
		if err := tx.Exec("SELECT pg_catalog.set_config('statement_timeout', ?, true), pg_catalog.set_config('lock_timeout', ?, true)",
			strconv.FormatInt(milliseconds, 10), strconv.FormatInt(milliseconds, 10)).Error; err != nil {
			return err
		}
		var observed struct {
			ReadOnlyRepeatable         bool
			ServerVersion              int
			TransactionStartedAtMicros int64
		}
		if err := tx.Raw(`SELECT
pg_catalog.current_setting('transaction_isolation')='repeatable read' AND pg_catalog.current_setting('transaction_read_only')='on' AS read_only_repeatable,
pg_catalog.current_setting('server_version_num')::integer AS server_version,
(EXTRACT(EPOCH FROM pg_catalog.transaction_timestamp())*1000000)::bigint AS transaction_started_at_micros`).Scan(&observed).Error; err != nil {
			return err
		}
		if !observed.ReadOnlyRepeatable || observed.ServerVersion < 90000 || observed.ServerVersion > 999999 || observed.TransactionStartedAtMicros <= 0 {
			return ErrConfiguration
		}
		var id string
		if err := tx.Raw(`SELECT CASE WHEN octet_length(snapshot_id) BETWEEN 1 AND 128 THEN snapshot_id ELSE '' END
FROM pg_catalog.pg_export_snapshot() AS exported(snapshot_id)`).Scan(&id).Error; err != nil {
			return err
		}
		if !validPostgresSnapshotID(id) {
			return ErrConfiguration
		}
		view := &postgresSnapshot{ctx: ctx, tx: tx, id: id, active: true,
			metadata: postgresSnapshotMetadata{observed.ServerVersion, observed.TransactionStartedAtMicros}}
		defer func() {
			view.mu.Lock()
			defer view.mu.Unlock()
			view.active, view.tx, view.id = false, nil, ""
			view.metadata = postgresSnapshotMetadata{}
			if finalErr == nil {
				finalErr = view.failure
			}
		}()
		return postgresSnapshotError(ctx, consume(view))
	}, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	return postgresSnapshotError(ctx, err)
}

func validatePostgresSnapshotRequest(ctx context.Context, s *Store, consume func(*postgresSnapshot) error) error {
	if ctx == nil || s == nil || s.db == nil || s.sql == nil || s.driver != "postgres" || s.db.Dialector == nil || s.db.Name() != "postgres" || consume == nil {
		return ErrConfiguration
	}
	if ctx.Err() != nil {
		return errPostgresSnapshotCanceled
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > maxMaintenanceDuration {
		return ErrConfiguration
	}
	return nil
}

// Only a bounded server token with three hex groups can reach a future dump
// argument. It is not a URI, path, shell fragment, or user-supplied SQL literal.
func validPostgresSnapshotID(id string) bool {
	if len(id) < 5 || len(id) > 128 {
		return false
	}
	groups := strings.Split(id, "-")
	if len(groups) != 3 {
		return false
	}
	for _, group := range groups {
		if len(group) == 0 {
			return false
		}
		for _, char := range group {
			if (char < '0' || char > '9') && (char < 'A' || char > 'F') && (char < 'a' || char > 'f') {
				return false
			}
		}
	}
	return true
}

func postgresSnapshotError(ctx context.Context, err error) error {
	// Cleanup uncertainty is stronger than ordinary cancellation: callers must
	// not mistake an unconfirmed server session for a successfully stopped dump.
	// Preserve only these exact closed sentinels, never their private wrappers.
	for _, known := range []error{errPostgresDumpIdentity, errPostgresDumpCleanup, errPostgresDumpUnseen} {
		if errors.Is(err, known) {
			return known
		}
	}
	if ctx != nil && ctx.Err() != nil {
		return errPostgresSnapshotCanceled
	}
	for _, known := range []error{errPostgresSnapshotClosed, errPostgresSnapshotCanceled,
		errSnapshotAuditNotInitialized, errSnapshotAuditLimit, errSnapshotAuditSegments,
		ErrSchemaMismatch, errSnapshotMigrationLimit,
		errSnapshotJobSource, errSnapshotJobLimit, errSnapshotJobBusy,
		errSnapshotReportInvalid, errSnapshotReportLimit, errSnapshotReportUnsupported,
		pgbackup.ErrConfiguration, pgbackup.ErrCanceled, pgbackup.ErrProcess,
		pgbackup.ErrOutput, pgbackup.ErrLimit, pgbackup.ErrVersion} {
		if errors.Is(err, known) {
			return known
		}
	}
	return persistenceError(err)
}
