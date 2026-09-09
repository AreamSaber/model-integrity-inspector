package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

// This private anchor is obtained only after authenticating one explicit
// organization's complete chain. It is not a full inventory, authorization,
// backup admission receipt, or independently retained anti-rollback anchor.
type auditSnapshotAnchor struct {
	organizationID          int64
	eventCount              int64
	endHash                 string
	keyVersion              string
	canonicalizationVersion string
}

func (auditSnapshotAnchor) String() string               { return "[private audit snapshot anchor]" }
func (a auditSnapshotAnchor) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, a.String()) }
func (a auditSnapshotAnchor) LogValue() slog.Value       { return slog.StringValue(a.String()) }
func (auditSnapshotAnchor) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (auditSnapshotAnchor) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

// verifyAuditSnapshot uses ONLY the supplied, caller-owned transaction. It
// neither opens/closes a transaction nor takes the public reader's PG SHARE
// head lock (which is prohibited in a genuine read-only transaction).
//
// This is a trusted repository-internal contract, not a privilege boundary.
// For SQLite the coordinator MUST continuously own one dedicated sql.Conn,
// verify native IsReadOnly("main") on that connection using Conn.Raw BEFORE
// starting this exact transaction, and keep it exclusive. sql.Tx has no Raw;
// query_only below is an additional check, NOT proof of an OS read-only open.
// TxOptions.ReadOnly alone does not make the pinned SQLite driver read-only.
// PostgreSQL must actually be READ ONLY and REPEATABLE READ or SERIALIZABLE.
// A live deadline is required for the potentially many bounded event pages.
// The caller retains commit/rollback and all inventory/maintenance duties.
func (s *Store) verifyAuditSnapshot(ctx context.Context, tx *gorm.DB, orgID int64) (auditSnapshotAnchor, error) {
	if ctx == nil || s == nil || tx == nil || tx.Error != nil || tx.Statement == nil ||
		tx.Dialector == nil || tx.Name() != s.driver {
		return auditSnapshotAnchor{}, ErrConfiguration
	}
	if ctx.Err() != nil {
		return auditSnapshotAnchor{}, ErrUnavailable
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return auditSnapshotAnchor{}, ErrConfiguration
	}
	if orgID <= 0 {
		return auditSnapshotAnchor{}, ErrOrganizationScope
	}
	if s.auditSigner == nil {
		return auditSnapshotAnchor{}, audit.ErrUnavailable
	}
	// Current repository adapters use database/sql transactions. Reject a naked
	// pool/connection rather than quietly issuing each page in a new read view.
	if actual, ok := tx.Statement.ConnPool.(*sql.Tx); !ok || actual == nil {
		return auditSnapshotAnchor{}, ErrConfiguration
	}
	// Clear unrelated caller query clauses without changing the actual ConnPool.
	read := tx.Session(&gorm.Session{NewDB: true, Context: ctx})
	if err := auditSnapshotTransaction(read, s.driver); err != nil {
		return auditSnapshotAnchor{}, err
	}
	var head auditChainHead
	if err := read.Select(auditHeadReadColumns(read)).Where("organization_id = ?", orgID).First(&head).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return auditSnapshotAnchor{}, audit.ErrIntegrity
		}
		return auditSnapshotAnchor{}, persistenceError(err)
	}
	if _, err := s.verifyAuditFull(read, head); err != nil {
		return auditSnapshotAnchor{}, persistenceError(err)
	}
	if ctx.Err() != nil {
		return auditSnapshotAnchor{}, ErrUnavailable
	}
	// audit.Verify accepts only this canonicalization contract; no version is
	// inferred from a mutable caller field or invented for an unsupported event.
	// For an empty chain it denotes the supported verification protocol, not an
	// observed event. Preserve the head key accepted by the existing algorithm.
	return auditSnapshotAnchor{organizationID: head.OrganizationID, eventCount: head.EventCount,
		endHash: head.EventHash, keyVersion: head.KeyVersion,
		canonicalizationVersion: audit.CanonicalizationVersion}, nil
}

func auditSnapshotTransaction(tx *gorm.DB, driver string) error {
	switch driver {
	case "sqlite":
		var queryOnly int
		if err := tx.Raw("PRAGMA query_only").Scan(&queryOnly).Error; err != nil {
			return persistenceError(err)
		}
		if queryOnly != 1 {
			return ErrConfiguration
		}
	case "postgres":
		var valid bool
		if err := tx.Raw("SELECT current_setting('transaction_read_only')='on' AND current_setting('transaction_isolation') IN ('repeatable read','serializable')").Scan(&valid).Error; err != nil {
			return persistenceError(err)
		}
		if !valid {
			return ErrConfiguration
		}
	default:
		return ErrConfiguration
	}
	return nil
}
