package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
)

const snapshotAuditOrganizationPage = 100

var (
	errSnapshotAuditNotInitialized = errors.New("SNAPSHOT_AUDIT_NOT_INITIALIZED")
	errSnapshotAuditLimit          = errors.New("SNAPSHOT_AUDIT_LIMIT")
	errSnapshotAuditSegments       = errors.New("SNAPSHOT_AUDIT_SEGMENTS_UNSUPPORTED")
)

// This owned set authenticates the complete organization/audit relationship in
// ONE snapshot. It is not the rest of the backup inventory, a maintenance or
// authorization receipt, schema certification, or an external rollback anchor.
type snapshotAuditInventory struct{ anchors []auditSnapshotAnchor }

func (snapshotAuditInventory) String() string { return "[private snapshot audit inventory]" }
func (v snapshotAuditInventory) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, v.String())
}
func (v snapshotAuditInventory) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (snapshotAuditInventory) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (snapshotAuditInventory) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

// The trusted caller continuously owns the actual RO transaction and its
// connection. SQLite MUST have its native physical RO flag checked with Raw
// before BeginTx, exactly as required by verifyAuditSnapshot. query_only is not
// proof of that open mode. This method never begins/ends a transaction or locks
// audit heads, and never returns a partial result on any failure.
func (s *Store) snapshotAuditInventory(ctx context.Context, tx *gorm.DB) (snapshotAuditInventory, error) {
	return s.snapshotAuditInventoryLimited(ctx, tx, backupmanifest.MaxOrganizations)
}

// The private limit may only tighten the fixed production cap; the production
// entry above never accepts caller configuration for this resource policy.
func (s *Store) snapshotAuditInventoryLimited(ctx context.Context, tx *gorm.DB, limit int) (snapshotAuditInventory, error) {
	if ctx == nil || s == nil || tx == nil || tx.Config == nil || tx.Error != nil || tx.Statement == nil ||
		tx.Dialector == nil || tx.Name() != s.driver || limit < 1 || limit > backupmanifest.MaxOrganizations {
		return snapshotAuditInventory{}, ErrConfiguration
	}
	if ctx.Err() != nil {
		return snapshotAuditInventory{}, ErrUnavailable
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return snapshotAuditInventory{}, ErrConfiguration
	}
	if actual, ok := tx.Statement.ConnPool.(*sql.Tx); !ok || actual == nil {
		return snapshotAuditInventory{}, ErrConfiguration
	}
	if s.auditSigner == nil {
		return snapshotAuditInventory{}, audit.ErrUnavailable
	}
	read := tx.Session(&gorm.Session{NewDB: true, Context: ctx})
	if err := auditSnapshotTransaction(read, s.driver); err != nil {
		return snapshotAuditInventory{}, err
	}
	if err := snapshotAuditInitialization(read); err != nil {
		return snapshotAuditInventory{}, err
	}
	// Each query returns one scalar, never materializes arbitrary orphan rows.
	// Include nonpositive IDs BEFORE using a positive cursor, or those records
	// would silently disappear from the inventory even after offline corruption.
	var invalid bool
	if err := read.Raw(`SELECT
EXISTS(SELECT 1 FROM organizations WHERE id IS NULL OR id<=0) OR
EXISTS(SELECT 1 FROM integrity_audit_chain_heads h WHERE h.organization_id IS NULL OR h.organization_id<=0 OR NOT EXISTS(SELECT 1 FROM organizations o WHERE o.id=h.organization_id)) OR
EXISTS(SELECT 1 FROM integrity_audit_logs e WHERE e.organization_id IS NULL OR e.organization_id<=0 OR NOT EXISTS(SELECT 1 FROM organizations o WHERE o.id=e.organization_id))`).Scan(&invalid).Error; err != nil {
		return snapshotAuditInventory{}, persistenceError(err)
	}
	if invalid {
		return snapshotAuditInventory{}, audit.ErrIntegrity
	}
	var segments bool
	if err := read.Raw("SELECT EXISTS(SELECT 1 FROM integrity_audit_segments)").Scan(&segments).Error; err != nil {
		return snapshotAuditInventory{}, persistenceError(err)
	}
	if segments {
		return snapshotAuditInventory{}, errSnapshotAuditSegments
	}
	result := snapshotAuditInventory{anchors: make([]auditSnapshotAnchor, 0, min(limit, snapshotAuditOrganizationPage))}
	var after int64
	for {
		if ctx.Err() != nil {
			return snapshotAuditInventory{}, ErrUnavailable
		}
		var ids []int64
		if err := read.Table("organizations").Where("id > ?", after).Order("id").Limit(snapshotAuditOrganizationPage).Pluck("id", &ids).Error; err != nil {
			return snapshotAuditInventory{}, persistenceError(err)
		}
		if len(ids) > limit-len(result.anchors) {
			return snapshotAuditInventory{}, errSnapshotAuditLimit
		}
		for _, id := range ids {
			if id <= after {
				return snapshotAuditInventory{}, audit.ErrIntegrity
			}
			anchor, err := s.verifyAuditSnapshot(ctx, read, id)
			if err != nil {
				return snapshotAuditInventory{}, err
			}
			result.anchors = append(result.anchors, anchor)
			after = id
		}
		if len(ids) < snapshotAuditOrganizationPage {
			break
		}
	}
	if len(result.anchors) == 0 {
		return snapshotAuditInventory{}, audit.ErrIntegrity
	}
	if ctx.Err() != nil {
		return snapshotAuditInventory{}, ErrUnavailable
	}
	return result, nil
}

// Backup eligibility is stricter than the public SetupStatus presence check:
// Initialize writes both canonical values in its atomic initialization commit.
// Missing marker is explicitly not initialized (even if other rows exist), not
// an empty successful manifest. This does not certify users/roles/other tables
// or replace maintenance admission and real authorization in the coordinator.
func snapshotAuditInitialization(tx *gorm.DB) error {
	marker, present, err := snapshotAuditSetting(tx, "initialized", 4)
	if err != nil {
		return err
	}
	if !present {
		return errSnapshotAuditNotInitialized
	}
	if marker != "true" {
		return audit.ErrIntegrity
	}
	value, present, err := snapshotAuditSetting(tx, "initial_organization_id", 19)
	if err != nil {
		return err
	}
	id, parseErr := strconv.ParseInt(value, 10, 64)
	if !present || parseErr != nil || id <= 0 || strconv.FormatInt(id, 10) != value {
		return audit.ErrIntegrity
	}
	var exists bool
	if err := tx.Raw("SELECT EXISTS(SELECT 1 FROM organizations WHERE id=?)", id).Scan(&exists).Error; err != nil {
		return persistenceError(err)
	}
	if !exists {
		return audit.ErrIntegrity
	}
	return nil
}

func snapshotAuditSetting(tx *gorm.DB, key string, maxBytes int) (string, bool, error) {
	var values []string
	if err := tx.Table("system_settings").Select(readBoundedText(tx, "value_json", "value_json", maxBytes)).Where("setting_key=?", key).Limit(2).Scan(&values).Error; err != nil {
		return "", false, persistenceError(err)
	}
	if len(values) > 1 {
		return "", false, audit.ErrIntegrity
	}
	if len(values) == 0 {
		return "", false, nil
	}
	return values[0], true, nil
}
