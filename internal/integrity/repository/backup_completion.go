package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
)

// BackupPublication is infrastructure input from the trusted coordinator AFTER
// the complete archive has been privately published, read back and authenticated.
// It is never an HTTP DTO or evidence that a file was actually verified. The
// repository authenticates durable facts, authority and fencing; the coordinator
// remains responsible for the physical snapshot and complete file verification.
// ObjectID is an internally generated opaque 256-bit name, never a path.
type BackupPublication struct {
	BackupID           int64
	SnapshotAtMicros   int64
	ManifestVersion    string
	ManifestSHA256     string
	DatabaseSHA256     string
	ArchiveSHA256      string
	ArchiveBytes       int64
	PlaintextBytes     int64
	Entries            int
	WrappingKeyVersion string
	ObjectID           string
}

// BackupIdentity returns the immutable identity assigned by the committed begin
// transaction. It is metadata for the manifest, not a fresh lease authorization.
func (lease *MaintenanceLease) BackupIdentity() (backupID, startedAtMicros int64) {
	if !lease.valid() || lease.startedAtMicros <= 0 {
		return 0, 0
	}
	return lease.operationID, lease.startedAtMicros
}

func (BackupPublication) String() string               { return "[private backup publication]" }
func (v BackupPublication) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (BackupPublication) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (*BackupPublication) UnmarshalJSON([]byte) error  { return ErrConfiguration }
func (BackupPublication) MarshalYAML() (any, error)    { return nil, ErrConfiguration }
func (v BackupPublication) LogValue() slog.Value       { return slog.StringValue(v.String()) }

// BackupCompletionReceipt contains immutable DB-authenticated facts, not a file
// handle. Download must additionally reauthorize the session and verify the file.
type BackupCompletionReceipt struct {
	BackupPublication   `gorm:"embedded"`
	Generation          int64
	InitiatedBy         int64
	InitiatingSessionID int64
	CompletedBy         int64
	CompletingSessionID int64
	ReasonCode          string
	StartedAtMicros     int64
	CompletedAtMicros   int64
	Digest              string
}

func (BackupCompletionReceipt) TableName() string            { return "system_backup_receipts" }
func (BackupCompletionReceipt) String() string               { return "[private backup completion receipt]" }
func (v BackupCompletionReceipt) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (BackupCompletionReceipt) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (*BackupCompletionReceipt) UnmarshalJSON([]byte) error  { return ErrConfiguration }
func (BackupCompletionReceipt) MarshalYAML() (any, error)    { return nil, ErrConfiguration }
func (v BackupCompletionReceipt) LogValue() slog.Value       { return slog.StringValue(v.String()) }

func validBackupPublication(p BackupPublication) bool {
	return p.BackupID > 0 && p.SnapshotAtMicros > 0 &&
		(p.ManifestVersion == backupmanifest.Version || p.ManifestVersion == backupmanifest.VersionV2 || p.ManifestVersion == backupmanifest.VersionV3) &&
		executionHash.MatchString(p.ManifestSHA256) && executionHash.MatchString(p.DatabaseSHA256) && executionHash.MatchString(p.ArchiveSHA256) &&
		p.ArchiveBytes > p.PlaintextBytes && p.ArchiveBytes <= backupmanifest.MaxFileBytes &&
		p.PlaintextBytes > 0 && p.PlaintextBytes <= backupmanifest.MaxFileBytes && p.Entries >= 3 && p.Entries <= backupmanifest.MaxEntries &&
		responseEvidenceVersion.MatchString(p.WrappingKeyVersion) && maintenanceOwnerPattern.MatchString(p.ObjectID)
}

func backupCompletionDigest(r BackupCompletionReceipt) (string, error) {
	if !validBackupPublication(r.BackupPublication) || r.Generation <= 0 || r.InitiatedBy <= 0 || r.InitiatingSessionID <= 0 || r.CompletedBy <= 0 || r.CompletingSessionID <= 0 || !validMaintenanceReason(r.ReasonCode) || r.StartedAtMicros <= 0 || r.SnapshotAtMicros < r.StartedAtMicros || r.CompletedAtMicros < r.SnapshotAtMicros {
		return "", ErrMaintenanceSource
	}
	// Explicit wire types prevent accidental serialization through the redacted
	// public types, and keep every bound fact independent of future ORM fields.
	type publicationWire struct {
		BackupID, SnapshotAtMicros                                     int64
		ManifestVersion, ManifestSHA256, DatabaseSHA256, ArchiveSHA256 string
		ArchiveBytes, PlaintextBytes                                   int64
		Entries                                                        int
		WrappingKeyVersion, ObjectID                                   string
	}
	canonical := struct {
		Version                                                                        string
		Publication                                                                    publicationWire
		Generation, InitiatedBy, InitiatingSessionID, CompletedBy, CompletingSessionID int64
		ReasonCode                                                                     string
		StartedAtMicros, CompletedAtMicros                                             int64
	}{"mii.backup-completion.v1", publicationWire{r.BackupID, r.SnapshotAtMicros, r.ManifestVersion, r.ManifestSHA256, r.DatabaseSHA256, r.ArchiveSHA256, r.ArchiveBytes, r.PlaintextBytes, r.Entries, r.WrappingKeyVersion, r.ObjectID}, r.Generation, r.InitiatedBy, r.InitiatingSessionID, r.CompletedBy, r.CompletingSessionID, r.ReasonCode, r.StartedAtMicros, r.CompletedAtMicros}
	data, err := json.Marshal(canonical)
	if err != nil || len(data) > 2048 {
		return "", ErrMaintenanceSource
	}
	sum := sha256.Sum256(append([]byte("mii/backup/completion/v1\x00"), data...))
	return hex.EncodeToString(sum[:]), nil
}

// CompleteBackup atomically authenticates the final live authority and lease,
// persists the completion facts, anchors the completion event, and reopens
// admission. No file I/O is performed inside this short transaction. Failed or
// superseded owners never obtain a successful receipt or unfreeze the system.
func (lease *MaintenanceLease) CompleteBackup(ctx context.Context, publication BackupPublication) (BackupCompletionReceipt, error) {
	if !lease.valid() || ctx == nil {
		return BackupCompletionReceipt{}, ErrMaintenanceLeaseLost
	}
	if !validBackupPublication(publication) || publication.BackupID != lease.operationID {
		return BackupCompletionReceipt{}, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	s := lease.store
	if err := s.auditReady(ctx); err != nil {
		return BackupCompletionReceipt{}, err
	}
	var out BackupCompletionReceipt
	err := s.maintenanceTransaction(ctx, func(db *gorm.DB) error {
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
		if op.CreatedAtMicros != lease.startedAtMicros {
			return ErrMaintenanceSource
		}
		// A supplied file receipt cannot authorize publishing a live/in-flight
		// database. This is a final blocker check, not proof of remote I/O exit or
		// a substitute for the same-snapshot job/attempt inventory.
		var running, dispatched []int64
		if err := db.Model(&Job{}).Select("id").Where("status='running'").Limit(1).Find(&running).Error; err != nil {
			return err
		}
		if err := db.Model(&AttemptRecord{}).Select("id").Where("status='DISPATCHED'").Limit(1).Find(&dispatched).Error; err != nil {
			return err
		}
		if len(running) != 0 || len(dispatched) != 0 {
			return ErrBackupNotDrained
		}
		out = BackupCompletionReceipt{BackupPublication: publication, Generation: op.Generation, InitiatedBy: op.InitiatedBy, InitiatingSessionID: op.SessionID, CompletedBy: lease.auth.UserID, CompletingSessionID: lease.auth.SessionID, ReasonCode: op.ReasonCode, StartedAtMicros: op.CreatedAtMicros, CompletedAtMicros: now.UnixMicro()}
		out.Digest, err = backupCompletionDigest(out)
		if err != nil {
			return err
		}
		if err := db.Create(&out).Error; err != nil {
			return err
		}
		after := before
		after.Version++
		after.UpdatedAtMicros = now.UnixMicro()
		after.Mode, after.Owner, after.LeaseUntilMicros, after.DeadlineMicros = MaintenanceNormal, "", 0, 0
		if err := s.transitionMaintenanceOperation(db, before, after, &op, lease.auth, "complete", "completed", now); err != nil {
			return err
		}
		if err := s.writeMaintenanceState(db, before, after); err != nil {
			return err
		}
		return s.finishMaintenanceAuthority(db, session, before.LeaseUntilMicros)
	})
	if err != nil {
		return BackupCompletionReceipt{}, managementError(err)
	}
	return out, nil
}

// ReadBackupCompletion reauthorizes a live system administrator and verifies the
// immutable operation/event/audit binding in a consistent transaction. It never
// trusts a receipt row alone and never grants access by organization membership.
func (s *Store) ReadBackupCompletion(ctx context.Context, auth ManagementAuthority, backupID int64) (BackupCompletionReceipt, error) {
	if ctx == nil || backupID <= 0 {
		return BackupCompletionReceipt{}, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var out BackupCompletionReceipt
	err := s.maintenanceTransaction(ctx, func(db *gorm.DB) error {
		if _, err := s.lockMaintenance(db, false); err != nil {
			return err
		}
		session, err := s.authorizeMaintenance(ctx, db, auth)
		if err != nil {
			return err
		}
		var op maintenanceOperation
		if err := db.Where("id=?", backupID).Take(&op).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if op.Status != "completed" {
			return ErrNotFound
		}
		event, err := s.verifyMaintenanceOperation(db, op)
		if err != nil {
			return err
		}
		out, err = s.loadBackupCompletion(db, op)
		if err != nil {
			return err
		}
		if out.Digest != event.CompletionDigest {
			return ErrMaintenanceSource
		}
		// No maintenance lease is required to read a historical receipt, but the
		// original user session must still be valid at the final clock read.
		return s.finishMaintenanceAuthority(db, session, math.MaxInt64)
	})
	if err != nil {
		return BackupCompletionReceipt{}, managementError(err)
	}
	return out, nil
}

func (s *Store) loadBackupCompletion(db *gorm.DB, op maintenanceOperation) (BackupCompletionReceipt, error) {
	var rows []BackupCompletionReceipt
	columns := "backup_id,snapshot_at_micros,archive_bytes,plaintext_bytes,entries,generation,initiated_by,initiating_session_id,completed_by,completing_session_id,started_at_micros,completed_at_micros"
	for _, field := range []struct {
		name  string
		limit int
	}{{"manifest_version", 128}, {"manifest_sha256", 64}, {"database_sha256", 64}, {"archive_sha256", 64}, {"wrapping_key_version", 128}, {"object_id", 64}, {"reason_code", 128}, {"digest", 64}} {
		columns += "," + readBoundedText(db, field.name, field.name, field.limit)
	}
	if err := db.Select(columns).Where("backup_id=?", op.ID).Limit(2).Find(&rows).Error; err != nil {
		return BackupCompletionReceipt{}, err
	}
	if len(rows) != 1 {
		return BackupCompletionReceipt{}, ErrMaintenanceSource
	}
	row := rows[0]
	digest, err := backupCompletionDigest(row)
	if err != nil || digest != row.Digest || row.BackupID != op.ID || row.Generation != op.Generation || row.InitiatedBy != op.InitiatedBy || row.InitiatingSessionID != op.SessionID || row.StartedAtMicros != op.CreatedAtMicros || row.CompletedAtMicros != op.UpdatedAtMicros || row.ReasonCode != op.ReasonCode || op.Status != "completed" {
		return BackupCompletionReceipt{}, ErrMaintenanceSource
	}
	return row, nil
}
