package secret

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"
)

var (
	ErrBackupInvalid     = errors.New("MI_BACKUP_ARCHIVE_INVALID")
	ErrBackupUnavailable = errors.New("MI_BACKUP_CRYPTO_UNAVAILABLE")
	ErrBackupLimit       = errors.New("MI_BACKUP_CRYPTO_LIMIT")
	ErrBackupCanceled    = errors.New("MI_BACKUP_CRYPTO_CANCELED")
	ErrBackupConsumer    = errors.New("MI_BACKUP_CRYPTO_CONSUMER_FAILED")
	ErrBackupClosed      = errors.New("MI_BACKUP_CRYPTO_CLOSED")
	ErrBackupIncomplete  = errors.New("MI_BACKUP_ARCHIVE_INCOMPLETE")
)

const (
	BackupFormatVersion       = "mii.backup-archive.v1"
	BackupMaxBytes      int64 = 1 << 40
	BackupMaxEntries          = 65536
	BackupMaxTimeout          = 24 * time.Hour
	backupChunkBytes          = 64 << 10
)

// Scope comes from the trusted coordinator's expected snapshot. A manifest hash
// supplied by the archive itself is not independent provenance or authorization.
type BackupScope struct {
	BackupID     int64
	ManifestHash string
}

// MaxBytes counts plaintext, including manifest/config entries; ciphertext has
// framing overhead. Upper layers must independently bound private output files.
// Hard ceilings are resource policies, not measured backup/restore capacities.
type BackupLimits struct {
	MaxBytes   int64
	MaxEntries int
	Timeout    time.Duration
}

// ID is a lowercase ASCII identifier, NOT a filesystem path. Future restore
// code must map authenticated entries to its own private staging destinations.
type BackupEntry struct{ Kind, ID string }

// Receipt is returned only after final authentication/framing, EOF (on Open),
// and cancellation checks. It is not a publication/audit/restore receipt.
type BackupReceipt struct {
	Version, KeyVersion, ArchiveSHA256 string
	Entries                            int
	PlaintextBytes, ArchiveBytes       int64
}

type BackupSealer struct {
	version string
	key     [32]byte
}
type BackupOpener struct{ keys map[string][32]byte }
type BackupArchiveWriter struct{ state *backupWriteState }

func (BackupScope) String() string                       { return "[backup scope]" }
func (v BackupScope) Format(s fmt.State, _ rune)         { _, _ = io.WriteString(s, v.String()) }
func (BackupScope) MarshalJSON() ([]byte, error)         { return nil, ErrSensitive }
func (v BackupScope) LogValue() slog.Value               { return slog.StringValue(v.String()) }
func (BackupEntry) String() string                       { return "[backup entry]" }
func (v BackupEntry) Format(s fmt.State, _ rune)         { _, _ = io.WriteString(s, v.String()) }
func (BackupEntry) MarshalJSON() ([]byte, error)         { return nil, ErrSensitive }
func (v BackupEntry) LogValue() slog.Value               { return slog.StringValue(v.String()) }
func (BackupSealer) String() string                      { return "[backup-only sealer]" }
func (v BackupSealer) Format(s fmt.State, _ rune)        { _, _ = io.WriteString(s, v.String()) }
func (BackupSealer) MarshalJSON() ([]byte, error)        { return nil, ErrSensitive }
func (v BackupSealer) LogValue() slog.Value              { return slog.StringValue(v.String()) }
func (BackupOpener) String() string                      { return "[backup-only opener]" }
func (v BackupOpener) Format(s fmt.State, _ rune)        { _, _ = io.WriteString(s, v.String()) }
func (BackupOpener) MarshalJSON() ([]byte, error)        { return nil, ErrSensitive }
func (v BackupOpener) LogValue() slog.Value              { return slog.StringValue(v.String()) }
func (BackupArchiveWriter) String() string               { return "[backup archive writer]" }
func (v BackupArchiveWriter) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (BackupArchiveWriter) MarshalJSON() ([]byte, error) { return nil, ErrSensitive }
func (v BackupArchiveWriter) LogValue() slog.Value       { return slog.StringValue(v.String()) }

// Copies only backup wrapping keys; neither capability retains a KeyRing or
// exposes credential, audit, response or request-decryption capabilities.
func (k *KeyRing) NewBackupCapabilities() (*BackupSealer, *BackupOpener, error) {
	if k == nil || !versionPattern.MatchString(k.active) {
		return nil, nil, ErrBackupUnavailable
	}
	active, ok := k.keys[k.active]
	if !ok || len(active.backupWrap) != 32 {
		return nil, nil, ErrBackupUnavailable
	}
	s := &BackupSealer{version: k.active}
	copy(s.key[:], active.backupWrap)
	o := &BackupOpener{keys: make(map[string][32]byte, len(k.keys))}
	for version, keys := range k.keys {
		if !versionPattern.MatchString(version) || len(keys.backupWrap) != 32 {
			return nil, nil, ErrBackupUnavailable
		}
		var key [32]byte
		copy(key[:], keys.backupWrap)
		o.keys[version] = key
	}
	return s, o, nil
}

func backupContext(ctx context.Context, scope BackupScope, limits BackupLimits) (context.Context, context.CancelFunc, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, ErrBackupCanceled
	}
	if scope.BackupID <= 0 || !evidenceHash.MatchString(scope.ManifestHash) {
		return nil, nil, ErrBackupInvalid
	}
	if limits.MaxBytes < 1 || limits.MaxBytes > BackupMaxBytes || limits.MaxEntries < 1 || limits.MaxEntries > BackupMaxEntries || limits.Timeout <= 0 || limits.Timeout > BackupMaxTimeout {
		return nil, nil, ErrBackupLimit
	}
	bounded, cancel := context.WithTimeout(ctx, limits.Timeout)
	return bounded, cancel, nil
}

func backupEntryCode(e BackupEntry) (byte, error) {
	if len(e.ID) < 1 || len(e.ID) > 64 {
		return 0, ErrBackupInvalid
	}
	for _, r := range e.ID {
		allowed := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-'
		if !allowed {
			return 0, ErrBackupInvalid
		}
	}
	if e.ID[0] == '_' || e.ID[0] == '-' {
		return 0, ErrBackupInvalid
	}
	switch e.Kind {
	case "database":
		return 1, nil
	case "manifest":
		return 2, nil
	case "report":
		return 3, nil
	case "rule":
		return 4, nil
	case "config":
		return 5, nil
	}
	return 0, ErrBackupInvalid
}
