package repository

import (
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrSecretSerialization = errors.New("SECRET_SERIALIZATION_FORBIDDEN")

// SecretRecord is encrypted persistence data, never a DTO. Only the Secret
// Service obtains these records; ordinary target reads select metadata only.
type SecretRecord struct {
	ID                int64
	OrganizationID    int64
	EncryptedDataKey  []byte
	Ciphertext        []byte
	Nonce             []byte
	KeyVersion        string
	PayloadKeyVersion string
	SecretVersion     int64
	Fingerprint       string
	LastFour          string
	CreatedAt         time.Time
	RotatedAt         *time.Time
	DeletedAt         *time.Time
}

func (SecretRecord) TableName() string            { return "integrity_secrets" }
func (SecretRecord) String() string               { return "[encrypted secret record]" }
func (r SecretRecord) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, r.String()) }
func (SecretRecord) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

type SecretMetadata struct {
	ID        int64      `json:"id"`
	Version   int64      `json:"version"`
	Mask      string     `json:"mask"`
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
}

func secretMask(lastFour string) string {
	if !utf8.ValidString(lastFour) || utf8.RuneCountInString(lastFour) > 4 || strings.IndexFunc(lastFour, unicode.IsControl) >= 0 {
		return "********"
	}
	return "********" + lastFour
}

func validSecretRecord(record SecretRecord, orgID int64) bool {
	return record.ID > 0 && record.OrganizationID == orgID && record.SecretVersion > 0 && record.SecretVersion <= math.MaxInt32 &&
		len(record.EncryptedDataKey) > 0 && len(record.EncryptedDataKey) <= 4096 &&
		len(record.Ciphertext) >= 16 && len(record.Ciphertext) <= 128<<10 && len(record.Nonce) == 12 &&
		len(record.KeyVersion) > 0 && len(record.KeyVersion) <= 64 && len(record.PayloadKeyVersion) > 0 && len(record.PayloadKeyVersion) <= 64 &&
		len(record.Fingerprint) == 64 && utf8.ValidString(record.LastFour) && utf8.RuneCountInString(record.LastFour) <= 4 &&
		strings.IndexFunc(record.LastFour, unicode.IsControl) < 0 && record.DeletedAt == nil
}

// GetSecretForWorker refuses retired or stale versions instead of silently
// substituting credentials into an already-frozen run snapshot.
func (t *Tenant) GetSecretForWorker(id, version int64) (SecretRecord, error) {
	if id <= 0 || version <= 0 {
		return SecretRecord{}, ErrNotFound
	}
	var record SecretRecord
	err := t.scoped().Where("id = ? AND secret_version = ? AND deleted_at IS NULL", id, version).
		Where("EXISTS (SELECT 1 FROM integrity_targets WHERE integrity_targets.organization_id = integrity_secrets.organization_id AND integrity_targets.secret_id = integrity_secrets.id AND integrity_targets.status = 'active' AND integrity_targets.deleted_at IS NULL)").First(&record).Error
	if err != nil {
		return SecretRecord{}, persistenceError(err)
	}
	return record, nil
}

func (t *Tenant) GetSecretMetadata(id int64) (SecretMetadata, error) {
	var record struct {
		ID            int64
		SecretVersion int64
		LastFour      string
		RotatedAt     *time.Time
	}
	err := t.scoped().Table("integrity_secrets").Select("id, secret_version, last_four, rotated_at").
		Where("id = ? AND deleted_at IS NULL", id).Take(&record).Error
	if err != nil {
		return SecretMetadata{}, persistenceError(err)
	}
	return SecretMetadata{record.ID, record.SecretVersion, secretMask(record.LastFour), record.RotatedAt}, nil
}
