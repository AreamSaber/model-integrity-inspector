// Package backupmanifest binds a backup's files and database inventory to a
// canonical, bounded document. Structural validation is not snapshot acquisition,
// authorization, audit-chain verification, or proof of independent provenance.
package backupmanifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
)

const (
	Version                = "mii.backup-manifest.v1"
	MaxBytes               = 16 << 20
	MaxEntries             = 65536
	MaxOrganizations       = 16384
	MaxMigrations          = 4096
	MaxFileBytes     int64 = 1 << 40
)

var (
	ErrInvalid  = errors.New("MI_BACKUP_MANIFEST_INVALID")
	ErrLimit    = errors.New("MI_BACKUP_MANIFEST_LIMIT")
	ErrMismatch = errors.New("MI_BACKUP_MANIFEST_MISMATCH")
)

// File contains an archive identifier, never a filesystem path. The coordinator
// chooses private destinations; even authenticated identifiers are not paths.
type File struct {
	EntryID string `json:"entry_id"`
	Bytes   int64  `json:"bytes"`
	SHA256  string `json:"sha256"`
}

type Database struct {
	Driver         string `json:"driver"`
	ServerVersion  string `json:"server_version"`
	SnapshotMethod string `json:"snapshot_method"`
	File           File   `json:"file"`
}

type Migration struct {
	Version int    `json:"version"`
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
}

type Report struct {
	ID               int64  `json:"id"`
	OrganizationID   int64  `json:"organization_id"`
	RunID            int64  `json:"run_id"`
	AnalysisRevision int64  `json:"analysis_revision"`
	Revision         int64  `json:"revision"`
	Format           string `json:"format"`
	SchemaVersion    string `json:"schema_version"`
	ContentSHA256    string `json:"content_sha256"`
	SourceSHA256     string `json:"source_sha256"`
	File             File   `json:"file"`
}

// Artifact includes every retained version, not just the current bundle. All
// categories use the archive's rule kind and an unambiguous manifest category.
type Artifact struct {
	Category string `json:"category"`
	Version  string `json:"version"`
	File     File   `json:"file"`
}

type AuditAnchor struct {
	OrganizationID          int64  `json:"organization_id"`
	EventCount              int64  `json:"event_count"`
	EndHash                 string `json:"end_hash"`
	KeyVersion              string `json:"key_version"`
	CanonicalizationVersion string `json:"canonicalization_version"`
}

// JobSummary preserves pending and uncertain work rather than inventing success.
// A publishable snapshot is drained: Running and DispatchedAttempts must be zero.
// The snapshot coordinator must establish these facts from the same snapshot.
type JobSummary struct {
	OrganizationID     int64 `json:"organization_id"`
	Pending            int64 `json:"pending"`
	Running            int64 `json:"running"`
	Completed          int64 `json:"completed"`
	Failed             int64 `json:"failed"`
	Cancelled          int64 `json:"cancelled"`
	DispatchedAttempts int64 `json:"dispatched_attempts"`
	UncertainAttempts  int64 `json:"uncertain_attempts"`
}

// Manifest must be constructed from one verified database snapshot. It has no
// free-form configuration, SQL, path, DSN, key material, credentials or prose.
// v1 requires complete audit history: sealed-segment support needs a new format
// before any backup coordinator can accept a database with archived segments.
type Manifest struct {
	SchemaVersion      string        `json:"schema_version"`
	BackupID           int64         `json:"backup_id"`
	StartedAtMicros    int64         `json:"started_at_micros"`
	SnapshotAtMicros   int64         `json:"snapshot_at_micros"`
	ApplicationVersion string        `json:"application_version"`
	SourceCommit       string        `json:"source_commit"`
	Database           Database      `json:"database"`
	Migrations         []Migration   `json:"migrations"`
	Reports            []Report      `json:"reports"`
	Artifacts          []Artifact    `json:"artifacts"`
	KeyVersions        []string      `json:"key_versions"`
	AuditHistory       string        `json:"audit_history"`
	AuditAnchors       []AuditAnchor `json:"audit_anchors"`
	Jobs               []JobSummary  `json:"jobs"`
	ConfigTemplate     File          `json:"config_template"`
}

// Serialization of infrastructure values is deliberately explicit. Encode is
// the only manifest serialization path; logging must not reveal audit anchors.
func (Manifest) String() string               { return "[private backup manifest]" }
func (m Manifest) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, m.String()) }
func (Manifest) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (Manifest) MarshalYAML() (any, error)    { return nil, ErrInvalid }
func (m Manifest) LogValue() slog.Value       { return slog.StringValue(m.String()) }

type wireManifest Manifest

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Encode makes owned copies of all lists and sorts their canonical keys. It
// rejects duplicates, inconsistent references and excessive inventory; it never
// truncates a backup to fit limits. Returned bytes contain protected metadata.
func Encode(in Manifest) ([]byte, string, error) {
	if err := bounded(in); err != nil {
		return nil, "", err
	}
	m := canonical(in)
	if err := validate(m); err != nil {
		return nil, "", err
	}
	data, err := json.Marshal(wireManifest(m))
	if err != nil {
		return nil, "", ErrInvalid
	}
	if len(data) > MaxBytes || inventoryBytes(m) > MaxFileBytes-int64(len(data)) {
		return nil, "", ErrLimit
	}
	return data, digest(data), nil
}

// Decode requires an independently expected backup ID and canonical SHA-256.
// Passing a hash obtained from the same untrusted archive does NOT authenticate
// its source or detect replacement with an older valid backup. The coordinator
// must obtain and retain the external anchor through an authorized channel.
func Decode(data []byte, expectedID int64, expectedSHA256 string) (Manifest, error) {
	if len(data) > MaxBytes {
		return Manifest{}, ErrLimit
	}
	if len(data) == 0 || expectedID <= 0 || !hash(expectedSHA256) {
		return Manifest{}, ErrInvalid
	}
	if digest(data) != expectedSHA256 {
		return Manifest{}, ErrMismatch
	}
	if err := preflight(data); err != nil {
		return Manifest{}, err
	}
	var wire wireManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return Manifest{}, ErrInvalid
	}
	if wire.BackupID != expectedID {
		return Manifest{}, ErrMismatch
	}
	encoded, _, err := Encode(Manifest(wire))
	if err != nil {
		return Manifest{}, err
	}
	// Exact canonical comparison rejects duplicate/case-aliased keys, omitted
	// fields, null arrays, escapes, whitespace, floats, trailing JSON and reordering.
	if !bytes.Equal(encoded, data) {
		return Manifest{}, ErrInvalid
	}
	return Manifest(wire), nil
}

func canonical(m Manifest) Manifest {
	m.Migrations = append([]Migration{}, m.Migrations...)
	m.Reports = append([]Report{}, m.Reports...)
	m.Artifacts = append([]Artifact{}, m.Artifacts...)
	m.KeyVersions = append([]string{}, m.KeyVersions...)
	m.AuditAnchors = append([]AuditAnchor{}, m.AuditAnchors...)
	m.Jobs = append([]JobSummary{}, m.Jobs...)
	slices.SortFunc(m.Migrations, func(a, b Migration) int { return compare(a.Version, b.Version) })
	slices.SortFunc(m.Reports, func(a, b Report) int { return compare(a.ID, b.ID) })
	slices.SortFunc(m.Artifacts, func(a, b Artifact) int {
		if v := compare(a.Category, b.Category); v != 0 {
			return v
		}
		return compare(a.Version, b.Version)
	})
	slices.Sort(m.KeyVersions)
	slices.SortFunc(m.AuditAnchors, func(a, b AuditAnchor) int { return compare(a.OrganizationID, b.OrganizationID) })
	slices.SortFunc(m.Jobs, func(a, b JobSummary) int { return compare(a.OrganizationID, b.OrganizationID) })
	return m
}

func compare[T ~int | ~int64 | ~string](a, b T) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
