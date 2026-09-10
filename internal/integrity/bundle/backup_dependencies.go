package bundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"
	"unicode/utf8"
)

var (
	ErrBackupDependencies     = errors.New("MI_BACKUP_DEPENDENCIES_INVALID")
	ErrBackupDependencyLimit  = errors.New("MI_BACKUP_DEPENDENCIES_LIMIT")
	ErrBackupDependencyRead   = errors.New("MI_BACKUP_DEPENDENCIES_READ_FAILED")
	ErrBackupDependencyClosed = errors.New("MI_BACKUP_DEPENDENCIES_CLOSED")
)

const (
	BackupDependenciesExplained           = "explained_unverified"
	BackupDependenciesOpaque              = "opaque_unverified"
	BackupDependencyMaxBytes        int64 = 1 << 40
	BackupDependencyMaxTimeout            = 24 * time.Hour
	BackupDependencyTemplateContent       = "template_container_content"
	// #nosec G101 -- Fixed hash-role identifier; contains no credential or key material.
	BackupDependencyTokenizerConfiguration = "tokenizer_configuration"
	BackupDependencyScoringParameters      = "scoring_parameters"
	BackupDependencyTokenRiskParameters    = "tokenrisk_parameters"
	BackupDependencyImplementation         = "implementation_version"
	BackupDependencyDeclared               = "declared_original"
	BackupDependencyDerived                = "derived_known_json_codec"
)

// Source comes from an independently completed same-snapshot inventory, not an
// HTTP request. This function checks the original bytes against the supplied
// identity; it cannot authenticate whoever supplied that identity. All statuses
// and organizations must be supplied by the collector, including unused history.
type BackupDependencySource struct {
	Category              string
	OrganizationID, RowID int64
	Version, SHA256       string
	Bytes                 int64
}

// MaxBytes bounds ONE complete source, not the eventual archive/source union.
// Bodies exceeding the known codec's 1 MiB ceiling are fully hashed in 64 KiB
// chunks and classified opaque, never buffered whole or truncated to decode.
type BackupDependencyLimits struct {
	MaxBytes int64
	Timeout  time.Duration
}

// Dependency is a requirement/observation, never evidence that a resource has
// been acquired, approved or is executable. Parameter hashes are derived from
// original finite fields with the known JSON codec, NOT a historical runtime
// attestation. Content, parameter and carrier hash roles are never exchangeable.
type BackupDependency struct {
	Scope                                      string
	OrganizationID                             int64
	Category, Version, HashRole, SHA256, Basis string
}

// Members carry only identities. Prompts/assertions remain in the original
// template carrier; they are not duplicated into the resource index.
type BackupTemplateMember struct {
	OrganizationID                                 int64
	ContainerVersion, ContainerSHA256, ID, Version string
}

// The opaque immutable result has no public constructor or execution method.
// Explained means finite dependency semantics only, not MAC/provenance,
// installed availability, complete closure or permission to restore execution.
type BackupDependencies struct {
	source                        BackupDependencySource
	classification, codec, reason string
	dependencies                  []BackupDependency
	members                       []BackupTemplateMember
}

func (o *BackupDependencies) Source() BackupDependencySource {
	if o == nil {
		return BackupDependencySource{}
	}
	return o.source
}
func (o *BackupDependencies) Classification() string {
	if o == nil {
		return ""
	}
	return o.classification
}
func (o *BackupDependencies) Codec() string {
	if o == nil {
		return ""
	}
	return o.codec
}
func (o *BackupDependencies) Reason() string {
	if o == nil {
		return ""
	}
	return o.reason
}
func (o *BackupDependencies) Dependencies() []BackupDependency {
	if o == nil {
		return nil
	}
	return slices.Clone(o.dependencies)
}
func (o *BackupDependencies) Members() []BackupTemplateMember {
	if o == nil {
		return nil
	}
	return slices.Clone(o.members)
}

func (BackupDependencySource) String() string               { return "[private backup dependency source]" }
func (v BackupDependencySource) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (v BackupDependencySource) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (BackupDependencySource) MarshalJSON() ([]byte, error) { return nil, ErrBackupDependencies }
func (BackupDependencySource) MarshalYAML() (any, error)    { return nil, ErrBackupDependencies }
func (BackupDependency) String() string                     { return "[private backup dependency]" }
func (v BackupDependency) Format(w fmt.State, _ rune)       { _, _ = io.WriteString(w, v.String()) }
func (v BackupDependency) LogValue() slog.Value             { return slog.StringValue(v.String()) }
func (BackupDependency) MarshalJSON() ([]byte, error)       { return nil, ErrBackupDependencies }
func (BackupDependency) MarshalYAML() (any, error)          { return nil, ErrBackupDependencies }
func (BackupTemplateMember) String() string                 { return "[private backup template member]" }
func (v BackupTemplateMember) Format(w fmt.State, _ rune)   { _, _ = io.WriteString(w, v.String()) }
func (v BackupTemplateMember) LogValue() slog.Value         { return slog.StringValue(v.String()) }
func (BackupTemplateMember) MarshalJSON() ([]byte, error)   { return nil, ErrBackupDependencies }
func (BackupTemplateMember) MarshalYAML() (any, error)      { return nil, ErrBackupDependencies }
func (BackupDependencies) String() string                   { return "[private backup dependency observation]" }
func (v BackupDependencies) Format(w fmt.State, _ rune)     { _, _ = io.WriteString(w, v.String()) }
func (v BackupDependencies) LogValue() slog.Value           { return slog.StringValue(v.String()) }
func (BackupDependencies) MarshalJSON() ([]byte, error)     { return nil, ErrBackupDependencies }
func (BackupDependencies) MarshalYAML() (any, error)        { return nil, ErrBackupDependencies }

func backupDependencyHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

// ObserveBackupDependencies consumes a single ORIGINAL staged object. read must
// call consume exactly once, synchronously, propagate source final/close errors
// and cooperate with ctx. It may wrap BackupWorkspace.Read/privatefile.Read.
// Retaining callbacks or detached work is forbidden. A final outer read failure
// discards all candidates even after consume has read every byte successfully.
// There is no SQL, path lookup, status/current-version filter or builtin fallback.
func ObserveBackupDependencies(ctx context.Context, source BackupDependencySource, limits BackupDependencyLimits, read func(context.Context, func(io.Reader) error) error) (observation *BackupDependencies, finalErr error) {
	returned := false
	defer func() {
		if !returned {
			_ = recover()
			finalErr = ErrBackupDependencyRead
		}
		if finalErr != nil {
			observation = nil
		}
	}()
	if ctx == nil || ctx.Err() != nil || read == nil || source.Category != "rule" && source.Category != "template" || source.OrganizationID <= 0 || source.RowID <= 0 || len(source.Version) > 128 || !utf8.ValidString(source.Version) || !backupDependencyHash(source.SHA256) || source.Bytes < 0 {
		returned = true
		return nil, ErrBackupDependencies
	}
	if limits.MaxBytes < 0 || limits.MaxBytes > BackupDependencyMaxBytes || source.Bytes > limits.MaxBytes || limits.Timeout <= 0 || limits.Timeout > BackupDependencyMaxTimeout {
		returned = true
		return nil, ErrBackupDependencyLimit
	}
	bounded, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()
	body, err := readBackupDependencySource(bounded, cancel, source, read)
	if err != nil {
		returned = true
		return nil, err
	}
	defer clear(body)
	if bounded.Err() != nil {
		returned = true
		return nil, ErrBackupDependencyRead
	}
	observation, finalErr = interpretBackupDependencySource(source, body)
	if bounded.Err() != nil {
		finalErr = ErrBackupDependencyRead
	}
	returned = true
	return observation, finalErr
}
