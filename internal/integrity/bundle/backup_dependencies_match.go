package bundle

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

var ErrBackupDependencyUnavailable = fmt.Errorf("MI_BACKUP_DEPENDENCY_UNAVAILABLE")

// A binding associates observed byte identities only. It is not acquisition of
// release binaries, authentication of historical execution, a closure receipt,
// or restore permission. A collector must still archive the actual carrier.
type BackupDependencyBinding struct {
	Source                       BackupDependencySource
	Dependency                   BackupDependency
	ResourceSource               BackupDependencySource
	CarrierSchema, CarrierSHA256 string
	CarrierBytes                 int64
}

func (BackupDependencyBinding) String() string               { return "[private backup dependency binding]" }
func (v BackupDependencyBinding) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (v BackupDependencyBinding) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (BackupDependencyBinding) MarshalJSON() ([]byte, error) { return nil, ErrBackupDependencies }
func (BackupDependencyBinding) MarshalYAML() (any, error)    { return nil, ErrBackupDependencies }

func backupDependencyFind(ctx context.Context, source *BackupDependencies, role string) (BackupDependency, error) {
	if ctx == nil || ctx.Err() != nil || source == nil || source.source.Category != "rule" || source.classification != BackupDependenciesExplained {
		return BackupDependency{}, ErrBackupDependencyUnavailable
	}
	for _, d := range source.dependencies {
		if d.HashRole == role {
			return d, nil
		}
	}
	return BackupDependency{}, ErrBackupDependencyUnavailable
}

// MatchBackupTemplateDependency requires exact tenant, ORIGINAL container
// version and content hash. Even an opaque template's complete bytes may match;
// that does not interpret its members. Use MatchBackupTemplateMember separately.
func MatchBackupTemplateDependency(ctx context.Context, rule, template *BackupDependencies) (BackupDependencyBinding, error) {
	d, err := backupDependencyFind(ctx, rule, BackupDependencyTemplateContent)
	if err != nil || template == nil || template.source.Category != "template" || template.source.OrganizationID != d.OrganizationID || template.source.Version != d.Version || template.source.SHA256 != d.SHA256 {
		return BackupDependencyBinding{}, ErrBackupDependencyUnavailable
	}
	if ctx.Err() != nil {
		return BackupDependencyBinding{}, ErrBackupDependencyUnavailable
	}
	return BackupDependencyBinding{Source: rule.source, Dependency: d, ResourceSource: template.source, CarrierSHA256: template.source.SHA256, CarrierBytes: template.source.Bytes}, nil
}

func MatchBackupTemplateMember(ctx context.Context, template *BackupDependencies, expected BackupTemplateMember) (BackupTemplateMember, error) {
	if ctx == nil || ctx.Err() != nil || template == nil || template.source.Category != "template" || template.classification != BackupDependenciesExplained || expected.OrganizationID != template.source.OrganizationID || expected.ContainerVersion != template.source.Version || expected.ContainerSHA256 != template.source.SHA256 {
		return BackupTemplateMember{}, ErrBackupDependencyUnavailable
	}
	for _, m := range template.members {
		if m == expected {
			if ctx.Err() != nil {
				break
			}
			return m, nil
		}
	}
	return BackupTemplateMember{}, ErrBackupDependencyUnavailable
}

// The caller must supply a real owned installed tokenizer capability, not a
// caller-created reference/string or a freshly downloaded current fallback.
// Ref's configuration hash matches the requirement; its DIFFERENT carrier hash
// identifies the actual rank/config/semantics bytes still to be archived.
func MatchBackupTokenizerDependency(ctx context.Context, rule *BackupDependencies, installed *tokenizer.InstalledArtifact) (BackupDependencyBinding, error) {
	d, err := backupDependencyFind(ctx, rule, BackupDependencyTokenizerConfiguration)
	if err != nil || installed == nil {
		return BackupDependencyBinding{}, ErrBackupDependencyUnavailable
	}
	r := installed.Ref()
	if r.SchemaVersion != tokenizer.InstalledArtifactSchema || r.Version != d.Version || r.ConfigurationSHA256 != d.SHA256 || !backupDependencyHash(r.SHA256) || r.Bytes <= 0 || r.Bytes > tokenizer.MaxInstalledArtifactBytes || ctx.Err() != nil {
		return BackupDependencyBinding{}, ErrBackupDependencyUnavailable
	}
	return BackupDependencyBinding{Source: rule.source, Dependency: d, CarrierSchema: r.SchemaVersion, CarrierSHA256: r.SHA256, CarrierBytes: r.Bytes}, nil
}

// This OPTIONAL reference match is deliberately restricted to the original
// installed reference rule. Tenant parameter variants remain in their own raw
// rule objects; failure here neither deletes them nor replaces them with the
// installed reference. No release implementation code is in this data carrier.
func MatchBackupInstalledScoringReference(ctx context.Context, rule *BackupDependencies, installed *InstalledScoringArtifact) ([]BackupDependencyBinding, error) {
	scores, err := backupDependencyFind(ctx, rule, BackupDependencyScoringParameters)
	if err != nil || installed == nil {
		return nil, ErrBackupDependencyUnavailable
	}
	tokens, err := backupDependencyFind(ctx, rule, BackupDependencyTokenRiskParameters)
	if err != nil {
		return nil, err
	}
	r := installed.Ref()
	if r.SchemaVersion != InstalledScoringSchema || r.ReferenceRuleSHA256 != rule.source.SHA256 || r.Version != scores.Version || r.Version != tokens.Version || r.ScoringSHA256 != scores.SHA256 || r.TokenRulesSHA256 != tokens.SHA256 || !backupDependencyHash(r.SHA256) || r.Bytes <= 0 || r.Bytes > MaxInstalledScoringBytes || ctx.Err() != nil {
		return nil, ErrBackupDependencyUnavailable
	}
	return []BackupDependencyBinding{
		{Source: rule.source, Dependency: scores, CarrierSchema: r.SchemaVersion, CarrierSHA256: r.SHA256, CarrierBytes: r.Bytes},
		{Source: rule.source, Dependency: tokens, CarrierSchema: r.SchemaVersion, CarrierSHA256: r.SHA256, CarrierBytes: r.Bytes},
	}, nil
}
