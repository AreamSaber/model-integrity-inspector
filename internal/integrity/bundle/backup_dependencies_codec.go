package bundle

import (
	"bytes"
	"encoding/json"
	"io"

	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
)

const backupRuntimeSchema = "mii.runtime-bundle.v1"

func backupOpaque(source BackupDependencySource, codec, reason string) *BackupDependencies {
	return &BackupDependencies{source: source, classification: BackupDependenciesOpaque, codec: codec, reason: reason}
}

// Current data codecs are finite structs. Decode does not use today's runtime
// admission/defaults to reject historical parameter values or implementation
// labels. Exact re-encoding establishes a complete, unambiguous field shape;
// unknown/partial/noncanonical historical bytes remain explicitly opaque.
func backupKnownJSON(data []byte, target any) bool {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return false
	}
	canonical, err := json.Marshal(target)
	return err == nil && bytes.Equal(data, canonical)
}

func interpretBackupDependencySource(source BackupDependencySource, data []byte) (*BackupDependencies, error) {
	if source.Bytes > MaxArtifactBytes {
		return backupOpaque(source, "", "codec_byte_limit"), nil
	}
	if source.Category == "template" {
		original, err := templates.Decode(data, source.SHA256)
		if err != nil {
			return backupOpaque(source, "", "unknown_template_codec"), nil
		}
		if original.Version != source.Version {
			return nil, ErrBackupDependencies
		}
		out := &BackupDependencies{source: source, classification: BackupDependenciesExplained, codec: "mii.template-bundle.canonical.v1"}
		for _, member := range original.Templates {
			out.members = append(out.members, BackupTemplateMember{source.OrganizationID, source.Version, source.SHA256, member.ID, member.Version})
		}
		return out, nil
	}
	var probe struct {
		SchemaVersion string `json:"schema_version"`
	}
	if json.Unmarshal(data, &probe) != nil {
		return backupOpaque(source, "", "unknown_rule_codec"), nil
	}
	var m Manifest
	var implementation string
	switch probe.SchemaVersion {
	case backupRuntimeSchema:
		if !backupKnownJSON(data, &m) {
			return backupOpaque(source, backupRuntimeSchema, "unknown_rule_shape"), nil
		}
	case RuleArtifactSchema:
		var a RuleArtifact
		if !backupKnownJSON(data, &a) {
			return backupOpaque(source, RuleArtifactSchema, "unknown_rule_shape"), nil
		}
		if a.Manifest.SchemaVersion != backupRuntimeSchema {
			return backupOpaque(source, RuleArtifactSchema, "unknown_nested_manifest_codec"), nil
		}
		m, implementation = a.Manifest, a.Implementation
		if implementation == "" {
			return nil, ErrBackupDependencies
		}
	default:
		// Do not recurse into unknown objects looking for version/hash strings.
		return backupOpaque(source, "", "unknown_rule_codec"), nil
	}
	if m.Version != source.Version || m.Scoring.Version == "" || m.TokenRisk.Version == "" || m.Template.Version == "" || m.Tokenizer.Version == "" || !backupDependencyHash(m.Template.SHA256) || !backupDependencyHash(m.Tokenizer.SHA256) || m.Scoring.TokenVersion != m.TokenRisk.Version || m.Scoring.BehaviorVersion != m.BehaviorVersion {
		return nil, ErrBackupDependencies
	}
	// These are the exact existing scoring/tokenrisk Rules JSON struct codecs,
	// used by their RulesHash/hashRules/Engine hash constructors. Hash the
	// supplied original parameters, never Parameters() or a current resolver.
	tokens, err := json.Marshal(m.TokenRisk)
	if err != nil {
		return nil, ErrBackupDependencies
	}
	defer clear(tokens)
	tokenHash := digest(tokens)
	if m.Scoring.TokenRulesHash != tokenHash {
		return nil, ErrBackupDependencies
	}
	scores, err := json.Marshal(m.Scoring)
	if err != nil {
		return nil, ErrBackupDependencies
	}
	defer clear(scores)
	out := &BackupDependencies{source: source, classification: BackupDependenciesExplained, codec: probe.SchemaVersion}
	out.dependencies = []BackupDependency{
		{"organization", source.OrganizationID, "template", m.Template.Version, BackupDependencyTemplateContent, m.Template.SHA256, BackupDependencyDeclared},
		{"installed", 0, "tokenizer", m.Tokenizer.Version, BackupDependencyTokenizerConfiguration, m.Tokenizer.SHA256, BackupDependencyDeclared},
		{"organization", source.OrganizationID, "scoring", m.Scoring.Version, BackupDependencyScoringParameters, digest(scores), BackupDependencyDerived},
		{"organization", source.OrganizationID, "tokenrisk", m.TokenRisk.Version, BackupDependencyTokenRiskParameters, tokenHash, BackupDependencyDerived},
	}
	for _, v := range []struct{ category, version string }{{"generator", m.GeneratorVersion}, {"features", m.FeatureVersion}, {"structure", m.StructureVersion}, {"behavior", m.BehaviorVersion}} {
		if v.version == "" {
			return nil, ErrBackupDependencies
		}
		out.dependencies = append(out.dependencies, BackupDependency{"release_implementation", 0, v.category, v.version, BackupDependencyImplementation, "", BackupDependencyDeclared})
	}
	if implementation != "" {
		out.dependencies = append(out.dependencies, BackupDependency{"release_implementation", 0, "analyzer", implementation, BackupDependencyImplementation, "", BackupDependencyDeclared})
	}
	return out, nil
}
