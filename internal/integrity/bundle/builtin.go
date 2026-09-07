// Package bundle verifies application-controlled runtime artifacts. Development
// admission is not rule publication, calibration, or an independent approval.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/behavior"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/structure"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

const BuiltinVersion = "1.0.0-dev.1"
const BuiltinHash = "fda4b1aaf5290b762c4fb687a9164298e4dcc1f14f7273c870f938ea23bc8d88"

var ErrIntegrity = errors.New("MI_RUNTIME_BUNDLE_INTEGRITY")

type ArtifactRef struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}
type Manifest struct {
	SchemaVersion    string          `json:"schema_version"`
	Version          string          `json:"version"`
	Status           string          `json:"status"`
	Template         ArtifactRef     `json:"template"`
	Tokenizer        ArtifactRef     `json:"tokenizer"`
	GeneratorVersion string          `json:"generator_version"`
	FeatureVersion   string          `json:"feature_version"`
	StructureVersion string          `json:"structure_version"`
	BehaviorVersion  string          `json:"behavior_version"`
	Scoring          scoring.Rules   `json:"scoring"`
	TokenRisk        tokenrisk.Rules `json:"token_risk"`
	BehaviorMinimums [5]float64      `json:"behavior_minimums_families_templates_languages_matches_fraction"`
	PairedMetrics    []string        `json:"paired_metrics"`
	PairedAlpha      float64         `json:"paired_alpha"`
	Limitations      []string        `json:"limitations"`
}

type Artifacts struct{ rule, template []byte }

func builtinBytes() ([]byte, error) {
	return json.Marshal(Manifest{SchemaVersion: "mii.runtime-bundle.v1", Version: BuiltinVersion, Status: "development_uncalibrated", Template: ArtifactRef{templates.BuiltinVersion, templates.BuiltinHash}, Tokenizer: ArtifactRef{tokenizer.BuiltinVersion, tokenizer.BuiltinHash}, GeneratorVersion: generator.Version, FeatureVersion: features.Version, StructureVersion: structure.Version, BehaviorVersion: behavior.Version, Scoring: scoring.Parameters(), TokenRisk: tokenrisk.Parameters(), BehaviorMinimums: [5]float64{behavior.MinimumFamilies, behavior.MinimumTemplates, behavior.MinimumLanguages, behavior.MinimumFamilyMatches, behavior.MinimumRepeatFraction}, PairedMetrics: []string{string(behavior.ContractDeviation), string(behavior.ExtraAffix), string(behavior.NeutralRefusal), string(behavior.UnsolicitedIdentity)}, PairedAlpha: .05, Limitations: []string{"MI_DEVELOPMENT_RULES_UNCALIBRATED", "MI_BASELINE_UNAVAILABLE", "MI_GATEWAY_EVIDENCE_UNAVAILABLE", "MI_PUBLIC_DEVELOPMENT_TEMPLATES"}})
}

// Builtin checks the independently frozen expected digest, not a hash supplied
// by a caller alongside arbitrary content. It also verifies template/tokenizer
// bytes. Any parameter/version change requires a deliberate artifact revision.
func Builtin() (*Artifacts, error) {
	rule, err := builtinBytes()
	if err != nil {
		return nil, ErrIntegrity
	}
	if digest(rule) != BuiltinHash {
		return nil, ErrIntegrity
	}
	template, hash, err := templates.Builtin().Canonical()
	if err != nil || hash != templates.BuiltinHash {
		return nil, ErrIntegrity
	}
	if _, err := templates.Decode(template, templates.BuiltinHash); err != nil {
		return nil, ErrIntegrity
	}
	tokens, err := tokenizer.NewBuiltin()
	if err != nil || tokens.Hash() != tokenizer.BuiltinHash || tokens.Version() != tokenizer.BuiltinVersion {
		return nil, ErrIntegrity
	}
	return &Artifacts{rule: rule, template: template}, nil
}
func digest(data []byte) string { hash := sha256.Sum256(data); return hex.EncodeToString(hash[:]) }
func (a *Artifacts) RuleBytes() []byte {
	if a == nil {
		return nil
	}
	return append([]byte(nil), a.rule...)
}
func (a *Artifacts) TemplateBytes() []byte {
	if a == nil {
		return nil
	}
	return append([]byte(nil), a.template...)
}
