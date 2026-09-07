package bundle

import (
	"bytes"
	"encoding/json"
	"reflect"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
)

const RuleArtifactSchema = "mii.rule-artifact.v1"
const DevelopmentImplementation = "mii.analyzer.development.v1"
const MaxArtifactBytes = 1 << 20

// RuleArtifact is finite data, not code or a release/trust assertion. The
// implementation ID selects installed code; version strings alone never do.
// Manifest reuses the frozen builtin field semantics without changing its bytes.
type RuleArtifact struct {
	SchemaVersion  string   `json:"schema_version"`
	Implementation string   `json:"implementation"`
	Manifest       Manifest `json:"manifest"`
}

func defaultManifest() (Manifest, error) {
	data, err := builtinBytes()
	if err != nil || digest(data) != BuiltinHash {
		return Manifest{}, ErrIntegrity
	}
	var m Manifest
	if json.Unmarshal(data, &m) != nil {
		return Manifest{}, ErrIntegrity
	}
	return m, nil
}

// DevelopmentArtifact starts a distinct candidate version with default knobs.
// Callers may edit only the explicitly admitted development parameters and must
// update the scoring-to-token hash binding before Canonical. No approval exists.
func DevelopmentArtifact(version string) (RuleArtifact, error) {
	m, err := defaultManifest()
	if err != nil || version == BuiltinVersion {
		return RuleArtifact{}, ErrIntegrity
	}
	m.Version, m.TokenRisk.Version = version, version
	tokens, err := tokenrisk.NewDevelopment(m.TokenRisk)
	if err != nil {
		return RuleArtifact{}, ErrIntegrity
	}
	m.Scoring.Version, m.Scoring.TokenVersion, m.Scoring.TokenRulesHash = version, version, tokens.Hash()
	a := RuleArtifact{RuleArtifactSchema, DevelopmentImplementation, m}
	if _, _, err := a.kernels(); err != nil {
		return RuleArtifact{}, err
	}
	return a, nil
}

func (a RuleArtifact) kernels() (*tokenrisk.Engine, *scoring.Engine, error) {
	if a.SchemaVersion != RuleArtifactSchema || a.Implementation != DevelopmentImplementation || a.Manifest.Version == BuiltinVersion || a.Manifest.Version != a.Manifest.TokenRisk.Version || a.Manifest.Version != a.Manifest.Scoring.Version {
		return nil, nil, ErrIntegrity
	}
	tokens, err := tokenrisk.NewDevelopment(a.Manifest.TokenRisk)
	if err != nil {
		return nil, nil, ErrIntegrity
	}
	scores, err := scoring.NewDevelopment(a.Manifest.Scoring, tokens)
	if err != nil {
		return nil, nil, ErrIntegrity
	}
	expected, err := defaultManifest()
	if err != nil {
		return nil, nil, err
	}
	expected.Version, expected.TokenRisk, expected.Scoring = a.Manifest.Version, tokens.Rules(), scores.Rules()
	// Everything outside the six admitted knobs/version/hash binding remains
	// byte-semantic equivalent to installed code, including all implementations,
	// template/wordlist refs, behavior minima, hypotheses and development limits.
	if !reflect.DeepEqual(a.Manifest, expected) {
		return nil, nil, ErrIntegrity
	}
	return tokens, scores, nil
}

func (a RuleArtifact) Canonical() ([]byte, string, error) {
	if _, _, err := a.kernels(); err != nil {
		return nil, "", err
	}
	data, err := json.Marshal(a)
	if err != nil || len(data) > MaxArtifactBytes || !utf8.Valid(data) {
		return nil, "", ErrIntegrity
	}
	return data, digest(data), nil
}

// DecodeRuleArtifact does not authenticate the operator supplying expectedHash.
// It proves exact canonical content and supported development semantics only.
func DecodeRuleArtifact(data []byte, expectedHash string) (RuleArtifact, error) {
	if len(data) == 0 || len(data) > MaxArtifactBytes || !utf8.Valid(data) || len(expectedHash) != 64 || digest(data) != expectedHash {
		return RuleArtifact{}, ErrIntegrity
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var a RuleArtifact
	if d.Decode(&a) != nil {
		return RuleArtifact{}, ErrIntegrity
	}
	canonical, hash, err := a.Canonical()
	// Exact canonical equality also rejects duplicate/case-aliased fields,
	// omitted zero-valued fields, noncanonical numbers and trailing documents.
	if err != nil || hash != expectedHash || !bytes.Equal(canonical, data) {
		return RuleArtifact{}, ErrIntegrity
	}
	return a, nil
}
