package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
)

const InstalledScoringSchema = "mii.scoring-installed.v1"
const MaxInstalledScoringBytes = 64 << 10

// InstalledScoringRef identifies installed implementation data and its builtin
// reference parameters, NOT the independently retained tenant rule parameters.
// A trusted backup anchor must supply the expected ref. This grants no release,
// calibration, gateway evidence or permission to execute historical code.
type InstalledScoringRef struct {
	SchemaVersion, Implementation, Version                       string
	ReferenceRuleSHA256, ScoringSHA256, TokenRulesSHA256, SHA256 string
	Bytes                                                        int64
}

func (InstalledScoringRef) String() string               { return "[private installed scoring reference]" }
func (v InstalledScoringRef) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (v InstalledScoringRef) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (InstalledScoringRef) MarshalJSON() ([]byte, error) { return nil, ErrIntegrity }
func (InstalledScoringRef) MarshalYAML() (any, error)    { return nil, ErrIntegrity }

// InstalledScoringArtifact is an owned data carrier, not a plugin or substitute
// application executable. Matching installed code is still necessary. Every
// original tenant rule/template and release identity must be archived separately.
type InstalledScoringArtifact struct {
	ref  InstalledScoringRef
	data []byte
}

func (InstalledScoringArtifact) String() string               { return "[private installed scoring artifact]" }
func (v InstalledScoringArtifact) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (v InstalledScoringArtifact) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (InstalledScoringArtifact) MarshalJSON() ([]byte, error) { return nil, ErrIntegrity }
func (InstalledScoringArtifact) MarshalYAML() (any, error)    { return nil, ErrIntegrity }

func (a *InstalledScoringArtifact) Ref() InstalledScoringRef {
	if a == nil {
		return InstalledScoringRef{}
	}
	return a.ref
}
func (a *InstalledScoringArtifact) Bytes() []byte {
	if a == nil {
		return nil
	}
	return bytes.Clone(a.data)
}

type installedScoringLimits struct {
	ScoringSamples, Hypotheses, TokenSamples, TokenObservations, TokenSeries int
	FeatureResponseBytes, FeatureBatchBytes                                  int
}

type installedScoringWire struct {
	SchemaVersion       string                 `json:"schema_version"`
	Implementation      string                 `json:"implementation"`
	Version             string                 `json:"version"`
	ReferenceRuleSHA256 string                 `json:"reference_rule_sha256"`
	ReferenceRule       json.RawMessage        `json:"reference_rule"`
	Limits              installedScoringLimits `json:"limits"`
}

func scoringResourceLimits() installedScoringLimits {
	return installedScoringLimits{scoring.MaxSamples, scoring.MaxHypotheses, tokenrisk.MaxSamples,
		tokenrisk.MaxObservations, tokenrisk.MaxSeries, features.MaxResponseBytes, features.MaxBatchBytes}
}

func installedScoringContext(ctx context.Context) error {
	if ctx == nil {
		return ErrIntegrity
	}
	return ctx.Err()
}

// The original bytes must come from the supplied installed artifact. Neither
// export nor restore calls Builtin/NewResolver/defaultManifest to replace bad
// input with today's defaults. BuiltinHash is the already frozen release anchor.
func scoringRuntimeFromOriginal(ctx context.Context, raw []byte) (*Runtime, error) {
	if err := installedScoringContext(ctx); err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > MaxInstalledScoringBytes || digest(raw) != BuiltinHash {
		return nil, ErrIntegrity
	}
	var m Manifest
	if json.Unmarshal(raw, &m) != nil || m.Version != BuiltinVersion || m.SchemaVersion != "mii.runtime-bundle.v1" || m.Status != "development_uncalibrated" {
		return nil, ErrIntegrity
	}
	tokens, err := tokenrisk.NewDevelopment(m.TokenRisk)
	if err != nil {
		return nil, ErrIntegrity
	}
	scores, err := scoring.NewDevelopment(m.Scoring, tokens)
	if err != nil {
		return nil, ErrIntegrity
	}
	runtime, err := makeRuntime(m, BuiltinHash, m.SchemaVersion, tokens, scores)
	if err != nil {
		return nil, ErrIntegrity
	}
	if err := installedScoringContext(ctx); err != nil {
		return nil, err
	}
	return runtime, nil
}

func scoringCarrier(ctx context.Context, raw []byte) (*InstalledScoringArtifact, *Runtime, error) {
	runtime, err := scoringRuntimeFromOriginal(ctx, raw)
	if err != nil {
		return nil, nil, err
	}
	wire := installedScoringWire{InstalledScoringSchema, DevelopmentImplementation, scoring.Version, BuiltinHash, raw, scoringResourceLimits()}
	data, err := json.Marshal(wire)
	if err != nil || len(data) > MaxInstalledScoringBytes {
		return nil, nil, ErrIntegrity
	}
	r := runtime.Ref()
	ref := InstalledScoringRef{InstalledScoringSchema, DevelopmentImplementation, scoring.Version,
		BuiltinHash, r.ScoringHash, r.TokenRulesHash, digest(data), int64(len(data))}
	if err := installedScoringContext(ctx); err != nil {
		return nil, nil, err
	}
	return &InstalledScoringArtifact{ref: ref, data: data}, runtime, nil
}

// InstalledScoringArtifact preserves the actual installed reference rule bytes,
// including all scoring/token parameters and feature/behavior/template/tokenizer
// version bindings. It must not be used to flatten same-name tenant variants.
func (a *Artifacts) InstalledScoringArtifact(ctx context.Context) (*InstalledScoringArtifact, error) {
	if a == nil {
		return nil, ErrIntegrity
	}
	carrier, _, err := scoringCarrier(ctx, a.rule)
	return carrier, err
}

func readInstalledScoring(ctx context.Context, data []byte, expected InstalledScoringRef) (*InstalledScoringArtifact, *Runtime, error) {
	if err := installedScoringContext(ctx); err != nil {
		return nil, nil, err
	}
	if len(data) == 0 || len(data) > MaxInstalledScoringBytes || expected.Bytes != int64(len(data)) || expected.SHA256 != digest(data) {
		return nil, nil, ErrIntegrity
	}
	// Owned before decoding: no RawMessage or result borrows caller storage.
	owned := bytes.Clone(data)
	var wire installedScoringWire
	decoder := json.NewDecoder(bytes.NewReader(owned))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil {
		return nil, nil, ErrIntegrity
	}
	canonical, runtime, err := scoringCarrier(ctx, wire.ReferenceRule)
	// Exact complete bytes reject trailing data, duplicate/case-aliased fields,
	// omitted fields, unknown limits and self-rehashed counterfeit metadata.
	if err != nil {
		return nil, nil, err
	}
	if canonical.ref != expected || !bytes.Equal(canonical.data, owned) {
		return nil, nil, ErrIntegrity
	}
	if err := installedScoringContext(ctx); err != nil {
		return nil, nil, err
	}
	return canonical, runtime, nil
}

func VerifyInstalledScoringArtifact(ctx context.Context, data []byte, expected InstalledScoringRef) (*InstalledScoringArtifact, error) {
	a, _, err := readInstalledScoring(ctx, data, expected)
	return a, err
}

// NewReferenceRuntime reconstructs from the archived ORIGINAL reference rule.
// It is explicitly the installed builtin reference, not a resolver for tenant
// candidates. Restore their separate exact rule artifacts through the resolver.
func (a *InstalledScoringArtifact) NewReferenceRuntime(ctx context.Context) (*Runtime, error) {
	if a == nil {
		return nil, ErrIntegrity
	}
	_, runtime, err := readInstalledScoring(ctx, a.data, a.ref)
	return runtime, err
}
