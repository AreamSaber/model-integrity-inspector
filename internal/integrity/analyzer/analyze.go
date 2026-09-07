package analyzer

import (
	"errors"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/behavior"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
)

const SchemaVersion = "mii.analysis.v1"

var ErrInput = errors.New("MI_ANALYSIS_INPUT_INVALID")

// Document is an immutable, body-free machine analysis, not a human approval.
// Source authenticity comes from the Worker lease + Manifest HMAC + evidence
// AAD boundary, never from receiving JSON shaped like this document.
type Document struct {
	SchemaVersion string                `json:"schema_version"`
	Features      features.Result       `json:"features"`
	Tokens        tokenrisk.Result      `json:"tokens"`
	Behavior      behavior.Batch        `json:"behavior"`
	Differences   []behavior.Difference `json:"paired_differences"`
	Multiplicity  scoring.FDRResult     `json:"paired_multiplicity"`
	Scores        scoring.Result        `json:"scores"`
}

// Analyze runs every fixed paired hypothesis, including untestable ones. The
// family is never selected after observing which differences were significant.
// These exploratory paired results are not a trusted-baseline risk component.
func Analyze(batch *features.Batch) (Document, error) {
	tokens, err := tokenrisk.NewDevelopment(tokenrisk.Parameters())
	if err != nil {
		return Document{}, err
	}
	scores, err := scoring.NewDevelopment(scoring.Parameters(), tokens)
	if err != nil {
		return Document{}, err
	}
	engine, err := NewDevelopment(tokens, scores)
	if err != nil {
		return Document{}, err
	}
	return engine.Analyze(batch)
}

func (e *Engine) analyze(batch *features.Batch) (Document, error) {
	if batch == nil {
		return Document{}, ErrInput
	}
	out := Document{SchemaVersion: SchemaVersion, Features: batch.Features(), Differences: []behavior.Difference{}}
	if err := batch.WithTokenInput(func(input features.OpaqueTokenInput) error {
		var err error
		out.Tokens, err = input.AnalyzeWith(e.tokens)
		return err
	}); err != nil {
		return Document{}, err
	}
	if err := batch.WithBehaviorInput(func(input features.OpaqueBehaviorInput) error {
		var err error
		out.Behavior, err = input.AnalyzeBatch()
		if err != nil {
			return err
		}
		for _, metric := range []behavior.Metric{behavior.ContractDeviation, behavior.ExtraAffix, behavior.NeutralRefusal, behavior.UnsolicitedIdentity} {
			difference, err := input.PairedDifference(metric)
			if err != nil {
				return err
			}
			out.Differences = append(out.Differences, difference)
		}
		return nil
	}); err != nil {
		return Document{}, err
	}
	family := make([]scoring.Hypothesis, 0, len(out.Differences))
	for _, d := range out.Differences {
		family = append(family, scoring.Hypothesis{ID: string(d.Metric), PValue: d.ExactTwoSidedP, Effect: d.RiskDifference})
	}
	var err error
	out.Multiplicity, err = scoring.BenjaminiHochberg(family, .05)
	if err != nil {
		return Document{}, err
	}
	input := scoring.Input{ExpectedSamples: out.Features.Expected, Partial: out.Features.Partial, Behavior: &out.Behavior, Tokens: &out.Tokens}
	for _, f := range out.Features.Samples {
		s := scoring.Observation{SampleID: f.SampleID, Family: f.Family, Language: f.Language, TemplateID: f.TemplateID, ClusterID: f.ClusterHash, Included: f.Included, AuxiliaryOnly: f.AuxiliaryOnly, ReasoningUnseparated: f.ReasoningUnseparated}
		if f.Local != nil {
			s.Tokenizer = f.Local.Quality
		}
		if p := f.Observations; p != nil {
			s.Protocol = &scoring.ProtocolObservation{Usage: scoring.ObservationState(p.Usage), HTTP: scoring.ObservationState(p.HTTP), ModelEcho: scoring.ObservationState(p.ModelEcho), Finish: scoring.ObservationState(p.Finish), Termination: scoring.ObservationState(p.Termination)}
		}
		input.Samples = append(input.Samples, s)
	}
	out.Scores, err = e.scores.Analyze(input)
	if err != nil {
		return Document{}, err
	}
	return out, nil
}
