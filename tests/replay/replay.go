package replay

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"slices"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/bundle"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

type Engine struct {
	keyID     string
	publicKey ed25519.PublicKey
	verifier  *generator.Generator
	runtime   *bundle.Runtime
	builder   *features.Builder
	tokens    *tokenizer.Engine
}

func New(config Config) (*Engine, error) {
	if !keyID.MatchString(config.CaptureKeyID) || len(config.CapturePublicKey) != ed25519.PublicKeySize || config.Verifier == nil || config.Runtime == nil || config.Runtime.Ref().Implementation != bundle.DevelopmentImplementation {
		return nil, ErrConfiguration
	}
	tokens, err := tokenizer.NewBuiltin()
	if err != nil {
		return nil, ErrConfiguration
	}
	artifact, hash, err := templates.Builtin().Canonical()
	if err != nil {
		return nil, ErrConfiguration
	}
	b, err := features.New(features.Config{Verifier: config.Verifier, Tokenizer: tokens, TemplateArtifact: artifact, TrustedTemplateHash: hash})
	if err != nil {
		return nil, ErrConfiguration
	}
	return &Engine{config.CaptureKeyID, slices.Clone(config.CapturePublicKey), config.Verifier, config.Runtime, b, tokens}, nil
}

// Replay only consumes supplied bytes and frozen local implementations. It
// cannot publish a Run, access credentials, read controller labels or dial out.
func (e *Engine) Replay(ctx context.Context, reader io.Reader) (Prediction, error) {
	verified, err := e.verify(ctx, reader)
	if err != nil {
		return Prediction{}, err
	}
	defer destroy(verified)
	input, err := e.input(ctx, verified)
	if err != nil {
		return Prediction{}, err
	}
	batch, err := e.builder.Build(input)
	if err != nil {
		return Prediction{}, ErrIntegrity
	}
	if ctx.Err() != nil {
		return Prediction{}, ErrCanceled
	}
	document, err := e.runtime.Analyze(batch)
	if err != nil {
		return Prediction{}, ErrIntegrity
	}
	if ctx.Err() != nil {
		return Prediction{}, ErrCanceled
	}
	if !document.Scores.Development || document.Scores.Calibrated || (document.Scores.EvidenceGrade != "C" && document.Scores.EvidenceGrade != "D") {
		return Prediction{}, ErrIntegrity
	}
	out := Prediction{SchemaVersion: PredictionSchema, Implementation: Implementation, CaseID: verified.data.CaseID, CaptureHash: verified.hash, CaptureKeyFingerprint: digest(e.publicKey), ManifestHash: verified.data.ManifestHash, SourcePublicationHash: verified.data.Commitment.PublicationHash, SourceRuleVersion: verified.plan.Versions.Rule, Runtime: e.runtime.Ref(), Provenance: "development_controller_statement", TimingSource: "capture_observed", Limitations: []string{"MI_REPLAY_DEVELOPMENT_SOURCE_ONLY", "MI_REPLAY_NO_INDEPENDENT_ACCEPTANCE", "MI_REPLAY_CAPTURE_TIMING_NOT_REMEASURED", "MI_REPLAY_NO_TIMEOUT_RETRY_TRAILING_SUPPORT"}, Analysis: document}
	encoded, err := json.Marshal(out)
	defer clear(encoded)
	if err != nil || len(encoded) > MaxPredictionBytes {
		return Prediction{}, ErrLimit
	}
	return out, nil
}

func (e *Engine) input(ctx context.Context, v *verifiedCapture) (features.Input, error) {
	if v == nil {
		return features.Input{}, ErrIntegrity
	}
	d := v.data
	input := features.Input{Run: features.RunBinding{OrganizationID: d.OrganizationID, ID: d.RunID, Plan: v.plan, ExecutionClosedAt: d.ExecutionClosedAt}}
	for i, sample := range d.Samples {
		if ctx.Err() != nil {
			return features.Input{}, ErrCanceled
		}
		frozen := v.plan.Probes[i].Samples[0]
		attempt := sample.Attempts[0]
		response, snapshot, err := e.parse(ctx, frozen, v.plan.Target.MaxOutputParameter, attempt)
		if err != nil {
			return features.Input{}, err
		}
		evidence, err := features.NewEvidence(features.EvidenceScope{OrganizationID: d.OrganizationID, RunID: d.RunID, SampleID: sample.ID, AttemptID: attempt.ID, RequestHash: snapshot.RequestHash}, response)
		if err != nil {
			return features.Input{}, ErrIntegrity
		}
		finalID := sample.FinalAttemptID
		row := features.SampleBinding{OrganizationID: d.OrganizationID, RunID: d.RunID, ID: sample.ID, ProbeInstanceID: sample.ProbeInstanceID, Ordinal: sample.Ordinal, ExecutionOrdinal: sample.ExecutionOrdinal, RequestPlan: frozen, PairID: sample.PairID, AttemptCount: sample.AttemptCount, FinalAttemptID: &finalID, Validity: sample.Validity, CompletedAt: sample.CompletedAt, Attempts: []features.AttemptBinding{{OrganizationID: d.OrganizationID, RunID: d.RunID, SampleID: sample.ID, ID: attempt.ID, JobID: attempt.JobID, Number: attempt.Number, Status: attempt.Status, Validity: attempt.Validity, ErrorCode: attempt.ErrorCode, Snapshot: snapshot, RequestHash: attempt.RequestHash, StartedAt: attempt.StartedAt, FinishedAt: attempt.FinishedAt, Evidence: evidence}}}
		input.Samples = append(input.Samples, row)
	}
	return input, nil
}

func destroy(v *verifiedCapture) {
	if v == nil {
		return
	}
	clear(v.data.Manifest)
	clear(v.plan.Manifest)
	for _, sample := range v.data.Samples {
		for _, attempt := range sample.Attempts {
			clear(attempt.WirePayload)
			clear(attempt.Response.Body)
		}
	}
}
