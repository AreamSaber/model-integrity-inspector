package features

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/behavior"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

type Builder struct {
	verifier *generator.Generator
	tokens   *tokenizer.Engine
	behavior *behavior.Engine
	hash     string
	version  string
}

func New(config Config) (*Builder, error) {
	if config.Verifier == nil || config.Tokenizer == nil || config.Tokenizer.Hash() != tokenizer.BuiltinHash || config.Tokenizer.Version() != tokenizer.BuiltinVersion || len(config.TemplateArtifact) > 1<<20 {
		return nil, ErrConfiguration
	}
	bundle, err := templates.Decode(config.TemplateArtifact, config.TrustedTemplateHash)
	if err != nil {
		return nil, ErrConfiguration
	}
	catalog, err := behavior.VerifyCatalog(config.TemplateArtifact, config.TrustedTemplateHash)
	if err != nil {
		return nil, ErrConfiguration
	}
	engine, err := behavior.New(catalog)
	if err != nil {
		return nil, ErrConfiguration
	}
	return &Builder{config.Verifier, config.Tokenizer, engine, config.TrustedTemplateHash, bundle.Version}, nil
}

// Build does not open a database or network connection. It replays the signed
// Manifest, then checks every persisted identity and both request encodings.
// Missing evidence is a partial observation; broken identity is a hard error.
func (b *Builder) Build(input Input) (*Batch, error) {
	if b == nil || b.verifier == nil || b.tokens == nil {
		return nil, ErrConfiguration
	}
	run := input.Run
	if run.OrganizationID <= 0 || run.ID <= 0 || run.ExecutionClosedAt.IsZero() || len(run.Plan.Manifest) == 0 || len(run.Plan.Manifest) > 2<<20 || len(input.Samples) > 150 {
		return nil, ErrBinding
	}
	m, err := b.verifier.Verify(run.Plan.Manifest, run.Plan.ManifestHash, run.OrganizationID)
	if err != nil || m.TemplateHash != b.hash || m.TemplateVersion != b.version || m.TokenizerHash != b.tokens.Hash() || m.TokenizerVersion != b.tokens.Version() {
		return nil, ErrBinding
	}
	plan, err := b.verifier.ExecutionPlan(run.Plan.Manifest, run.Plan.ManifestHash, run.OrganizationID)
	if err != nil || len(input.Samples) != len(m.Samples) || !sameJSON(run.Plan, plan) {
		return nil, ErrBinding
	}
	adapter, err := openaichat.New(openaichat.Config{Endpoint: "https://analysis.invalid/v1", MaxOutputParameter: plan.Target.MaxOutputParameter, Doer: noNetwork{}})
	if err != nil {
		return nil, ErrBinding
	}
	ordered := make([]SampleBinding, len(m.Samples))
	seenSamples, seenProbes, seenAttempts, seenOrdinals := map[int64]bool{}, map[int64]bool{}, map[int64]bool{}, map[int]bool{}
	resourceBytes := len(run.Plan.Manifest)
	for _, sample := range input.Samples {
		if sample.OrganizationID != run.OrganizationID || sample.RunID != run.ID || sample.ID <= 0 || sample.ProbeInstanceID <= 0 || sample.Ordinal < 0 || sample.Ordinal >= len(m.Samples) || sample.ExecutionOrdinal != sample.Ordinal || seenSamples[sample.ID] || seenProbes[sample.ProbeInstanceID] || seenOrdinals[sample.Ordinal] || sample.CompletedAt.IsZero() || sample.CompletedAt.After(run.ExecutionClosedAt) || !validity(sample.Validity) || sample.AttemptCount != len(sample.Attempts) || sample.AttemptCount > plan.MaxRetries+1 {
			return nil, ErrBinding
		}
		seenSamples[sample.ID], seenProbes[sample.ProbeInstanceID], seenOrdinals[sample.Ordinal] = true, true, true
		signed := m.Samples[sample.Ordinal]
		expected := plan.Probes[sample.Ordinal].Samples[0]
		if sample.PairID != signed.PairID || !sameJSON(sample.RequestPlan, expected) {
			return nil, ErrBinding
		}
		_, snapshot, err := adapter.BuildRequest(context.Background(), expected.Request)
		if err != nil {
			return nil, ErrBinding
		}
		selected := false
		seenNumbers := map[int]bool{}
		for _, attempt := range sample.Attempts {
			if attempt.OrganizationID != run.OrganizationID || attempt.RunID != run.ID || attempt.SampleID != sample.ID || attempt.ID <= 0 || attempt.JobID <= 0 || seenAttempts[attempt.ID] || attempt.Number < 1 || attempt.Number > sample.AttemptCount || seenNumbers[attempt.Number] || (attempt.Status != "COMPLETED" && attempt.Status != "UNCERTAIN") || !validity(attempt.Validity) || attempt.StartedAt.IsZero() || attempt.FinishedAt.Before(attempt.StartedAt) || attempt.FinishedAt.After(sample.CompletedAt) || attempt.RequestHash != snapshot.RequestHash || !sameSnapshot(attempt.Snapshot, snapshot) {
				return nil, ErrBinding
			}
			seenAttempts[attempt.ID], seenNumbers[attempt.Number] = true, true
			if attempt.Number < sample.AttemptCount && (attempt.Status != "COMPLETED" || attempt.Validity != "INVALID_RETRYABLE") {
				return nil, ErrBinding
			}
			resourceBytes += len(attempt.Snapshot.Payload)
			if attempt.Evidence != nil {
				if attempt.Evidence.scope != (EvidenceScope{run.OrganizationID, run.ID, sample.ID, attempt.ID, snapshot.RequestHash}) || !responseBounded(attempt.Evidence.response) {
					return nil, ErrBinding
				}
				encoded, err := json.Marshal(attempt.Evidence.response)
				size := len(encoded)
				clear(encoded)
				if err != nil || size > MaxResponseBytes {
					return nil, ErrLimit
				}
				resourceBytes += size
			}
			if resourceBytes > MaxBatchBytes {
				return nil, ErrLimit
			}
			if sample.FinalAttemptID != nil && attempt.ID == *sample.FinalAttemptID {
				if selected || attempt.Number != sample.AttemptCount || attempt.Validity != sample.Validity {
					return nil, ErrBinding
				}
				selected = true
			}
		}
		if (sample.FinalAttemptID != nil && !selected) || (sample.FinalAttemptID == nil && sample.Validity != "NOT_APPLICABLE") {
			return nil, ErrBinding
		}
		ordered[sample.Ordinal] = sample
	}
	batch := &Batch{engine: b.behavior, features: Result{Version: Version, OrganizationID: strconv.FormatInt(run.OrganizationID, 10), RunID: strconv.FormatInt(run.ID, 10), ManifestHash: plan.ManifestHash, Expected: len(m.Samples), Samples: []SampleFeature{}, Limitations: []string{}}, tokens: tokenrisk.Input{OrganizationID: run.OrganizationID, RunID: run.ID, ExpectedSamples: len(m.Samples)}, behavior: []behavior.Sample{}}
	batch.templateHash, batch.tokenizerHash = m.TemplateHash, m.TokenizerHash
	if m.Options.MaxOutputTokens > 0 {
		value := int64(m.Options.MaxOutputTokens)
		batch.tokens.DeclaredModelOutputLimit = &value
	}
	if m.Completeness != "COMPLETE" {
		batch.features.Partial = true
		batch.features.Limitations = append(batch.features.Limitations, "MI_FEATURE_PLAN_REDUCED")
	}
	for _, sample := range ordered {
		feature, tokens, behaviorSample := b.sample(run, m, sample)
		batch.features.Samples = append(batch.features.Samples, feature)
		if tokens != nil {
			batch.tokens.Samples = append(batch.tokens.Samples, *tokens)
		}
		if behaviorSample != nil {
			batch.behavior = append(batch.behavior, *behaviorSample)
		}
		if feature.Included {
			batch.features.Included++
		} else {
			batch.features.Excluded++
		}
		if !feature.Included && !feature.AuxiliaryOnly {
			batch.features.Partial = true
		}
		for _, limitation := range feature.Limitations {
			if !slices.Contains(batch.features.Limitations, limitation) {
				batch.features.Limitations = append(batch.features.Limitations, limitation)
			}
		}
	}
	batch.tokens.Partial = batch.features.Partial
	return batch, nil
}

// The real target is checked against the full signed Plan above. This constant
// URL is used ONLY for deterministic body serialization, without contemporary
// endpoint policy changing historical facts. Do is prohibited even by mistake.
type noNetwork struct{}

func (noNetwork) Do(*http.Request) (*http.Response, error) { return nil, ErrConfiguration }

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func digestJSON(value any) string {
	data, _ := json.Marshal(value)
	defer clear(data)
	return digest(data)
}
func sameJSON(a, b any) bool {
	left, err := json.Marshal(a)
	if err != nil || len(left) > MaxBatchBytes {
		return false
	}
	defer clear(left)
	right, err := json.Marshal(b)
	defer clear(right)
	return err == nil && bytes.Equal(left, right)
}
func sameSnapshot(a, b domain.RequestSnapshot) bool {
	return a.Model == b.Model && a.Stream == b.Stream && a.MaxOutputTokens == b.MaxOutputTokens && a.MaxOutputParameter == b.MaxOutputParameter && a.PayloadBytes == b.PayloadBytes && a.RequestHash == b.RequestHash && bytes.Equal(a.Payload, b.Payload)
}
func validity(s string) bool {
	return slices.Contains([]string{"VALID", "VALID_WITH_WARNING", "INVALID_RETRYABLE", "INVALID_PROTOCOL", "INVALID_SAFETY_LIMIT", "NOT_APPLICABLE"}, s)
}
