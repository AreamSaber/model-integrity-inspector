package features

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/behavior"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/structure"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

type derivedScope struct {
	OrganizationID int64  `json:"organization_id"`
	RunID          int64  `json:"run_id"`
	SampleID       int64  `json:"sample_id"`
	ProbeID        int64  `json:"probe_id"`
	AttemptID      int64  `json:"attempt_id"`
	JobID          int64  `json:"job_id"`
	Number         int    `json:"number"`
	Ordinal        int    `json:"ordinal"`
	ManifestHash   string `json:"manifest_hash"`
	RequestHash    string `json:"request_hash"`
	OutcomeHash    string `json:"outcome_hash"`
}

type derivedExtractor struct {
	Features                string `json:"features"`
	Behavior                string `json:"behavior"`
	Structure               string `json:"structure"`
	Tokenizer               string `json:"tokenizer"`
	TokenizerImplementation string `json:"tokenizer_implementation"`
	TokenizerHash           string `json:"tokenizer_hash"`
	Template                string `json:"template"`
	TemplateHash            string `json:"template_hash"`
}

type derivedPayload struct {
	Version    string                    `json:"version"`
	Scope      derivedScope              `json:"scope"`
	Extractor  derivedExtractor          `json:"extractor"`
	SourceHash string                    `json:"source_hash"`
	Feature    SampleFeature             `json:"feature"`
	Usage      tokenizer.UsageComparison `json:"usage_comparison"`
	Behavior   []byte                    `json:"behavior_observation"`
}

func scopeFor(run RunBinding, row SampleBinding, a AttemptBinding) derivedScope {
	return derivedScope{run.OrganizationID, run.ID, row.ID, row.ProbeInstanceID, a.ID, a.JobID, a.Number, row.Ordinal, run.Plan.ManifestHash, a.RequestHash, digestJSON([]string{"mii/derived-outcome/v1", a.Status, a.Validity, a.ErrorCode})}
}

func (b *Builder) extractor() derivedExtractor {
	return derivedExtractor{Version, behavior.Version, structure.Version, b.tokens.Version(), tokenizer.ImplementationVersion, b.tokens.Hash(), b.version, b.hash}
}

func validDerivedHash(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	for _, c := range hash {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// DeriveAttempt is a trusted Worker memory boundary, NOT a DB authenticator.
// The run need not be execution-closed; the attempt's actual outcome is known,
// but no commit timestamp/final sample pointer is invented. Every restored
// attempt is later bound to the real committed rows by BuildDerived.
func (b *Builder) DeriveAttempt(ctx context.Context, run RunBinding, row SampleBinding, a AttemptBinding) (*PreparedDerived, error) {
	if ctx == nil || b == nil || b.verifier == nil || b.tokens == nil {
		return nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if run.OrganizationID <= 0 || run.ID <= 0 || len(run.Plan.Manifest) == 0 || len(run.Plan.Manifest) > 2<<20 {
		return nil, ErrBinding
	}
	m, err := b.verifier.Verify(run.Plan.Manifest, run.Plan.ManifestHash, run.OrganizationID)
	if err != nil || m.Options.AnalysisSourceVersion != DerivedVersion || m.TemplateHash != b.hash || m.TemplateVersion != b.version || m.TokenizerHash != b.tokens.Hash() || m.TokenizerVersion != b.tokens.Version() {
		return nil, ErrBinding
	}
	plan, err := b.verifier.ExecutionPlan(run.Plan.Manifest, run.Plan.ManifestHash, run.OrganizationID)
	if err != nil || !sameJSON(plan, run.Plan) || row.Ordinal < 0 || row.Ordinal >= len(m.Samples) || row.ExecutionOrdinal != row.Ordinal || row.OrganizationID != run.OrganizationID || row.RunID != run.ID || row.ID <= 0 || row.ProbeInstanceID <= 0 {
		return nil, ErrBinding
	}
	expected := plan.Probes[row.Ordinal].Samples[0]
	if !sameJSON(row.RequestPlan, expected) || row.PairID != m.Samples[row.Ordinal].PairID || a.OrganizationID != run.OrganizationID || a.RunID != run.ID || a.SampleID != row.ID || a.ID <= 0 || a.JobID <= 0 || a.Number < 1 || a.Number > plan.MaxRetries+1 || !validity(a.Validity) || (a.Status != "COMPLETED" && a.Status != "UNCERTAIN") || len(a.ErrorCode) > 128 {
		return nil, ErrBinding
	}
	adapter, err := openaichat.New(openaichat.Config{Endpoint: "https://analysis.invalid/v1", MaxOutputParameter: plan.Target.MaxOutputParameter, Doer: noNetwork{}})
	if err != nil {
		return nil, ErrBinding
	}
	_, snapshot, err := adapter.BuildRequest(ctx, expected.Request)
	if err != nil || a.RequestHash != snapshot.RequestHash || !sameSnapshot(a.Snapshot, snapshot) {
		return nil, ErrBinding
	}
	sourceHash, err := derivedSourceHash(run, row, a)
	if err != nil {
		return nil, err
	}
	// A private projection is used to invoke exactly the same per-final-attempt
	// extractor. The real persisted final pointer is never modified or assumed.
	row.Attempts, row.FinalAttemptID, row.Validity = []AttemptBinding{a}, &a.ID, a.Validity
	f, tokens, sample := b.sample(run, m, row)
	payload := derivedPayload{Version: DerivedVersion, Scope: scopeFor(run, row, a), Extractor: b.extractor(), SourceHash: sourceHash, Feature: f}
	if tokens != nil {
		payload.Usage = tokens.Usage
	}
	if sample != nil {
		observation, err := b.behavior.Derive(*sample)
		if err != nil {
			return nil, ErrBinding
		}
		payload.Behavior, err = observation.Canonical()
		if err != nil {
			return nil, ErrLimit
		}
	}
	canonical, err := json.Marshal(payload)
	if err != nil || len(canonical) > MaxDerivedBytes {
		clear(canonical)
		return nil, ErrLimit
	}
	if err := ctx.Err(); err != nil {
		clear(canonical)
		return nil, err
	}
	return &PreparedDerived{canonical}, nil
}

// BuildDerived accepts records only through their MAC-verifying capability.
// Every real attempt, including an explicit missing-response observation, is
// required. Unknown or missing provenance is a hard error, never a silent zero.
// The S2 frozen Plan is replayed transiently; it is not copied into S1 records.
func (b *Builder) BuildDerived(ctx context.Context, input Input, records []DerivedRecord, verifier *DerivedVerifier) (*Batch, error) {
	if ctx == nil || verifier == nil {
		return nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(records) > 450 {
		return nil, ErrLimit
	}
	count := 0
	for _, row := range input.Samples {
		for _, a := range row.Attempts {
			if a.Evidence != nil {
				return nil, ErrBinding
			}
			count++
		}
	}
	if count != len(records) {
		return nil, ErrBinding
	}
	// Reuse the complete raw-path persisted graph, final-pointer, temporal and
	// exact request checks before any observation can enter an aggregate.
	batch, err := b.build(input, DerivedVersion)
	if err != nil {
		return nil, err
	}
	m, err := b.verifier.Verify(input.Run.Plan.Manifest, input.Run.Plan.ManifestHash, input.Run.OrganizationID)
	if err != nil {
		return nil, ErrBinding
	}
	observations := make(map[int64]derivedPayload, len(records))
	resourceBytes := len(input.Run.Plan.Manifest)
	for _, record := range records {
		resourceBytes += len(record.Payload)
		if resourceBytes > MaxBatchBytes {
			return nil, ErrLimit
		}
		p, err := verifier.open(ctx, record)
		if err != nil {
			return nil, err
		}
		if p.Extractor != b.extractor() || p.Scope.AttemptID <= 0 || !validDerivedHash(p.SourceHash) {
			return nil, ErrBinding
		}
		if _, duplicate := observations[p.Scope.AttemptID]; duplicate {
			return nil, ErrBinding
		}
		observations[p.Scope.AttemptID] = p
	}
	ordered := make([]SampleBinding, len(input.Samples))
	for _, row := range input.Samples {
		ordered[row.Ordinal] = row
		for _, a := range row.Attempts {
			resourceBytes += len(a.Snapshot.Payload)
			if resourceBytes > MaxBatchBytes {
				return nil, ErrLimit
			}
			if p, ok := observations[a.ID]; !ok || p.Scope != scopeFor(input.Run, row, a) {
				return nil, ErrBinding
			}
		}
	}
	batch.features.Samples, batch.features.Limitations = []SampleFeature{}, []string{}
	batch.features.Included, batch.features.Excluded = 0, 0
	batch.features.Partial = m.Completeness != "COMPLETE"
	if batch.features.Partial {
		batch.features.Limitations = append(batch.features.Limitations, "MI_FEATURE_PLAN_REDUCED")
	}
	batch.tokens.Samples, batch.behavior = nil, []behavior.Sample{}
	batch.derivedBehavior, batch.useDerivedBehavior = []*behavior.Derived{}, true
	for _, row := range ordered {
		f, tokens, _ := b.sample(input.Run, m, row)
		if row.FinalAttemptID != nil {
			p := observations[*row.FinalAttemptID]
			f = p.Feature
			if err := b.restoreSample(m, row, p, tokens, batch); err != nil {
				return nil, err
			}
		}
		batch.features.Samples = append(batch.features.Samples, f)
		if tokens != nil {
			batch.tokens.Samples = append(batch.tokens.Samples, *tokens)
		}
		batch.includeFeature(f)
	}
	batch.tokens.Partial = batch.features.Partial
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return batch, nil
}

// BuildResponseReference is an explicit verification oracle, never an automatic
// fallback. It requires the complete authenticated derived record set before
// building a raw-response reference for the SAME signed derived-mode Run. All
// provided response fields and explicit no-response observations must match the
// authenticated source hashes, including non-final attempts. Without original
// responses for a recorded source, a response reference cannot be constructed.
func (b *Builder) BuildResponseReference(ctx context.Context, input Input, records []DerivedRecord, verifier *DerivedVerifier) (*Batch, error) {
	if ctx == nil {
		return nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(input.Samples) > 150 || len(records) > 450 {
		return nil, ErrLimit
	}
	// Clone only the slices we modify. All other projections are read-only and
	// Evidence itself owns its detached response; never clear the caller's input.
	bodyless := input
	bodyless.Samples = slices.Clone(input.Samples)
	count := 0
	for i := range bodyless.Samples {
		count += len(bodyless.Samples[i].Attempts)
		if count > 450 {
			return nil, ErrLimit
		}
		bodyless.Samples[i].Attempts = slices.Clone(input.Samples[i].Attempts)
		for j := range bodyless.Samples[i].Attempts {
			bodyless.Samples[i].Attempts[j].Evidence = nil
		}
	}
	if _, err := b.BuildDerived(ctx, bodyless, records, verifier); err != nil {
		return nil, err
	}
	// The shared core also enforces the complete raw byte budget before the
	// source-hash comparisons below. Never release this reference on mismatch.
	batch, err := b.build(input, DerivedVersion)
	if err != nil {
		return nil, err
	}
	sources := make(map[int64]string, len(records))
	for _, record := range records {
		p, err := verifier.open(ctx, record)
		if err != nil {
			return nil, err
		}
		sources[p.Scope.AttemptID] = p.SourceHash
	}
	for _, row := range input.Samples {
		for _, a := range row.Attempts {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			sourceHash, err := derivedSourceHash(input.Run, row, a)
			if err != nil || sourceHash != sources[a.ID] {
				return nil, ErrBinding
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return batch, nil
}

func derivedSourceHash(run RunBinding, row SampleBinding, a AttemptBinding) (string, error) {
	if a.Evidence == nil {
		return digestJSON([]string{"mii/derived-source/v1", a.RequestHash, "no_response"}), nil
	}
	if a.Evidence.scope != (EvidenceScope{run.OrganizationID, run.ID, row.ID, a.ID, a.RequestHash}) || !responseBounded(a.Evidence.response) {
		return "", ErrBinding
	}
	encoded, err := json.Marshal(a.Evidence.response)
	defer clear(encoded)
	if err != nil || len(encoded) > MaxResponseBytes {
		return "", ErrLimit
	}
	return digestJSON([]string{"mii/derived-source/v1", a.RequestHash, digest(encoded)}), nil
}

func (b *Builder) restoreSample(m generator.Manifest, row SampleBinding, p derivedPayload, t *tokenrisk.Sample, batch *Batch) error {
	if t == nil || p.Feature.SampleID != strconv.FormatInt(row.ID, 10) || p.Feature.AttemptID != strconv.FormatInt(t.AttemptID, 10) || p.Feature.AttemptNumber != t.AttemptNumber {
		return ErrBinding
	}
	f := p.Feature
	signed := m.Samples[row.Ordinal]
	if !validity(f.Validity) || f.Ordinal != row.Ordinal || f.Family != signed.Family || f.Language != signed.Language || f.TemplateID != signed.TemplateID || f.TemplateVersion != signed.TemplateVersion || f.ManifestRequestHash != signed.RequestHash || f.WireRequestHash != p.Scope.RequestHash || f.RequestedMaxTokens != signed.MaxOutputTokens || f.Stream != signed.Stream || f.AuxiliaryOnly != signed.AuxiliaryOnly || f.ConditionHash != t.ConditionID || f.ClusterHash != t.GroupID {
		return ErrBinding
	}
	pairHash := ""
	if signed.PairID != "" {
		pairHash = digestJSON([]string{Version, signed.PairID})
	}
	if f.PairHash != pairHash {
		return ErrBinding
	}
	t.Validity, t.SeriesID, t.ReasoningUnseparated = tokenrisk.Validity(f.Validity), f.SeriesHash, f.ReasoningUnseparated
	t.Usage = p.Usage
	if f.Local != nil {
		t.Local = *f.Local
	}
	if f.Structure != nil {
		if f.Structure.Version != structure.Version {
			return ErrBinding
		}
		t.Structure = *f.Structure
	}
	if f.SeriesHash != seriesHash(m, signed, row.RequestPlan.Request, t.Local) {
		return ErrBinding
	}
	if f.Protocol != nil {
		t.ProtocolChecked, t.ProtocolAnomaly = true, f.Protocol.Partial || len(f.Protocol.Warnings) > 0
	}
	if f.Behavior == nil {
		if len(p.Behavior) != 0 {
			return ErrBinding
		}
		return nil
	}
	if len(p.Behavior) == 0 {
		return ErrBinding
	}
	observation, err := behavior.DecodeAuthenticatedDerived(p.Behavior)
	if err != nil {
		return ErrBinding
	}
	var a AttemptBinding
	for _, attempt := range row.Attempts {
		if attempt.ID == *row.FinalAttemptID {
			a = attempt
		}
	}
	sample := makeBehavior(m, m.Samples[row.Ordinal], row, a, f.Validity, "")
	if b.behavior.VerifyDerivedBinding(sample, observation, *f.Behavior) != nil {
		return ErrBinding
	}
	batch.behavior = append(batch.behavior, sample)
	batch.derivedBehavior = append(batch.derivedBehavior, observation)
	t.SuffixChecked = f.Behavior.State == behavior.Analyzed && f.Behavior.Contract != behavior.ContractNotApplicable
	for _, evidence := range f.Behavior.Evidence {
		if evidence.Kind == behavior.Suffix && evidence.Candidate {
			t.SuffixFingerprint = evidence.NormalizedSHA256
			break
		}
	}
	return nil
}

func (b *Batch) includeFeature(feature SampleFeature) {
	if feature.Included {
		b.features.Included++
	} else {
		b.features.Excluded++
	}
	if !feature.Included && !feature.AuxiliaryOnly {
		b.features.Partial = true
	}
	for _, limitation := range feature.Limitations {
		if !slices.Contains(b.features.Limitations, limitation) {
			b.features.Limitations = append(b.features.Limitations, limitation)
		}
	}
}
