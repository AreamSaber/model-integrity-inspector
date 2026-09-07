package features

import (
	"errors"
	"strconv"
	"strings"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/behavior"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/structure"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func (b *Builder) sample(run RunBinding, m generator.Manifest, row SampleBinding) (SampleFeature, *tokenrisk.Sample, *behavior.Sample) {
	s := m.Samples[row.Ordinal]
	f := SampleFeature{SampleID: strconv.FormatInt(row.ID, 10), Ordinal: row.Ordinal, Validity: row.Validity, Family: s.Family, Language: s.Language, TemplateID: s.TemplateID, TemplateVersion: s.TemplateVersion, ConditionHash: digestJSON([]string{Version, s.ConditionID}), ClusterHash: digestJSON(struct {
		Version  string
		Org, Run int64
		Group    string
	}{Version, run.OrganizationID, run.ID, s.GroupID}), ManifestRequestHash: s.RequestHash, RequestedMaxTokens: s.MaxOutputTokens, Stream: s.Stream, AuxiliaryOnly: s.AuxiliaryOnly, Limitations: []string{}}
	if s.PairID != "" {
		f.PairHash = digestJSON([]string{Version, s.PairID})
	}
	var selected *AttemptBinding
	for i := range row.Attempts {
		if row.FinalAttemptID != nil && row.Attempts[i].ID == *row.FinalAttemptID {
			selected = &row.Attempts[i]
		}
	}
	unavailable := tokenizer.Estimate{Quality: tokenizer.Unavailable, Scope: "visible_output", BundleVersion: b.tokens.Version(), BundleHash: b.tokens.Hash()}
	f.SeriesHash = seriesHash(m, s, row.RequestPlan.Request, unavailable)
	if selected == nil {
		f.Limitations = append(f.Limitations, "MI_FEATURE_FINAL_ATTEMPT_MISSING")
		return f, nil, nil
	}
	a := *selected
	f.AttemptID, f.AttemptNumber, f.WireRequestHash = strconv.FormatInt(a.ID, 10), a.Number, a.RequestHash
	t := &tokenrisk.Sample{ID: row.ID, AttemptID: a.ID, FinalAttemptID: a.ID, AttemptNumber: a.Number, Validity: tokenrisk.Validity(f.Validity), Family: s.Family, Language: s.Language, TemplateID: s.TemplateID, TemplateVersion: s.TemplateVersion, Variant: s.Variant, ConditionID: f.ConditionHash, SeriesID: f.SeriesHash, GroupID: f.ClusterHash, Repetition: s.Repetition, Seed: s.Seed, RequestedMaxTokens: int64(s.MaxOutputTokens), Stream: s.Stream, AuxiliaryOnly: s.AuxiliaryOnly, Local: unavailable}
	for _, code := range []string{"MI_NETWORK_TEMPORARY", "MI_CONNECTION_RESET", "MI_TIMEOUT", "MI_SERVICE_UNAVAILABLE"} {
		if a.ErrorCode == code {
			t.NetworkFailure = true
		}
	}
	// An old uncertain request is never promoted by the mere presence of text.
	if a.Status == "UNCERTAIN" {
		f.Validity, t.Validity = "INVALID_RETRYABLE", tokenrisk.InvalidRetryable
		f.Limitations = append(f.Limitations, "MI_FEATURE_ATTEMPT_UNCERTAIN")
		return f, t, nil
	}
	if a.Evidence == nil {
		f.Validity, t.Validity = "NOT_APPLICABLE", tokenrisk.NotApplicable
		f.Limitations = append(f.Limitations, "MI_FEATURE_EVIDENCE_MISSING")
		return f, t, nil
	}
	if a.Validity != "VALID" && a.Validity != "VALID_WITH_WARNING" {
		code := "MI_FEATURE_FINAL_ATTEMPT_INVALID"
		if a.Validity == "INVALID_SAFETY_LIMIT" {
			code = "MI_FEATURE_SAFETY_LIMIT"
		}
		f.Limitations = append(f.Limitations, code)
		return f, t, nil
	}
	r := a.Evidence.response
	if !protocolValid(r, s.Stream) {
		f.Validity, t.Validity = "INVALID_PROTOCOL", tokenrisk.InvalidProtocol
		f.Limitations = append(f.Limitations, "MI_FEATURE_PROTOCOL_INVALID")
		return f, t, nil
	}
	warnings := protocolWarnings(r.ParseWarnings)
	if r.ParseStatus == "partial" || len(warnings) > 0 {
		f.Validity, t.Validity = "VALID_WITH_WARNING", tokenrisk.ValidWithWarning
	}
	f.Protocol = &ProtocolFeature{HTTPStatus: r.HTTPStatus, Partial: r.ParseStatus == "partial", StreamTerminated: r.StreamTerminated, ModelMismatch: r.ModelReported != "" && r.ModelReported != m.Options.Target.Model, DurationMillis: r.DurationMs, FirstByteMillis: r.FirstByteMs, FirstTokenMillis: r.FirstTokenMs, ChunkCount: r.StreamChunkCount, Warnings: warnings}
	f.Protocol.State = "valid"
	if r.ParseStatus == "partial" || len(warnings) > 0 {
		f.Protocol.State = "valid_with_warning"
	}
	f.Protocol.ModelEcho = "matches"
	if r.ModelReported == "" {
		f.Protocol.ModelEcho = "unavailable"
	} else if f.Protocol.ModelMismatch {
		f.Protocol.ModelEcho = "differs"
	}
	t.ProtocolChecked = true
	t.ProtocolAnomaly = len(warnings) > 0 || r.ParseStatus == "partial"
	local, err := b.tokens.CountOutput(r.Content, tokenizer.Selection{ReportedModel: r.ModelReported, RequestedModel: m.Options.Target.Model, StandardModel: m.Options.StandardModel})
	if err != nil {
		f.Validity, t.Validity = "INVALID_SAFETY_LIMIT", tokenrisk.InvalidSafetyLimit
		f.Limitations = append(f.Limitations, "MI_FEATURE_TOKENIZER_LIMIT")
		return f, t, nil
	}
	f.Local, t.Local = &local, local
	f.SeriesHash = seriesHash(m, s, row.RequestPlan.Request, local)
	t.SeriesID = f.SeriesHash
	if local.Quality == tokenizer.Heuristic || local.Quality == tokenizer.Unavailable {
		f.Limitations = append(f.Limitations, "MI_FEATURE_TOKENIZER_APPROXIMATE")
	}
	comparison := tokenizer.CompareUsage(r, local, m.Options.ReasoningModel)
	t.Usage = comparison
	t.ReasoningUnseparated = m.Options.ReasoningModel && r.ReasoningTokens == nil
	f.ReasoningUnseparated = t.ReasoningUnseparated
	f.Usage = &UsageFeature{ReportedPrompt: r.PromptTokens, ReportedCompletion: r.CompletionTokens, ReportedTotal: r.TotalTokens, ReportedReasoning: r.ReasoningTokens, Available: comparison.Available, Direction: comparison.Direction, Band: comparison.Band, Eligible: comparison.EligibleForAggregate, ReasoningSeparated: comparison.ReasoningSeparated}
	if comparison.Available {
		value := comparison.RelativeError
		f.Usage.RelativeError = &value
	}
	if comparison.Warning != "" {
		f.Limitations = append(f.Limitations, comparison.Warning)
	}
	contract := structure.Contract{Kind: structure.Text}
	builtin := m.TemplateHash == templates.BuiltinHash && m.TemplateVersion == templates.BuiltinVersion
	if builtin {
		switch s.Family {
		case "sequence":
			contract = structure.Contract{Kind: structure.Sequence, SequencePrefix: s.Variables.Nonce, FirstNumber: 1, ExpectedUnits: int64(s.Variables.Count)}
		case "jsonl":
			contract = structure.Contract{Kind: structure.JSONL, FirstNumber: 1, ExpectedUnits: int64(s.Variables.Count), JSONNumberKey: "n"}
		case "format":
			if s.Variant == 3 {
				contract.Kind = structure.JSON
			}
		}
	} else {
		f.Limitations = append(f.Limitations, "MI_FEATURE_CONTRACT_UNSUPPORTED")
	}
	shape, err := structure.Analyze(structure.Input{Content: r.Content, Contract: contract, FinishReason: r.FinishReason, RequestedMaxTokens: int64(s.MaxOutputTokens), LocalCompletionTokens: local.Tokens, TokenizerQuality: local.Quality, Stream: s.Stream, StreamTerminated: r.StreamTerminated, ReasoningModel: m.Options.ReasoningModel, ReasoningTokens: r.ReasoningTokens, Refusal: r.Refusal, EndCause: r.EndCause})
	if err != nil || shape.LimitExceeded {
		f.Validity, t.Validity = "INVALID_SAFETY_LIMIT", tokenrisk.InvalidSafetyLimit
		code := "MI_FEATURE_STRUCTURE_INVALID"
		if errors.Is(err, structure.ErrLimit) || shape.LimitExceeded {
			code = "MI_FEATURE_STRUCTURE_LIMIT"
		}
		f.Limitations = append(f.Limitations, code)
		return f, t, nil
	}
	f.Structure, t.Structure = &shape, shape
	if r.Refusal || shape.FinishReason == "CONTENT_FILTER" || shape.FinishReason == "TOOL_CALL" {
		f.Validity, t.Validity = "NOT_APPLICABLE", tokenrisk.NotApplicable
		f.Limitations = append(f.Limitations, "MI_FEATURE_TERMINATION_NOT_APPLICABLE")
		return f, t, nil
	}
	f.Included = !s.AuxiliaryOnly
	if s.AuxiliaryOnly {
		f.Limitations = append(f.Limitations, "MI_FEATURE_AUXILIARY_ONLY")
	}
	if !builtin {
		return f, t, nil
	}
	behaviorSample := makeBehavior(m, s, row, a, f.Validity, r.Content)
	if len(r.Content) > behavior.MaxTextBytes {
		f.Limitations = append(f.Limitations, "MI_FEATURE_BEHAVIOR_LIMIT")
		return f, t, nil
	}
	bf, err := b.behavior.Analyze(behaviorSample)
	if err != nil {
		f.Limitations = append(f.Limitations, "MI_FEATURE_BEHAVIOR_INVALID")
		return f, t, nil
	}
	f.Behavior = &bf
	t.SuffixChecked = bf.State == behavior.Analyzed && bf.Contract != behavior.ContractNotApplicable
	for _, evidence := range bf.Evidence {
		if evidence.Kind == behavior.Suffix && evidence.Candidate {
			t.SuffixFingerprint = evidence.NormalizedSHA256
			break
		}
	}
	return f, t, &behaviorSample
}

// Series identity includes fixed template/locale/request/tokenizer parameters,
// not varying cap, stream arm, repetition, seed or nonce. A different actual
// tokenizer mapping creates a different series instead of pooling unlike counts.
func seriesHash(m generator.Manifest, s generator.Sample, request domain.NormalizedRequest, local tokenizer.Estimate) string {
	return digestJSON(struct {
		Version, TemplateHash, TemplateID, TemplateVersion, Family, Language string
		Variant                                                              int
		Protocol, Model, StandardModel, OutputParameter, Style               string
		Temperature, TopP                                                    *float64
		Stop                                                                 []string
		Format                                                               *domain.ResponseFormat
		Extras                                                               map[string]any
		TokenizerID, TokenizerVersion, TokenizerHash                         string
		Quality                                                              tokenizer.Quality
	}{Version, m.TemplateHash, s.TemplateID, s.TemplateVersion, s.Family, s.Language, s.Variant, m.Options.Target.Protocol, request.Model, m.Options.StandardModel, m.Options.Target.MaxOutputParameter, s.Variables.Style, request.Temperature, request.TopP, request.Stop, request.ResponseFormat, request.ExtraAllowedParams, local.TokenizerID, local.TokenizerVersion, m.TokenizerHash, local.Quality})
}

func makeBehavior(m generator.Manifest, s generator.Sample, row SampleBinding, a AttemptBinding, validity, content string) behavior.Sample {
	contract := behavior.Contract{Kind: behavior.NoContract}
	switch s.Family {
	case "format", "differential":
		contract = behavior.Contract{Kind: behavior.Exact, Expected: s.Variables.Nonce}
		if s.Family == "format" && s.Variant == 3 {
			contract.Kind, contract.Key = behavior.JSONField, s.Variables.Label
		}
	case "neutral":
		contract = behavior.Contract{Kind: behavior.Exact, Expected: strings.ToUpper(s.Variables.Nonce)}
	}
	out := behavior.Sample{ID: row.ID, Template: behavior.TemplateRef{ID: s.TemplateID, Version: s.TemplateVersion, SHA256: m.TemplateHash}, Contract: contract, Variables: []string{s.Variables.Nonce, s.Variables.Label}, Attempts: []behavior.Attempt{{ID: a.ID, Number: a.Number, Validity: behavior.Validity(validity), Content: content}}, FinalAttemptID: a.ID, AuxiliaryOnly: s.AuxiliaryOnly}
	if s.PairID != "" {
		// Only the compiler's surface contrast is supported. Contract semantics
		// and fixed settings remain bound; template variant is the planned change.
		comparable := row.RequestPlan.Request
		comparable.Messages = nil
		hash := digestJSON(struct {
			Version, TemplateHash, Family, Language, Pair, Nonce, Label string
			Request                                                     domain.NormalizedRequest
		}{Version, m.TemplateHash, s.Family, s.Language, s.PairID, s.Variables.Nonce, s.Variables.Label, comparable})
		out.Pair = behavior.Pair{ID: s.PairID, Arm: behavior.Arm(s.Arm), Contrast: behavior.SurfaceContrast, ComparableSHA256: hash}
	}
	return out
}
