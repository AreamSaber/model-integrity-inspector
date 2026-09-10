package run

import (
	"encoding/json"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/report"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

type frozenReport struct {
	Versions report.Versions `json:"versions"`
	Input    report.Input    `json:"input"`
}

// BuildReportSnapshot accepts only a private leased repository source. Existing
// result validators project its single database snapshot; no service re-reads.
// Returned encoded bytes are internal S1 storage, never an HTTP request/response.
func BuildReportSnapshot(source *repository.ReportSource) (*report.Snapshot, []byte, error) {
	if source == nil {
		return nil, nil, repository.ErrReportInvalid
	}
	bound := source.Scope()
	var frozen frozenReport
	var encoded []byte
	err := source.Use(func(data repository.PublishedRead, stored []byte) error {
		if len(stored) > 0 {
			if err := strictDocument(string(stored), report.MaxInputBytes, &frozen); err != nil {
				return err
			}
			encoded = stored
			return nil
		}
		var err error
		frozen, err = reportProjection(data, bound)
		if err != nil {
			return err
		}
		encoded, err = json.Marshal(frozen)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	scope := report.Scope{ReportID: decimal(bound.ReportID), OrganizationID: decimal(bound.OrganizationID), RunID: decimal(bound.RunID), AnalysisRevision: bound.AnalysisRevision, GeneratedAt: bound.GeneratedAt, Versions: frozen.Versions}
	snapshot, err := report.NewDevelopmentSnapshot(scope, frozen.Input)
	if err != nil {
		return nil, nil, err
	}
	return snapshot, encoded, nil
}

func reportProjection(data repository.PublishedRead, bound repository.ReportScope) (frozenReport, error) {
	if data.Run.OrganizationID != bound.OrganizationID || data.Run.ID != bound.RunID || data.Result.AnalysisRevision != bound.AnalysisRevision || data.Run.FinishedAt == nil {
		return frozenReport{}, repository.ErrReportInvalid
	}
	doc, err := decodePublished(data)
	if err != nil {
		return frozenReport{}, err
	}
	history, err := historyItem(data.Run)
	if err != nil {
		return frozenReport{}, err
	}
	summary, err := summary(bound.AnalysisRevision, data.Result.OverallRisk, data.Result.Confidence, data.Result.RiskLevel, data.Result.EvidenceGrade, data.Result.Completeness)
	if err != nil {
		return frozenReport{}, err
	}
	tokens, behavior, err := statisticsViews(doc)
	if err != nil {
		return frozenReport{}, err
	}
	findings, err := findingsViews(data, doc, bound.OrganizationID, bound.RunID, bound.AnalysisRevision, repository.ListOptions{Limit: 256})
	if err != nil {
		return frozenReport{}, err
	}
	v := history.Versions
	frozen := frozenReport{Versions: report.Versions{Rule: v.Rule, Template: v.Template, Scoring: v.Scoring, Tokenizer: v.Tokenizer}}
	in := &frozen.Input
	in.Run = report.Run{ID: history.ID, TargetID: history.TargetID, Package: history.Package, CreatedAt: history.CreatedAt, StartedAt: history.StartedAt, FinishedAt: *history.FinishedAt, RequestCount: history.RequestCount, TokenCount: history.TokenCount, EstimatedCostMicros: history.EstimatedCostMicros}
	in.Result = report.Result{RunID: decimal(bound.RunID), AnalysisRevision: bound.AnalysisRevision, Versions: frozen.Versions, ExpectedSamples: doc.Scores.ExpectedSamples, ValidSamples: doc.Scores.ValidSamples, OverallRisk: summary.OverallRisk, PromptRisk: data.Result.PromptRisk, TokenRisk: data.Result.TokenRisk, ResponseRisk: data.Result.ResponseRisk, EvidenceRisk: data.Result.EvidenceRisk, Confidence: summary.Confidence, EvidenceGrade: summary.EvidenceGrade, RiskLevel: summary.RiskLevel, Completeness: summary.Completeness, Limitations: safeCodes(doc.Scores.Limitations)}
	if tokens != nil {
		t := &report.TokenStatistics{UsageSamples: tokens.UsageSamples, StreamPairs: tokens.StreamPairs, Limitations: tokens.Limitations}
		if t.UsageSamples > 0 {
			t.UsageMedianError = &tokens.UsageMedianRelativeError
		}
		if t.StreamPairs > 0 {
			t.StreamMedianDifference = &tokens.StreamMedianRelativeDifference
		}
		for _, x := range tokens.Tiers {
			t.Tiers = append(t.Tiers, report.Tier{SeriesID: x.SeriesID, Family: x.Family, Language: x.Language, RequestedMaxTokens: x.RequestedMaxTokens, Samples: x.Samples, Median: x.Median, MAD: x.MAD, RobustCV: x.RobustCV})
		}
		for _, x := range tokens.Plateaus {
			t.Plateaus = append(t.Plateaus, report.Plateau{SeriesID: x.SeriesID, Family: x.Family, LowRequested: x.LowRequested, HighRequested: x.HighRequested, GrowthRatio: x.GrowthRatio, Strength: x.Strength, Candidate: x.Candidate, Limited: x.Limited, Paired: x.Paired, Lower: x.Lower, Upper: x.Upper, IndependentGroups: x.IndependentGroups, Limitations: x.Limitations, SampleRefs: x.SampleRefs})
		}
		in.Result.Token = t
	}
	if behavior != nil {
		b := &report.BehaviorStatistics{AnalyzedSamples: behavior.AnalyzedSamples, AuxiliarySamples: behavior.AuxiliarySamples, Limitations: behavior.Limitations}
		for _, x := range behavior.Patterns {
			b.Patterns = append(b.Patterns, report.Pattern{Kind: x.Kind, Fingerprint: x.Fingerprint, State: x.State, FamilyCount: x.FamilyCount, TemplateCount: x.TemplateCount, LanguageCount: x.LanguageCount, SampleRefs: x.SampleRefs})
		}
		for _, x := range behavior.Differences {
			b.Differences = append(b.Differences, report.Difference{Metric: x.Metric, State: x.State, Pairs: x.Pairs, EffectSize: x.EffectSize, PValue: x.PValue, AdjustedP: x.AdjustedP})
		}
		in.Result.Behavior = b
	}
	for _, x := range findings {
		f := report.Finding{ID: x.ID, RunID: x.RunID, AnalysisRevision: x.AnalysisRevision, Category: x.Category, RuleID: x.RuleID, RuleVersion: x.RuleVersion, Severity: x.Severity, RiskScore: x.RiskScore, Confidence: x.Confidence, EvidenceGrade: x.EvidenceGrade, Alternatives: x.AlternativeExplanations, SampleRefs: x.SampleRefs}
		for _, s := range x.Statistics {
			f.Statistics = append(f.Statistics, report.Statistic{Name: s.Name, Actual: s.Actual, Unit: s.Unit})
		}
		in.Findings = append(in.Findings, f)
	}
	featureByID := map[string]features.SampleFeature{}
	for _, f := range doc.Features.Samples {
		featureByID[f.SampleID] = f
	}
	attemptsBySample := map[int64][]repository.ResultAttemptRecord{}
	for _, a := range data.Attempts {
		attemptsBySample[a.LogicalSampleID] = append(attemptsBySample[a.LogicalSampleID], a)
	}
	for _, row := range data.Samples {
		f, found := featureByID[decimal(row.ID)]
		if !found {
			return frozenReport{}, repository.ErrResultDocument
		}
		attempts, err := attemptsViews(attemptsBySample[row.ID], bound.OrganizationID, bound.RunID, row.ID)
		if err != nil || len(attempts) != row.AttemptCount {
			return frozenReport{}, repository.ErrResultDocument
		}
		x := sampleView(bound.RunID, row, f)
		s := report.Sample{ID: x.ID, RunID: x.RunID, ProbeInstanceID: x.ProbeInstanceID, Ordinal: x.Ordinal, Family: x.Family, Language: x.Language, Validity: x.Validity, Included: x.Included, AuxiliaryOnly: x.AuxiliaryOnly, RequestedMaxTokens: x.RequestedMaxTokens, LocalCompletionTokens: x.LocalCompletionTokens, ReportedCompletionTokens: x.ReportedCompletionTokens, TokenizerID: x.TokenizerID, TokenizerQuality: x.TokenizerQuality, Stream: x.Stream, FinishReason: x.FinishReason, StructureComplete: x.StructureComplete, HardTruncation: x.HardTruncation, Contract: x.Contract, RefusalClass: x.RefusalClass, IdentityClass: x.IdentityClass, ResponseHash: x.ResponseHash, FinalAttemptID: x.FinalAttemptID, Limitations: x.Limitations}
		for _, a := range attempts {
			s.Attempts = append(s.Attempts, report.Attempt{ID: a.ID, AttemptNo: a.AttemptNo, Validity: a.Validity, ErrorCode: a.ErrorCode, HTTPStatus: a.HTTPStatus, PromptTokens: a.PromptTokens, CompletionTokens: a.CompletionTokens, TotalTokens: a.TotalTokens, DurationMS: a.DurationMS, StartedAt: a.StartedAt, FinishedAt: a.FinishedAt})
		}
		delete(attemptsBySample, row.ID)
		in.Samples = append(in.Samples, s)
	}
	if len(attemptsBySample) != 0 {
		return frozenReport{}, repository.ErrResultDocument
	}
	return frozen, nil
}
