package run

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/behavior"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
	"model-integrity-inspector.local/mii/internal/integrity/analyzer"
	runtimebundle "model-integrity-inspector.local/mii/internal/integrity/bundle"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

// Deliberately synthetic, body-free storage projection for read-boundary tests.
// It is not evidence that a Worker, paid upstream or publication was executed.
func reviewPublished(t *testing.T) (repository.PublishedRead, analyzer.Document) {
	t.Helper()
	now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	d := analyzer.Document{SchemaVersion: analyzer.SchemaVersion,
		Features: features.Result{Version: features.Version, OrganizationID: "1", RunID: "2", ManifestHash: strings.Repeat("a", 64), Expected: 1, Excluded: 1, Partial: true,
			Samples: []features.SampleFeature{{SampleID: "4", Validity: "NOT_APPLICABLE", Family: "format", Language: "en-US", TemplateID: "format.en-us.1", TemplateVersion: templates.BuiltinVersion, RequestedMaxTokens: 32}}},
		Tokens:   tokenrisk.Result{Version: tokenrisk.Version, RulesHash: tokenrisk.RulesHash(), Development: true, ExpectedSamples: 1},
		Behavior: behavior.Batch{Version: behavior.Version},
		Scores:   scoring.Result{Version: scoring.Version, RulesHash: scoring.RulesHash(), TokenRulesHash: tokenrisk.RulesHash(), Development: true, ExpectedSamples: 1, Completeness: "INSUFFICIENT", EvidenceGrade: "D", RiskLevel: "insufficient"}}
	row := repository.RunHistoryRecord{ID: 2, OrganizationID: 1, TargetID: 3, CreatedBy: 7, Version: 3, Package: "quick", Status: "REVIEW_REQUIRED", ManifestHash: d.Features.ManifestHash,
		RuleBundleVersion: runtimebundle.BuiltinVersion, TemplateBundleVersion: templates.BuiltinVersion, ScoringVersion: scoring.Version, TokenizerBundleVersion: tokenizer.BuiltinVersion,
		PlannedSamples: 1, CompletedSamples: 1, CreatedAt: now, FinishedAt: &now, ExecutionClosedAt: &now}
	data := repository.PublishedRead{Run: row, Result: repository.RunResultRecord{OrganizationID: 1, RunID: 2, AnalysisRevision: 1, IsPublished: true, Completeness: "INSUFFICIENT", EvidenceGrade: "D", RiskLevel: "insufficient", CreatedAt: now},
		Samples: []repository.ResultSampleRecord{{ID: 4, OrganizationID: 1, RunID: 2, ProbeInstanceID: 5, Validity: "NOT_APPLICABLE", CompletedAt: &now}}}
	reviewDocument(t, &data, d)
	if _, err := decodePublished(data); err != nil {
		t.Fatal("synthetic insufficient baseline rejected", err)
	}
	return data, d
}

func reviewDocument(t *testing.T, data *repository.PublishedRead, d analyzer.Document) {
	t.Helper()
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	data.Result.ConclusionJSON = string(raw)
}

func TestResultReviewRejectsUntrustedPublishedVersionFields(t *testing.T) {
	for _, field := range []string{"rule", "template", "tokenizer"} {
		t.Run(field, func(t *testing.T) {
			data, _ := reviewPublished(t)
			canary := "SYNTHETIC PRIVATE BODY\nNOT A VERSION"
			switch field {
			case "rule":
				data.Run.RuleBundleVersion = canary
			case "template":
				data.Run.TemplateBundleVersion = canary
			case "tokenizer":
				data.Run.TokenizerBundleVersion = canary
			}
			if _, err := decodePublished(data); !errors.Is(err, repository.ErrResultDocument) {
				t.Fatal("untrusted run version accepted for direct Result DTO projection")
			}
		})
	}
}

func TestResultReviewRejectsHealthyResultWithZeroIncludedSamples(t *testing.T) {
	data, d := reviewPublished(t)
	zero := float64(0)
	d.Scores.Completeness, d.Scores.EvidenceGrade, d.Scores.RiskLevel = "COMPLETE", "C", "low"
	d.Scores.Confidence.Score, d.Scores.Overall.Score = 74, &zero
	data.Result.Completeness, data.Result.EvidenceGrade, data.Result.RiskLevel = "COMPLETE", "C", "low"
	data.Result.Confidence, data.Result.OverallRisk = 74, &zero
	data.Run.Status = "COMPLETED"
	reviewDocument(t, &data, d)
	if _, err := decodePublished(data); !errors.Is(err, repository.ErrResultDocument) {
		t.Error("zero included samples accepted as complete low-risk confidence 74")
	}
	data.Run.AnalysisRevision = &data.Result.AnalysisRevision
	data.Run.OverallRisk = data.Result.OverallRisk
	data.Run.Confidence = &data.Result.Confidence
	data.Run.RiskLevel = &data.Result.RiskLevel
	data.Run.EvidenceGrade = &data.Result.EvidenceGrade
	data.Run.Completeness = &data.Result.Completeness
	if _, err := historyItem(data.Run); !errors.Is(err, repository.ErrResultDocument) {
		t.Fatal("history accepted a healthy zero-valid-sample result")
	}
}

func TestResultReviewUsageDenominatorFollowsSelectedHeuristicCohort(t *testing.T) {
	_, d := reviewPublished(t)
	d.Features.Expected = 6
	d.Tokens.Usage = tokenrisk.UsageResult{Available: true, Samples: 0, HeuristicSamples: 6, IncludedSamples: 6, MedianRelativeError: .75}
	tokens, _, err := statisticsViews(d)
	if err != nil {
		t.Fatal(err)
	}
	if tokens.UsageSamples != 6 {
		t.Fatal("reported denominator excludes the six actually selected heuristic comparisons")
	}
}
