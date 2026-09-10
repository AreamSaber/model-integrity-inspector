package run

import (
	"context"
	"math"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

type VersionsView struct {
	Rule      string `json:"rule_bundle"`
	Template  string `json:"template_bundle"`
	Scoring   string `json:"scoring"`
	Tokenizer string `json:"tokenizer_bundle"`
}
type ResultSummary struct {
	AnalysisRevision int      `json:"analysis_revision"`
	OverallRisk      *float64 `json:"overall_risk"`
	Confidence       int      `json:"confidence"`
	EvidenceGrade    string   `json:"evidence_grade"`
	RiskLevel        string   `json:"risk_level"`
	Completeness     string   `json:"completeness"`
}
type HistoryItem struct {
	ID                  string         `json:"id"`
	TargetID            string         `json:"target_id"`
	CreatedBy           string         `json:"created_by"`
	Package             string         `json:"package"`
	Status              string         `json:"status"`
	Version             int64          `json:"version"`
	Versions            VersionsView   `json:"versions"`
	RequestCount        int64          `json:"request_count"`
	TokenCount          int64          `json:"token_count"`
	EstimatedCostMicros *int64         `json:"estimated_cost_micros"`
	ValidSampleCount    int            `json:"valid_sample_count"`
	PlannedSamples      int            `json:"planned_samples"`
	CompletedSamples    int            `json:"completed_samples"`
	CreatedAt           time.Time      `json:"created_at"`
	StartedAt           *time.Time     `json:"started_at"`
	FinishedAt          *time.Time     `json:"finished_at"`
	CurrentTargetName   *string        `json:"current_target_name"`
	CurrentModel        *string        `json:"current_model"`
	CurrentChannelID    *string        `json:"current_channel_id"`
	Result              *ResultSummary `json:"result"`
}

func (s *Service) History(ctx context.Context, orgID int64, page repository.ListOptions, filters repository.RunFilters) ([]HistoryItem, error) {
	tenant, err := s.tenant(ctx, orgID)
	if err != nil {
		return nil, err
	}
	rows, err := tenant.ListRunHistory(page, filters)
	if err != nil {
		return nil, err
	}
	items := make([]HistoryItem, 0, len(rows))
	for _, r := range rows {
		view, err := historyItem(r)
		if err != nil {
			return nil, err
		}
		items = append(items, view)
	}
	return items, nil
}

func historyItem(r repository.RunHistoryRecord) (HistoryItem, error) {
	if r.Status == "" {
		return HistoryItem{}, repository.ErrResultDocument
	}
	if r.ID <= 0 || r.TargetID <= 0 || r.CreatedBy <= 0 || r.Version < 1 || r.Version > 2147483647 || r.PlannedSamples < 0 || r.PlannedSamples > 1000 || r.CompletedSamples < 0 || r.CompletedSamples > r.PlannedSamples || r.ValidSampleCount < 0 || r.ValidSampleCount > r.PlannedSamples || r.RequestCount < 0 || r.RequestCount > 100000 || r.TokenCount < 0 || r.TokenCount > 9007199254740991 || r.EstimatedCostMicros < 0 || r.EstimatedCostMicros > 9007199254740991 || !slices.Contains([]string{"quick", "standard", "deep", "custom"}, r.Package) || !(repository.RunFilters{Status: r.Status}).Valid() {
		return HistoryItem{}, repository.ErrResultDocument
	}
	if r.RuleBundleVersion != scoring.Version || r.TemplateBundleVersion != templates.BuiltinVersion || r.ScoringVersion != scoring.Version || r.TokenizerBundleVersion != tokenizer.BuiltinVersion {
		return HistoryItem{}, repository.ErrResultDocument
	}
	for _, value := range []*string{r.CurrentTargetName, r.CurrentModel, r.CurrentChannelID} {
		if value != nil && (len(*value) > 256 || !utf8.ValidString(*value) || strings.ContainsAny(*value, "\x00\r\n")) {
			return HistoryItem{}, repository.ErrResultDocument
		}
	}
	out := HistoryItem{ID: decimal(r.ID), TargetID: decimal(r.TargetID), CreatedBy: decimal(r.CreatedBy), Package: r.Package, Status: r.Status, Version: r.Version, Versions: VersionsView{r.RuleBundleVersion, r.TemplateBundleVersion, r.ScoringVersion, r.TokenizerBundleVersion}, RequestCount: r.RequestCount, TokenCount: r.TokenCount, ValidSampleCount: r.ValidSampleCount, PlannedSamples: r.PlannedSamples, CompletedSamples: r.CompletedSamples, CreatedAt: r.CreatedAt, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, CurrentTargetName: r.CurrentTargetName, CurrentModel: r.CurrentModel, CurrentChannelID: r.CurrentChannelID}
	if r.CostKnown {
		n := r.EstimatedCostMicros
		out.EstimatedCostMicros = &n
	}
	if r.AnalysisRevision != nil {
		if r.ValidSampleCount == 0 && (r.OverallRisk != nil || r.Completeness == nil || *r.Completeness != "INSUFFICIENT" || r.EvidenceGrade == nil || *r.EvidenceGrade != "D" || r.RiskLevel == nil || *r.RiskLevel != "insufficient") {
			return HistoryItem{}, repository.ErrResultDocument
		}
		if *r.AnalysisRevision != 1 || r.Confidence == nil || r.RiskLevel == nil || r.EvidenceGrade == nil || r.Completeness == nil {
			return HistoryItem{}, repository.ErrResultDocument
		}
		summary, err := summary(*r.AnalysisRevision, r.OverallRisk, *r.Confidence, *r.RiskLevel, *r.EvidenceGrade, *r.Completeness)
		if err != nil {
			return HistoryItem{}, err
		}
		out.Result = &summary
	}
	return out, nil
}

func summary(revision int, risk *float64, confidence float64, level, grade, complete string) (ResultSummary, error) {
	mappedLevel, ok := map[string]string{"low": "low", "attention": "watch", "medium": "medium", "high": "high", "severe_black_box_statistical_judgment": "critical", "insufficient": "insufficient"}[level]
	mappedComplete, completeOK := map[string]string{"COMPLETE": "full", "PARTIAL": "partial", "INSUFFICIENT": "insufficient"}[complete]
	if !ok || !completeOK || revision != 1 || !resultScore(confidence) || math.Trunc(confidence) != confidence || confidence > 74 || complete != "COMPLETE" && confidence > 59 || !slices.Contains([]string{"C", "D"}, grade) || risk != nil && !resultScore(*risk) || complete == "INSUFFICIENT" && (grade != "D" || level != "insufficient") {
		return ResultSummary{}, repository.ErrResultDocument
	}
	return ResultSummary{revision, risk, int(confidence), grade, mappedLevel, mappedComplete}, nil
}
