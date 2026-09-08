package repository

import (
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// RunResultRecord is an immutable machine-analysis revision. IsPublished means
// available to authorized readers, not formally reviewed/approved by a person.
// Raw JSON is internal: API/report services must decode their strict S1 schema.
type RunResultRecord struct {
	OrganizationID                                                 int64 `gorm:"primaryKey"`
	RunID                                                          int64 `gorm:"primaryKey"`
	AnalysisRevision                                               int   `gorm:"primaryKey"`
	PromptRisk, TokenRisk, ResponseRisk, EvidenceRisk, OverallRisk *float64
	Confidence                                                     float64
	RiskLevel, EvidenceGrade, Completeness                         string
	ConclusionJSON                                                 string `gorm:"column:conclusion_json" json:"-"`
	IsPublished                                                    bool
	CreatedAt                                                      time.Time
}

func (RunResultRecord) TableName() string { return "integrity_run_results" }

type FindingRecord struct {
	ID, OrganizationID, RunID     int64
	AnalysisRevision              int
	Category, Type, Severity      string
	RiskScore, Confidence         float64
	EvidenceGrade, Title, Summary string
	StatisticsJSON                string `gorm:"column:statistics_json" json:"-"`
	AlternativeExplanations       string `json:"-"`
	SampleRefs                    string `json:"-"`
	RuleID, RuleVersion           string
	CreatedAt                     time.Time
}

func (FindingRecord) TableName() string { return "integrity_findings" }

// AnalysisPublication is a trusted Worker output, never HTTP input. Repository
// validates storage/binding invariants, not the algorithm or S1 classification;
// only the body-free analyzer document may be supplied by the actual handler.
type AnalysisPublication struct {
	Document                                                       json.RawMessage `json:"-"`
	PromptRisk, TokenRisk, ResponseRisk, EvidenceRisk, OverallRisk *float64
	Confidence                                                     float64
	RiskLevel, EvidenceGrade, Completeness                         string
	ExpectedSamples, ValidSamples                                  int
	Findings                                                       []AnalysisFinding
}
type AnalysisFinding struct {
	Category, Type, Severity, Title, Summary string
	RiskScore, Confidence                    float64
	EvidenceGrade, RuleID, RuleVersion       string
	Statistics                               json.RawMessage `json:"-"`
	Alternatives                             []string
	SampleIDs                                []int64
}

func analysisScore(n float64) bool { return !math.IsNaN(n) && !math.IsInf(n, 0) && n >= 0 && n <= 100 }
func analysisObject(data []byte, limit int) bool {
	if len(data) < 2 || len(data) > limit || !utf8.Valid(data) {
		return false
	}
	var object map[string]json.RawMessage
	return json.Unmarshal(data, &object) == nil && object != nil
}
func analysisText(s string, limit int) bool {
	return len(s) > 0 && len(s) <= limit && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n\t")
}
func validPublication(p AnalysisPublication) bool {
	if !analysisObject(p.Document, 4<<20) || !analysisScore(p.Confidence) || p.Confidence > 74 || !slices.Contains([]string{"C", "D"}, p.EvidenceGrade) || !slices.Contains([]string{"COMPLETE", "PARTIAL", "INSUFFICIENT"}, p.Completeness) || !slices.Contains([]string{"low", "attention", "medium", "high", "severe_black_box_statistical_judgment", "insufficient"}, p.RiskLevel) || p.ExpectedSamples < 1 || p.ExpectedSamples > 1000 || p.ValidSamples < 0 || p.ValidSamples > p.ExpectedSamples || len(p.Findings) > 256 {
		return false
	}
	if p.Completeness != "COMPLETE" && p.Confidence > 59 {
		return false
	}
	if p.Completeness == "INSUFFICIENT" && (p.EvidenceGrade != "D" || p.RiskLevel != "insufficient") {
		return false
	}
	if p.ValidSamples == 0 && (p.OverallRisk != nil || p.Completeness != "INSUFFICIENT") {
		return false
	}
	for _, n := range []*float64{p.PromptRisk, p.TokenRisk, p.ResponseRisk, p.EvidenceRisk, p.OverallRisk} {
		if n != nil && !analysisScore(*n) {
			return false
		}
	}
	for _, f := range p.Findings {
		if !slices.Contains([]string{"prompt", "token", "response", "protocol"}, f.Category) || !executionLabel.MatchString(f.Type) || !slices.Contains([]string{"info", "low", "medium", "high"}, f.Severity) || !analysisText(f.Title, 256) || !analysisText(f.Summary, 2048) || !analysisScore(f.RiskScore) || !analysisScore(f.Confidence) || f.Confidence > p.Confidence || !slices.Contains([]string{"C", "D"}, f.EvidenceGrade) || !executionLabel.MatchString(f.RuleID) || !executionLabel.MatchString(f.RuleVersion) || !analysisObject(f.Statistics, 64<<10) || len(f.Alternatives) > 32 || len(f.SampleIDs) > p.ExpectedSamples {
			return false
		}
		for _, code := range f.Alternatives {
			if !executionLabel.MatchString(code) {
				return false
			}
		}
	}
	return true
}

// PublishRunAnalysis commits revision, findings, final Run state, audit and Job
// completion atomically through CompleteWith. No upsert/update path exists for a
// published revision. A repeated or stale completion fails the persistent fence.
func (tx *TenantTransaction) PublishRunAnalysis(source *AnalysisSource, publication AnalysisPublication) error {
	if tx.closed.Load() {
		return ErrTransactionClosed
	}
	if source == nil || source.store != tx.store || source.organizationID != tx.orgID || source.jobID != tx.leaseJobID || source.generation != tx.leaseGeneration || !validPublication(publication) {
		return ErrAnalysisSource
	}
	job, err := tx.executionJob(JobRunAnalyze, source.runID, true)
	if err != nil {
		return err
	}
	if job.IdempotencyKey != "analyze:"+strconv.FormatInt(source.runID, 10)+":1" {
		return ErrAnalysisSource
	}
	run, _, err := tx.lockRun(source.runID)
	if err != nil {
		return err
	}
	if run.Status != "ANALYZING" || run.Version != source.runVersion || run.ManifestHash != source.manifestHash || run.AnalysisSourceVersion != source.sourceVersion || run.ExecutionClosedAt == nil || run.CancelRequestedAt != nil || run.ReservedTokens != 0 || run.ReservedCostMicros != 0 {
		return ErrAnalysisSource
	}
	if err := tx.validateRunAnalysisSource(source); err != nil {
		return err
	}
	// Bind the immutable document's identity and summary to this receipt and
	// the indexed projection; readers must never see contradictory summaries.
	if !publicationDocumentBound(publication, run) {
		return ErrAnalysisSource
	}
	var sampleIDs []int64
	if err := tx.db.Model(&LogicalSampleRecord{}).Where("organization_id = ? AND run_id = ? AND completed_at IS NOT NULL", tx.orgID, run.ID).Order("id").Pluck("id", &sampleIDs).Error; err != nil {
		return err
	}
	if len(sampleIDs) != publication.ExpectedSamples {
		return ErrAnalysisSource
	}
	for _, f := range publication.Findings {
		seen := map[int64]bool{}
		for _, id := range f.SampleIDs {
			if _, found := slices.BinarySearch(sampleIDs, id); !found || seen[id] {
				return ErrAnalysisSource
			}
			seen[id] = true
		}
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return err
	}
	record := RunResultRecord{OrganizationID: tx.orgID, RunID: run.ID, AnalysisRevision: 1, PromptRisk: publication.PromptRisk, TokenRisk: publication.TokenRisk, ResponseRisk: publication.ResponseRisk, EvidenceRisk: publication.EvidenceRisk, OverallRisk: publication.OverallRisk, Confidence: publication.Confidence, RiskLevel: publication.RiskLevel, EvidenceGrade: publication.EvidenceGrade, Completeness: publication.Completeness, ConclusionJSON: string(publication.Document), IsPublished: true, CreatedAt: now}
	if err := tx.db.Create(&record).Error; err != nil {
		return err
	}
	for _, f := range publication.Findings {
		id, err := NewID()
		if err != nil {
			return err
		}
		refs := make([]string, 0, len(f.SampleIDs))
		for _, sampleID := range f.SampleIDs {
			refs = append(refs, strconv.FormatInt(sampleID, 10))
		}
		refJSON, _ := json.Marshal(refs)
		alternatives := append([]string{}, f.Alternatives...)
		altJSON, _ := json.Marshal(alternatives)
		finding := FindingRecord{ID: id, OrganizationID: tx.orgID, RunID: run.ID, AnalysisRevision: 1, Category: f.Category, Type: f.Type, Severity: f.Severity, RiskScore: f.RiskScore, Confidence: f.Confidence, EvidenceGrade: f.EvidenceGrade, Title: f.Title, Summary: f.Summary, StatisticsJSON: string(f.Statistics), AlternativeExplanations: string(altJSON), SampleRefs: string(refJSON), RuleID: f.RuleID, RuleVersion: f.RuleVersion, CreatedAt: now}
		if err := tx.db.Create(&finding).Error; err != nil {
			return err
		}
	}
	status := "COMPLETED"
	if publication.Completeness == "PARTIAL" {
		status = "PARTIAL"
	}
	if publication.Completeness == "INSUFFICIENT" {
		status = "REVIEW_REQUIRED"
	}
	if err := tx.db.Model(&RunRecord{}).Where("organization_id = ? AND id = ? AND version = ?", tx.orgID, run.ID, source.runVersion).Updates(map[string]any{"status": status, "finished_at": now, "version": run.Version + 1}).Error; err != nil {
		return err
	}
	return tx.store.appendAudit(tx.ctx, tx.db, tx.orgID, auditObject("run.analysis.publish", "run", run.ID), nil)
}

func publicationDocumentBound(p AnalysisPublication, run RunRecord) bool {
	var document struct {
		SchemaVersion string `json:"schema_version"`
		Features      struct {
			OrganizationID string `json:"organization_id"`
			RunID          string `json:"run_id"`
			ManifestHash   string `json:"manifest_hash"`
			Expected       int    `json:"expected_samples"`
			Included       int    `json:"included_samples"`
		} `json:"features"`
		Scores struct {
			Version                                string
			ValidSamples                           int
			Completeness, EvidenceGrade, RiskLevel string
			Confidence                             struct {
				Score float64 `json:"score"`
			}
			Prompt, Token, Response, Protocol, Overall struct {
				Score *float64 `json:"score"`
			}
		} `json:"scores"`
	}
	if json.Unmarshal(p.Document, &document) != nil || document.SchemaVersion != "mii.analysis.v1" {
		return false
	}
	f, s := document.Features, document.Scores
	if f.OrganizationID != strconv.FormatInt(run.OrganizationID, 10) || f.RunID != strconv.FormatInt(run.ID, 10) || f.ManifestHash != run.ManifestHash || f.Expected != p.ExpectedSamples || f.Included != p.ValidSamples || s.ValidSamples != p.ValidSamples || p.ValidSamples > run.ValidSampleCount || s.Version != run.ScoringVersion || s.Completeness != p.Completeness || s.EvidenceGrade != p.EvidenceGrade || s.RiskLevel != p.RiskLevel || s.Confidence.Score != p.Confidence {
		return false
	}
	left := []*float64{s.Prompt.Score, s.Token.Score, s.Response.Score, s.Protocol.Score, s.Overall.Score}
	right := []*float64{p.PromptRisk, p.TokenRisk, p.ResponseRisk, p.EvidenceRisk, p.OverallRisk}
	for i, n := range left {
		if (n == nil) != (right[i] == nil) || n != nil && *n != *right[i] {
			return false
		}
	}
	return true
}

func (t *Tenant) GetPublishedAnalysis(runID int64, revision int) (RunResultRecord, error) {
	var record RunResultRecord
	err := t.scoped().Where("run_id = ? AND analysis_revision = ? AND is_published = ?", runID, revision, true).First(&record).Error
	return record, executionError(err)
}
func (t *Tenant) ListAnalysisFindings(runID int64, revision int) ([]FindingRecord, error) {
	if _, err := t.GetPublishedAnalysis(runID, revision); err != nil {
		return nil, err
	}
	var records []FindingRecord
	err := t.scoped().Where("run_id = ? AND analysis_revision = ?", runID, revision).Order("id").Limit(257).Find(&records).Error
	if err == nil && len(records) > 256 {
		return nil, ErrAnalysisLimit
	}
	return records, executionError(err)
}
