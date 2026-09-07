package worker

import (
	"context"
	"encoding/json"
	"strconv"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/analyzer"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

type AnalysisConfig struct {
	Builder      *features.Builder
	EvidenceKeys *secret.KeyRing
}

// NewAnalysisHandler has no network/credential capability. It consumes only
// closed execution evidence and returns an atomic immutable publication.
func NewAnalysisHandler(config AnalysisConfig) (Handler, error) {
	if config.Builder == nil || config.EvidenceKeys == nil {
		return nil, ErrConfiguration
	}
	return func(ctx context.Context, execution Execution) (Completion, error) {
		if execution.Queue == nil || repository.JobType(execution.Lease.Job.Type) != repository.JobRunAnalyze {
			return nil, repository.ErrJobInvalid
		}
		source, err := execution.Queue.LoadRunAnalysis(ctx, execution.Lease)
		if err != nil {
			return nil, err
		}
		var document analyzer.Document
		err = source.Use(func(data repository.AnalysisData) error {
			input, err := analysisInput(ctx, data, config.EvidenceKeys)
			if err != nil {
				return err
			}
			if input.Run.Plan.Versions.Scoring != scoring.Version {
				return repository.ErrAnalysisSource
			}
			batch, err := config.Builder.Build(input)
			if err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			document, err = analyzer.Analyze(batch)
			return err
		})
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		publication, err := analysisPublication(document)
		if err != nil {
			return nil, err
		}
		return func(tx *repository.TenantTransaction) error { return tx.PublishRunAnalysis(source, publication) }, nil
	}, nil
}

func analysisInput(ctx context.Context, data repository.AnalysisData, keys *secret.KeyRing) (features.Input, error) {
	var snapshot struct {
		Plan domain.ExecutionPlan `json:"plan"`
	}
	if data.Run.ExecutionClosedAt == nil || len(data.Run.ConfigSnapshot) > 8<<20 || json.Unmarshal([]byte(data.Run.ConfigSnapshot), &snapshot) != nil {
		return features.Input{}, repository.ErrAnalysisSource
	}
	input := features.Input{Run: features.RunBinding{OrganizationID: data.Run.OrganizationID, ID: data.Run.ID, Plan: snapshot.Plan, ExecutionClosedAt: *data.Run.ExecutionClosedAt}}
	bySample := make(map[int64][]repository.AttemptRecord, len(data.Samples))
	for _, a := range data.Attempts {
		bySample[a.LogicalSampleID] = append(bySample[a.LogicalSampleID], a)
	}
	byAttempt := make(map[int64]repository.ResponseEvidenceRecord, len(data.Evidence))
	for _, e := range data.Evidence {
		byAttempt[e.AttemptID] = e
	}
	for _, sample := range data.Samples {
		if err := ctx.Err(); err != nil {
			return features.Input{}, err
		}
		if sample.CompletedAt == nil {
			return features.Input{}, repository.ErrAnalysisSource
		}
		var plan domain.SamplePlan
		if json.Unmarshal([]byte(sample.RequestPlan), &plan) != nil {
			return features.Input{}, repository.ErrAnalysisSource
		}
		row := features.SampleBinding{OrganizationID: sample.OrganizationID, RunID: sample.RunID, ID: sample.ID, ProbeInstanceID: sample.ProbeInstanceID, Ordinal: sample.Ordinal, ExecutionOrdinal: sample.ExecutionOrdinal, RequestPlan: plan, AttemptCount: sample.AttemptCount, FinalAttemptID: sample.FinalAttemptID, Validity: sample.Validity, CompletedAt: *sample.CompletedAt}
		if sample.PairID != nil {
			row.PairID = *sample.PairID
		}
		for _, a := range bySample[sample.ID] {
			var wire domain.RequestSnapshot
			if a.StartedAt == nil || a.FinishedAt == nil || json.Unmarshal([]byte(a.RequestSnapshot), &wire) != nil {
				return features.Input{}, repository.ErrAnalysisSource
			}
			attempt := features.AttemptBinding{OrganizationID: a.OrganizationID, RunID: a.RunID, SampleID: a.LogicalSampleID, ID: a.ID, JobID: a.JobID, Number: a.AttemptNo, Status: a.Status, Validity: a.Validity, Snapshot: wire, RequestHash: a.RequestHash, StartedAt: *a.StartedAt, FinishedAt: *a.FinishedAt}
			if a.ErrorCode != nil {
				attempt.ErrorCode = *a.ErrorCode
			}
			if evidence, found := byAttempt[a.ID]; found {
				// Scope comes from authoritative rows, never from payload JSON. An
				// expired/missing record stays nil; tampered ciphertext/key failure
				// is explicit failure, not evidence of a normal response.
				scope := secret.EvidenceScope{OrganizationID: data.Run.OrganizationID, RunID: data.Run.ID, LogicalSampleID: sample.ID, AttemptID: a.ID, RequestHash: a.RequestHash}
				record := secret.EvidenceRecord{KeyVersion: evidence.KeyVersion, Nonce: evidence.Nonce, Ciphertext: evidence.Ciphertext, PlaintextBytes: evidence.PlaintextBytes, ContentHash: evidence.ContentHash}
				err := keys.WithResponseEvidence(scope, record, func(response domain.NormalizedResponse) error {
					var err error
					attempt.Evidence, err = features.NewEvidence(features.EvidenceScope{OrganizationID: scope.OrganizationID, RunID: scope.RunID, SampleID: scope.LogicalSampleID, AttemptID: scope.AttemptID, RequestHash: scope.RequestHash}, response)
					return err
				})
				if err != nil {
					return features.Input{}, err
				}
			}
			row.Attempts = append(row.Attempts, attempt)
		}
		input.Samples = append(input.Samples, row)
	}
	return input, nil
}

func analysisPublication(document analyzer.Document) (repository.AnalysisPublication, error) {
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > 4<<20 {
		return repository.AnalysisPublication{}, repository.ErrAnalysisLimit
	}
	s := document.Scores
	p := repository.AnalysisPublication{Document: encoded, PromptRisk: s.Prompt.Score, TokenRisk: s.Token.Score, ResponseRisk: s.Response.Score, EvidenceRisk: s.Protocol.Score, OverallRisk: s.Overall.Score, Confidence: float64(s.Confidence.Score), RiskLevel: s.RiskLevel, EvidenceGrade: s.EvidenceGrade, Completeness: s.Completeness, ExpectedSamples: s.ExpectedSamples, ValidSamples: s.ValidSamples}
	for _, item := range []struct {
		name      string
		dimension scoring.Dimension
	}{{"prompt", s.Prompt}, {"token", s.Token}, {"response", s.Response}, {"protocol", s.Protocol}} {
		if item.dimension.Score == nil || *item.dimension.Score == 0 {
			continue
		}
		stats, err := json.Marshal(item.dimension)
		if err != nil {
			return repository.AnalysisPublication{}, repository.ErrAnalysisSource
		}
		finding := repository.AnalysisFinding{Category: item.name, Type: "development_aggregate", Severity: "low", Title: "Development " + item.name + " observation", Summary: "This aggregate describes observed deviations, not proven provider misconduct. Sample references identify contributing observations, not independent positive findings.", RiskScore: *item.dimension.Score, Confidence: p.Confidence, EvidenceGrade: p.EvidenceGrade, RuleID: "development.aggregate." + item.name, RuleVersion: s.Version, Statistics: stats, Alternatives: []string{"MI_DEVELOPMENT_RULES_UNCALIBRATED", "ordinary_model_variation", "capability_or_protocol_limits"}}
		if finding.RiskScore >= 40 {
			finding.Severity = "medium"
		}
		if finding.RiskScore >= 70 {
			finding.Severity = "high"
		}
		for _, sample := range document.Features.Samples {
			if sample.AuxiliaryOnly {
				continue
			}
			if item.name != "protocol" && !sample.Included {
				continue
			}
			if item.name == "prompt" && (sample.Family == "sequence" || sample.Family == "jsonl") {
				continue
			}
			id, err := strconv.ParseInt(sample.SampleID, 10, 64)
			if err != nil {
				return repository.AnalysisPublication{}, repository.ErrAnalysisSource
			}
			finding.SampleIDs = append(finding.SampleIDs, id)
		}
		p.Findings = append(p.Findings, finding)
	}
	return p, nil
}
