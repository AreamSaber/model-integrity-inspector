package repository

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

// Storage-only fixture, not an assertion of statistically calibrated evidence.
func analysisPublicationFixture(t *testing.T, run RunRecord, samples []LogicalSampleRecord) AnalysisPublication {
	t.Helper()
	risk := float64(50)
	p := AnalysisPublication{PromptRisk: &risk, OverallRisk: &risk, Confidence: 50, RiskLevel: "medium", EvidenceGrade: "C", Completeness: "PARTIAL", ExpectedSamples: len(samples), ValidSamples: len(samples), Findings: []AnalysisFinding{{Category: "prompt", Type: "format_contract", Severity: "medium", Title: "Observed format deviation", Summary: "Development observation requires review.", RiskScore: 50, Confidence: 50, EvidenceGrade: "C", RuleID: "development.format", RuleVersion: run.ScoringVersion, Statistics: json.RawMessage(`{"count":1}`), Alternatives: []string{"ordinary_model_variation"}, SampleIDs: []int64{samples[0].ID}}}}
	scores := map[string]any{"Version": run.ScoringVersion, "ValidSamples": p.ValidSamples, "Completeness": p.Completeness, "EvidenceGrade": p.EvidenceGrade, "RiskLevel": p.RiskLevel, "Confidence": map[string]any{"score": p.Confidence}, "Prompt": map[string]any{"score": p.PromptRisk}, "Overall": map[string]any{"score": p.OverallRisk}}
	data, err := json.Marshal(map[string]any{"schema_version": "mii.analysis.v1", "features": map[string]any{"organization_id": strconv.FormatInt(run.OrganizationID, 10), "run_id": strconv.FormatInt(run.ID, 10), "manifest_hash": run.ManifestHash, "expected_samples": p.ExpectedSamples, "included_samples": p.ValidSamples}, "scores": scores})
	if err != nil {
		t.Fatal(err)
	}
	p.Document = data
	return p
}

func TestAnalysisPublicationAtomicImmutableScopedAndAudited(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, queue, run, samples, lease := analysisReadyFixture(t, store, 2)
		source, err := queue.LoadRunAnalysis(context.Background(), lease)
		if err != nil {
			t.Fatal(err)
		}
		publication := analysisPublicationFixture(t, run, samples)
		publish := func(tx *TenantTransaction) error { return tx.PublishRunAnalysis(source, publication) }
		if err := queue.WithLease(context.Background(), lease, publish); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("publication outside completion", err)
		}
		originalSigner := store.auditSigner
		broken := &switchAuditSigner{}
		broken.fail.Store(true)
		store.auditSigner = broken
		if err := queue.CompleteWith(context.Background(), lease, publish); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatal("audit failure not returned", err)
		}
		store.auditSigner = originalSigner
		for _, model := range []any{&RunResultRecord{}, &FindingRecord{}} {
			var count int64
			if err := store.db.Model(model).Count(&count).Error; err != nil || count != 0 {
				t.Fatal("partial publication escaped rollback")
			}
		}
		still, _ := tenant.GetRun(run.ID)
		job, _ := tenant.GetJob(lease.Job.ID)
		if still.Status != "ANALYZING" || still.Version != run.Version || job.Status != "running" {
			t.Fatal("publication rollback changed run/job")
		}
		if err := queue.CompleteWith(context.Background(), lease, publish); err != nil {
			t.Fatal(err)
		}
		result, err := tenant.GetPublishedAnalysis(run.ID, 1)
		if err != nil || !result.IsPublished || result.ConclusionJSON != string(publication.Document) || result.Confidence != 50 {
			t.Fatal("immutable document not published", err)
		}
		findings, err := tenant.ListAnalysisFindings(run.ID, 1)
		if err != nil || len(findings) != 1 || findings[0].RunID != run.ID || findings[0].SampleRefs != `["`+strconv.FormatInt(samples[0].ID, 10)+`"]` {
			t.Fatal("finding binding lost", err)
		}
		finished, _ := tenant.GetRun(run.ID)
		job, _ = tenant.GetJob(lease.Job.ID)
		if finished.Status != "PARTIAL" || finished.Version != run.Version+1 || finished.FinishedAt == nil || job.Status != "completed" || finished.ValidSampleCount != run.ValidSampleCount {
			t.Fatal("run/job finalization not atomic")
		}
		foreign, _ := store.WithOrganization(t.Context(), tenant.orgID+1)
		if _, err := foreign.GetPublishedAnalysis(run.ID, 1); !errors.Is(err, ErrNotFound) {
			t.Fatal("cross-org result")
		}
		if _, err := foreign.ListAnalysisFindings(run.ID, 1); !errors.Is(err, ErrNotFound) {
			t.Fatal("cross-org findings")
		}
		if err := queue.CompleteWith(context.Background(), lease, publish); !errors.Is(err, ErrJobLeaseLost) {
			t.Fatal("repeated completion overwrote result", err)
		}
		unchanged, _ := tenant.GetPublishedAnalysis(run.ID, 1)
		if unchanged.ConclusionJSON != result.ConclusionJSON || !unchanged.CreatedAt.Equal(result.CreatedAt) {
			t.Fatal("published revision changed")
		}
	})
}

func TestAnalysisPublicationRejectsStaleAndInvalidProjection(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, queue, run, samples, lease := analysisReadyFixture(t, store, 2)
		source, err := queue.LoadRunAnalysis(context.Background(), lease)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name   string
			mutate func(*AnalysisPublication)
		}{
			{"A-not-verified", func(p *AnalysisPublication) { p.EvidenceGrade = "A" }},
			{"B-not-calibrated", func(p *AnalysisPublication) { p.EvidenceGrade = "B" }},
			{"nonfinite", func(p *AnalysisPublication) { p.Confidence = math.NaN() }},
			{"partial-overconfident", func(p *AnalysisPublication) { p.Confidence = 60 }},
			{"wrong-count", func(p *AnalysisPublication) { p.ExpectedSamples++ }},
			{"wrong-indexed-score", func(p *AnalysisPublication) { n := 51.0; p.PromptRisk = &n }},
			{"unscoped-document", func(p *AnalysisPublication) { p.Document = json.RawMessage(`{"schema_version":"mii.analysis.v1"}`) }},
			{"array-document", func(p *AnalysisPublication) { p.Document = json.RawMessage(`[]`) }},
			{"foreign-finding", func(p *AnalysisPublication) { p.Findings[0].SampleIDs = []int64{1} }},
			{"duplicate-ref", func(p *AnalysisPublication) { p.Findings[0].SampleIDs = []int64{samples[0].ID, samples[0].ID} }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				p := analysisPublicationFixture(t, run, samples)
				tc.mutate(&p)
				if err := queue.CompleteWith(context.Background(), lease, func(tx *TenantTransaction) error { return tx.PublishRunAnalysis(source, p) }); !errors.Is(err, ErrAnalysisSource) {
					t.Fatal("invalid publication accepted", err)
				}
			})
		}
		p := analysisPublicationFixture(t, run, samples)
		if err := store.db.Model(&RunRecord{}).Where("organization_id = ? AND id = ?", tenant.orgID, run.ID).Update("version", run.Version+1).Error; err != nil {
			t.Fatal(err)
		}
		if err := queue.CompleteWith(context.Background(), lease, func(tx *TenantTransaction) error { return tx.PublishRunAnalysis(source, p) }); !errors.Is(err, ErrAnalysisSource) {
			t.Fatal("stale source published", err)
		}
		if _, err := tenant.GetPublishedAnalysis(run.ID, 1); !errors.Is(err, ErrNotFound) {
			t.Fatal("rejected output still visible")
		}
	})
}

func TestAnalysisPublicationConcurrentLeaseHasOneWinner(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, queue, run, samples, lease := analysisReadyFixture(t, store, 1)
		source, err := queue.LoadRunAnalysis(context.Background(), lease)
		if err != nil {
			t.Fatal(err)
		}
		publication := analysisPublicationFixture(t, run, samples)
		start, results := make(chan struct{}), make(chan error, 2)
		for range 2 {
			go func() {
				<-start
				results <- queue.CompleteWith(context.Background(), lease, func(tx *TenantTransaction) error { return tx.PublishRunAnalysis(source, publication) })
			}()
		}
		close(start)
		winners := 0
		for range 2 {
			if err := <-results; err == nil {
				winners++
			} else if !errors.Is(err, ErrJobLeaseLost) {
				t.Fatal("unexpected publication loser", err)
			}
		}
		if winners != 1 {
			t.Fatal("multiple publication winners")
		}
		findings, err := tenant.ListAnalysisFindings(run.ID, 1)
		if err != nil || len(findings) != 1 {
			t.Fatal("duplicate findings", err)
		}
		if _, err := tenant.VerifyAuditFull(); err != nil {
			t.Fatal(err)
		}
	})
}
