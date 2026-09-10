package worker

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/analyzer"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	mockupstream "model-integrity-inspector.local/mii/tests/mock-upstream"
)

func signedAnalysisRun(t *testing.T, f runFixture) (*repository.Tenant, repository.RunRecord, *features.Builder, int) {
	t.Helper()
	return signedAnalysisRunMode(t, f, "")
}

func signedAnalysisRunMode(t *testing.T, f runFixture, mode string) (*repository.Tenant, repository.RunRecord, *features.Builder, int) {
	t.Helper()
	value := f.createTarget(t, "max_tokens")
	s, err := f.service.Snapshot(f.ctx, f.orgID, value.ID)
	if err != nil {
		t.Fatal(err)
	}
	artifact, hash, err := templates.Builtin().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := generator.New(artifact, hash, f.tokens, f.ring)
	if err != nil {
		t.Fatal(err)
	}
	builder, err := features.New(features.Config{Verifier: compiler, Tokenizer: f.tokens, TemplateArtifact: artifact, TrustedTemplateHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	opts := generator.Options{OrganizationID: f.orgID, Target: domain.ExecutionTarget{ID: s.TargetID, Version: s.TargetVersion, SecretID: s.SecretID, SecretVersion: s.SecretVersion, Endpoint: s.Endpoint, Model: s.Model, Protocol: s.Protocol, MaxOutputParameter: "max_tokens", AuthType: s.AuthType, AuthHeaderName: s.AuthHeaderName, TimeoutSeconds: s.Options.TimeoutSeconds}, Package: "quick", Budget: domain.ExecutionBudget{MaxRequests: 20, MaxTokens: 50000, TimeoutSeconds: 900}, RuleVersion: scoring.Version, ScoringVersion: scoring.Version, ContextWindow: 128000, MaxOutputTokens: 4096, SupportsStream: true, Concurrency: 1, MaxRetries: 2}
	opts.AnalysisSourceVersion = mode
	manifest, err := compiler.Generate(opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, digest, err := manifest.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := compiler.ExecutionPlan(raw, digest, f.orgID)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := scheduler.NewPolicy(scheduler.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := f.store.WithOrganization(f.ctx, f.orgID)
	if err != nil {
		t.Fatal(err)
	}
	run, err := tenant.CreateRun(plan, policy, "signed-real-analysis")
	if err != nil {
		t.Fatal(err)
	}
	return tenant, run, builder, len(manifest.Samples)
}

func closedSignedAnalysisRun(t *testing.T, f runFixture) (*repository.Tenant, repository.RunRecord, *features.Builder, *repository.JobQueue, repository.JobLease, int) {
	t.Helper()
	tenant, run, builder, expected := signedAnalysisRun(t, f)
	mock, err := mockupstream.NewHandler(mockupstream.Config{RequiredAPIKey: workerCanary})
	if err != nil {
		t.Fatal(err)
	}
	handlers, err := NewRunHandlers(runTLSConfig(t, f, mock))
	if err != nil {
		t.Fatal(err)
	}
	queue, err := f.store.OpenJobQueue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queue.Close(context.Background()) })
	for i := 0; i < expected+3; i++ {
		lease, err := queue.Claim(context.Background())
		if err != nil || lease == nil {
			t.Fatal("claim", err)
		}
		if repository.JobType(lease.Job.Type) == repository.JobRunAnalyze {
			if len(mock.Records()) != expected {
				t.Fatal("wrong real outbound count", len(mock.Records()), expected)
			}
			closed, err := tenant.GetRun(run.ID)
			if err != nil || closed.Status != "ANALYZING" || closed.ExecutionClosedAt == nil {
				t.Fatal("execution not closed", err)
			}
			return tenant, closed, builder, queue, *lease, expected
		}
		handler := handlers[repository.JobType(lease.Job.Type)]
		if handler == nil {
			t.Fatal("unexpected job")
		}
		completion, err := handler(context.Background(), Execution{Queue: queue, Lease: *lease})
		if err != nil {
			t.Fatal("execute", err)
		}
		if err := queue.CompleteWith(context.Background(), *lease, completion); err != nil {
			t.Fatal("complete", err)
		}
	}
	t.Fatal("analysis never queued")
	return nil, repository.RunRecord{}, nil, nil, repository.JobLease{}, 0
}

func TestAnalysisWorkerActualTLSManifestEvidenceToImmutableResult(t *testing.T) {
	eachRunDatabase(t, func(t *testing.T, f runFixture) {
		tenant, run, builder, queue, lease, expected := closedSignedAnalysisRun(t, f)
		handler, err := NewAnalysisHandler(AnalysisConfig{Builder: builder, EvidenceKeys: f.ring})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.GetPublishedAnalysis(run.ID, 1); !errors.Is(err, repository.ErrNotFound) {
			t.Fatal("result before analysis")
		}
		completion, err := handler(context.Background(), Execution{Queue: queue, Lease: lease})
		if err != nil {
			t.Fatal("real analysis", err)
		}
		if _, err := tenant.GetPublishedAnalysis(run.ID, 1); !errors.Is(err, repository.ErrNotFound) {
			t.Fatal("handler published outside completion")
		}
		if err := queue.CompleteWith(context.Background(), lease, completion); err != nil {
			t.Fatal("publish", err)
		}
		result, err := tenant.GetPublishedAnalysis(run.ID, 1)
		if err != nil {
			t.Fatal(err)
		}
		var document analyzer.Document
		if json.Unmarshal([]byte(result.ConclusionJSON), &document) != nil || document.SchemaVersion != analyzer.SchemaVersion || document.Features.Expected != expected || document.Features.Included == 0 || document.Scores.ValidSamples != document.Features.Included {
			t.Fatal("missing real feature/score result")
		}
		if document.Scores.Calibrated || !document.Scores.Development || document.Scores.Confidence.Score > 59 || document.Scores.EvidenceGrade == "A" || document.Scores.EvidenceGrade == "B" {
			t.Fatal("uncalibrated work acquired approval")
		}
		if document.Multiplicity.FamilySize != 4 || len(document.Differences) != 4 {
			t.Fatal("selectively omitted paired hypotheses")
		}
		for _, sample := range document.Features.Samples {
			if sample.Observations == nil || sample.Observations.HTTP != "normal" {
				t.Fatal("successful actual protocol not measured")
			}
		}
		findings, err := tenant.ListAnalysisFindings(run.ID, 1)
		if err != nil || len(findings) == 0 {
			t.Fatal("missing aggregate findings", err)
		}
		finished, err := tenant.GetRun(run.ID)
		if err != nil || finished.Status != "PARTIAL" || finished.RequestCount != int64(expected) || finished.ReservedTokens != 0 {
			t.Fatal("wrong finalized run state", err)
		}
		if strings.Contains(result.ConclusionJSON, workerCanary) || strings.Contains(result.ConclusionJSON, "Authorization") || strings.Contains(result.ConclusionJSON, "request_snapshot") {
			t.Fatal("secret/S2 in immutable S1 document")
		}
		var raw struct {
			Plan domain.ExecutionPlan `json:"plan"`
		}
		_ = json.Unmarshal([]byte(run.ConfigSnapshot), &raw)
		for _, probe := range raw.Plan.Probes {
			for _, sample := range probe.Samples {
				if strings.Contains(result.ConclusionJSON, sample.Nonce) {
					t.Fatal("nonce leaked to analysis document")
				}
			}
		}
		if _, err := tenant.VerifyAuditFull(); err != nil {
			t.Fatal("analysis audit chain", err)
		}
	})
}

func TestAnalysisWorkerExpiredEvidenceIsMissingAndTamperFailsClosed(t *testing.T) {
	for _, mode := range []string{"expired", "tampered"} {
		t.Run(mode, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				tenant, run, builder, queue, lease, _ := closedSignedAnalysisRun(t, f)
				if mode == "expired" {
					if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_response_evidence SET expires_at = created_at WHERE organization_id=$1 AND run_id=$2", f.orgID, run.ID); err != nil {
						t.Fatal("expire fixture evidence")
					}
				} else {
					if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_response_evidence SET content_hash=$1 WHERE organization_id=$2 AND run_id=$3", strings.Repeat("e", 64), f.orgID, run.ID); err != nil {
						t.Fatal("tamper fixture evidence")
					}
				}
				handler, err := NewAnalysisHandler(AnalysisConfig{Builder: builder, EvidenceKeys: f.ring})
				if err != nil {
					t.Fatal(err)
				}
				completion, err := handler(context.Background(), Execution{Queue: queue, Lease: lease})
				if mode == "tampered" {
					if !errors.Is(err, secret.ErrEvidenceUnavailable) || completion != nil {
						t.Fatal("AAD tamper not rejected", err)
					}
					if _, err := tenant.GetPublishedAnalysis(run.ID, 1); !errors.Is(err, repository.ErrNotFound) {
						t.Fatal("tamper published scores")
					}
					return
				}
				if err != nil {
					t.Fatal("expired evidence analysis", err)
				}
				if err := queue.CompleteWith(context.Background(), lease, completion); err != nil {
					t.Fatal(err)
				}
				result, err := tenant.GetPublishedAnalysis(run.ID, 1)
				if err != nil {
					t.Fatal(err)
				}
				if result.EvidenceGrade != "D" || result.Completeness != "INSUFFICIENT" || result.OverallRisk != nil {
					t.Fatal("missing evidence became normal")
				}
			})
		})
	}
}
