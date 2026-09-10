package repository_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
	"model-integrity-inspector.local/mii/internal/integrity/analyzer"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

type resultReferenceNoNetwork struct{}

func (resultReferenceNoNetwork) Do(*http.Request) (*http.Response, error) {
	panic("pure result observer test must never use network")
}

// Real compiler, signed replay, adapter request encoding, feature Builder,
// tokenrisk, behavior and scoring. The evidence is controlled test data, not a
// claim of authentic production traffic or a calibrated statistical golden.
func snapshotResultActualDocument(t *testing.T, org, run int64, plan domain.ExecutionPlan, samples []repository.LogicalSampleRecord, mode string) []byte {
	t.Helper()
	artifact, hash, err := templates.Builtin().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := tokenizer.NewBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := secret.NewKeyRing("reference-historical-key", map[string][]byte{"reference-historical-key": bytes.Repeat([]byte{41}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := generator.New(artifact, hash, tokens, ring)
	if err != nil {
		t.Fatal(err)
	}
	builder, err := features.New(features.Config{Verifier: compiler, Tokenizer: tokens, TemplateArtifact: artifact, TrustedTemplateHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := compiler.Verify(plan.Manifest, plan.ManifestHash, org)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := openaichat.New(openaichat.Config{Endpoint: plan.Target.Endpoint, MaxOutputParameter: plan.Target.MaxOutputParameter, Doer: resultReferenceNoNetwork{}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	input := features.Input{Run: features.RunBinding{OrganizationID: org, ID: run, Plan: plan, ExecutionClosedAt: now.Add(time.Second)}}
	for i, signed := range manifest.Samples {
		sample := repository.LogicalSampleRecord{ID: 1000 + int64(i), ProbeInstanceID: 2000 + int64(i)}
		if samples != nil {
			sample = samples[i]
		}
		frozen := plan.Probes[i].Samples[0]
		row := features.SampleBinding{OrganizationID: org, RunID: run, ID: sample.ID, ProbeInstanceID: sample.ProbeInstanceID, Ordinal: i, ExecutionOrdinal: i, RequestPlan: frozen, PairID: signed.PairID, Validity: "NOT_APPLICABLE", CompletedAt: now.Add(20 * time.Millisecond)}
		if mode != "no-attempt" {
			_, snapshot, err := adapter.BuildRequest(context.Background(), frozen.Request)
			if err != nil {
				t.Fatal(err)
			}
			attemptID := int64(3000 + i)
			attempt := features.AttemptBinding{OrganizationID: org, RunID: run, SampleID: row.ID, ID: attemptID, JobID: int64(4000 + i), Number: 1, Status: "COMPLETED", Validity: "VALID", Snapshot: snapshot, RequestHash: snapshot.RequestHash, StartedAt: now, FinishedAt: now.Add(10 * time.Millisecond)}
			if mode != "unavailable" {
				body := signed.Variables.Nonce + "|1\n" + signed.Variables.Nonce + "|2"
				local, err := tokens.CountOutput(body, tokenizer.Selection{RequestedModel: plan.Target.Model})
				if err != nil {
					t.Fatal(err)
				}
				prompt, total, first := int64(10), int64(10)+*local.Tokens, int64(2)
				response := domain.NormalizedResponse{ModelReported: plan.Target.Model, Content: body, FinishReason: "stop", PromptTokens: &prompt, CompletionTokens: local.Tokens, TotalTokens: &total, HTTPStatus: 200, ContentType: "application/json", FirstByteMs: 1, DurationMs: 10, RawResponseBytes: int64(len(body) + 256), ParseStatus: "valid", ChoiceCount: 1, EndCause: "complete"}
				if signed.Stream {
					response.StreamTerminated, response.ContentType, response.EndCause, response.FirstTokenMs, response.StreamChunkCount = true, "text/event-stream", "done", &first, 3
				}
				attempt.Evidence, err = features.NewEvidence(features.EvidenceScope{OrganizationID: org, RunID: run, SampleID: row.ID, AttemptID: attemptID, RequestHash: snapshot.RequestHash}, response)
				if err != nil {
					t.Fatal(err)
				}
			}
			row.AttemptCount, row.FinalAttemptID, row.Validity, row.Attempts = 1, &attemptID, "VALID", []features.AttemptBinding{attempt}
		}
		input.Samples = append(input.Samples, row)
	}
	var batch *features.Batch
	if plan.AnalysisSourceVersion == domain.AnalysisSourceDerivedV1 {
		sealer, verifier, capErr := features.NewDerivedCapabilities("result-derived-source", bytes.Repeat([]byte{0x36}, 32))
		if capErr != nil {
			t.Fatal(capErr)
		}
		var records []features.DerivedRecord
		for i := range input.Samples {
			for j, attempt := range input.Samples[i].Attempts {
				prepared, deriveErr := builder.DeriveAttempt(t.Context(), input.Run, input.Samples[i], attempt)
				if deriveErr != nil {
					t.Fatal("actual S1 extraction", deriveErr)
				}
				record, sealErr := sealer.Seal(t.Context(), prepared)
				if sealErr != nil {
					t.Fatal("actual S1 seal", sealErr)
				}
				records = append(records, record)
				input.Samples[i].Attempts[j].Evidence = nil
			}
		}
		batch, err = builder.BuildDerived(t.Context(), input, records, verifier)
	} else {
		batch, err = builder.Build(input)
	}
	if err != nil {
		t.Fatal("actual feature builder", err)
	}
	document, err := analyzer.Analyze(batch)
	if err != nil {
		t.Fatal("actual analyzer", err)
	}
	if document.Scores.RulesHash != scoring.RulesHash() || document.Tokens.RulesHash != tokenrisk.RulesHash() || document.Scores.TokenRulesHash != document.Tokens.RulesHash {
		t.Fatal("actual producer hashes")
	}
	if mode == "unavailable" || mode == "no-attempt" {
		if len(document.Tokens.Series) != 0 {
			t.Fatal("unavailable unexpectedly formed tokenizer series")
		}
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSnapshotResultReferencesPureActualAnalyzer(t *testing.T) {
	for _, mode := range []string{"no-attempt", "unavailable", "exact", "heuristic", "derived-bodyless"} {
		t.Run(mode, func(t *testing.T) {
			target := repository.TargetState{Target: repository.TargetRecord{ID: 31, Version: 1, Endpoint: "https://source.example/v1", Model: "gpt-4o-2024-08-06", Protocol: "openai_chat"}, Secret: repository.SecretMetadata{ID: 37, Version: 1}}
			if mode == "heuristic" {
				target.Target.Model = "unknown-original-model"
			}
			source := ""
			if mode == "derived-bodyless" {
				source = domain.AnalysisSourceDerivedV1
			}
			plan := snapshotReferenceActualCompile(t, 17, target, source)
			body := snapshotResultActualDocument(t, 17, 23, plan, nil, mode)
			repository.SnapshotResultReferencesPureProducerBridge(t, plan, 17, 23, body)
		})
	}
}

func TestSnapshotResultReferencesActualAnalyzerSources(t *testing.T) {
	for _, source := range []string{"", domain.AnalysisSourceDerivedV1} {
		t.Run("source-"+source, func(t *testing.T) {
			repository.SnapshotResultReferencesActualProducerBridge(t, func(org int64, target repository.TargetState) domain.ExecutionPlan {
				return snapshotReferenceActualCompile(t, org, target, source)
			}, func(org, run int64, plan domain.ExecutionPlan, samples []repository.LogicalSampleRecord) []byte {
				return snapshotResultActualDocument(t, org, run, plan, samples, "no-attempt")
			})
		})
	}
}
