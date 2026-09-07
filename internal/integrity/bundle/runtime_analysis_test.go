package bundle

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analyzer"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

type syntheticManifestSigner struct{}

func (syntheticManifestSigner) ActiveVersion() string { return "fixture" }
func (syntheticManifestSigner) ProbeMAC(_ string, data []byte) ([]byte, error) {
	m := hmac.New(sha256.New, []byte("synthetic-offline-runtime-fixture"))
	_, _ = m.Write(data)
	return m.Sum(nil), nil
}

type prohibitNetwork struct{}

func (prohibitNetwork) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("network prohibited in runtime fixture")
}

// Real compiler, request serializer, offline tokenizer and bound feature builder.
// Only responses are synthetic; there is no external network or paid call.
func runtimeBatch(t *testing.T, custom bool) *features.Batch {
	t.Helper()
	packageTemplates := templates.Builtin()
	if custom {
		packageTemplates.Templates[0].Prompt += " Different synthetic contract."
	}
	artifact, hash, err := packageTemplates.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := tokenizer.NewBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	g, err := generator.New(artifact, hash, tokens, syntheticManifestSigner{})
	if err != nil {
		t.Fatal(err)
	}
	options := generator.Options{OrganizationID: 1, Target: domain.ExecutionTarget{ID: 1, Version: 1, SecretID: 1, SecretVersion: 1, Model: "gpt-4o-2024-08-06", Endpoint: "https://example.com/v1", Protocol: "openai_chat", MaxOutputParameter: "max_tokens"}, Package: "custom", Custom: &generator.Custom{Families: []string{"format", "differential"}, Languages: []string{"en-US"}, Repetitions: 3}, Budget: domain.ExecutionBudget{MaxRequests: 150, MaxTokens: 1000000, TimeoutSeconds: 600}, RuleVersion: BuiltinVersion, ScoringVersion: BuiltinVersion, ContextWindow: 128000, MaxOutputTokens: 4096, Concurrency: 1}
	manifest, err := g.Generate(options)
	if err != nil {
		t.Fatal(err)
	}
	data, manifestHash, err := manifest.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := g.ExecutionPlan(data, manifestHash, 1)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := openaichat.New(openaichat.Config{Endpoint: options.Target.Endpoint, MaxOutputParameter: "max_tokens", Doer: prohibitNetwork{}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 7, 1, 0, 0, 0, time.UTC)
	input := features.Input{Run: features.RunBinding{OrganizationID: 1, ID: 2, Plan: plan, ExecutionClosedAt: now.Add(time.Second)}}
	for i, s := range manifest.Samples {
		id, attemptID := int64(i+100), int64(i+200)
		frozen := plan.Probes[i].Samples[0]
		_, snapshot, err := adapter.BuildRequest(t.Context(), frozen.Request)
		if err != nil {
			t.Fatal(err)
		}
		content := s.Variables.Nonce
		if s.Family == "format" && s.Variant == 3 {
			content = fmt.Sprintf(`{"%s":"%s"}`, s.Variables.Label, s.Variables.Nonce)
		}
		local, err := tokens.CountOutput(content, tokenizer.Selection{RequestedModel: options.Target.Model})
		if err != nil {
			t.Fatal(err)
		}
		prompt, total := int64(10), int64(10)+*local.Tokens
		response := domain.NormalizedResponse{ModelReported: options.Target.Model, Content: content, FinishReason: "stop", PromptTokens: &prompt, CompletionTokens: local.Tokens, TotalTokens: &total, HTTPStatus: 200, ContentType: "application/json", DurationMs: 10, FirstByteMs: 1, RawResponseBytes: int64(len(content) + 256), ParseStatus: "valid", ChoiceCount: 1, EndCause: "complete"}
		evidence, err := features.NewEvidence(features.EvidenceScope{OrganizationID: 1, RunID: 2, SampleID: id, AttemptID: attemptID, RequestHash: snapshot.RequestHash}, response)
		if err != nil {
			t.Fatal(err)
		}
		attempt := features.AttemptBinding{OrganizationID: 1, RunID: 2, SampleID: id, ID: attemptID, JobID: int64(i + 300), Number: 1, Status: "COMPLETED", Validity: "VALID", Snapshot: snapshot, RequestHash: snapshot.RequestHash, StartedAt: now, FinishedAt: now.Add(10 * time.Millisecond), Evidence: evidence}
		input.Samples = append(input.Samples, features.SampleBinding{OrganizationID: 1, RunID: 2, ID: id, ProbeInstanceID: int64(i + 400), Ordinal: i, ExecutionOrdinal: i, RequestPlan: frozen, PairID: s.PairID, AttemptCount: 1, FinalAttemptID: &attemptID, Validity: "VALID", CompletedAt: now.Add(20 * time.Millisecond), Attempts: []features.AttemptBinding{attempt}})
	}
	builder, err := features.New(features.Config{Verifier: g, Tokenizer: tokens, TemplateArtifact: artifact, TrustedTemplateHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := builder.Build(input)
	if err != nil {
		t.Fatal(err)
	}
	return batch
}

func TestRuntimeExecutesSelectedKernelsAndReplaysBuiltinExactly(t *testing.T) {
	r, err := NewResolver()
	if err != nil {
		t.Fatal(err)
	}
	installed, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := r.Resolve(installed.RuleBytes(), BuiltinHash)
	if err != nil {
		t.Fatal(err)
	}
	batch := runtimeBatch(t, false)
	old, err := analyzer.Analyze(batch)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := legacy.Analyze(batch)
	if err != nil {
		t.Fatal(err)
	}
	a, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(resolved)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("legacy full analysis changed")
	}
	candidate := candidate(t, "1.0.0-dev.2")
	candidate.Manifest.Scoring.NoBaselineFactor = .4
	data, hash := canonicalCandidate(t, candidate)
	selected, err := r.Resolve(data, hash)
	if err != nil {
		t.Fatal(err)
	}
	result, err := selected.Analyze(batch)
	if err != nil {
		t.Fatal(err)
	}
	if result.Scores.Version != candidate.Manifest.Version || result.Tokens.Version != candidate.Manifest.Version || result.Scores.RulesHash != selected.Ref().ScoringHash || result.Tokens.RulesHash != selected.Ref().TokenRulesHash || result.Scores.Confidence.BaselineFactor != .4 || result.Scores.Confidence.Score >= old.Scores.Confidence.Score || result.Scores.Calibrated || !result.Scores.Development || result.Scores.EvidenceGrade == "A" || result.Scores.EvidenceGrade == "B" {
		t.Fatal("selected rules not executed or falsely approved")
	}
	again, err := legacy.Analyze(batch)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(again)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, after) {
		t.Fatal("candidate altered original runtime")
	}
	if _, err := selected.Analyze(runtimeBatch(t, true)); !errors.Is(err, ErrIntegrity) {
		t.Fatal("unknown actual template hash accepted", err)
	}
}
