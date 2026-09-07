package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/bundle"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
	"model-integrity-inspector.local/mii/tests/replay"
	"model-integrity-inspector.local/mii/tests/replay/localfile"
)

type cliFixture struct {
	capture, rule, public, manifestKey []byte
	nonces                             []string
}

type fixtureDoer struct{ body []byte }

func (d fixtureDoer) Do(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(d.body)), Request: r}, nil
}
func fixtureHash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// A synthetic parser/kernel fixture, NOT a real Worker capture, run completion
// proof, calibration dataset, or acceptance sample. The separate capturefixture
// controller tests are responsible for genuine final DB settlement provenance.
func syntheticFixture(t *testing.T) cliFixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	signer, err := localfile.NewManifestSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	tokens, err := tokenizer.NewBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	template, templateHash, err := templates.Builtin().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	g, err := generator.New(template, templateHash, tokens, signer)
	if err != nil {
		t.Fatal(err)
	}
	o := generator.Options{OrganizationID: 7, Target: domain.ExecutionTarget{ID: 10, Version: 1, SecretID: 11, SecretVersion: 1, Model: "gpt-4o", Endpoint: "https://never-dial.invalid/v1", Protocol: "openai_chat", MaxOutputParameter: "max_tokens", TimeoutSeconds: 180}, Package: "custom", Custom: &generator.Custom{Families: []string{"format"}, Languages: []string{"en-US"}, Repetitions: 1}, StreamModes: []bool{false}, SupportsStream: true, SupportsSeed: true, Budget: domain.ExecutionBudget{MaxRequests: 150, MaxTokens: 1000000, TimeoutSeconds: 600}, RuleVersion: bundle.BuiltinVersion, ScoringVersion: bundle.BuiltinVersion, ContextWindow: 128000, MaxOutputTokens: 4096, Concurrency: 1}
	m, err := g.Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	manifest, manifestHash, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := g.ExecutionPlan(manifest, manifestHash, o.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 7, 1, 0, 0, 0, time.UTC)
	draft := replay.CaptureDraft{SchemaVersion: replay.SchemaVersion, Implementation: replay.Implementation, CaseID: strings.Repeat("a", 32), KeyID: "dev-cli-synthetic", OrganizationID: 7, RunID: 13, Manifest: manifest, ManifestHash: manifestHash, ExecutionClosedAt: now.Add(time.Second), Commitment: replay.Commitment{RunStatus: "COMPLETED", RunVersion: 5, AnalysisRevision: 1, PublicationHash: fixtureHash([]byte("synthetic-not-db-proof")), FinishedAt: now.Add(2 * time.Second), SettledRequests: len(m.Samples)}}
	var out cliFixture
	for i, sample := range m.Samples {
		frozen := plan.Probes[i].Samples[0]
		content := sample.Variables.Nonce
		out.nonces = append(out.nonces, content)
		if sample.Variant == 3 {
			data, err := json.Marshal(map[string]string{sample.Variables.Label: content})
			if err != nil {
				t.Fatal(err)
			}
			content = string(data)
		}
		local, err := tokens.CountOutput(content, tokenizer.Selection{RequestedModel: "gpt-4o"})
		if err != nil || local.Tokens == nil {
			t.Fatalf("token count: %v", err)
		}
		body, err := json.Marshal(map[string]any{"id": "synthetic", "object": "chat.completion", "model": "gpt-4o", "choices": []any{map[string]any{"index": 0, "message": map[string]string{"role": "assistant", "content": content}, "finish_reason": "stop"}}, "usage": map[string]int64{"prompt_tokens": 10, "completion_tokens": *local.Tokens, "total_tokens": 10 + *local.Tokens}})
		if err != nil {
			t.Fatal(err)
		}
		adapter, err := openaichat.New(openaichat.Config{Endpoint: "https://replay.invalid/v1", MaxOutputParameter: "max_tokens", Doer: fixtureDoer{body}, Now: func() time.Time { return now }, MaxResponseBytes: replay.MaxBodyBytes})
		if err != nil {
			t.Fatal(err)
		}
		response, wire, err := adapter.Call(t.Context(), frozen.Request, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		protocol, timing, err := replay.ObserveResponse(response)
		if err != nil {
			t.Fatal(err)
		}
		attemptID := int64(300 + i)
		draft.Samples = append(draft.Samples, replay.SampleCapture{ID: int64(100 + i), ProbeInstanceID: int64(200 + i), Ordinal: i, ExecutionOrdinal: i, PairID: sample.PairID, AttemptCount: 1, FinalAttemptID: attemptID, Validity: "VALID", CompletedAt: now.Add(200 * time.Millisecond), Attempts: []replay.AttemptCapture{{ID: attemptID, JobID: int64(400 + i), Number: 1, Status: "COMPLETED", Validity: "VALID", StartedAt: now, FinishedAt: now.Add(100 * time.Millisecond), WirePayload: wire.Payload, RequestHash: wire.RequestHash, Response: replay.ResponseCapture{HTTPStatus: 200, Headers: []replay.Header{{Name: "Content-Type", Values: []string{"application/json"}}}, Body: body, BodyHash: fixtureHash(body), End: "eof", ProtocolHash: protocol, Timing: timing}}}})
	}
	out.capture, err = replay.SealDevelopment(draft, private)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := bundle.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	out.rule = installed.RuleBytes()
	out.public, err = localfile.EncodeDevelopmentCapturePublicKey(draft.KeyID, public)
	if err != nil {
		t.Fatal(err)
	}
	out.manifestKey, err = localfile.EncodeDevelopmentManifestKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(out.capture); clear(out.manifestKey) })
	return out
}
