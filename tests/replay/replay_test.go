package replay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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
)

// Synthetic codec/kernel fixture, not a real Worker capture or acceptance case.
type developmentSigner struct{ key []byte }

func (s developmentSigner) ActiveVersion() string { return "dev-fixture" }
func (s developmentSigner) ProbeMAC(version string, data []byte) ([]byte, error) {
	if version != s.ActiveVersion() {
		return nil, ErrIntegrity
	}
	m := hmac.New(sha256.New, s.key)
	_, _ = m.Write(data)
	return m.Sum(nil), nil
}

type fixture struct {
	draft     CaptureDraft
	engine    *Engine
	key       ed25519.PrivateKey
	generator *generator.Generator
	model     string
}

func newFixture(t *testing.T, model string, omitDone bool) fixture {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifestKey := make([]byte, 32)
	if _, err := rand.Read(manifestKey); err != nil {
		t.Fatal(err)
	}
	tokens, err := tokenizer.NewBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	template, templateHash, err := templates.Builtin().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	g, err := generator.New(template, templateHash, tokens, developmentSigner{manifestKey})
	if err != nil {
		t.Fatal(err)
	}
	o := generator.Options{OrganizationID: 7, Target: domain.ExecutionTarget{ID: 10, Version: 1, SecretID: 11, SecretVersion: 1, Model: model, Endpoint: "https://never-dial.invalid/v1", Protocol: "openai_chat", MaxOutputParameter: "max_tokens", TimeoutSeconds: 180}, Package: "custom", Custom: &generator.Custom{Families: []string{"format", "sequence"}, Tiers: []int{64, 128}, Languages: []string{"en-US"}, Repetitions: 3}, SupportsStream: true, SupportsSeed: true, Budget: domain.ExecutionBudget{MaxRequests: 150, MaxTokens: 1000000, TimeoutSeconds: 600}, RuleVersion: bundle.BuiltinVersion, ScoringVersion: bundle.BuiltinVersion, ContextWindow: 128000, MaxOutputTokens: 4096, Concurrency: 1}
	m, err := g.Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	manifest, hash, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := g.ExecutionPlan(manifest, hash, o.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	r, err := bundle.NewResolver()
	if err != nil {
		t.Fatal(err)
	}
	installed, err := bundle.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := r.Resolve(installed.RuleBytes(), bundle.BuiltinHash)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(Config{CaptureKeyID: "dev-unit", CapturePublicKey: public, Verifier: g, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 7, 1, 0, 0, 0, time.UTC)
	d := CaptureDraft{SchemaVersion: SchemaVersion, Implementation: Implementation, CaseID: strings.Repeat("a", 32), KeyID: "dev-unit", OrganizationID: 7, RunID: 13, Manifest: manifest, ManifestHash: hash, ExecutionClosedAt: now.Add(time.Second), Commitment: Commitment{RunStatus: "COMPLETED", RunVersion: 5, AnalysisRevision: 1, PublicationHash: digest([]byte("synthetic-unit-publication-not-a-database-receipt")), FinishedAt: now.Add(2 * time.Second), SettledRequests: len(m.Samples)}}
	for i, sample := range m.Samples {
		frozen := plan.Probes[i].Samples[0]
		content := sample.Variables.Nonce
		if sample.Variant == 3 {
			content = fmt.Sprintf(`{"%s":"%s"}`, sample.Variables.Label, content)
		}
		local, err := tokens.CountOutput(content, tokenizer.Selection{RequestedModel: model})
		if err != nil {
			t.Fatal(err)
		}
		body := responseBody(t, model, content, *local.Tokens, frozen.Request.Stream, omitDone)
		media, end := "application/json", "eof"
		if frozen.Request.Stream {
			media = "text/event-stream"
			if !omitDone {
				end = "done"
			}
		}
		capture := ResponseCapture{HTTPStatus: 200, Headers: []Header{{"Content-Type", []string{media}}}, Body: body, BodyHash: digest(body), End: end}
		doer := &recordedDoer{response: responseWire(capture)}
		adapter, err := openaichat.New(openaichat.Config{Endpoint: "https://replay.invalid/v1", MaxOutputParameter: "max_tokens", Doer: doer, Now: func() time.Time { return now }, MaxResponseBytes: MaxBodyBytes})
		if err != nil {
			t.Fatal(err)
		}
		_, snap, err := adapter.BuildRequest(t.Context(), frozen.Request)
		if err != nil {
			t.Fatal(err)
		}
		doer.wire = snap.Payload
		response, _, err := adapter.Call(t.Context(), frozen.Request, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if local.Quality == tokenizer.Heuristic || local.Quality == tokenizer.Unavailable {
			response.ParseWarnings = append(response.ParseWarnings, "LOCAL_TOKENIZER_APPROXIMATE")
		}
		capture.ProtocolHash, capture.Timing, err = ObserveResponse(response)
		if err != nil {
			t.Fatal(err)
		}
		validity := "VALID"
		if response.ParseStatus == "partial" || len(response.ParseWarnings) > 0 {
			validity = "VALID_WITH_WARNING"
		}
		attemptID := int64(300 + i)
		attempt := AttemptCapture{ID: attemptID, JobID: int64(400 + i), Number: 1, Status: "COMPLETED", Validity: validity, StartedAt: now, FinishedAt: now.Add(100 * time.Millisecond), WirePayload: snap.Payload, RequestHash: snap.RequestHash, Response: capture}
		d.Samples = append(d.Samples, SampleCapture{ID: int64(100 + i), ProbeInstanceID: int64(200 + i), Ordinal: i, ExecutionOrdinal: i, PairID: sample.PairID, AttemptCount: 1, FinalAttemptID: attemptID, Validity: validity, CompletedAt: now.Add(200 * time.Millisecond), Attempts: []AttemptCapture{attempt}})
	}
	return fixture{d, engine, key, g, model}
}

func responseBody(t *testing.T, model, content string, count int64, stream, omitDone bool) []byte {
	t.Helper()
	usage := map[string]any{"prompt_tokens": 10, "completion_tokens": count, "total_tokens": count + 10}
	if !stream {
		data, err := json.Marshal(map[string]any{"id": "synthetic-response", "object": "chat.completion", "model": model, "choices": []any{map[string]any{"index": 0, "message": map[string]string{"role": "assistant", "content": content}, "finish_reason": "stop"}}, "usage": usage})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	event, err := json.Marshal(map[string]any{"id": "synthetic-response", "object": "chat.completion.chunk", "model": model, "choices": []any{map[string]any{"index": 0, "delta": map[string]string{"content": content}, "finish_reason": "stop"}}, "usage": usage})
	if err != nil {
		t.Fatal(err)
	}
	data := append([]byte("data: "), event...)
	data = append(data, '\n', '\n')
	if !omitDone {
		data = append(data, []byte("data: [DONE]\n\n")...)
	}
	return data
}

func sealed(t *testing.T, f fixture) []byte {
	t.Helper()
	data, err := SealDevelopment(f.draft, f.key)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func unsafeSeal(t *testing.T, f fixture) []byte {
	t.Helper()
	raw, err := json.Marshal(draftData(f.draft))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(envelope{draftData(f.draft), digest(raw), ed25519.Sign(f.key, signMessage(raw))})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func cloneFixture(t *testing.T, f fixture) fixture {
	t.Helper()
	raw, err := json.Marshal(draftData(f.draft))
	if err != nil {
		t.Fatal(err)
	}
	var d CaptureDraft
	if json.Unmarshal(raw, &d) != nil {
		t.Fatal("clone synthetic capture")
	}
	f.draft = d
	return f
}

func TestReplayReparsesRecountsAndIsDeterministic(t *testing.T) {
	for _, model := range []string{"gpt-4o", "gpt-4o-2024-08-06", "unknown-synthetic-model"} {
		t.Run(model, func(t *testing.T) {
			f := newFixture(t, model, false)
			data := sealed(t, f)
			first, err := f.engine.Replay(t.Context(), bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			second, err := f.engine.Replay(t.Context(), bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			a, _ := json.Marshal(first)
			b, _ := json.Marshal(second)
			if !bytes.Equal(a, b) || first.Provenance != "development_controller_statement" || first.TimingSource != "capture_observed" || first.Analysis.Scores.Calibrated || !first.Analysis.Scores.Development || first.Analysis.Features.Included < 1 {
				t.Fatal("not deterministic development analysis")
			}
			for _, feature := range first.Analysis.Features.Samples {
				if feature.Local == nil || feature.Local.Tokens == nil || *feature.Local.Tokens < 1 {
					t.Fatal("actual local recount absent")
				}
				if model == "unknown-synthetic-model" && feature.Local.Quality != tokenizer.Heuristic {
					t.Fatal("input model masquerades as exact")
				}
				if model == "gpt-4o" && feature.Local.Quality != tokenizer.Exact {
					t.Fatal("known exact offline wordlist not used")
				}
				if model == "gpt-4o-2024-08-06" && feature.Local.Quality != tokenizer.Compatible {
					t.Fatal("known offline wordlist not used")
				}
			}
			var m generator.Manifest
			if json.Unmarshal(f.draft.Manifest, &m) != nil {
				t.Fatal("fixture manifest")
			}
			for _, sample := range m.Samples {
				if bytes.Contains(a, []byte(sample.Variables.Nonce)) {
					t.Fatal("nonce leaked to prediction")
				}
			}
			for _, forbidden := range []string{`"messages"`, `"content"`, `"wire_payload"`, `"body"`, `"signature"`, `"manifest"`} {
				if bytes.Contains(a, []byte(forbidden)) {
					t.Fatal("S2 leaked to prediction")
				}
			}
		})
	}
}

func TestReplayMissingDoneIsActualParserWarning(t *testing.T) {
	f := newFixture(t, "gpt-4o-2024-08-06", true)
	out, err := f.engine.Replay(t.Context(), bytes.NewReader(sealed(t, f)))
	if err != nil {
		t.Fatal(err)
	}
	streams := 0
	for _, s := range out.Analysis.Features.Samples {
		if s.Stream {
			streams++
			if s.Protocol == nil || !s.Protocol.Partial || s.Protocol.StreamTerminated || !contains(s.Protocol.Warnings, "MI_PROTOCOL_STREAM_EOF_BEFORE_DONE") {
				t.Fatal("partial SSE disguised as complete")
			}
		}
	}
	if streams == 0 {
		t.Fatal("fixture omitted stream coverage")
	}
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func TestReplayRejectsTamperingUnsupportedAndUnsettled(t *testing.T) {
	base := newFixture(t, "gpt-4o-2024-08-06", false)
	tests := map[string]func(*CaptureDraft){
		"schema":         func(d *CaptureDraft) { d.SchemaVersion = "unknown" },
		"implementation": func(d *CaptureDraft) { d.Implementation = "trusted" },
		"key":            func(d *CaptureDraft) { d.KeyID = "dev-other" },
		"scope":          func(d *CaptureDraft) { d.OrganizationID++ },
		"manifest":       func(d *CaptureDraft) { d.Manifest[0] ^= 1 },
		"publication":    func(d *CaptureDraft) { d.Commitment.PublicationHash = "" },
		"unsettled":      func(d *CaptureDraft) { d.Commitment.ReservedTokens = 1 },
		"unpublished":    func(d *CaptureDraft) { d.Commitment.RunStatus = "ANALYZING" },
		"request-count":  func(d *CaptureDraft) { d.Commitment.SettledRequests++ },
		"scope-run":      func(d *CaptureDraft) { d.RunID = 0 },
		"sample-extra":   func(d *CaptureDraft) { d.Samples = append(d.Samples, d.Samples[0]) },
		"missing-final":  func(d *CaptureDraft) { d.Samples[0].FinalAttemptID = 0 },
		"swap-final":     func(d *CaptureDraft) { d.Samples[0].FinalAttemptID = d.Samples[1].FinalAttemptID },
		"retry":          func(d *CaptureDraft) { d.Samples[0].AttemptCount = 2 },
		"extra-attempt":  func(d *CaptureDraft) { d.Samples[0].Attempts = append(d.Samples[0].Attempts, d.Samples[0].Attempts[0]) },
		"ordinal":        func(d *CaptureDraft) { d.Samples[0].ExecutionOrdinal++ },
		"wire": func(d *CaptureDraft) {
			a := &d.Samples[0].Attempts[0]
			a.WirePayload = []byte(`{"model":"other"}`)
			a.RequestHash = digest(a.WirePayload)
		},
		"body":                     func(d *CaptureDraft) { a := &d.Samples[0].Attempts[0]; a.Response.Body[0] ^= 1 },
		"protocol":                 func(d *CaptureDraft) { d.Samples[0].Attempts[0].Response.ProtocolHash = strings.Repeat("0", 64) },
		"timeout":                  func(d *CaptureDraft) { d.Samples[0].Attempts[0].Response.End = "timeout" },
		"http-error":               func(d *CaptureDraft) { d.Samples[0].Attempts[0].Response.HTTPStatus = 503 },
		"negative-time":            func(d *CaptureDraft) { d.Samples[0].Attempts[0].Response.Timing.DurationMillis = -1 },
		"time-over-adapter-budget": func(d *CaptureDraft) { d.Samples[0].Attempts[0].Response.Timing.DurationMillis = 180001 },
		"header-secret": func(d *CaptureDraft) {
			d.Samples[0].Attempts[0].Response.Headers = append(d.Samples[0].Attempts[0].Response.Headers, Header{"Set-Cookie", []string{"secret-canary"}})
		},
		"duplicate-media": func(d *CaptureDraft) {
			d.Samples[0].Attempts[0].Response.Headers[0].Values = []string{"application/json", "application/json"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := cloneFixture(t, base)
			mutate(&f.draft)
			_, err := f.engine.Replay(t.Context(), bytes.NewReader(unsafeSeal(t, f)))
			if err == nil {
				t.Fatal("unsafe capture accepted")
			}
			if strings.Contains(err.Error(), "canary") {
				t.Fatal("input echoed")
			}
		})
	}
}

func TestReplayStrictEnvelopeAndResourceBounds(t *testing.T) {
	f := newFixture(t, "gpt-4o-2024-08-06", false)
	data := sealed(t, f)
	for name, altered := range map[string][]byte{
		"trailing":          append(append([]byte(nil), data...), []byte("{}")...),
		"space":             append(append([]byte(nil), data...), ' '),
		"unknown":           bytes.Replace(data, []byte(`"capture":{`), []byte(`"capture":{"labels":["normal"],`), 1),
		"duplicate":         bytes.Replace(data, []byte(`"capture":{`), []byte(`"capture":{"schema_version":"bad",`), 1),
		"alias":             bytes.Replace(data, []byte(`"case_id":`), []byte(`"CASE_ID":`), 1),
		"input-exact":       bytes.Replace(data, []byte(`"http_status":200`), []byte(`"tokenizer_quality":"exact","http_status":200`), 1),
		"input-count":       bytes.Replace(data, []byte(`"http_status":200`), []byte(`"local_count":0,"http_status":200`), 1),
		"invalid-utf8":      append([]byte{255}, data...),
		"invalid-signature": bytes.Replace(data, []byte(`"signature":"`), []byte(`"signature":"A`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.engine.Replay(t.Context(), bytes.NewReader(altered)); err == nil {
				t.Fatal("noncanonical/privileged field accepted")
			}
		})
	}
	if _, err := f.engine.Replay(t.Context(), io.LimitReader(zeroReader{}, MaxCaptureBytes+1)); !errors.Is(err, ErrLimit) {
		t.Fatal("unbounded capture", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.engine.Replay(ctx, bytes.NewReader(data)); !errors.Is(err, ErrCanceled) {
		t.Fatal("cancellation ignored", err)
	}
	if _, err := json.Marshal(f.draft); !errors.Is(err, ErrSensitive) {
		t.Fatal("raw capture marshaled")
	}
	if strings.Contains(fmt.Sprintf("%+v", f.draft), "wire_payload") {
		t.Fatal("ordinary formatting not protected")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestReplayRejectsTrailingSSEEvenWhenBodyHashUpdated(t *testing.T) {
	f := newFixture(t, "gpt-4o-2024-08-06", false)
	plan, err := f.generator.ExecutionPlan(f.draft.Manifest, f.draft.ManifestHash, f.draft.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range plan.Probes {
		if p.Samples[0].Request.Stream {
			a := &f.draft.Samples[i].Attempts[0]
			a.Response.Body = append(a.Response.Body, []byte("data: malicious-trailing\n\n")...)
			a.Response.BodyHash = digest(a.Response.Body)
			if _, err := f.engine.Replay(t.Context(), bytes.NewReader(sealed(t, f))); !errors.Is(err, ErrIntegrity) {
				t.Fatal("trailing bytes consumed as valid capture", err)
			}
			return
		}
	}
	t.Fatal("no stream fixture")
}

func TestRecordedDoerRejectsAnyDifferentRequest(t *testing.T) {
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://other.invalid/v1/chat/completions", strings.NewReader("canary"))
	if err != nil {
		t.Fatal(err)
	}
	d := &recordedDoer{}
	if _, err := d.Do(r); !errors.Is(err, ErrIntegrity) || !d.failed {
		t.Fatal("network destination accepted")
	}
}
