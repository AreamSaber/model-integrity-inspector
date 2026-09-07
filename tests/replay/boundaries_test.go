package replay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/bundle"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func TestDevelopmentRuntimeChangesOnlyEvaluationVersion(t *testing.T) {
	f := newFixture(t, "gpt-4o", false)
	data := sealed(t, f)
	before, err := f.engine.Replay(t.Context(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	a, err := bundle.DevelopmentArtifact("1.0.0-dev.2")
	if err != nil {
		t.Fatal(err)
	}
	a.Manifest.Scoring.NoBaselineFactor = .4
	raw, hash, err := a.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := bundle.NewResolver()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := resolver.Resolve(raw, hash)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(Config{CaptureKeyID: f.engine.keyID, CapturePublicKey: f.engine.publicKey, Verifier: f.generator, Runtime: candidate})
	if err != nil {
		t.Fatal(err)
	}
	after, err := engine.Replay(t.Context(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if after.SourceRuleVersion != bundle.BuiltinVersion || after.Runtime.SHA256 != hash || after.Analysis.Scores.Version != a.Manifest.Version || after.Analysis.Scores.Confidence.BaselineFactor != .4 || after.Analysis.Scores.Confidence.Score >= before.Analysis.Scores.Confidence.Score || after.Analysis.Scores.Calibrated {
		t.Fatal("candidate not executed separately from frozen source")
	}
	again, err := f.engine.Replay(t.Context(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	x, _ := json.Marshal(before)
	y, _ := json.Marshal(again)
	if !bytes.Equal(x, y) {
		t.Fatal("candidate mutated legacy evaluation")
	}
}

// This helper recaptures SYNTHETIC bytes through the real parser; it is not a
// substitute for the next checkpoint's committed Worker/TLS capture fixture.
func recaptureSynthetic(t *testing.T, f *fixture, index int, body []byte) {
	t.Helper()
	p, err := f.generator.ExecutionPlan(f.draft.Manifest, f.draft.ManifestHash, f.draft.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	sample := p.Probes[index].Samples[0]
	a := &f.draft.Samples[index].Attempts[0]
	a.Response.Body, a.Response.BodyHash = body, digest(body)
	doer := &recordedDoer{wire: a.WirePayload, response: responseWire(a.Response)}
	adapter, err := openaichat.New(openaichat.Config{Endpoint: "https://replay.invalid/v1", MaxOutputParameter: p.Target.MaxOutputParameter, Doer: doer, Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := adapter.Call(t.Context(), sample.Request, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	local, err := f.engine.tokens.CountOutput(r.Content, tokenizer.Selection{ReportedModel: r.ModelReported, RequestedModel: sample.Request.Model})
	if err != nil {
		t.Fatal(err)
	}
	if local.Quality == tokenizer.Heuristic || local.Quality == tokenizer.Unavailable {
		r.ParseWarnings = append(r.ParseWarnings, "LOCAL_TOKENIZER_APPROXIMATE")
	}
	a.Validity = "VALID"
	if r.ParseStatus == "partial" || len(r.ParseWarnings) > 0 {
		a.Validity = "VALID_WITH_WARNING"
	}
	f.draft.Samples[index].Validity = a.Validity
	a.Response.ProtocolHash, a.Response.Timing, err = ObserveResponse(r)
	if err != nil {
		t.Fatal(err)
	}
}

func TestReplayCountsContentNotReportedUsage(t *testing.T) {
	f := newFixture(t, "gpt-4o", false)
	original, err := f.engine.Replay(t.Context(), bytes.NewReader(sealed(t, f)))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := f.generator.ExecutionPlan(f.draft.Manifest, f.draft.ManifestHash, f.draft.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	index := 0
	body := responseBody(t, "gpt-4o", "hello world", 900, plan.Probes[index].Samples[0].Request.Stream, false)
	recaptureSynthetic(t, &f, index, body)
	changed, err := f.engine.Replay(t.Context(), bytes.NewReader(sealed(t, f)))
	if err != nil {
		t.Fatal(err)
	}
	feature := changed.Analysis.Features.Samples[index]
	if feature.Local == nil || feature.Local.Tokens == nil || *feature.Local.Tokens != 2 || feature.Usage == nil || feature.Usage.ReportedCompletion == nil || *feature.Usage.ReportedCompletion != 900 || feature.Usage.RelativeError == nil || *feature.Usage.RelativeError <= 0 {
		t.Fatal("local count trusted claimed Usage")
	}
	if original.Analysis.Features.Samples[index].Local == nil || *original.Analysis.Features.Samples[index].Local.Tokens == *feature.Local.Tokens {
		t.Fatal("changed bytes were not recounted")
	}
}

func TestReplayAttachesOnlyBoundedCaptureObservedTiming(t *testing.T) {
	f := newFixture(t, "gpt-4o", false)
	plan, err := f.generator.ExecutionPlan(f.draft.Manifest, f.draft.ManifestHash, f.draft.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range plan.Probes {
		if !p.Samples[0].Request.Stream {
			continue
		}
		r := &f.draft.Samples[i].Attempts[0].Response
		tokenAt := int64(10)
		r.Timing.DurationMillis = 40
		r.Timing.FirstByteMillis = 1
		r.Timing.FirstTokenMillis = &tokenAt
		for j := range r.Timing.Events {
			r.Timing.Events[j].ArrivalMillis = int64((j + 1) * 10)
			r.Timing.Events[j].IntervalMillis = 10
		}
		out, err := f.engine.Replay(t.Context(), bytes.NewReader(sealed(t, f)))
		if err != nil {
			t.Fatal(err)
		}
		protocol := out.Analysis.Features.Samples[i].Protocol
		if protocol == nil || protocol.DurationMillis != 40 || protocol.FirstByteMillis != 1 || protocol.FirstTokenMillis == nil || *protocol.FirstTokenMillis != 10 {
			t.Fatal("timing remeasured or discarded")
		}
		r.Timing.Events[0].Sequence++
		if _, err := f.engine.Replay(t.Context(), bytes.NewReader(unsafeSeal(t, f))); err == nil {
			t.Fatal("unbound event timing accepted")
		}
		return
	}
	t.Fatal("missing stream fixture")
}

func TestReplayTimingUsesFrozenRequestAndRunBudgets(t *testing.T) {
	for _, tc := range []struct {
		name          string
		targetSeconds int
		runSeconds    int64
		limitMillis   int64
	}{
		{"frozen-target-request-not-run-budget", 1, 600, 1000},
		{"frozen-run-budget-not-target-request", 180, 2, 2000},
		{"development-hard-ceiling", 180, 600, 180000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "gpt-4o", false)
			regenerateTimingFixture(t, &f, tc.targetSeconds, tc.runSeconds)
			a := &f.draft.Samples[0].Attempts[0]
			a.Response.Timing.DurationMillis = tc.limitMillis
			if a.Response.Timing.DurationMillis <= a.FinishedAt.Sub(a.StartedAt).Milliseconds() {
				t.Fatal("fixture did not separate adapter and reservation origins")
			}
			if _, err := f.engine.Replay(t.Context(), bytes.NewReader(sealed(t, f))); err != nil {
				t.Fatal("valid independent timing intervals rejected", err)
			}
			a.Response.Timing.DurationMillis++
			if _, err := f.engine.Replay(t.Context(), bytes.NewReader(unsafeSeal(t, f))); !errors.Is(err, ErrIntegrity) {
				t.Fatal("adapter timing exceeded authenticated frozen budget", err)
			}
		})
	}
	for _, seconds := range []int{0, 181} {
		f := newFixture(t, "gpt-4o", false)
		regenerateTimingFixture(t, &f, seconds, 600)
		if _, err := f.engine.Replay(t.Context(), bytes.NewReader(sealed(t, f))); !errors.Is(err, ErrIntegrity) {
			t.Fatal("target timeout unsupported by actual Worker accepted", err)
		}
	}
}

// Generate a fresh authenticated Manifest through the real compiler instead of
// trusting a caller-supplied Plan or editing a signed timeout. Rebuild the exact
// request bindings and reparse synthetic bodies; this is not a Worker receipt.
func regenerateTimingFixture(t *testing.T, f *fixture, targetSeconds int, runSeconds int64) {
	t.Helper()
	m, err := f.generator.Verify(f.draft.Manifest, f.draft.ManifestHash, f.draft.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	o := m.Options
	o.Target.TimeoutSeconds, o.Budget.TimeoutSeconds = targetSeconds, runSeconds
	m, err = f.generator.Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	f.draft.Manifest, f.draft.ManifestHash, err = m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.generator.ExecutionPlan(f.draft.Manifest, f.draft.ManifestHash, f.draft.OrganizationID)
	if err != nil || len(p.Probes) != len(f.draft.Samples) {
		t.Fatal("fresh signed timing fixture is not bound")
	}
	adapter, err := openaichat.New(openaichat.Config{Endpoint: "https://replay.invalid/v1", MaxOutputParameter: p.Target.MaxOutputParameter, Doer: &recordedDoer{}})
	if err != nil {
		t.Fatal(err)
	}
	for i, probe := range p.Probes {
		request := probe.Samples[0].Request
		_, snap, err := adapter.BuildRequest(t.Context(), request)
		if err != nil {
			t.Fatal(err)
		}
		s := &f.draft.Samples[i]
		s.PairID = probe.Samples[0].PairID
		a := &s.Attempts[0]
		a.WirePayload, a.RequestHash = snap.Payload, snap.RequestHash
		media, end := "application/json", "eof"
		if request.Stream {
			media, end = "text/event-stream", "done"
		}
		a.Response.Headers, a.Response.End = []Header{{"Content-Type", []string{media}}}, end
		recaptureSynthetic(t, f, i, responseBody(t, f.model, "hello", 1, request.Stream, false))
	}
}

func TestCaptureRetainsInternalTimingConstraints(t *testing.T) {
	base := newFixture(t, "gpt-4o", false)
	for name, timing := range map[string]ObservedTiming{
		"negative-duration":                {DurationMillis: -1},
		"first-byte-after-duration":        {DurationMillis: 10, FirstByteMillis: 11},
		"first-token-before-first-byte":    {DurationMillis: 10, FirstByteMillis: 2, FirstTokenMillis: new(int64(1))},
		"first-token-after-duration":       {DurationMillis: 10, FirstTokenMillis: new(int64(11))},
		"event-after-duration":             {DurationMillis: 10, Events: []EventTiming{{Sequence: 1, ArrivalMillis: 11}}},
		"event-sequence-regression":        {DurationMillis: 10, Events: []EventTiming{{Sequence: 2, ArrivalMillis: 1, IntervalMillis: 1}, {Sequence: 1, ArrivalMillis: 2, IntervalMillis: 1}}},
		"adjacent-event-interval-mismatch": {DurationMillis: 10, Events: []EventTiming{{Sequence: 1, ArrivalMillis: 1, IntervalMillis: 1}, {Sequence: 2, ArrivalMillis: 3, IntervalMillis: 1}}},
	} {
		t.Run(name, func(t *testing.T) {
			f := cloneFixture(t, base)
			f.draft.Samples[0].Attempts[0].Response.Timing = timing
			if _, err := f.engine.Replay(t.Context(), bytes.NewReader(unsafeSeal(t, f))); !errors.Is(err, ErrIntegrity) {
				t.Fatal("invalid internal adapter timing accepted", err)
			}
		})
	}
}

func TestCaptureLimitsConfigurationAndSafeErrors(t *testing.T) {
	f := newFixture(t, "gpt-4o", false)
	for name, mutate := range map[string]func(*CaptureDraft){
		"manifest-size": func(d *CaptureDraft) { d.Manifest = make([]byte, MaxManifestBytes+1) },
		"wire-size": func(d *CaptureDraft) {
			d.Samples[0].Attempts[0].WirePayload = make([]byte, openaichat.MaxRequestBytes+1)
		},
		"body-size":     func(d *CaptureDraft) { d.Samples[0].Attempts[0].Response.Body = make([]byte, MaxBodyBytes+1) },
		"header-values": func(d *CaptureDraft) { d.Samples[0].Attempts[0].Response.Headers[0].Values = make([]string, 5) },
		"header-size": func(d *CaptureDraft) {
			d.Samples[0].Attempts[0].Response.Headers[0].Values = []string{strings.Repeat("x", 513)}
		},
		"header-control": func(d *CaptureDraft) {
			d.Samples[0].Attempts[0].Response.Headers[0].Values = []string{"text/plain\nsecret-canary"}
		},
		"header-empty": func(d *CaptureDraft) { d.Samples[0].Attempts[0].Response.Headers = nil },
		"events-limit": func(d *CaptureDraft) { d.Samples[0].Attempts[0].Response.Timing.Events = make([]EventTiming, 17) },
		"future-timing": func(d *CaptureDraft) {
			d.Samples[0].Attempts[0].FinishedAt = d.Samples[0].Attempts[0].StartedAt.Add(181 * time.Second)
			d.Samples[0].CompletedAt = d.Samples[0].Attempts[0].FinishedAt
			d.ExecutionClosedAt = d.Samples[0].CompletedAt
			d.Commitment.FinishedAt = d.ExecutionClosedAt
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := cloneFixture(t, f)
			mutate(&copy.draft)
			if _, err := SealDevelopment(copy.draft, copy.key); err == nil {
				t.Fatal("unsafe development draft sealed")
			}
		})
	}
	if _, err := SealDevelopment(f.draft, nil); !errors.Is(err, ErrConfiguration) {
		t.Fatal("missing signing key accepted")
	}
	if _, err := New(Config{}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("empty config accepted")
	}
	if _, err := New(Config{CaptureKeyID: "dev-unit", CapturePublicKey: f.engine.publicKey, Verifier: f.generator, Runtime: &bundle.Runtime{}}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("zero runtime accepted")
	}
	var empty *Engine
	if _, err := empty.Replay(t.Context(), bytes.NewReader(nil)); !errors.Is(err, ErrConfiguration) {
		t.Fatal("nil engine accepted")
	}
	//nolint:staticcheck // Deliberately exercise rejection of an invalid nil context.
	if _, err := f.engine.Replay(nil, bytes.NewReader(nil)); !errors.Is(err, ErrConfiguration) {
		t.Fatal("nil context accepted")
	}
	if _, err := f.engine.Replay(t.Context(), nil); !errors.Is(err, ErrConfiguration) {
		t.Fatal("nil input accepted")
	}
	if _, err := f.engine.Replay(t.Context(), errorReader{}); !errors.Is(err, ErrIntegrity) || strings.Contains(err.Error(), "secret") {
		t.Fatal("reader error leaked")
	}
	log := bytes.Buffer{}
	slog.New(slog.NewTextHandler(&log, nil)).Info("capture", "value", f.draft)
	if !strings.Contains(log.String(), "protected development capture") || strings.Contains(log.String(), "wire_payload") {
		t.Fatal("S2 capture logging unsafe")
	}
	if _, _, err := ObserveResponse(domain.NormalizedResponse{DurationMs: -1}); !errors.Is(err, ErrIntegrity) {
		t.Fatal("invalid observation accepted")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic secret-canary reader failure")
}

func TestLineBodyPreservesCRLFAndStopsAfterTerminalEvent(t *testing.T) {
	data := []byte("a\rb\r\nc\nd")
	reader := &lineBody{data: data}
	if n, err := reader.Read(nil); n != 0 || err != nil {
		t.Fatal("zero read changed state")
	}
	got, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(data, got) {
		t.Fatal("line body changed bytes")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := reader.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatal("closed reader remained active")
	}
}

func TestCapturePublicKeyIsDetached(t *testing.T) {
	f := newFixture(t, "gpt-4o", false)
	public := append(ed25519.PublicKey(nil), f.engine.publicKey...)
	e, err := New(Config{CaptureKeyID: f.engine.keyID, CapturePublicKey: public, Verifier: f.generator, Runtime: f.engine.runtime})
	if err != nil {
		t.Fatal(err)
	}
	clear(public)
	if _, err := e.Replay(t.Context(), bytes.NewReader(sealed(t, f))); err != nil {
		t.Fatal("caller mutated frozen public key", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := e.input(ctx, &verifiedCapture{data: draftData(f.draft)}); !errors.Is(err, ErrCanceled) {
		t.Fatal("canceled input mapping proceeded", err)
	}
	if _, err := e.input(t.Context(), nil); !errors.Is(err, ErrIntegrity) {
		t.Fatal("empty verified source accepted")
	}
	destroy(nil)
}
