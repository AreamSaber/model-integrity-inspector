package features

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/behavior"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

type fixtureSigner struct{}

func (fixtureSigner) ActiveVersion() string { return "fixture" }
func (fixtureSigner) ProbeMAC(version string, data []byte) ([]byte, error) {
	if version != "fixture" {
		return nil, errors.New("fixture version")
	}
	m := hmac.New(sha256.New, []byte("synthetic-unit-test-manifest-signing-key"))
	_, _ = m.Write(data)
	return m.Sum(nil), nil
}

type fixture struct {
	builder  *Builder
	input    Input
	manifest generator.Manifest
}

func newFixture(t *testing.T, modify func(*generator.Options), bundles ...templates.Bundle) fixture {
	t.Helper()
	bundle := templates.Builtin()
	if len(bundles) > 0 {
		bundle = bundles[0]
	}
	artifact, hash, err := bundle.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := tokenizer.NewBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	g, err := generator.New(artifact, hash, tokens, fixtureSigner{})
	if err != nil {
		t.Fatal(err)
	}
	builder, err := New(Config{Verifier: g, Tokenizer: tokens, TemplateArtifact: artifact, TrustedTemplateHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	o := generator.Options{OrganizationID: 42, Target: domain.ExecutionTarget{ID: 11, Version: 2, SecretID: 12, SecretVersion: 3, Model: "gpt-4o-2024-08-06", Endpoint: "https://example.com/v1", Protocol: "openai_chat", MaxOutputParameter: "max_tokens", AuthType: "bearer", TimeoutSeconds: 180}, Package: "standard", Budget: domain.ExecutionBudget{MaxRequests: 150, MaxTokens: 1000000, TimeoutSeconds: 600}, RuleVersion: "1.0.0-dev.1", ScoringVersion: "1.0.0-dev.1", StandardModel: "gpt-4o-2024-08-06", ContextWindow: 128000, MaxOutputTokens: 4096, SupportsSeed: true, SupportsStream: true, Concurrency: 3, MaxRetries: 2}
	if modify != nil {
		modify(&o)
	}
	m, err := g.Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	raw, manifestHash, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := g.ExecutionPlan(raw, manifestHash, o.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := openaichat.New(openaichat.Config{Endpoint: o.Target.Endpoint, MaxOutputParameter: o.Target.MaxOutputParameter, Doer: noNetwork{}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	const runID = int64(9007199254740993)
	input := Input{Run: RunBinding{OrganizationID: o.OrganizationID, ID: runID, Plan: plan, ExecutionClosedAt: now.Add(time.Second)}}
	for i, signed := range m.Samples {
		sampleID, attemptID := runID+100+int64(i), runID+1000+int64(i)
		frozen := plan.Probes[i].Samples[0]
		_, snapshot, err := adapter.BuildRequest(t.Context(), frozen.Request)
		if err != nil {
			t.Fatal(err)
		}
		body := signed.Variables.Nonce
		switch signed.Family {
		case "sequence":
			body += "|1\n" + signed.Variables.Nonce + "|2"
		case "jsonl":
			body = fmt.Sprintf("{\"%s\":\"%s\",\"n\":1}\n{\"%s\":\"%s\",\"n\":2}", signed.Variables.Label, signed.Variables.Nonce, signed.Variables.Label, signed.Variables.Nonce)
		case "neutral":
			body = strings.ToUpper(body)
		case "format":
			if signed.Variant == 3 {
				body = fmt.Sprintf("{\"%s\":\"%s\"}", signed.Variables.Label, signed.Variables.Nonce)
			}
		case "style":
			body = "Sort the blank cards by their color."
		case "self_report":
			body = "I do not know."
		}
		local, err := tokens.CountOutput(body, tokenizer.Selection{RequestedModel: o.Target.Model})
		if err != nil {
			t.Fatal(err)
		}
		prompt, total, first := int64(10), int64(10)+*local.Tokens, int64(2)
		r := domain.NormalizedResponse{ModelReported: o.Target.Model, Content: body, FinishReason: "stop", PromptTokens: &prompt, CompletionTokens: local.Tokens, TotalTokens: &total, HTTPStatus: 200, ContentType: "application/json", FirstByteMs: 1, DurationMs: 10, RawResponseBytes: int64(len(body) + 256), ParseStatus: "valid", ChoiceCount: 1, EndCause: "complete"}
		if signed.Stream {
			r.StreamTerminated, r.ContentType, r.EndCause, r.FirstTokenMs, r.StreamChunkCount = true, "text/event-stream", "done", &first, 3
		}
		evidence, err := NewEvidence(EvidenceScope{o.OrganizationID, runID, sampleID, attemptID, snapshot.RequestHash}, r)
		if err != nil {
			t.Fatal(err)
		}
		attempt := AttemptBinding{OrganizationID: o.OrganizationID, RunID: runID, SampleID: sampleID, ID: attemptID, JobID: runID + 2000 + int64(i), Number: 1, Status: "COMPLETED", Validity: "VALID", Snapshot: snapshot, RequestHash: snapshot.RequestHash, StartedAt: now, FinishedAt: now.Add(10 * time.Millisecond), Evidence: evidence}
		input.Samples = append(input.Samples, SampleBinding{OrganizationID: o.OrganizationID, RunID: runID, ID: sampleID, ProbeInstanceID: runID + 3000 + int64(i), Ordinal: i, ExecutionOrdinal: i, RequestPlan: frozen, PairID: signed.PairID, AttemptCount: 1, FinalAttemptID: &attemptID, Validity: "VALID", CompletedAt: now.Add(20 * time.Millisecond), Attempts: []AttemptBinding{attempt}})
	}
	return fixture{builder, input, m}
}

func TestBuildRealManifestAndAdapterFinalFeatures(t *testing.T) {
	f := newFixture(t, nil)
	// Persistence fetch ordering must not change the frozen experiment order.
	slices.Reverse(f.input.Samples)
	batch, err := f.builder.Build(f.input)
	if err != nil {
		t.Fatal(err)
	}
	result := batch.Features()
	if result.Expected != 60 || len(result.Samples) != 60 || result.Partial || result.Included+result.Excluded != 60 || result.RunID != "9007199254740993" {
		t.Fatal("manifest coverage or safe IDs wrong")
	}
	for i, sample := range result.Samples {
		if sample.Ordinal != i || sample.Local == nil || (sample.Local.Quality != tokenizer.Exact && sample.Local.Quality != tokenizer.Compatible) || sample.Local.Tokens == nil || sample.Protocol == nil || sample.Protocol.ModelEcho != "matches" || sample.Structure == nil {
			t.Fatalf("derived feature unavailable at ordinal %d: %+v", i, sample)
		}
		if sample.ManifestRequestHash == sample.WireRequestHash {
			t.Fatal("normalized and wire hashes incorrectly conflated")
		}
		if sample.Usage == nil || !sample.Usage.Available || sample.Usage.RelativeError == nil || *sample.Usage.RelativeError != 0 {
			t.Fatal("usage not derived from real tokenizer")
		}
		if sample.Family == "sequence" || sample.Family == "jsonl" {
			if sample.Structure.CompleteUnits != 2 || sample.Structure.TaskComplete == nil || *sample.Structure.TaskComplete {
				t.Fatal("frozen structure contract not applied")
			}
		}
		if sample.Family == "format" || sample.Family == "neutral" || sample.Family == "differential" {
			if sample.Behavior == nil || sample.Behavior.Contract != behavior.Matches {
				t.Fatal("frozen exact contract not applied")
			}
		}
	}
	if err := batch.WithTokenInput(func(input OpaqueTokenInput) error {
		result, err := input.Analyze()
		if err != nil || result.FinalSamples != 60 || result.DuplicateFinals != 0 || result.IgnoredAttempts != 0 {
			t.Fatal("kernel received incorrect final selection", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := batch.WithBehaviorInput(func(input OpaqueBehaviorInput) error {
		if _, err := input.AnalyzeBatch(); err != nil {
			t.Fatal(err)
		}
		pairs, err := input.PairedDifference(behavior.ContractDeviation)
		if err != nil || pairs.CompletePairs == 0 {
			t.Fatal("compiler surface pairs not retained", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBuildRejectsManifestRowAndFinalAttemptMisbinding(t *testing.T) {
	tests := map[string]func(*Input){
		"org":                   func(i *Input) { i.Run.OrganizationID++ },
		"run":                   func(i *Input) { i.Run.ID++ },
		"open-run":              func(i *Input) { i.Run.ExecutionClosedAt = time.Time{} },
		"target-secret-version": func(i *Input) { i.Run.Plan.Target.SecretVersion++ },
		"target-endpoint":       func(i *Input) { i.Run.Plan.Target.Endpoint = "https://different.example/v1" },
		"model":                 func(i *Input) { i.Run.Plan.Target.Model = "forged-model" },
		"manifest":              func(i *Input) { i.Run.Plan.Manifest[20] ^= 1 },
		"manifest-hash":         func(i *Input) { i.Run.Plan.ManifestHash = strings.Repeat("a", 64) },
		"rule":                  func(i *Input) { i.Run.Plan.Versions.Rule = "different" },
		"missing-row":           func(i *Input) { i.Samples = i.Samples[1:] },
		"duplicate-sample":      func(i *Input) { i.Samples[1].ID = i.Samples[0].ID },
		"duplicate-probe":       func(i *Input) { i.Samples[1].ProbeInstanceID = i.Samples[0].ProbeInstanceID },
		"ordinal":               func(i *Input) { i.Samples[0].Ordinal = i.Samples[1].Ordinal },
		"order":                 func(i *Input) { i.Samples[0].ExecutionOrdinal++ },
		"sample-org":            func(i *Input) { i.Samples[0].OrganizationID++ },
		"sample-run":            func(i *Input) { i.Samples[0].RunID++ },
		"sample-request":        func(i *Input) { i.Samples[0].RequestPlan.Request.MaxOutputTokens++ },
		"sample-pair":           func(i *Input) { i.Samples[0].PairID = "forged" },
		"sample-validity":       func(i *Input) { i.Samples[0].Validity = "INVALID_PROTOCOL" },
		"sample-not-completed":  func(i *Input) { i.Samples[0].CompletedAt = time.Time{} },
		"attempt-count":         func(i *Input) { i.Samples[0].AttemptCount++ },
		"final-pointer":         func(i *Input) { value := i.Samples[0].Attempts[0].ID + 99; i.Samples[0].FinalAttemptID = &value },
		"duplicate-attempt":     func(i *Input) { i.Samples[1].Attempts[0].ID = i.Samples[0].Attempts[0].ID },
		"attempt-org":           func(i *Input) { i.Samples[0].Attempts[0].OrganizationID++ },
		"attempt-run":           func(i *Input) { i.Samples[0].Attempts[0].RunID++ },
		"attempt-sample":        func(i *Input) { i.Samples[0].Attempts[0].SampleID++ },
		"attempt-number":        func(i *Input) { i.Samples[0].Attempts[0].Number = 2 },
		"attempt-dispatched":    func(i *Input) { i.Samples[0].Attempts[0].Status = "DISPATCHED" },
		"attempt-hash":          func(i *Input) { i.Samples[0].Attempts[0].RequestHash = strings.Repeat("a", 64) },
		"wire-body":             func(i *Input) { i.Samples[0].Attempts[0].Snapshot.Payload = []byte(`{"fake":true}`) },
		"wire-model":            func(i *Input) { i.Samples[0].Attempts[0].Snapshot.Model = "fake" },
		"wire-bytes":            func(i *Input) { i.Samples[0].Attempts[0].Snapshot.PayloadBytes++ },
		"evidence-org":          func(i *Input) { i.Samples[0].Attempts[0].Evidence.scope.OrganizationID++ },
		"evidence-run":          func(i *Input) { i.Samples[0].Attempts[0].Evidence.scope.RunID++ },
		"evidence-sample":       func(i *Input) { i.Samples[0].Attempts[0].Evidence.scope.SampleID++ },
		"evidence-attempt":      func(i *Input) { i.Samples[0].Attempts[0].Evidence.scope.AttemptID++ },
		"evidence-hash":         func(i *Input) { i.Samples[0].Attempts[0].Evidence.scope.RequestHash = strings.Repeat("a", 64) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, func(o *generator.Options) { o.Package = "quick" })
			mutate(&f.input)
			if batch, err := f.builder.Build(f.input); !errors.Is(err, ErrBinding) || batch != nil {
				t.Fatal("mismatched authoritative projection accepted", err)
			}
		})
	}
}

func TestOnlyFinalAttemptAndExplicitMissingEvidence(t *testing.T) {
	f := newFixture(t, nil)
	row := &f.input.Samples[0]
	old := row.Attempts[0]
	old.ID += 10000
	old.Validity = "INVALID_RETRYABLE"
	old.Evidence = nil
	row.Attempts[0].Number = 2
	row.Attempts = append([]AttemptBinding{old}, row.Attempts...)
	row.AttemptCount = 2
	batch, err := f.builder.Build(f.input)
	if err != nil {
		t.Fatal(err)
	}
	if batch.Features().Samples[0].AttemptNumber != 2 {
		t.Fatal("selected retry instead of final")
	}
	if err := batch.WithTokenInput(func(in OpaqueTokenInput) error {
		r, e := in.Analyze()
		if e != nil || r.FinalSamples != 60 || r.IgnoredAttempts != 0 {
			t.Fatal("retry inflated observations", e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	row.FinalAttemptID = &old.ID
	row.Validity = old.Validity
	if _, err = f.builder.Build(f.input); !errors.Is(err, ErrBinding) {
		t.Fatal("older attempt was selectable")
	}
	for _, kind := range []string{"missing-evidence", "uncertain", "safety", "invalid", "no-final"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, nil)
			row := &f.input.Samples[0]
			switch kind {
			case "missing-evidence":
				row.Attempts[0].Evidence = nil
			case "uncertain":
				row.Attempts[0].Status = "UNCERTAIN"
				row.Validity = "INVALID_RETRYABLE"
				row.Attempts[0].Validity = row.Validity
			case "safety":
				row.Validity = "INVALID_SAFETY_LIMIT"
				row.Attempts[0].Validity = row.Validity
			case "invalid":
				row.Validity = "INVALID_PROTOCOL"
				row.Attempts[0].Validity = row.Validity
			case "no-final":
				row.FinalAttemptID = nil
				row.Attempts = nil
				row.AttemptCount = 0
				row.Validity = "NOT_APPLICABLE"
			}
			batch, err := f.builder.Build(f.input)
			if err != nil {
				t.Fatal(err)
			}
			result := batch.Features()
			s := result.Samples[0]
			if !result.Partial || s.Included || s.Local != nil || s.Usage != nil || s.Structure != nil || s.Behavior != nil || len(s.Limitations) == 0 {
				t.Fatal("unavailable sample became valid zero")
			}
			if err := batch.WithTokenInput(func(in OpaqueTokenInput) error { _, e := in.Analyze(); return e }); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFeaturesNeverSerializeS2AndCapabilitiesExpire(t *testing.T) {
	f := newFixture(t, nil)
	f.input.Samples[0].Attempts[0].Evidence.response.HeaderSummary = map[string]string{"X-Request-Id": "raw-header-canary"}
	f.input.Samples[0].Attempts[0].Evidence.response.ParseWarnings = []string{"untrusted-warning-canary"}
	batch, err := f.builder.Build(f.input)
	if err != nil {
		t.Fatal(err)
	}
	var savedToken OpaqueTokenInput
	var savedBehavior OpaqueBehaviorInput
	values := []any{f.input, f.input.Run, f.input.Samples[0], f.input.Samples[0].Attempts[0], f.input.Samples[0].Attempts[0].Evidence, batch, batch.Features(), f.builder}
	if err := batch.WithTokenInput(func(in OpaqueTokenInput) error {
		savedToken = in
		values = append(values, in)
		r, e := in.Analyze()
		values = append(values, r)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err := batch.WithBehaviorInput(func(in OpaqueBehaviorInput) error {
		savedBehavior = in
		values = append(values, in)
		r, e := in.AnalyzeBatch()
		values = append(values, r)
		p, e2 := in.PairedDifference(behavior.ContractDeviation)
		values = append(values, p)
		if e != nil {
			return e
		}
		return e2
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := savedToken.Analyze(); !errors.Is(err, ErrConfiguration) {
		t.Fatal("token capability escaped callback")
	}
	if _, err := savedBehavior.AnalyzeBatch(); !errors.Is(err, ErrConfiguration) {
		t.Fatal("behavior capability escaped callback")
	}
	var all bytes.Buffer
	for _, v := range values {
		_, _ = fmt.Fprintf(&all, "%v %+v %#v", v, v, v)
		raw, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		all.Write(raw)
		slog.New(slog.NewJSONHandler(&all, nil)).Info("fixture", "value", v)
		slog.New(slog.NewTextHandler(&all, nil)).Info("fixture", "value", v)
	}
	for _, canary := range []string{f.manifest.RunNonce, f.manifest.Samples[0].Variables.Nonce, strings.ToUpper(f.manifest.Samples[0].Variables.Nonce), f.manifest.Samples[0].Variables.Label, "raw-header-canary", "untrusted-warning-canary", f.input.Samples[0].RequestPlan.Request.Messages[0].Content} {
		if strings.Contains(all.String(), canary) {
			t.Fatal("S2 escaped protected boundary")
		}
	}
	for _, s := range f.manifest.Samples {
		if s.Seed != nil && strings.Contains(all.String(), strconv.FormatInt(*s.Seed, 10)) {
			t.Fatal("seed escaped")
		}
	}
	// Caller mutations cannot change a later feature view or protected kernel.
	copy := batch.Features()
	*copy.Samples[0].Local.Tokens = 123456
	copy.Samples[0].Limitations = append(copy.Samples[0].Limitations, "mutated")
	if *batch.Features().Samples[0].Local.Tokens == 123456 {
		t.Fatal("feature accessor shared pointers")
	}
}
