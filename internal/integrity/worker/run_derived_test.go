package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

type runDerivedNoNetwork struct{}

func (runDerivedNoNetwork) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("synthetic network must not be called")
}

type runDerivedFixture struct {
	config   RunConfig
	plan     domain.ExecutionPlan
	sample   repository.LogicalSampleRecord
	attempt  repository.AttemptRecord
	response domain.NormalizedResponse
	outcome  domain.AttemptOutcome
	verifier *features.DerivedVerifier
	mac      features.DerivedAuthenticator
}

func newRunDerivedFixture(t *testing.T, selectedOrdinals ...int) runDerivedFixture {
	t.Helper()
	selected := 0
	if len(selectedOrdinals) > 0 {
		selected = selectedOrdinals[0]
	}
	artifact, hash, err := templates.Builtin().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := tokenizer.NewBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := secret.NewKeyRing("PREPARE.v1", map[string][]byte{"PREPARE.v1": bytes.Repeat([]byte{0x68}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	g, err := generator.New(artifact, hash, tokens, ring)
	if err != nil {
		t.Fatal(err)
	}
	builder, err := features.New(features.Config{Verifier: g, Tokenizer: tokens, TemplateArtifact: artifact, TrustedTemplateHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	mac, err := ring.NewDerivedSourceMAC()
	if err != nil {
		t.Fatal(err)
	}
	sealer, verifier, err := features.NewDerivedCapabilitiesWithMAC("PREPARE.v1", mac)
	if err != nil {
		t.Fatal(err)
	}
	o := generator.Options{AnalysisSourceVersion: domain.AnalysisSourceDerivedV1, OrganizationID: 42, Target: domain.ExecutionTarget{ID: 11, Version: 2, SecretID: 12, SecretVersion: 3, Model: "gpt-4o-2024-08-06", Endpoint: "https://example.com/v1", Protocol: "openai_chat", MaxOutputParameter: "max_tokens", AuthType: "bearer", TimeoutSeconds: 180}, Package: "custom", Custom: &generator.Custom{Families: []string{"neutral"}, Repetitions: 1, Languages: []string{"en-US"}}, Budget: domain.ExecutionBudget{MaxRequests: 20, MaxTokens: 50000, TimeoutSeconds: 600}, RuleVersion: "1.0.0-dev.1", ScoringVersion: "1.0.0-dev.1", ContextWindow: 128000, MaxOutputTokens: 4096, SupportsSeed: true, SupportsStream: true, Concurrency: 1, MaxRetries: 2}
	o.Custom.Repetitions = selected + 1
	m, err := g.Generate(o)
	if err != nil || len(m.Samples) != selected+1 {
		t.Fatal("single real signed probe unavailable", err)
	}
	raw, manifestHash, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := g.ExecutionPlan(raw, manifestHash, o.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := openaichat.New(openaichat.Config{Endpoint: plan.Target.Endpoint, MaxOutputParameter: plan.Target.MaxOutputParameter, Doer: runDerivedNoNetwork{}})
	if err != nil {
		t.Fatal(err)
	}
	frozen := plan.Probes[selected].Samples[0]
	_, wire, err := adapter.BuildRequest(t.Context(), frozen.Request)
	if err != nil {
		t.Fatal(err)
	}
	frozenBytes, err := json.Marshal(frozen)
	if err != nil {
		t.Fatal(err)
	}
	wireBytes, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	jobID := int64(707)
	started := time.Date(2026, 9, 8, 1, 0, 0, 0, time.UTC)
	sample := repository.LogicalSampleRecord{ID: 1001, OrganizationID: 42, RunID: 999, ProbeInstanceID: 500, Ordinal: selected, ExecutionOrdinal: selected, JobID: &jobID, RequestPlan: string(frozenBytes), Validity: "PENDING"}
	attempt := repository.AttemptRecord{ID: 2001, OrganizationID: 42, RunID: 999, LogicalSampleID: sample.ID, JobID: jobID, LeaseGeneration: 1, AttemptNo: 1, Status: "DISPATCHED", Validity: "PENDING", DerivedReceipt: repository.DerivedPending, RequestSnapshot: string(wireBytes), RequestHash: wire.RequestHash, StartedAt: &started}
	body := strings.ToUpper(m.Samples[selected].Variables.Nonce)
	local, err := tokens.CountOutput(body, tokenizer.Selection{RequestedModel: plan.Target.Model})
	if err != nil || local.Tokens == nil {
		t.Fatal("real token measurement unavailable", err)
	}
	prompt, total := int64(10), 10+*local.Tokens
	response := domain.NormalizedResponse{ModelReported: plan.Target.Model, Content: body, FinishReason: "stop", PromptTokens: &prompt, CompletionTokens: local.Tokens, TotalTokens: &total, HTTPStatus: 200, ContentType: "application/json", FirstByteMs: 1, DurationMs: 10, RawResponseBytes: int64(len(body) + 256), ParseStatus: "valid", ChoiceCount: 1, EndCause: "complete"}
	outcome := domain.AttemptOutcome{Validity: "VALID", HTTPStatus: 200, PromptTokens: &prompt, CompletionTokens: local.Tokens, LocalCompletionTokens: *local.Tokens, TokenizerID: local.TokenizerID, TokenizerQuality: string(local.Quality), DurationMillis: 10}
	// No Store, Secrets, EvidenceKeys, networking or clock capability is passed.
	return runDerivedFixture{RunConfig{DerivedBuilder: builder, DerivedSealer: sealer}, plan, sample, attempt, response, outcome, verifier, mac}
}

func runDerivedSourceHash(t *testing.T, wireHash string, response *domain.NormalizedResponse) string {
	t.Helper()
	hash := func(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
	value := "no_response"
	if response != nil {
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		value = hash(encoded)
	}
	encoded, err := json.Marshal([]string{"mii/derived-source/v1", wireHash, value})
	if err != nil {
		t.Fatal(err)
	}
	return hash(encoded)
}

// Simulate the later committed timestamps only in this pure test oracle. The
// production preparation function neither obtains nor invents these values.
func verifyRunDerivedCandidate(t *testing.T, f runDerivedFixture, candidate repository.AttemptDerivedCandidate, response *domain.NormalizedResponse) features.Result {
	t.Helper()
	var frozen domain.SamplePlan
	var wire domain.RequestSnapshot
	if json.Unmarshal([]byte(f.sample.RequestPlan), &frozen) != nil || json.Unmarshal([]byte(f.attempt.RequestSnapshot), &wire) != nil {
		t.Fatal("fixture decode")
	}
	started := *f.attempt.StartedAt
	a := features.AttemptBinding{OrganizationID: f.sample.OrganizationID, RunID: f.sample.RunID, SampleID: f.sample.ID, ID: f.attempt.ID, JobID: f.attempt.JobID, Number: 1, Status: candidate.Status, Validity: candidate.Validity, ErrorCode: candidate.ErrorCode, Snapshot: wire, RequestHash: f.attempt.RequestHash, StartedAt: started, FinishedAt: started.Add(10 * time.Millisecond)}
	row := features.SampleBinding{OrganizationID: f.sample.OrganizationID, RunID: f.sample.RunID, ID: f.sample.ID, ProbeInstanceID: f.sample.ProbeInstanceID, Ordinal: 0, ExecutionOrdinal: 0, RequestPlan: frozen, AttemptCount: 1, FinalAttemptID: &a.ID, Validity: candidate.Validity, CompletedAt: started.Add(20 * time.Millisecond), Attempts: []features.AttemptBinding{a}}
	input := features.Input{Run: features.RunBinding{OrganizationID: f.sample.OrganizationID, ID: f.sample.RunID, Plan: f.plan, ExecutionClosedAt: started.Add(time.Second)}, Samples: []features.SampleBinding{row}}
	record := features.DerivedRecord{Version: candidate.Record.Version, KeyVersion: candidate.Record.KeyVersion, Payload: candidate.Record.Payload, MAC: candidate.Record.MAC}
	batch, err := f.config.DerivedBuilder.BuildDerived(t.Context(), input, []features.DerivedRecord{record}, f.verifier)
	if err != nil {
		t.Fatal("candidate did not authenticate against actual completed key", err)
	}
	if response != nil {
		input.Samples[0].Attempts[0].Evidence, err = features.NewEvidence(features.EvidenceScope{OrganizationID: f.sample.OrganizationID, RunID: f.sample.RunID, SampleID: f.sample.ID, AttemptID: f.attempt.ID, RequestHash: f.attempt.RequestHash}, *response)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.config.DerivedBuilder.BuildResponseReference(t.Context(), input, []features.DerivedRecord{record}, f.verifier); err != nil {
		t.Fatal("candidate discarded or changed real response", err)
	}
	var payload struct {
		SourceHash string `json:"source_hash"`
	}
	if json.Unmarshal(record.Payload, &payload) != nil || payload.SourceHash != runDerivedSourceHash(t, f.attempt.RequestHash, response) {
		t.Fatal("candidate source differs from actual response")
	}
	return batch.Features()
}

func TestPrepareRunDerivedActualResponseAndOverrideCandidates(t *testing.T) {
	f := newRunDerivedFixture(t)
	beforeSample, beforeAttempt, beforeOutcome := f.sample, f.attempt, f.outcome
	set, err := prepareRunDerived(t.Context(), f.config, f.plan, f.sample, f.attempt, &f.response, f.outcome, false)
	if err != nil || len(set.Items) != 4 {
		t.Fatal("four candidates unavailable", err)
	}
	expectedScope := repository.AttemptDerivedScope{OrganizationID: f.sample.OrganizationID, RunID: f.sample.RunID, LogicalSampleID: f.sample.ID, ProbeInstanceID: f.sample.ProbeInstanceID, AttemptID: f.attempt.ID, JobID: f.attempt.JobID, AttemptNo: f.attempt.AttemptNo, Ordinal: f.sample.ExecutionOrdinal, ManifestHash: f.plan.ManifestHash, RequestHash: f.attempt.RequestHash}
	if set.Scope != expectedScope || !reflect.DeepEqual(beforeSample, f.sample) || !reflect.DeepEqual(beforeAttempt, f.attempt) || !reflect.DeepEqual(beforeOutcome, f.outcome) {
		t.Fatal("scope or original persistence projections changed")
	}
	seen := map[[3]string]bool{}
	for i, candidate := range set.Items {
		key := [3]string{candidate.Status, candidate.Validity, candidate.ErrorCode}
		if seen[key] || len(candidate.Record.Payload) > features.MaxDerivedBytes || len(candidate.Record.MAC) != 32 {
			t.Fatal("duplicate or unbounded candidate")
		}
		seen[key] = true
		result := verifyRunDerivedCandidate(t, f, candidate, &f.response)
		if (i == 0 && result.Included != 1) || (i > 0 && result.Included != 0) {
			t.Fatal("actual and overridden outcomes share fabricated feature classification")
		}
	}
	for _, code := range []string{"MI_EXECUTION_CANCELLED", "MI_EXECUTION_TARGET_STALE", "MI_EXECUTION_BUDGET_EXCEEDED"} {
		f.outcome.Validity, f.outcome.ErrorCode = "NOT_APPLICABLE", code
		set, err := prepareRunDerived(t.Context(), f.config, f.plan, f.sample, f.attempt, &f.response, f.outcome, false)
		if err != nil || len(set.Items) != 3 || set.Items[0].ErrorCode != code {
			t.Fatal("actual override was not deduplicated", err)
		}
		for _, candidate := range set.Items {
			verifyRunDerivedCandidate(t, f, candidate, &f.response)
		}
	}
}

func TestPrepareRunDerivedEmptyMinimalAndRecoveredSources(t *testing.T) {
	for _, mode := range []string{"empty", "transport-zero", "minimal", "recovered"} {
		t.Run(mode, func(t *testing.T) {
			f := newRunDerivedFixture(t)
			response := &f.response
			recovered := false
			switch mode {
			case "empty":
				f.response.Content = ""
			case "transport-zero":
				f.response = domain.NormalizedResponse{}
				f.outcome = domain.AttemptOutcome{Validity: "INVALID_RETRYABLE", ErrorCode: "MI_NETWORK_TEMPORARY"}
			case "minimal":
				f.response = domain.NormalizedResponse{HTTPStatus: 200, ParseStatus: "invalid", EndCause: "client_safety_limit", ParseWarnings: []string{"MI_EVIDENCE_LIMIT"}, DurationMs: 10}
				f.outcome.Validity, f.outcome.ErrorCode = "INVALID_SAFETY_LIMIT", "MI_EVIDENCE_LIMIT"
			case "recovered":
				response, recovered = nil, true
				f.outcome = domain.AttemptOutcome{Validity: "INVALID_RETRYABLE", ErrorCode: "MI_UNCERTAIN_ATTEMPT"}
			}
			before := f.outcome
			set, err := prepareRunDerived(t.Context(), f.config, f.plan, f.sample, f.attempt, response, f.outcome, recovered)
			if err != nil || len(set.Items) == 0 || !reflect.DeepEqual(before, f.outcome) {
				t.Fatal("source preparation changed accounting or failed", err)
			}
			if recovered && (len(set.Items) != 1 || set.Items[0].Status != "UNCERTAIN") {
				t.Fatal("recovery fabricated normal or multiple candidates")
			}
			for _, candidate := range set.Items {
				verifyRunDerivedCandidate(t, f, candidate, response)
			}
		})
	}
}

func TestPrepareRunDerivedBindsNonzeroExecutionOrdinal(t *testing.T) {
	f := newRunDerivedFixture(t, 1)
	set, err := prepareRunDerived(t.Context(), f.config, f.plan, f.sample, f.attempt, &f.response, f.outcome, false)
	if err != nil || set.Scope.Ordinal != 1 || len(set.Items) != 4 {
		t.Fatal("nonzero global execution ordinal lost", err)
	}
	for _, candidate := range set.Items {
		run := features.RunBinding{OrganizationID: f.sample.OrganizationID, ID: f.sample.RunID, Plan: f.plan}
		row := features.SampleBinding{ID: f.sample.ID, ProbeInstanceID: f.sample.ProbeInstanceID, Ordinal: f.sample.ExecutionOrdinal}
		attempt := features.AttemptBinding{ID: f.attempt.ID, JobID: f.attempt.JobID, Number: f.attempt.AttemptNo, Status: candidate.Status, Validity: candidate.Validity, ErrorCode: candidate.ErrorCode, RequestHash: f.attempt.RequestHash}
		record := features.DerivedRecord{Version: candidate.Record.Version, KeyVersion: candidate.Record.KeyVersion, Payload: candidate.Record.Payload, MAC: candidate.Record.MAC}
		if err := f.config.DerivedBuilder.VerifyDerivedRecord(t.Context(), run, row, attempt, record, f.verifier); err != nil {
			t.Fatal("candidate MAC scope differs from repository execution ordinal", err)
		}
	}
}

func TestPrepareRunDerivedRejectsInvalidSourcesAndBindings(t *testing.T) {
	for _, mode := range []string{"legacy", "unknown-mode", "signed-mode", "sample-org", "attempt-run", "attempt-sample", "job", "ordinal", "probe", "number", "final", "finished", "status", "receipt", "request-plan", "wire", "unknown-json", "duplicate-json", "trailing-json", "nil-normal", "recovery-response", "recovery-key", "normal-uncertain", "unknown-outcome", "manifest-limit", "probe-limit", "plan-limit", "wire-limit", "response-limit"} {
		t.Run(mode, func(t *testing.T) {
			f := newRunDerivedFixture(t)
			response, recovered := &f.response, false
			switch mode {
			case "legacy":
				f.plan.AnalysisSourceVersion = ""
			case "unknown-mode":
				f.plan.AnalysisSourceVersion = "mii.derived-s1.v99"
			case "signed-mode":
				f.plan.Manifest = bytes.Replace(f.plan.Manifest, []byte(domain.AnalysisSourceDerivedV1), []byte("mii.derived-s1.v2"), 1)
			case "sample-org":
				f.sample.OrganizationID++
			case "attempt-run":
				f.attempt.RunID++
			case "attempt-sample":
				f.attempt.LogicalSampleID++
			case "job":
				f.attempt.JobID++
			case "ordinal":
				f.sample.ExecutionOrdinal++
			case "probe":
				f.sample.ProbeInstanceID = 0
			case "number":
				f.attempt.AttemptNo = f.plan.MaxRetries + 2
			case "final":
				f.sample.FinalAttemptID = &f.attempt.ID
			case "finished":
				f.attempt.FinishedAt = f.attempt.StartedAt
			case "status":
				f.attempt.Status = "COMPLETED"
			case "receipt":
				f.attempt.DerivedReceipt = repository.DerivedLegacy
			case "request-plan":
				f.sample.RequestPlan = strings.Replace(f.sample.RequestPlan, "gpt-4o-2024-08-06", "different-model", 1)
			case "wire":
				f.attempt.RequestSnapshot = strings.Replace(f.attempt.RequestSnapshot, "gpt-4o-2024-08-06", "different-model", 1)
			case "unknown-json":
				f.sample.RequestPlan = `{"private-canary":true,` + f.sample.RequestPlan[1:]
			case "duplicate-json":
				f.sample.RequestPlan = `{"ordinal":0,` + f.sample.RequestPlan[1:]
			case "trailing-json":
				f.attempt.RequestSnapshot += `{}`
			case "nil-normal":
				response = nil
			case "recovery-response":
				recovered = true
				f.outcome = domain.AttemptOutcome{Validity: "INVALID_RETRYABLE", ErrorCode: "MI_UNCERTAIN_ATTEMPT"}
			case "recovery-key":
				response, recovered = nil, true
			case "normal-uncertain":
				f.outcome = domain.AttemptOutcome{Validity: "INVALID_RETRYABLE", ErrorCode: "MI_UNCERTAIN_ATTEMPT"}
			case "unknown-outcome":
				f.outcome.Validity, f.outcome.ErrorCode = "INVALID_PROTOCOL", "private-canary"
			case "manifest-limit":
				f.plan.Manifest = make([]byte, (2<<20)+1)
			case "probe-limit":
				f.plan.Probes = make([]domain.ProbePlan, 151)
			case "plan-limit":
				f.sample.RequestPlan = strings.Repeat(" ", (2<<20)+1)
			case "wire-limit":
				f.attempt.RequestSnapshot = strings.Repeat(" ", (2<<20)+1)
			case "response-limit":
				f.response.Content = strings.Repeat("x", features.MaxResponseBytes+1)
			}
			set, err := prepareRunDerived(t.Context(), f.config, f.plan, f.sample, f.attempt, response, f.outcome, recovered)
			if err == nil || len(set.Items) != 0 || set.Scope != (repository.AttemptDerivedScope{}) || strings.Contains(err.Error(), "private-canary") {
				t.Fatal("invalid source released candidates or sensitive diagnostics")
			}
		})
	}
}

type runDerivedFailMAC struct {
	inner       features.DerivedAuthenticator
	calls, fail int
	cancel      context.CancelFunc
}

func (m *runDerivedFailMAC) DerivedMAC(version string, payload []byte) ([]byte, error) {
	m.calls++
	if m.calls == m.fail {
		if m.cancel != nil {
			m.cancel()
		} else {
			return nil, errors.New("private-canary-synthetic-MAC-failure")
		}
	}
	return m.inner.DerivedMAC(version, payload)
}

func TestPrepareRunDerivedContextAndMACFailureReturnNoPartialCandidates(t *testing.T) {
	for _, mode := range []string{"nil-context", "deadline-before", "cancel-before", "cancel-second-MAC", "fail-second-MAC", "missing-builder", "missing-sealer"} {
		t.Run(mode, func(t *testing.T) {
			f := newRunDerivedFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			mac := &runDerivedFailMAC{inner: f.mac}
			var err error
			f.config.DerivedSealer, _, err = features.NewDerivedCapabilitiesWithMAC("PREPARE.v1", mac)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "nil-context":
				ctx = nil
			case "deadline-before":
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(ctx, time.Unix(1, 0))
				defer stop()
			case "cancel-before":
				cancel()
			case "cancel-second-MAC":
				mac.fail, mac.cancel = 2, cancel
			case "fail-second-MAC":
				mac.fail = 2
			case "missing-builder":
				f.config.DerivedBuilder = nil
			case "missing-sealer":
				f.config.DerivedSealer = nil
			}
			set, err := prepareRunDerived(ctx, f.config, f.plan, f.sample, f.attempt, &f.response, f.outcome, false)
			if err == nil || len(set.Items) != 0 || set.Scope != (repository.AttemptDerivedScope{}) || strings.Contains(err.Error(), "private-canary") {
				t.Fatal("failure released partial candidates or sensitive diagnostics")
			}
			if strings.HasPrefix(mode, "cancel-") && !errors.Is(err, context.Canceled) {
				t.Fatal("context cancellation was detached or hidden")
			}
			if mode == "deadline-before" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("context deadline was detached or hidden")
			}
			if strings.HasSuffix(mode, "second-MAC") && mac.calls != 2 {
				t.Fatal("fixture did not interrupt an already partially prepared set")
			}
		})
	}
}
