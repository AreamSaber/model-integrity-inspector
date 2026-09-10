package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/evidencedisplay"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/target"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func displayRun(t *testing.T, f runFixture, credentials secret.Input, requestContent string, streams []bool) (*repository.Tenant, repository.RunRecord, []repository.LogicalSampleRecord) {
	t.Helper()
	value, err := f.service.Create(f.ctx, f.orgID, target.Input{Name: "Display fixture", Endpoint: "https://upstream.example.com/v1", Protocol: "openai_chat", Model: "mock-model", Options: target.Options{MaxOutputParameter: "max_tokens"}}, credentials)
	if err != nil {
		t.Fatal("create display fixture target", err)
	}
	s, err := f.service.Snapshot(f.ctx, f.orgID, value.ID)
	if err != nil {
		t.Fatal(err)
	}
	manifest := json.RawMessage(`{"fixture":"display-worker"}`)
	digest := sha256.Sum256(manifest)
	plan := domain.ExecutionPlan{Target: domain.ExecutionTarget{ID: s.TargetID, Version: s.TargetVersion, SecretID: s.SecretID, SecretVersion: s.SecretVersion, Endpoint: s.Endpoint, Model: s.Model, Protocol: s.Protocol, MaxOutputParameter: "max_tokens", AuthType: s.AuthType, AuthHeaderName: s.AuthHeaderName, TimeoutSeconds: s.Options.TimeoutSeconds}, Package: "custom", Manifest: manifest, ManifestHash: hex.EncodeToString(digest[:]), Versions: domain.BundleVersions{Rule: "1", Template: "1", Scoring: "1", Tokenizer: f.tokens.Version()}, Budget: domain.ExecutionBudget{MaxRequests: 12, MaxTokens: 10000, TimeoutSeconds: 60}, Concurrency: 1, MaxRetries: 0}
	probe := domain.ProbePlan{Type: "contract", TemplateID: "fixture", TemplateVersion: "1", Category: "format", Variant: "en"}
	for i, stream := range streams {
		probe.Samples = append(probe.Samples, domain.SamplePlan{Ordinal: i, Nonce: fmt.Sprintf("fixture-nonce-%d", i), EstimatedInputTokens: 10, Request: domain.NormalizedRequest{Model: s.Model, Messages: []domain.NormalizedMessage{{Role: "user", Content: requestContent}}, MaxOutputTokens: 256, Stream: stream}})
	}
	plan.Probes = []domain.ProbePlan{probe}
	policy, err := scheduler.NewPolicy(scheduler.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := f.store.WithOrganization(f.ctx, f.orgID)
	if err != nil {
		t.Fatal(err)
	}
	run, err := tenant.CreateRun(plan, policy, "display-real-worker")
	if err != nil {
		t.Fatal(err)
	}
	samples, err := tenant.ListExecutionSamples(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	return tenant, run, samples
}

func readWorkerDisplay(t *testing.T, f runFixture, sample repository.LogicalSampleRecord, attempt repository.AttemptRecord) repository.DisplayEvidenceRecord {
	t.Helper()
	var v repository.DisplayEvidenceRecord
	err := f.db.QueryRowContext(f.ctx, "SELECT organization_id,run_id,logical_sample_id,attempt_id,request_hash,policy,state,source_hash,version,key_version,nonce,ciphertext,plaintext_bytes,payload_hash,captured_at_micros,expires_at_micros FROM integrity_display_evidence WHERE organization_id=$1 AND run_id=$2 AND logical_sample_id=$3 AND attempt_id=$4", f.orgID, sample.RunID, sample.ID, attempt.ID).Scan(&v.OrganizationID, &v.RunID, &v.LogicalSampleID, &v.AttemptID, &v.RequestHash, &v.Policy, &v.State, &v.SourceHash, &v.Version, &v.KeyVersion, &v.Nonce, &v.Ciphertext, &v.PlaintextBytes, &v.PayloadHash, &v.CapturedAtMicros, &v.ExpiresAtMicros)
	if err != nil {
		t.Fatal("read scoped display evidence")
	}
	return v
}

func displayCryptoParts(v repository.DisplayEvidenceRecord) (secret.DisplayBinding, secret.DisplayRecord) {
	return secret.DisplayBinding{Scope: secret.EvidenceScope{OrganizationID: v.OrganizationID, RunID: v.RunID, LogicalSampleID: v.LogicalSampleID, AttemptID: v.AttemptID, RequestHash: v.RequestHash}, SourceHash: v.SourceHash, CapturedAtMicros: v.CapturedAtMicros, ExpiresAtMicros: v.ExpiresAtMicros}, secret.DisplayRecord{Version: v.Version, Policy: v.Policy, KeyVersion: v.KeyVersion, Nonce: v.Nonce, Ciphertext: v.Ciphertext, PlaintextBytes: v.PlaintextBytes, PayloadHash: v.PayloadHash}
}

func TestRunWorkerDisplayActualCredentialsTLSAndUnchangedAnalysis(t *testing.T) {
	for _, auth := range []string{"bearer", "custom_header"} {
		t.Run(auth, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				const firstHeader = "display-ordinary-header-canary-892e"
				const secondHeader = "display-routing-header-canary-afe2"
				credentials := secret.Input{Type: auth, APIKey: []byte(workerCanary), Headers: map[string]string{"X-Plain-Marker": firstHeader, "X-Routing-Marker": secondHeader}}
				if auth == "custom_header" {
					credentials.HeaderName = "X-Actual-Credential"
				}
				encodedFirst := base64.StdEncoding.EncodeToString([]byte(firstHeader))
				encodedSecond := hex.EncodeToString([]byte(secondHeader))
				content := "safe-prefix " + workerCanary + " " + firstHeader + " " + encodedFirst + " " + secondHeader + " " + encodedSecond + " 安全尾部"
				var calls atomic.Int64
				var invalid atomic.Bool
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					var request struct {
						Stream bool `json:"stream"`
					}
					if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&request) != nil || r.Header.Get("X-Plain-Marker") != firstHeader || r.Header.Get("X-Routing-Marker") != secondHeader || auth == "bearer" && r.Header.Get("Authorization") != "Bearer "+workerCanary || auth == "custom_header" && r.Header.Get("X-Actual-Credential") != workerCanary {
						invalid.Store(true)
						w.WriteHeader(400)
						return
					}
					for _, name := range []string{"Retry-After", "X-Request-Id", "Request-Id", "Openai-Processing-Ms"} {
						w.Header().Set(name, workerCanary)
					}
					if !request.Stream {
						w.Header().Set("Content-Type", "application/json; fixture="+workerCanary)
						_ = json.NewEncoder(w).Encode(map[string]any{"id": workerCanary, "model": workerCanary, "choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": content}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 10, "completion_tokens": 50, "total_tokens": 60}})
						return
					}
					w.Header().Set("Content-Type", "text/event-stream; fixture="+workerCanary)
					// Split the actual key across separate SSE content_delta events.
					cut := strings.Index(content, workerCanary) + len(workerCanary)/2
					for _, chunk := range []string{content[:cut], content[cut:]} {
						payload, _ := json.Marshal(map[string]any{"id": workerCanary, "model": workerCanary, "choices": []any{map[string]any{"index": 0, "delta": map[string]string{"content": chunk}}}})
						_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
						w.(http.Flusher).Flush()
					}
					_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":50,\"total_tokens\":60}}\n\ndata: [DONE]\n\n")
				})
				tenant, run, samples := displayRun(t, f, credentials, "Emit a fixture: "+workerCanary+" / "+firstHeader+" / "+secondHeader, []bool{false, true})
				var logs executionLogBuffer
				t.Cleanup(func() {
					for _, canary := range []string{workerCanary, firstHeader, secondHeader, encodedFirst, encodedSecond} {
						if strings.Contains(logs.String(), canary) {
							t.Error("display capture leaked credentials to full Worker log")
						}
					}
				})
				startRunWorker(t, f, runTLSConfig(t, f, handler), &logs)
				finished := awaitRunClosed(t, tenant, run.ID)
				if invalid.Load() || calls.Load() != 2 || finished.RequestCount != 2 || finished.ValidSampleCount != 2 {
					t.Fatal("actual credential fixture did not complete real requests")
				}
				_, opener, err := f.ring.NewDisplayCapabilities(nil)
				if err != nil {
					t.Fatal(err)
				}
				for _, sample := range samples {
					attempt, response := evidenceFor(t, f, tenant, sample)
					if response.Content != content || response.ModelReported != workerCanary || !strings.Contains(response.ContentType, workerCanary) || response.HeaderSummary["Request-Id"] != workerCanary || response.ProviderRequestID != workerCanary {
						t.Fatal("display redaction changed original analysis response")
					}
					estimate, err := f.tokens.CountOutput(response.Content, tokenizer.Selection{ReportedModel: response.ModelReported, RequestedModel: "mock-model"})
					if err != nil || estimate.Tokens == nil || attempt.LocalCompletionTokens == nil || *estimate.Tokens != *attempt.LocalCompletionTokens || estimate.TokenizerID != attempt.TokenizerID || string(estimate.Quality) != attempt.TokenizerQuality {
						t.Fatal("display path changed actual tokenizer observation")
					}
					v := readWorkerDisplay(t, f, sample, attempt)
					if v.State != repository.DisplayCaptured || v.Policy != evidencedisplay.PolicyVersion || v.CapturedAtMicros < attempt.StartedAt.UnixMicro() || v.ExpiresAtMicros-v.CapturedAtMicros != int64(30*24*time.Hour/time.Microsecond) {
						t.Fatalf("display did not capture exact persisted scope: %s", v.State)
					}
					original, _ := json.Marshal(response)
					source := sha256.New()
					_, _ = source.Write([]byte("mii/display-source/v1\x00" + attempt.RequestHash + "\x00"))
					_, _ = source.Write(original)
					if hex.EncodeToString(source.Sum(nil)) != v.SourceHash {
						t.Fatal("display source not bound to unchanged actual response")
					}
					binding, record := displayCryptoParts(v)
					opened, err := opener.Open(f.ctx, binding, record)
					if err != nil {
						t.Fatal("actual scoped display authentication failed")
					}
					err = opened.WithCanonicalForDisplay(f.ctx, func(payload []byte) error {
						for _, canary := range []string{workerCanary, firstHeader, secondHeader, encodedFirst, encodedSecond} {
							if bytes.Contains(payload, []byte(canary)) {
								t.Error("actual known credential leaked into authenticated display")
							}
						}
						var doc struct {
							RequestJSON     string `json:"request_json"`
							RequestChanged  bool   `json:"request_changed"`
							MetadataOmitted bool   `json:"metadata_omitted"`
							Response        struct {
								Content          string                      `json:"content"`
								Model            string                      `json:"model_reported"`
								PromptTokens     *int64                      `json:"prompt_tokens"`
								CompletionTokens *int64                      `json:"completion_tokens"`
								TotalTokens      *int64                      `json:"total_tokens"`
								DurationMS       int64                       `json:"duration_ms"`
								FirstTokenMS     *int64                      `json:"first_token_ms"`
								Events           []domain.StreamEventSummary `json:"events"`
							} `json:"response"`
						}
						if json.Unmarshal(payload, &doc) != nil || !doc.RequestChanged || !doc.MetadataOmitted || !json.Valid([]byte(doc.RequestJSON)) || !strings.Contains(doc.Response.Content, "safe-prefix") || !strings.Contains(doc.Response.Content, "安全尾部") || doc.Response.Model == workerCanary || !reflect.DeepEqual(doc.Response.PromptTokens, response.PromptTokens) || !reflect.DeepEqual(doc.Response.CompletionTokens, response.CompletionTokens) || !reflect.DeepEqual(doc.Response.TotalTokens, response.TotalTokens) || doc.Response.DurationMS != response.DurationMs || !reflect.DeepEqual(doc.Response.FirstTokenMS, response.FirstTokenMs) || !reflect.DeepEqual(doc.Response.Events, response.Events) {
							t.Error("display omitted truthful bounded observations")
						}
						return nil
					})
					opened.Close()
					if err != nil {
						t.Fatal(err)
					}
					for _, change := range []func(*secret.DisplayBinding){func(b *secret.DisplayBinding) { b.Scope.OrganizationID++ }, func(b *secret.DisplayBinding) { b.Scope.AttemptID++ }, func(b *secret.DisplayBinding) { b.SourceHash = strings.Repeat("f", 64) }, func(b *secret.DisplayBinding) { b.ExpiresAtMicros++ }} {
						wrong := binding
						change(&wrong)
						if value, err := opener.Open(f.ctx, wrong, record); err == nil {
							value.Close()
							t.Fatal("display accepted changed exact history binding")
						}
					}
				}
			})
		})
	}
}

func TestRunWorkerDisplayFailuresDoNotChangeSuccessfulAttempt(t *testing.T) {
	for _, scenario := range []string{"short_header", "clock_behind", "clock_expired", "broken_sealer"} {
		t.Run(scenario, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				headers := map[string]string{"X-Plain-Marker": "safe-header-value"}
				expected := repository.DisplayUnavailableSeal
				if scenario == "short_header" {
					headers["X-Plain-Marker"] = "abc"
					expected = repository.DisplayUnavailablePolicy
				}
				tenant, run, samples := displayRun(t, f, secret.Input{Type: "bearer", APIKey: []byte(workerCanary), Headers: headers}, "Produce fixture OK", []bool{false})
				config := runTLSConfig(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"model":"mock-model","choices":[{"index":0,"message":{"role":"assistant","content":"real response unchanged"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
				}))
				switch scenario {
				case "clock_behind":
					config.DisplaySealer, _, _ = f.ring.NewDisplayCapabilities(func() time.Time { return time.Now().UTC().Add(-time.Hour) })
				case "clock_expired":
					config.DisplaySealer, _, _ = f.ring.NewDisplayCapabilities(func() time.Time { return time.Now().UTC().Add(31 * 24 * time.Hour) })
				case "broken_sealer":
					config.DisplaySealer = &secret.DisplaySealer{}
				}
				startRunWorker(t, f, config, nil)
				finished := awaitRunClosed(t, tenant, run.ID)
				if finished.RequestCount != 1 || finished.ValidSampleCount != 1 || finished.ReservedTokens != 0 {
					t.Fatal("display failure changed real attempt counts")
				}
				attempt, response := evidenceFor(t, f, tenant, samples[0])
				if response.Content != "real response unchanged" || attempt.Status != "COMPLETED" || attempt.ErrorCode == nil || *attempt.ErrorCode != "" {
					t.Fatal("display failure changed real analysis evidence")
				}
				v := readWorkerDisplay(t, f, samples[0], attempt)
				if v.State != expected || len(v.Ciphertext) != 0 || len(v.Nonce) != 0 || v.SourceHash != "" || v.KeyVersion != "" || v.PayloadHash != "" || v.CapturedAtMicros != 0 || v.ExpiresAtMicros != 0 {
					t.Fatal("failed display retained envelope or pretended captured")
				}
			})
		})
	}
}

func TestRunDisplayCancelledAndInvalidSourceAreClosedWithoutMutatingResult(t *testing.T) {
	result := runCallResult{attempt: repository.AttemptRecord{OrganizationID: 1, RunID: 2, LogicalSampleID: 3, ID: 4, RequestHash: strings.Repeat("a", 64)}, response: domain.NormalizedResponse{Content: "untouched actual response"}, outcome: domain.AttemptOutcome{Validity: "VALID", HTTPStatus: 200}}
	original := result
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := captureRunDisplay(ctx, Execution{}, nil, domain.NormalizedRequest{}, result, nil, nil); got.State != repository.DisplayUnavailableCancelled {
		t.Fatal("cancel did not fail closed")
	}
	if got := captureRunDisplay(t.Context(), Execution{}, nil, domain.NormalizedRequest{}, result, nil, nil); got.State != repository.DisplayUnavailableSource {
		t.Fatal("invalid snapshot did not fail closed")
	}
	if !reflect.DeepEqual(result, original) || !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("display mutated source")
	}
}

func TestRunWorkerDisplayActualTLSPreparedThenLostLeaseOrSQLFailureNeverPersists(t *testing.T) {
	for _, fault := range []string{"lease_owner", "final_context_cancel", "display_insert", "finish_audit"} {
		t.Run(fault, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				tenant, run, samples := f.createRun(t, []bool{false})
				var calls atomic.Int64
				config := runTLSConfig(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Header.Get("Authorization") != "Bearer "+workerCanary {
						t.Error("fixture did not receive actual scoped key")
					}
					_, _ = io.Copy(io.Discard, r.Body)
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"model": "mock-model", "choices": []any{map[string]any{"index": 0, "message": map[string]string{"role": "assistant", "content": "actual completion " + workerCanary}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}})
				}))
				handlers, err := NewRunHandlers(config)
				if err != nil {
					t.Fatal(err)
				}
				queue, err := f.store.OpenJobQueue(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = queue.Close(context.Background()) })
				planLease, err := queue.Claim(f.ctx)
				if err != nil || planLease == nil || repository.JobType(planLease.Job.Type) != repository.JobRunPlan {
					t.Fatal("claim real run plan")
				}
				start, err := handlers[repository.JobRunPlan](f.ctx, Execution{Queue: queue, Lease: *planLease})
				if err != nil {
					t.Fatal(err)
				}
				if err := queue.CompleteWith(f.ctx, *planLease, start); err != nil {
					t.Fatal(err)
				}
				lease, err := queue.Claim(f.ctx)
				if err != nil || lease == nil || repository.JobType(lease.Job.Type) != repository.JobSampleExecute {
					t.Fatal("claim real sample")
				}
				completion, err := handlers[repository.JobSampleExecute](f.ctx, Execution{Queue: queue, Lease: *lease})
				if err != nil || completion == nil || calls.Load() != 1 {
					t.Fatal("real TLS handler did not prepare result")
				}
				assertNoEvidence := func() {
					t.Helper()
					for _, query := range []string{
						"SELECT count(*) FROM integrity_display_evidence WHERE organization_id=$1 AND run_id=$2",
						"SELECT count(*) FROM integrity_response_evidence WHERE organization_id=$1 AND run_id=$2",
						"SELECT count(*) FROM integrity_jobs WHERE organization_id=$1 AND object_id=$2 AND type='integrity.run.analyze'",
					} {
						var count int
						if err := f.db.QueryRowContext(f.ctx, query, f.orgID, run.ID).Scan(&count); err != nil || count != 0 {
							t.Fatal("orphan evidence or dependent Job after failed completion")
						}
					}
					current, err := tenant.GetRun(run.ID)
					if err != nil || current.ValidSampleCount != 0 || current.RequestCount != 1 || current.TokenCount != 0 || current.ReservedTokens == 0 || current.ExecutionClosedAt != nil {
						t.Fatal("failing display completion altered run accounting")
					}
					attempts, err := tenant.ListAttempts(samples[0].ID)
					if err != nil || len(attempts) != 1 || attempts[0].Status != "DISPATCHED" || attempts[0].FinishedAt != nil {
						t.Fatal("failing display completion altered actual Attempt")
					}
					var count int
					if err := f.db.QueryRowContext(f.ctx, "SELECT count(*) FROM integrity_audit_logs WHERE organization_id=$1 AND action='run.attempt.finish'", f.orgID).Scan(&count); err != nil || count != 0 {
						t.Fatal("failed completion committed finish audit")
					}
				}
				assertNoEvidence() // No side effect during Prepare/Seal or leaving Use.
				if fault == "lease_owner" {
					if _, err := f.db.ExecContext(f.ctx, "UPDATE integrity_jobs SET lease_owner='replacement-owner' WHERE organization_id=$1 AND id=$2", f.orgID, lease.Job.ID); err != nil {
						t.Fatal("replace current owner")
					}
				}
				if fault == "display_insert" || fault == "finish_audit" {
					table, condition := "integrity_display_evidence", "state = 'captured'"
					if fault == "finish_audit" {
						table, condition = "integrity_audit_logs", "action = 'run.attempt.finish'"
					}
					statement := "ALTER TABLE " + table + " ADD CONSTRAINT worker_display_failure CHECK (NOT (" + condition + ")) NOT VALID"
					if fault == "display_insert" {
						// Both captured and legitimate unavailable rows are display
						// inserts. The fault must exercise either actual INSERT.
						statement = "ALTER TABLE integrity_display_evidence ADD CONSTRAINT worker_display_failure CHECK (FALSE) NOT VALID"
					}
					if strings.HasSuffix(t.Name(), "/sqlite") {
						statement = "CREATE TRIGGER worker_display_failure BEFORE INSERT ON " + table + " WHEN NEW." + condition + " BEGIN SELECT RAISE(ABORT, 'synthetic worker display failure'); END"
						if fault == "display_insert" {
							statement = "CREATE TRIGGER worker_display_failure BEFORE INSERT ON integrity_display_evidence BEGIN SELECT RAISE(ABORT, 'synthetic worker display failure'); END"
						}
					}
					if _, err := f.db.ExecContext(f.ctx, statement); err != nil {
						t.Fatal("install real Worker transaction fault")
					}
				}
				actualCompletion := completion
				commitCtx, cancelCommit := context.WithCancel(f.ctx)
				defer cancelCommit()
				if fault == "final_context_cancel" {
					actualCompletion = func(tx *repository.TenantTransaction) error {
						if err := completion(tx); err != nil {
							return err
						}
						// Cancel the completion context only after all typed writes. The
						// transaction must reject the final commit and roll everything back.
						cancelCommit()
						return nil
					}
				}
				err = queue.CompleteWith(commitCtx, *lease, actualCompletion)
				if err == nil {
					// Failure-only metadata: SQL maps arbitrary TEXT to small codes;
					// Go checks those codes again before selecting fixed labels. Never
					// load/log body, ciphertext, source hashes or driver error text.
					diagnosticCtx, stopDiagnostic := context.WithTimeout(f.ctx, time.Second)
					defer stopDiagnostic()
					var displayCode, attemptCode, receiptCode int
					var rawExists bool
					diagnosticErr := f.db.QueryRowContext(diagnosticCtx, `SELECT
COALESCE((SELECT CASE state WHEN 'captured' THEN 1 WHEN 'unavailable_redaction_policy' THEN 2 WHEN 'unavailable_safety_limit' THEN 3 WHEN 'unavailable_source_invalid' THEN 4 WHEN 'unavailable_cancelled' THEN 5 WHEN 'unavailable_capture' THEN 6 WHEN 'unavailable_seal' THEN 7 ELSE 8 END FROM integrity_display_evidence WHERE organization_id=$1 AND run_id=$2 AND logical_sample_id=$3 LIMIT 1),0),
COALESCE((SELECT CASE status WHEN 'PLANNED' THEN 1 WHEN 'DISPATCHED' THEN 2 WHEN 'COMPLETED' THEN 3 WHEN 'UNCERTAIN' THEN 4 ELSE 5 END FROM integrity_sample_attempts WHERE organization_id=$1 AND run_id=$2 AND logical_sample_id=$3 AND attempt_no=1 LIMIT 1),0),
COALESCE((SELECT CASE response_body_receipt WHEN 'legacy_not_recorded' THEN 1 WHEN 'not_captured' THEN 2 WHEN 'not_retained' THEN 3 WHEN 'recorded' THEN 4 ELSE 5 END FROM integrity_sample_attempts WHERE organization_id=$1 AND run_id=$2 AND logical_sample_id=$3 AND attempt_no=1 LIMIT 1),0),
EXISTS(SELECT 1 FROM integrity_response_evidence WHERE organization_id=$1 AND run_id=$2 AND logical_sample_id=$3)`, f.orgID, run.ID, samples[0].ID).Scan(&displayCode, &attemptCode, &receiptCode, &rawExists)
					if diagnosticErr != nil {
						t.Log("display failure diagnostic query=unavailable")
					} else {
						label := func(code int, labels []string) string {
							if code < 0 || code >= len(labels) {
								return "invalid_code"
							}
							return labels[code]
						}
						displayState := label(displayCode, []string{"missing", "captured", "unavailable_redaction_policy", "unavailable_safety_limit", "unavailable_source_invalid", "unavailable_cancelled", "unavailable_capture", "unavailable_seal", "invalid_state"})
						attemptState := label(attemptCode, []string{"missing", "PLANNED", "DISPATCHED", "COMPLETED", "UNCERTAIN", "invalid_state"})
						receiptState := label(receiptCode, []string{"missing", "legacy_not_recorded", "not_captured", "not_retained", "recorded", "invalid_state"})
						t.Logf("display failure diagnostic display=%s attempt=%s body_receipt=%s raw_exists=%t", displayState, attemptState, receiptState, rawExists)
					}
					t.Fatal("real TLS result committed through injected failure")
				}
				if fault == "lease_owner" && !errors.Is(err, repository.ErrJobLeaseLost) {
					t.Fatal("changed owner not fenced")
				}
				if fault == "display_insert" && !errors.Is(err, repository.ErrConflict) {
					t.Fatal("display INSERT fault did not produce the closed constraint error")
				}
				assertNoEvidence()
				if calls.Load() != 1 {
					t.Fatal("failed final commit redispatched upstream")
				}
				if fault == "display_insert" {
					if err := queue.CheckLease(f.ctx, *lease); err != nil {
						t.Fatal("display INSERT rollback lost the original lease")
					}
					statement := "ALTER TABLE integrity_display_evidence DROP CONSTRAINT worker_display_failure"
					if strings.HasSuffix(t.Name(), "/sqlite") {
						statement = "DROP TRIGGER worker_display_failure"
					}
					if _, err := f.db.ExecContext(f.ctx, statement); err != nil {
						t.Fatal("remove the test-owned display INSERT fault")
					}
					// No new handler, lease or request: removing only the fault must
					// let this exact already-prepared completion commit atomically.
					if err := queue.CompleteWith(f.ctx, *lease, completion); err != nil {
						t.Fatal("same completion failed after removing display INSERT fault", err)
					}
					attempts, err := tenant.ListAttempts(samples[0].ID)
					if err != nil || len(attempts) != 1 || attempts[0].Status != "COMPLETED" || attempts[0].FinishedAt == nil || attempts[0].ResponseBodyReceipt != repository.BodyRecorded {
						t.Fatal("same completion did not settle the original Attempt")
					}
					for _, query := range []string{
						"SELECT count(*) FROM integrity_display_evidence WHERE organization_id=$1 AND run_id=$2 AND logical_sample_id=$3 AND attempt_id=$4",
						"SELECT count(*) FROM integrity_response_evidence WHERE organization_id=$1 AND run_id=$2 AND logical_sample_id=$3 AND attempt_id=$4",
					} {
						var count int
						if err := f.db.QueryRowContext(f.ctx, query, f.orgID, run.ID, samples[0].ID, attempts[0].ID).Scan(&count); err != nil || count != 1 {
							t.Fatal("same completion did not persist exactly one scoped evidence row")
						}
					}
					if calls.Load() != 1 {
						t.Fatal("retrying only settlement redispatched upstream")
					}
				}
			})
		})
	}
}
