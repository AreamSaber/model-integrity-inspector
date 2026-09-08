package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
	"model-integrity-inspector.local/mii/internal/integrity/worker"
)

type resultHTTPFixture struct {
	controlFixture
	cookie     *http.Cookie
	headers    map[string]string
	ctx        context.Context
	org, runID int64
	queue      *repository.JobQueue
	engine     *tokenizer.Engine
	builder    *features.Builder
	keys       *secret.KeyRing
}

type resultNoNetwork struct{}

func (resultNoNetwork) Do(*http.Request) (*http.Response, error) {
	return nil, repository.ErrUnavailable
}

func newResultHTTPFixture(t *testing.T) resultHTTPFixture {
	t.Helper()
	var engine *tokenizer.Engine
	var builder *features.Builder
	var keys *secret.KeyRing
	f := newControlFixture(t, func(cfg *ControlConfig) {
		var err error
		engine, err = tokenizer.NewBuiltin()
		if err != nil {
			t.Fatal(err)
		}
		keys = cfg.CursorSigner.(*secret.KeyRing)
		artifact, hash, err := templates.Builtin().Canonical()
		if err != nil {
			t.Fatal(err)
		}
		compiler, err := generator.New(artifact, hash, engine, keys)
		if err != nil {
			t.Fatal(err)
		}
		builder, err = features.New(features.Config{Verifier: compiler, Tokenizer: engine, TemplateArtifact: artifact, TrustedTemplateHash: hash})
		if err != nil {
			t.Fatal(err)
		}
		cfg.Runs, err = runservice.NewService(runservice.Config{Store: cfg.Store, Targets: cfg.Targets, Generator: compiler, Limits: scheduler.DefaultLimits(), RuleVersion: scoring.Version, ScoringVersion: scoring.Version, ExecutionReady: func(context.Context) bool { return true }})
		if err != nil {
			t.Fatal(err)
		}
	})
	f.initialize(t)
	cookie, csrf, org := f.login(t)
	headers := map[string]string{"X-Organization-ID": org, "X-CSRF-Token": csrf}
	w := f.request(t, "POST", "/api/v1/targets", targetHTTPBody, headers, cookie)
	expectControl(t, w, 201, "")
	var target targetHTTPView
	managementHTTPData(t, w, &target)
	runHTTPPassedPrecheck(t, f, cookie, headers, target.ID)
	w = f.request(t, "POST", "/api/v1/runs/estimate", `{"target_id":"`+target.ID+`","target_version":1,"package":"quick"}`, headers, cookie)
	expectControl(t, w, 200, "")
	var quote runHTTPQuote
	managementHTTPData(t, w, &quote)
	w = f.request(t, "POST", "/api/v1/runs", runHTTPConfirm(quote), headers, cookie)
	expectControl(t, w, 202, "")
	var run runHTTPView
	managementHTTPData(t, w, &run)
	runID, _ := managementID(run.ID)
	orgID, _ := managementID(org)
	session, err := f.cfg.Store.GetSession(t.Context(), digest(cookie.Value), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := f.cfg.Store.BindControlAuthority(audit.WithActor(t.Context(), audit.Actor{ActorID: session.UserID, ReasonCode: "result.http.test"}), digest(cookie.Value), orgID)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := f.cfg.Store.OpenJobQueue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queue.Close(context.Background()) })
	return resultHTTPFixture{f, cookie, headers, ctx, orgID, runID, queue, engine, builder, keys}
}

// This control-plane integration uses synthetic normalized responses (no paid
// network API), real adapter request serialization, AES-GCM evidence, final
// attempt fences, production analysis handler, and atomic result publication.
func (f resultHTTPFixture) publish(t *testing.T) {
	t.Helper()
	tenant, err := f.cfg.Store.WithOrganization(f.ctx, f.org)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := openaichat.New(openaichat.Config{Endpoint: "https://example.com/v1", MaxOutputParameter: "max_tokens", Doer: resultNoNetwork{}})
	if err != nil {
		t.Fatal(err)
	}
	for steps := 0; steps < 25; steps++ {
		lease, err := f.queue.Claim(f.ctx)
		if err != nil || lease == nil {
			t.Fatal("result job missing", err)
		}
		switch repository.JobType(lease.Job.Type) {
		case repository.JobRunPlan:
			if err := f.queue.CompleteWith(f.ctx, *lease, func(tx *repository.TenantTransaction) error { return tx.StartRun(f.runID) }); err != nil {
				t.Fatal(err)
			}
		case repository.JobSampleExecute:
			samples, err := tenant.ListExecutionSamples(f.runID)
			if err != nil {
				t.Fatal(err)
			}
			var sample repository.LogicalSampleRecord
			for _, row := range samples {
				if row.ID == lease.Job.ObjectID {
					sample = row
				}
			}
			var plan domain.SamplePlan
			if json.Unmarshal([]byte(sample.RequestPlan), &plan) != nil {
				t.Fatal("sample plan fixture")
			}
			_, snapshot, err := adapter.BuildRequest(f.ctx, plan.Request)
			if err != nil {
				t.Fatal(err)
			}
			var attempt repository.AttemptRecord
			if err := f.queue.WithLease(f.ctx, *lease, func(tx *repository.TenantTransaction) error {
				var e error
				attempt, e = tx.ReserveAttempt(sample.ID, snapshot)
				return e
			}); err != nil {
				t.Fatal(err)
			}
			body := "PRIVATE_RESULT_CANARY_907. Complete response."
			local, err := f.engine.CountOutput(body, tokenizer.Selection{RequestedModel: plan.Request.Model})
			if err != nil || local.Tokens == nil {
				t.Fatal(err)
			}
			prompt := int64(10)
			total := prompt + *local.Tokens
			response := domain.NormalizedResponse{Content: body, ModelReported: plan.Request.Model, FinishReason: "stop", PromptTokens: &prompt, CompletionTokens: local.Tokens, TotalTokens: &total, HTTPStatus: 200, ContentType: "application/json", DurationMs: 1, ParseStatus: "valid", ChoiceCount: 1, StreamTerminated: plan.Request.Stream, EndCause: "complete"}
			response.ParseWarnings = []string{"OBJECT_MISSING"}
			if plan.Request.Stream {
				response.ContentType = "text/event-stream"
				response.EndCause = "done"
			}
			// Capture the actual DB scope/time/policy before final completion.
			// This fixture has no display-redaction capture, so retain a valid
			// explicit unavailable record alongside the original analysis body.
			var capture *repository.AttemptBodyCapture
			if err := f.queue.WithLease(f.ctx, *lease, func(tx *repository.TenantTransaction) error {
				var e error
				capture, e = tx.BindAttemptResponseCapture(sample.ID, attempt.ID, snapshot.RequestHash)
				return e
			}); err != nil {
				t.Fatal(err)
			}
			e, err := f.keys.EncryptResponseEvidence(secret.EvidenceScope{OrganizationID: f.org, RunID: f.runID, LogicalSampleID: sample.ID, AttemptID: attempt.ID, RequestHash: snapshot.RequestHash}, response)
			if err != nil {
				t.Fatal(err)
			}
			outcome := domain.AttemptOutcome{Validity: "VALID_WITH_WARNING", HTTPStatus: 200, PromptTokens: &prompt, CompletionTokens: local.Tokens, LocalCompletionTokens: *local.Tokens, TokenizerID: local.TokenizerID, TokenizerQuality: string(local.Quality), DurationMillis: 1}
			record := repository.ResponseEvidenceRecord{OrganizationID: f.org, RunID: f.runID, LogicalSampleID: sample.ID, AttemptID: attempt.ID, RequestHash: snapshot.RequestHash, KeyVersion: e.KeyVersion, Nonce: e.Nonce, Ciphertext: e.Ciphertext, PlaintextBytes: e.PlaintextBytes, ContentHash: e.ContentHash}
			display := capture.DisplayBinding()
			display.State = repository.DisplayUnavailableCapture
			display.CapturedAtMicros, display.ExpiresAtMicros = 0, 0
			bodies, err := capture.WithRecords(record, display)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.queue.CompleteWith(f.ctx, *lease, func(tx *repository.TenantTransaction) error {
				return tx.FinishLegacyAttemptWithCapture(sample.ID, attempt.ID, outcome, 0, bodies)
			}); err != nil {
				t.Fatal(err)
			}
		case repository.JobRunAnalyze:
			handler, err := worker.NewAnalysisHandler(worker.AnalysisConfig{Builder: f.builder, EvidenceKeys: f.keys})
			if err != nil {
				t.Fatal(err)
			}
			completion, err := handler(f.ctx, worker.Execution{Queue: f.queue, Lease: *lease})
			if err != nil {
				t.Fatal("actual analysis", err)
			}
			if err := f.queue.CompleteWith(f.ctx, *lease, completion); err != nil {
				t.Fatal(err)
			}
			return
		default:
			t.Fatal("unexpected result fixture job")
		}
	}
	t.Fatal("analysis not reached")
}

func resultNoS2(t *testing.T, body string) {
	t.Helper()
	for _, value := range []string{"PRIVATE_RESULT_CANARY_907", targetHTTPKey, `"Content"`, `"content"`, `"ciphertext"`, `"nonce"`, `"messages"`, `"request_plan"`, `"conclusion_json"`, `"response_content"`, `"request_snapshot"`, `"ConfigSnapshot"`} {
		if strings.Contains(body, value) {
			t.Fatal("S2 disclosed", value)
		}
	}
}

func TestRunResultHTTPPublishedProjectionPaginationAndScopes(t *testing.T) {
	f := newResultHTTPFixture(t)
	path := "/api/v1/runs/" + strconv.FormatInt(f.runID, 10)
	expectControl(t, f.request(t, "GET", path+"/result", "", f.headers, f.cookie), 404, "MI_NOT_FOUND")
	f.publish(t)
	for _, suffix := range []string{"/result", "/result?include=statistics", "/findings?limit=1", "/samples?limit=1"} {
		w := f.request(t, "GET", path+suffix, "", f.headers, f.cookie)
		expectControl(t, w, 200, "")
		resultNoS2(t, w.Body.String())
	}
	w := f.request(t, "GET", path+"/result", "", f.headers, f.cookie)
	var result runservice.ResultView
	managementHTTPData(t, w, &result)
	if result.RunID != strconv.FormatInt(f.runID, 10) || result.AnalysisRevision != 1 || result.ExpectedSamples != 18 || result.ValidSamples < 1 || result.ValidSamples > result.ExpectedSamples || !result.Development || result.Calibrated || result.TokenAnalysis != nil || result.BehaviorAnalysis != nil || result.EvidenceGrade == "A" || result.EvidenceGrade == "B" {
		t.Fatal("result summary policy")
	}
	w = f.request(t, "GET", path+"/result?include=statistics", "", f.headers, f.cookie)
	managementHTTPData(t, w, &result)
	if result.TokenAnalysis == nil || result.BehaviorAnalysis == nil {
		t.Fatal("statistics absent")
	}
	w = f.request(t, "GET", path+"/samples?limit=1", "", f.headers, f.cookie)
	var page struct {
		Items []runservice.SampleView `json:"items"`
		Next  *string                 `json:"next_cursor"`
	}
	managementHTTPData(t, w, &page)
	if len(page.Items) != 1 || page.Next == nil {
		t.Fatal("sample page missing cursor")
	}
	sample := page.Items[0]
	w = f.request(t, "GET", path+"/samples/"+sample.ID, "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	resultNoS2(t, w.Body.String())
	var detail runservice.SampleDetail
	managementHTTPData(t, w, &detail)
	if len(detail.Attempts) != 1 || detail.Sample.ContentState != "redacted" || detail.Attempts[0].ContentState != "redacted" || detail.Attempts[0].ErrorCode != nil || detail.Attempts[0].Validity != "VALID_WITH_WARNING" || !strings.Contains(w.Body.String(), "MI_PROTOCOL_OBJECT_MISSING") {
		t.Fatal("S1 sample/attempt")
	}
	w = f.request(t, "GET", path+"/samples?limit=1&cursor="+*page.Next, "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	managementHTTPData(t, w, &page)
	if page.Items[0].ID == sample.ID {
		t.Fatal("cursor repeated first sample")
	}
	w = f.request(t, "GET", "/api/v1/runs?limit=1", "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	resultNoS2(t, w.Body.String())
	var history struct {
		Items []runservice.HistoryItem `json:"items"`
	}
	managementHTTPData(t, w, &history)
	if len(history.Items) != 1 || history.Items[0].Result == nil || history.Items[0].CompletedSamples != 18 {
		t.Fatal("published history missing")
	}
	for _, suffix := range []string{"/result?analysis_revision=2", "/samples/1"} {
		expectControl(t, f.request(t, "GET", path+suffix, "", f.headers, f.cookie), 404, "MI_NOT_FOUND")
	}
	for _, suffix := range []string{"/result?include=body", "/result?analysis_revision=01", "/result?analysis_revision=1&analysis_revision=1", "/samples?limit=101", "/samples?cursor=wrong", "/samples?q=body", "/findings?cursor=" + *page.Next} {
		expectControl(t, f.request(t, "GET", path+suffix, "", f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
	}
	for _, query := range []string{"limit=0", "status=", "status=%20", "model=%20", "risk_level=attention", "date_from=2026-01-02T00:00:00Z&date_to=2026-01-01T00:00:00Z", "model=x&model=y", "unknown=y"} {
		expectControl(t, f.request(t, "GET", "/api/v1/runs?"+query, "", f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
	}
	if err := f.cfg.Store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}

func TestRunResultHTTPReaderTenantAndSignedCursorAuthority(t *testing.T) {
	f := newResultHTTPFixture(t)
	f.publish(t)
	org, csrf := f.headers["X-Organization-ID"], f.headers["X-CSRF-Token"]
	path := "/api/v1/runs/" + strconv.FormatInt(f.runID, 10)
	viewer := runAuthorizationMember(t, f.controlFixture, f.cookie, csrf, org, "result-reader", "viewer", nil)
	viewerHeaders := runAuthorizationHeaders(org, viewer.csrf)
	paths := []string{"/api/v1/runs", path + "/result", path + "/result?include=statistics", path + "/findings", path + "/samples"}
	for _, endpoint := range paths {
		w := f.request(t, "GET", endpoint, "", viewerHeaders, viewer.cookie)
		expectControl(t, w, 200, "")
		resultNoS2(t, w.Body.String())
		expectControl(t, f.request(t, "GET", endpoint, "", f.headers, nil), 401, "MI_SESSION_REQUIRED")
		expectControl(t, f.request(t, "GET", endpoint, "", nil, f.cookie), 400, "MI_INVALID_REQUEST")
	}
	w := f.request(t, "GET", path+"/samples?limit=1", "", f.headers, f.cookie)
	var samplePage struct {
		Items []runservice.SampleView `json:"items"`
		Next  *string                 `json:"next_cursor"`
	}
	managementHTTPData(t, w, &samplePage)
	if samplePage.Next == nil || len(samplePage.Items) != 1 {
		t.Fatal("sample cursor unavailable")
	}
	samplePath := path + "/samples/" + samplePage.Items[0].ID
	paths = append(paths, samplePath)
	expectControl(t, f.request(t, "GET", path+"/samples?cursor="+*samplePage.Next, "", viewerHeaders, viewer.cookie), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "GET", path+"/samples?analysis_revision=2&cursor="+*samplePage.Next, "", f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
	w = f.request(t, "POST", "/api/v1/organizations", `{"name":"Isolated result readers","timezone":"UTC"}`, f.headers, f.cookie)
	expectControl(t, w, 201, "")
	var other managementHTTPObject
	managementHTTPData(t, w, &other)
	otherHeaders := runAuthorizationHeaders(other.ID, csrf)
	for _, endpoint := range paths[1:] {
		expectControl(t, f.request(t, "GET", endpoint, "", otherHeaders, f.cookie), 404, "MI_NOT_FOUND")
		expectControl(t, f.request(t, "GET", endpoint, "", runAuthorizationHeaders(other.ID, viewer.csrf), viewer.cookie), 403, "MI_PERMISSION_DENIED")
	}
	w = f.request(t, "GET", "/api/v1/runs", "", otherHeaders, f.cookie)
	expectControl(t, w, 200, "")
	var history struct {
		Items []runservice.HistoryItem `json:"items"`
		Next  *string                  `json:"next_cursor"`
	}
	managementHTTPData(t, w, &history)
	if len(history.Items) != 0 {
		t.Fatal("other organization learned run history")
	}

	// Issue a genuine status-filtered cursor and transition the anchor through
	// the ordinary cancellation endpoint between pages. The immutable ordering
	// boundary survives; changing the signed filter or reader does not.
	rows, err := f.cfg.Runs.History(f.ctx, f.org, repository.ListOptions{Limit: 1}, repository.RunFilters{})
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	for range 2 {
		quote := runAuthorizationEstimate(t, f.controlFixture, f.cookie, csrf, org, runAuthorizationQuick(rows[0].TargetID))
		runAuthorizationConfirm(t, f.controlFixture, f.cookie, csrf, org, quote)
	}
	w = f.request(t, "GET", "/api/v1/runs?limit=1&status=QUEUED", "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	managementHTTPData(t, w, &history)
	if len(history.Items) != 1 || history.Next == nil {
		t.Fatal("history cursor missing")
	}
	anchor, cursor := history.Items[0], *history.Next
	expectControl(t, f.request(t, "POST", "/api/v1/runs/"+anchor.ID+"/cancel", `{"version":1}`, f.headers, f.cookie), 200, "")
	w = f.request(t, "GET", "/api/v1/runs?status=QUEUED&cursor="+cursor, "", f.headers, f.cookie)
	expectControl(t, w, 200, "")
	managementHTTPData(t, w, &history)
	if len(history.Items) != 1 || history.Items[0].ID == anchor.ID {
		t.Fatal("mutable anchor lost remaining history")
	}
	for _, query := range []string{"status=RUNNING", "status=QUEUED&q=x", "status=QUEUED&package=quick"} {
		expectControl(t, f.request(t, "GET", "/api/v1/runs?"+query+"&cursor="+cursor, "", f.headers, f.cookie), 400, "MI_INVALID_REQUEST")
	}
	expectControl(t, f.request(t, "GET", "/api/v1/runs?status=QUEUED&cursor="+cursor, "", viewerHeaders, viewer.cookie), 400, "MI_INVALID_REQUEST")
	// Membership revocation is observed even while the login session remains.
	w = f.request(t, "PATCH", "/api/v1/organizations/"+org+"/members/"+viewer.member.ID, `{"version":1,"status":"disabled"}`, f.headers, f.cookie)
	expectControl(t, w, 200, "")
	for _, endpoint := range paths {
		expectControl(t, f.request(t, "GET", endpoint, "", viewerHeaders, viewer.cookie), 403, "MI_PERMISSION_DENIED")
	}
	expectControl(t, f.request(t, "POST", "/api/v1/auth/logout", `{}`, f.headers, f.cookie), 200, "")
	for _, endpoint := range paths {
		expectControl(t, f.request(t, "GET", endpoint, "", f.headers, f.cookie), 401, "MI_SESSION_REQUIRED")
	}
	if err := f.cfg.Store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}
