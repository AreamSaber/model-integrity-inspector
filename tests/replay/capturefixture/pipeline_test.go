package capturefixture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/identity"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/bundle"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/target"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
	"model-integrity-inspector.local/mii/internal/integrity/worker"
	"model-integrity-inspector.local/mii/tests/replay"
	"model-integrity-inspector.local/mii/tests/replay/localfile"
)

type loopbackResolver struct{}

func (loopbackResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(data)
}

func TestActualWorkerTLSCaptureThenOfflineReplay(t *testing.T) {
	for _, driver := range []string{"sqlite", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			for _, omitDone := range []bool{false, true} {
				name := "complete"
				if omitDone {
					name = "stream-terminal-omitted"
				}
				t.Run(name, func(t *testing.T) { captureActual(t, driver, omitDone, false, false) })
			}
		})
	}
}

func TestActualPublicationRollbackCannotSealCapture(t *testing.T) {
	for _, driver := range []string{"sqlite", "postgres"} {
		t.Run(driver, func(t *testing.T) { captureActual(t, driver, false, true, false) })
	}
}

func captureActual(t *testing.T, driver string, omitDone, failCommit, delayReservation bool) {
	t.Helper()
	// All material is newly generated for this disposable DEVELOPMENT run.
	// No real production credential, official upstream or acceptance label exists.
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	ring, err := secret.NewKeyRing("dev-capture", map[string][]byte{"dev-capture": master})
	// Retain only this test's known canaries for finite export leakage checks.
	// The application master itself is never an exportable ManifestSigner.
	forbidden := secretCanaries(master)
	clear(master)
	if err != nil {
		t.Fatal(err)
	}
	dbConfig := captureDatabase(t, driver)
	dbConfig.AuditSigner = ring
	store, err := repository.Open(t.Context(), dbConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	actors := audit.WithActor(t.Context(), audit.Actor{ReasonCode: "development.capture"})
	accounts, err := identity.NewService(actors, store)
	if err != nil {
		t.Fatal(err)
	}
	password := "Development-" + randomHex(t, 20)
	if err := accounts.Initialize(actors, "Development capture", "admin", password); err != nil {
		t.Fatal(err)
	}
	session, err := accounts.Login(actors, "admin", password)
	if err != nil || len(session.Organizations) != 1 {
		t.Fatal("actual login failed")
	}
	orgID := session.Organizations[0].ID
	principal, err := accounts.Principal(actors, session.CookieValue(), orgID)
	if err != nil {
		t.Fatal(err)
	}
	ctx := audit.WithActor(t.Context(), audit.Actor{ActorID: principal.UserID, ReasonCode: "development.capture"})
	ctx, err = store.BindControlAuthority(ctx, hash([]byte(session.CookieValue())), orgID)
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := store.WithOrganization(ctx, orgID)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := secret.NewService(store, ring)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := target.NewService(target.Config{Store: store, Secrets: secrets})
	if err != nil {
		t.Fatal(err)
	}
	credential := randomHex(t, 32)
	targetRecord, err := targets.Create(ctx, orgID, target.Input{Name: "Development TLS capture", Endpoint: "https://upstream.example.com/v1", Protocol: "openai_chat", Model: "gpt-4o", Options: target.Options{MaxOutputParameter: "max_tokens", TimeoutSeconds: 10, Concurrency: 1, RPM: 1000}}, secret.Input{Type: "bearer", APIKey: []byte(credential)})
	if err != nil {
		t.Fatal(err)
	}
	recorder := newRecorder(t, credential, omitDone)
	tls := httptest.NewTLSServer(recorder)
	t.Cleanup(tls.Close)
	roots := x509.NewCertPool()
	roots.AddCert(tls.Certificate())
	dial := func(callCtx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "8.8.8.8:443" {
			return nil, errCapture
		}
		return (&net.Dialer{}).DialContext(callCtx, network, tls.Listener.Addr().String())
	}
	tokens, err := tokenizer.NewBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	artifact, artifactHash, err := templates.Builtin().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	manifestSigner, err := localfile.NewManifestSigner()
	if err != nil {
		t.Fatal("independent development manifest signer unavailable")
	}
	// Cleanup runs after stopWorker, which is registered below (LIFO).
	t.Cleanup(manifestSigner.Destroy)
	compiler, err := generator.New(artifact, artifactHash, tokens, manifestSigner)
	if err != nil {
		t.Fatal(err)
	}
	builder, err := features.New(features.Config{Verifier: compiler, Tokenizer: tokens, TemplateArtifact: artifact, TrustedTemplateHash: artifactHash})
	if err != nil {
		t.Fatal(err)
	}
	handlers, err := worker.NewRunHandlers(worker.RunConfig{Store: store, Secrets: secrets, EvidenceKeys: ring, Tokenizer: tokens, Resolver: loopbackResolver{}, DialContext: dial, RootCAs: roots, RequestTimeout: 10 * time.Second, LivenessInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if delayReservation {
		handlers[repository.JobSampleExecute] = delayedReservation(t, dbConfig, handlers[repository.JobSampleExecute])
	}
	precheck, err := worker.NewPrecheckHandler(worker.PrecheckConfig{Store: store, Secrets: secrets, Resolver: loopbackResolver{}, DialContext: dial, RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	handlers[repository.JobTargetPrecheck] = precheck
	analysis, err := worker.NewAnalysisHandler(worker.AnalysisConfig{Builder: builder, EvidenceKeys: ring})
	if err != nil {
		t.Fatal(err)
	}
	public, captureKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(captureKey)
	forbidden = append(forbidden, secretCanaries(captureKey)...)
	forbidden = append(forbidden, secretCanaries(captureKey.Seed())...)
	forbidden = append(forbidden, credential, password)
	exporter := settledExporter{store: store, tenant: tenant, signer: manifestSigner, key: captureKey, forbidden: forbidden}
	exportDir := capturePrivateDir(t)
	caseID := randomHex(t, 16)
	pending := make(chan replay.CaptureDraft, 1)
	release := make(chan struct{})
	rollbackReached := make(chan struct{}, 1)
	handlers[repository.JobRunAnalyze] = func(callCtx context.Context, execution worker.Execution) (worker.Completion, error) {
		source, err := execution.Queue.LoadRunAnalysis(callCtx, execution.Lease)
		if err != nil {
			return nil, err
		}
		records, err := recorder.snapshot()
		if err != nil {
			return nil, err
		}
		var draft replay.CaptureDraft
		err = source.Use(func(data repository.AnalysisData) error {
			var err error
			draft, err = draftFromLease(data, ring, records, caseID)
			if err == nil {
				err = rejectChangedSource(data, ring, records, caseID)
			}
			return err
		})
		if err != nil {
			return nil, err
		}
		completion, err := analysis(callCtx, execution)
		if err != nil {
			return nil, err
		}
		select {
		case pending <- draft:
		case <-callCtx.Done():
			return nil, callCtx.Err()
		}
		// The handler is done computing, but CompleteWith has not run yet.
		select {
		case <-release:
			if failCommit {
				return func(tx *repository.TenantTransaction) error {
					if err := completion(tx); err != nil {
						return err
					}
					select {
					case rollbackReached <- struct{}{}:
					default:
					}
					// Actual publication/audit writes have executed, but this error
					// forces the original queue completion transaction to roll back.
					return errCapture
				}, nil
			}
			return completion, nil
		case <-callCtx.Done():
			return nil, callCtx.Err()
		}
	}
	runner, err := worker.New(worker.Config{Store: store, Handlers: handlers, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), PollInterval: 10 * time.Millisecond, HeartbeatInterval: 100 * time.Millisecond, Maintenance: worker.ReconcileRunJobs})
	if err != nil {
		t.Fatal(err)
	}
	workerCtx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- runner.Run(workerCtx) }()
	var stopOnce sync.Once
	stopWorker := func() {
		stopOnce.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error("capture worker did not stop cleanly")
				}
			case <-time.After(7 * time.Second):
				t.Error("capture worker shutdown deadline")
			}
		})
	}
	joinFailedCompletion := func() {
		stopOnce.Do(func() {
			// An intentionally failed completion must exit with its sanitized
			// storage error while the parent is STILL LIVE. Canceling immediately
			// after rollbackReached races Runner's return-time cancellation
			// normalization, incorrectly demanding graceful nil from a failure.
			defer cancel()
			select {
			case err := <-done:
				if !errors.Is(err, repository.ErrUnavailable) {
					t.Error("injected completion failure did not stop Worker with its closed storage error")
				}
			case <-time.After(7 * time.Second):
				t.Error("failed completion Worker exit deadline")
			}
		})
	}
	t.Cleanup(stopWorker)
	poll(t, func() bool { return runner.Ready() })
	pc, err := targets.EnqueuePrecheck(ctx, orgID, targetRecord.ID, targetRecord.Version, "development-precheck")
	if err != nil {
		t.Fatal(err)
	}
	poll(t, func() bool {
		value, e := targets.GetPrecheck(ctx, orgID, targetRecord.ID, pc.ID)
		if e != nil {
			t.Fatal(e)
		}
		if value.Status == "failed" {
			t.Fatal("actual TLS precheck failed")
		}
		return value.Status == "passed"
	})
	service, err := runservice.NewService(runservice.Config{Store: store, Targets: targets, Generator: compiler, Limits: scheduler.DefaultLimits(), RuleVersion: bundle.BuiltinVersion, ScoringVersion: bundle.BuiltinVersion, ExecutionReady: func(context.Context) bool { return runner.Ready() }})
	if err != nil {
		t.Fatal(err)
	}
	zero, one, three := 0, 1, 3
	quote, err := service.Estimate(ctx, orgID, runservice.Input{TargetID: targetRecord.ID, TargetVersion: targetRecord.Version, Package: "custom", Options: runservice.Options{MaxRetries: &zero, Concurrency: &one, Repetitions: &three, MaxOutputLevels: []int{64, 128}, ProbeTypes: []string{"format", "sequence"}, Languages: []string{"en-US"}, StreamModes: []bool{false, true}}})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := tenant.GetRunEstimate(quote.ID)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := repository.DecodeRunEstimate(stored)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := compiler.Verify(plan.Manifest, plan.ManifestHash, orgID)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.KeyVersion != localfile.ManifestKeyVersion || manifest.KeyVersion == ring.ActiveVersion() {
		t.Fatal("actual Run did not freeze the independent development Manifest signer")
	}
	recorder.prepare(t, manifest, plan, tokens)
	run, err := service.Confirm(ctx, orgID, quote.ID, quote.ManifestHash)
	if err != nil {
		t.Fatal(err)
	}
	var draft replay.CaptureDraft
	select {
	case draft = <-pending:
	case <-time.After(30 * time.Second):
		t.Fatal("actual analysis did not reach capture boundary")
	}
	if draft.RunID != run.ID {
		t.Fatal("captured wrong actual Run")
	}
	if delayReservation {
		assertSeparateTimingOrigins(t, draft)
	}
	if encoded, _, err := sealSettled(ctx, tenant, draft, captureKey); err == nil || len(encoded) != 0 {
		t.Fatal("uncommitted analysis yielded a sealed capture")
	}
	if _, _, err := exporter.write(ctx, exportDir, draft); err == nil {
		t.Fatal("uncommitted analysis exported files")
	}
	assertNoExport(t, exportDir)
	if _, err := tenant.GetPublishedAnalysis(run.ID, 1); !errors.Is(err, repository.ErrNotFound) {
		t.Fatal("analysis published outside actual completion")
	}
	close(release)
	if failCommit {
		select {
		case <-rollbackReached:
		case <-time.After(10 * time.Second):
			t.Fatal("actual publication rollback path not reached")
		}
		joinFailedCompletion()
		if _, err := tenant.GetPublishedAnalysis(run.ID, 1); !errors.Is(err, repository.ErrNotFound) {
			t.Fatal("rolled-back analysis remained published")
		}
		if encoded, _, err := sealSettled(ctx, tenant, draft, captureKey); err == nil || len(encoded) != 0 {
			t.Fatal("failed completion produced sealed capture bytes")
		}
		if _, _, err := exporter.write(ctx, exportDir, draft); err == nil {
			t.Fatal("rolled-back publication exported files")
		}
		assertNoExport(t, exportDir)
		if err := store.VerifyAllAudit(t.Context(), true); err != nil {
			t.Fatal("rollback broke actual audit chain")
		}
		return
	}
	poll(t, func() bool {
		value, e := tenant.GetRun(run.ID)
		if e != nil {
			t.Fatal(e)
		}
		if value.Status == "FAILED" || value.Status == "CANCELLED" {
			t.Fatal("actual Run failed")
		}
		return value.FinishedAt != nil
	})
	// Stop the controller before exporting. Publication/settlement remain in the
	// database, but no Worker can race signer destruction or make another call.
	stopWorker()
	assertRejectedExports(t, ctx, exportDir, exporter, draft)
	encoded, original, err := exporter.write(ctx, exportDir, draft)
	if err != nil {
		t.Fatal("seal committed capture:", err)
	}
	if bytes.Contains(encoded, []byte(credential)) || bytes.Contains(encoded, []byte(password)) {
		t.Fatal("credential in capture")
	}
	// Manifest/wire/body are base64 in the envelope. Inspect decoded payloads,
	// not only their outer JSON representation, before calling this S2 safe.
	var sealedEnvelope struct {
		Capture replay.CaptureDraft `json:"capture"`
	}
	if json.Unmarshal(encoded, &sealedEnvelope) != nil || captureContainsSecret(sealedEnvelope.Capture, credential, password) {
		t.Fatal("credential in decoded capture payload")
	}
	if err := store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal("actual capture workflow audit failed")
	}
	resolver, err := bundle.NewResolver()
	if err != nil {
		t.Fatal(err)
	}
	installed, err := bundle.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := resolver.Resolve(installed.RuleBytes(), bundle.BuiltinHash)
	if err != nil {
		t.Fatal(err)
	}
	detector, err := replay.New(replay.Config{CaptureKeyID: "dev-worker-capture", CapturePublicKey: public, Verifier: compiler, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	// Server is genuinely gone. Replay cannot use its formerly valid TLS route.
	tls.Close()
	prediction, err := detector.Replay(t.Context(), bytes.NewReader(encoded))
	if err != nil {
		t.Fatal("first offline replay:", err)
	}
	again, err := detector.Replay(t.Context(), bytes.NewReader(encoded))
	if err != nil {
		t.Fatal("repeated offline replay:", err)
	}
	originalBytes, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := tenant.GetPublishedAnalysis(run.ID, 1)
	if err != nil || !bytes.Equal([]byte(publication.ConclusionJSON), originalBytes) {
		t.Fatal("comparison source differs from exact immutable publication bytes")
	}
	replayedBytes, err := json.Marshal(prediction.Analysis)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalBytes, replayedBytes) {
		t.Fatal("actual immutable Worker analysis differs from byte replay")
	}
	x, _ := json.Marshal(prediction)
	y, _ := json.Marshal(again)
	if !bytes.Equal(x, y) {
		t.Fatal("actual capture replay not deterministic")
	}
	assertActualCLIExport(t, exportDir, x, originalBytes)
	for _, sample := range manifest.Samples {
		if bytes.Contains(x, []byte(sample.Variables.Nonce)) {
			t.Fatal("captured nonce leaked into S1 prediction")
		}
	}
	if strings.Contains(string(x), credential) || prediction.Analysis.Scores.Calibrated || !prediction.Analysis.Scores.Development {
		t.Fatal("capture acquired credential or approval")
	}
	streamCount := 0
	for _, sample := range prediction.Analysis.Features.Samples {
		if sample.Local == nil || sample.Local.Quality != tokenizer.Exact {
			t.Fatal("actual captured response not locally recounted")
		}
		if sample.Stream {
			streamCount++
			if sample.Protocol == nil || sample.Protocol.StreamTerminated == omitDone || sample.Protocol.Partial != omitDone {
				t.Fatal("actual stream intervention not reflected")
			}
		}
	}
	if streamCount == 0 {
		t.Fatal("actual TLS capture lacked stream coverage")
	}
}

func poll(t *testing.T, read func() bool) {
	t.Helper()
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for !read() {
		select {
		case <-tick.C:
		case <-timer.C:
			t.Fatal("controlled capture did not converge")
		case <-t.Context().Done():
			t.Fatal("controlled capture canceled")
		}
	}
}
