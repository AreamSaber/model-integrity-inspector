package app

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"model-integrity-inspector.local/mii/internal/identity"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	integrityapi "model-integrity-inspector.local/mii/internal/integrity/api"
	runtimebundle "model-integrity-inspector.local/mii/internal/integrity/bundle"
	"model-integrity-inspector.local/mii/internal/integrity/catalog"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/target"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
	"model-integrity-inspector.local/mii/internal/integrity/worker"
	webui "model-integrity-inspector.local/mii/web"
)

var ErrStartup = errors.New("MI_STARTUP_FAILED")

type application struct {
	store   *repository.Store
	handler http.Handler
	worker  *worker.Runner
}

// prepare validates keys and schema before opening a listening socket. Workers
// only check schema; only server/all may migrate. Audit corruption fails closed.
func prepare(ctx context.Context, cfg Config) (*application, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	key, err := secret.LoadKeyFile(cfg.MasterKeyFile, cfg.MasterKeyVersion)
	if err != nil {
		return nil, err
	}
	artifacts, err := runtimebundle.Builtin()
	if err != nil {
		return nil, err
	}
	bootstrap := &repository.BootstrapArtifacts{RuleVersion: runtimebundle.BuiltinVersion, RuleHash: runtimebundle.BuiltinHash, RuleJSON: string(artifacts.RuleBytes()), TemplateVersion: templates.BuiltinVersion, TemplateHash: templates.BuiltinHash, TemplateJSON: string(artifacts.TemplateBytes()), ScoringVersion: scoring.Version, TokenizerVersion: tokenizer.BuiltinVersion}
	if cfg.DatabaseDriver == "sqlite" {
		if err := os.MkdirAll(filepath.Dir(cfg.DatabasePath), 0700); err != nil {
			return nil, ErrStartup
		}
		// Create a new file with restrictive Unix mode before the SQLite driver;
		// never truncate or replace an existing database.
		// #nosec G304 -- Operator-selected database path, validated before startup.
		file, err := os.OpenFile(cfg.DatabasePath, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, ErrStartup
		}
		if err := file.Close(); err != nil {
			return nil, ErrStartup
		}
	}
	if err := os.MkdirAll(cfg.ReportPath, 0700); err != nil {
		return nil, ErrStartup
	}
	dsn := cfg.DatabaseDSN
	if cfg.DatabaseDriver == "sqlite" {
		dsn = cfg.DatabasePath
	}
	store, err := repository.Open(ctx, repository.Config{Driver: cfg.DatabaseDriver, DSN: dsn, AuditSigner: key, Bootstrap: bootstrap})
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = store.Close()
		}
	}()
	if cfg.Role.Components().Server {
		err = store.Migrate(ctx)
	} else {
		err = store.CheckSchema(ctx)
	}
	if err != nil {
		return nil, err
	}
	if err = store.VerifyAllAudit(ctx, true); err != nil {
		return nil, err
	}
	if cfg.Role.Components().Server {
		if err := store.SyncBootstrapBundles(ctx); err != nil {
			return nil, err
		}
	}
	app := &application{store: store}
	secretService, err := secret.NewService(store, key)
	if err != nil {
		return nil, err
	}
	engine, err := tokenizer.NewBuiltin()
	if err != nil {
		return nil, err
	}
	compiler, err := generator.New(artifacts.TemplateBytes(), templates.BuiltinHash, engine, key)
	if err != nil {
		return nil, err
	}
	builder, err := features.New(features.Config{Verifier: compiler, Tokenizer: engine, TemplateArtifact: artifacts.TemplateBytes(), TrustedTemplateHash: templates.BuiltinHash})
	if err != nil {
		return nil, err
	}
	if cfg.Role.Components().Worker {
		precheck, err := worker.NewPrecheckHandler(worker.PrecheckConfig{Store: store, Secrets: secretService})
		if err != nil {
			return nil, err
		}
		handlers, err := worker.NewRunHandlers(worker.RunConfig{Store: store, Secrets: secretService, EvidenceKeys: key, Tokenizer: engine})
		if err != nil {
			return nil, err
		}
		handlers[repository.JobTargetPrecheck] = precheck
		analysis, err := worker.NewAnalysisHandler(worker.AnalysisConfig{Builder: builder, EvidenceKeys: key})
		if err != nil {
			return nil, err
		}
		handlers[repository.JobRunAnalyze] = analysis
		app.worker, err = worker.New(worker.Config{Store: store, Handlers: handlers, Maintenance: func(ctx context.Context, queue *repository.JobQueue) error {
			if err := worker.ReconcileRunJobs(ctx, queue); err != nil {
				return err
			}
			return queue.ExpireRunEstimates(ctx)
		}})
		if err != nil {
			return nil, err
		}
	}
	readiness := func(ctx context.Context) bool {
		if cfg.Role.Components().Worker && (app.worker == nil || !app.worker.Ready()) {
			return false
		}
		return store.VerifyAllAudit(ctx, false) == nil
	}
	if cfg.Role.Components().Server {
		service, err := identity.NewService(ctx, store)
		if err != nil {
			return nil, err
		}
		targets, err := target.NewService(target.Config{Store: store, Secrets: secretService})
		if err != nil {
			return nil, err
		}
		catalogService, err := catalog.NewService(store, service)
		if err != nil {
			return nil, err
		}
		// Runtime now has verified development artifacts and a real analysis
		// handler. Confirmation remains fail-closed until result/history access
		// and the user-visible uncalibrated disclosure are connected end to end.
		runs, err := runservice.NewService(runservice.Config{Store: store, Targets: targets, Generator: compiler, Limits: scheduler.DefaultLimits(), RuleVersion: runtimebundle.BuiltinVersion, ScoringVersion: scoring.Version})
		if err != nil {
			return nil, err
		}
		app.handler, err = integrityapi.NewControlHandler(integrityapi.ControlConfig{Identity: service, Store: store, Build: cfg.Build, PublicOrigin: cfg.PublicOrigin, AllowInsecureLoopback: cfg.AllowInsecureLoopback, SetupToken: cfg.SetupToken, Readiness: readiness, CursorSigner: key, Targets: targets, Catalog: catalogService, Runs: runs, Frontend: webui.Handler()})
		if err != nil {
			return nil, err
		}
	} else {
		app.handler = integrityapi.NewStatusHandler(cfg.Build, cfg.Role, readiness)
	}
	failed = false
	return app, nil
}

func Run(ctx context.Context, cfg Config, logger *slog.Logger) error {
	startup, cancel := context.WithTimeout(ctx, 60*time.Second)
	app, err := prepare(startup, cfg)
	cancel()
	if err != nil {
		return err
	}
	defer func() { _ = app.store.Close() }()
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Addr)
	if err != nil {
		return ErrStartup
	}
	return app.serve(ctx, cfg, listener, logger)
}

func (a *application) serve(ctx context.Context, cfg Config, listener net.Listener, logger *slog.Logger) error {
	workCtx, stopWorker := context.WithCancel(ctx)
	defer stopWorker()
	var workerDone chan error
	if a.worker != nil {
		workerDone = make(chan error, 1)
		go func() { workerDone <- a.worker.Run(workCtx) }()
	}
	server := &http.Server{Handler: a.handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(listener) }()
	logger.Info("control listener started", "role", string(cfg.Role))
	var result error
	workerStopped := false
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			result = ErrStartup
		}
	case <-workerDone:
		workerStopped = true
		if ctx.Err() == nil {
			// A required consumer exiting is not a healthy server-only fallback.
			result = ErrStartup
		}
	}
	stopWorker()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		_ = server.Close()
		result = ErrStartup
	}
	if workerDone != nil && !workerStopped {
		select {
		case err := <-workerDone:
			if err != nil && !errors.Is(err, context.Canceled) {
				result = ErrStartup
			}
		case <-shutdown.Done():
			result = ErrStartup
		}
	}
	return result
}
