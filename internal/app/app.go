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
	integrityapi "model-integrity-inspector.local/mii/internal/integrity/api"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	webui "model-integrity-inspector.local/mii/web"
)

var ErrStartup = errors.New("MI_STARTUP_FAILED")

type application struct {
	store   *repository.Store
	handler http.Handler
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
	store, err := repository.Open(ctx, repository.Config{Driver: cfg.DatabaseDriver, DSN: dsn, AuditSigner: key})
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
	app := &application{store: store}
	readiness := func(ctx context.Context) bool {
		// Worker execution is connected in M2-07; do not report a scaffold as ready.
		if cfg.Role.Components().Worker {
			return false
		}
		return store.VerifyAllAudit(ctx, false) == nil
	}
	if cfg.Role.Components().Server {
		service, err := identity.NewService(ctx, store)
		if err != nil {
			return nil, err
		}
		app.handler, err = integrityapi.NewControlHandler(integrityapi.ControlConfig{Identity: service, Store: store, Build: cfg.Build, PublicOrigin: cfg.PublicOrigin, AllowInsecureLoopback: cfg.AllowInsecureLoopback, SetupToken: cfg.SetupToken, Readiness: readiness, CursorSigner: key, Frontend: webui.Handler()})
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
	server := &http.Server{Handler: a.handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(listener) }()
	logger.Info("control listener started", "role", string(cfg.Role))
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return ErrStartup
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return ErrStartup
	}
}
