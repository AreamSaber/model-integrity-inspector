package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"model-integrity-inspector.local/mii/internal/buildinfo"
	integrityapi "model-integrity-inspector.local/mii/internal/integrity/api"
	"model-integrity-inspector.local/mii/internal/integrity/worker"
	appruntime "model-integrity-inspector.local/mii/internal/platform/runtime"
)

type Config struct {
	Role  appruntime.Role
	Addr  string
	Build buildinfo.Info
}

func Run(ctx context.Context, cfg Config, logger *slog.Logger) error {
	errCh := make(chan error, 2)
	components := cfg.Role.Components()

	if components.Worker {
		go func() {
			errCh <- worker.Run(ctx, logger)
		}()
	}

	if components.Server {
		server := &http.Server{
			Addr:              cfg.Addr,
			Handler:           integrityapi.NewHandler(cfg.Build, cfg.Role),
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			logger.Info("server scaffold ready", "addr", cfg.Addr, "role", cfg.Role)
			errCh <- server.ListenAndServe()
		}()

		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return server.Shutdown(shutdownCtx)
		case err := <-errCh:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		}
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}
