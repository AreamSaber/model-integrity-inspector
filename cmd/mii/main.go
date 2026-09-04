package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"model-integrity-inspector.local/mii/internal/app"
	"model-integrity-inspector.local/mii/internal/buildinfo"
	appruntime "model-integrity-inspector.local/mii/internal/platform/runtime"
)

func main() {
	printed, err := writeVersion(os.Args, os.Stdout)
	if err != nil {
		slog.Error("write build information", "error", err)
		os.Exit(1)
	}
	if printed {
		return
	}

	role, err := appruntime.ParseRole(os.Getenv("APP_ROLE"))
	if err != nil {
		slog.Error("invalid runtime role", "error", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := app.Config{
		Role:  role,
		Addr:  envOrDefault("MII_ADDR", "127.0.0.1:8080"),
		Build: buildinfo.Current(),
	}
	if err := app.Run(ctx, cfg, slog.Default()); err != nil {
		slog.Error("mii stopped with an error", "error", err)
		os.Exit(1)
	}
}

func writeVersion(args []string, output io.Writer) (bool, error) {
	if len(args) != 2 || (args[1] != "version" && args[1] != "--version") {
		return false, nil
	}
	return true, json.NewEncoder(output).Encode(buildinfo.Current())
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
