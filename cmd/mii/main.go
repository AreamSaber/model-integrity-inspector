package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"model-integrity-inspector.local/mii/internal/app"
	"model-integrity-inspector.local/mii/internal/buildinfo"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := execute(ctx, os.Args[1:], os.Stdout, slog.Default()); err != nil {
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

func execute(ctx context.Context, args []string, output io.Writer, logger *slog.Logger) error {
	command := "run"
	if len(args) > 0 && (args[0] == "run" || args[0] == "keygen") {
		command = args[0]
		args = args[1:]
	}
	flags := flag.NewFlagSet("mii", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // Errors cannot echo arbitrary credential-like arguments.
	configPath := flags.String("config", os.Getenv("MII_CONFIG"), "strict YAML configuration path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return app.ErrConfig
	}
	cfg, err := app.LoadConfig(*configPath, os.Getenv)
	if err != nil {
		return err
	}
	cfg.Build = buildinfo.Current()
	if command == "keygen" {
		if err := os.MkdirAll(filepath.Dir(cfg.MasterKeyFile), 0700); err != nil {
			return app.ErrStartup
		}
		if _, err := secret.CreateKeyFile(cfg.MasterKeyFile, cfg.MasterKeyVersion); err != nil {
			return err
		}
		_, err := io.WriteString(output, "Master key created securely. Back it up separately from the database; existing keys are never overwritten.\n")
		return err
	}
	return app.Run(ctx, cfg, logger)
}
