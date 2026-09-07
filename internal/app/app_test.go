package app

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	cfg, err := LoadConfig("", noEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg.DatabasePath = filepath.Join(dir, "app.db")
	cfg.MasterKeyFile = filepath.Join(dir, "master.key")
	cfg.ReportPath = filepath.Join(dir, "reports")
	if _, err := secret.CreateKeyFile(cfg.MasterKeyFile, cfg.MasterKeyVersion); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestApplicationPersistsInitializationAcrossRestart(t *testing.T) {
	cfg := testConfig(t)
	app, err := prepare(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- app.serve(ctx, cfg, listener, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	client := &http.Client{Timeout: 5 * time.Second}
	endpoint := "http://" + listener.Addr().String()
	request, err := http.NewRequestWithContext(t.Context(), "POST", endpoint+"/api/v1/setup/initialize", strings.NewReader(`{"organization_name":"Persistent Test","username":"admin","password":"synthetic-persist-test-422"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", cfg.PublicOrigin)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 201 {
		t.Fatalf("initialization status %d", response.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("server shutdown did not complete")
	}
	if err := app.store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := prepare(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restarted.store.Close() }()
	initialized, err := restarted.store.SetupStatus(t.Context())
	if err != nil || !initialized {
		t.Fatal("initialization did not survive restart")
	}
	if err := restarted.store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}

func TestApplicationRejectsMissingOrWrongMasterKey(t *testing.T) {
	cfg := testConfig(t)
	cfg.MasterKeyFile = filepath.Join(t.TempDir(), "missing.key")
	if app, err := prepare(t.Context(), cfg); err == nil {
		_ = app.store.Close()
		t.Fatal("missing master key accepted")
	}
}

func TestApplicationReadinessTracksRealWorkerAndCleanShutdown(t *testing.T) {
	cfg := testConfig(t)
	app, err := prepare(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.store.Close() }()
	readiness := func() int {
		w := httptest.NewRecorder()
		app.handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), "GET", "/ready", nil))
		return w.Code
	}
	if readiness() != 503 || app.worker == nil || app.worker.Ready() {
		t.Fatal("unstarted worker reported ready")
	}
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- app.serve(ctx, cfg, listener, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for !app.worker.Ready() {
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("worker never acquired consumer")
		}
	}
	if readiness() != 200 {
		t.Fatal("healthy consumer not reflected in readiness")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("worker shutdown not bounded")
	}
	if app.worker.Ready() || readiness() != 503 {
		t.Fatal("stopped worker still reported ready")
	}
	queue, err := app.store.OpenJobQueue(t.Context())
	if err != nil {
		t.Fatal("stopped worker retained SQLite singleton lease")
	}
	if err := queue.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}
