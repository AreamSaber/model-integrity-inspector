package main

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func TestListenerRestrictedToLoopback(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8090", "[::1]:8090"} {
		if err := validateAddress(address); err != nil {
			t.Errorf("%s: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:8090", ":8090", "[::]:8090", "10.0.0.1:8090", "localhost:8090", "example.com:8090", "127.0.0.1"} {
		if validateAddress(address) == nil {
			t.Errorf("accepted unsafe listener %s", address)
		}
	}
}

func TestProductionAndUnsafeConfigurationFailClosed(t *testing.T) {
	if runWithContext(t.Context(), []string{"-addr", "0.0.0.0:8090"}, io.Discard) == nil {
		t.Fatal("unsafe listener accepted")
	}
	if runWithContext(t.Context(), []string{"-config", "does-not-exist.json"}, io.Discard) == nil {
		t.Fatal("missing configuration accepted")
	}
	t.Setenv("APP_ENV", "production")
	if runWithContext(t.Context(), nil, io.Discard) == nil {
		t.Fatal("production mock enabled")
	}
}

type notifyWriter struct{ written chan string }

func (writer notifyWriter) Write(data []byte) (int, error) {
	writer.written <- string(data)
	return len(data), nil
}

func TestLoopbackLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	output := notifyWriter{written: make(chan string, 1)}
	done := make(chan error, 1)
	go func() { done <- runWithContext(ctx, []string{"-addr", "127.0.0.1:0"}, output) }()
	select {
	case message := <-output.written:
		if !strings.Contains(message, "127.0.0.1:") {
			t.Fatal("listener address missing")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mock did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mock did not shut down")
	}
}
