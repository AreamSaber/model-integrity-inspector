package worker

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestRunStopsWithContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after cancellation")
	}
}
