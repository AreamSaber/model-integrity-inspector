package repository

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/pgbackup"
)

func TestPostgresDumpRejectsMissingSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for _, source := range []*Store{nil, {}} {
		receipt, err := source.dumpPostgresSnapshot(ctx, nil, "", pgbackup.Connection{}, pgbackup.DumpRequest{}, io.Discard)
		if !errors.Is(err, ErrConfiguration) || receipt != (pgbackup.DumpReceipt{}) {
			t.Fatal("missing source entered the native or database dump lifecycle")
		}
	}
}

func TestPostgresSnapshotDumpErrorsRemainClosed(t *testing.T) {
	for _, want := range []error{
		pgbackup.ErrConfiguration, pgbackup.ErrCanceled, pgbackup.ErrProcess,
		pgbackup.ErrOutput, pgbackup.ErrLimit, pgbackup.ErrVersion,
		errPostgresDumpIdentity, errPostgresDumpCleanup, errPostgresDumpUnseen,
	} {
		for _, incoming := range []error{want, fmt.Errorf("private-wrapper-canary: %w", want)} {
			if got := postgresSnapshotError(context.Background(), incoming); got != want { //nolint:errorlint // Exact sentinel identity proves private wrapper text was discarded, not merely wrapped again.
				t.Fatalf("snapshot boundary lost a closed dump error: want=%s got=%s", want, got)
			}
		}
	}
	if got := postgresSnapshotError(context.Background(), errors.New("private-driver-message-canary")); got != ErrUnavailable { //nolint:errorlint // Unknown driver text must become the exact public sentinel without retaining a wrapper.
		t.Fatal("unclassified driver text escaped the snapshot boundary")
	}
	if got := postgresSnapshotError(context.Background(), nil); got != nil {
		t.Fatal("successful snapshot incorrectly failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, want := range []error{errPostgresDumpCleanup, errPostgresDumpUnseen, errPostgresDumpIdentity} {
		if got := postgresSnapshotError(ctx, fmt.Errorf("private-control-canary: %w", want)); got != want { //nolint:errorlint // Cancellation must not hide uncertain cleanup, and wrappers must still be stripped.
			t.Fatalf("uncertain dump cleanup became ordinary cancellation: want=%s got=%s", want, got)
		}
	}
	if got := postgresSnapshotError(ctx, pgbackup.ErrOutput); !errors.Is(got, errPostgresSnapshotCanceled) {
		t.Fatal("outer snapshot cancellation lost its existing precedence")
	}
}
