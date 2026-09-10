package bundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"
)

type backupDependencyReaderFunc func([]byte) (int, error)

func (f backupDependencyReaderFunc) Read(p []byte) (int, error) { return f(p) }

type backupDependencyTypedNilReader struct{}

func (*backupDependencyTypedNilReader) Read([]byte) (int, error) { panic("private reader canary") }

func TestBackupDependenciesCompleteSourceFailureMatrix(t *testing.T) {
	raw := []byte("historical source body")
	for _, mode := range []string{"hash", "size_short", "size_long", "no_consume", "consume_twice_swallowed", "outer_late_error", "outer_late_cancel", "outer_panic", "outer_panic_nil", "reader_error_swallowed", "reader_panic", "reader_panic_nil", "typed_nil", "nil_reader", "zero_progress", "invalid_read_count", "extra_byte", "last_byte_then_error", "cancel_at_eof"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			source := backupDependencyTestSource("rule", "old", 1, 2, raw)
			if mode == "hash" {
				source.SHA256 = strings.Repeat("a", 64)
			}
			if mode == "size_short" {
				source.Bytes--
			}
			if mode == "size_long" {
				source.Bytes++
			}
			completed := false
			got, err := ObserveBackupDependencies(ctx, source, BackupDependencyLimits{int64(len(raw) + 1), time.Second}, func(_ context.Context, consume func(io.Reader) error) error {
				if mode == "no_consume" {
					return nil
				}
				var reader io.Reader = bytes.NewReader(raw)
				switch mode {
				case "reader_error_swallowed":
					reader = backupDependencyReaderFunc(func([]byte) (int, error) { return 0, errors.New("private reader canary") })
				case "reader_panic":
					reader = backupDependencyReaderFunc(func([]byte) (int, error) { panic("private reader canary") })
				case "reader_panic_nil":
					reader = backupDependencyReaderFunc(func([]byte) (int, error) { panic(nil) })
				case "typed_nil":
					reader = (*backupDependencyTypedNilReader)(nil)
				case "nil_reader":
					reader = nil
				case "zero_progress":
					reader = backupDependencyReaderFunc(func([]byte) (int, error) { return 0, nil })
				case "invalid_read_count":
					reader = backupDependencyReaderFunc(func(p []byte) (int, error) { return len(p) + 1, nil })
				case "extra_byte":
					reader = bytes.NewReader(append(bytes.Clone(raw), 'x'))
				case "last_byte_then_error":
					reader = backupDependencyReaderFunc(func(p []byte) (int, error) { return copy(p, raw), errors.New("private final read canary") })
				case "cancel_at_eof":
					original := bytes.NewReader(raw)
					reader = backupDependencyReaderFunc(func(p []byte) (int, error) {
						n, err := original.Read(p)
						if errors.Is(err, io.EOF) {
							cancel()
						}
						return n, err
					})
				}
				readErr := consume(reader)
				completed = readErr == nil
				switch mode {
				case "consume_twice_swallowed":
					_ = consume(bytes.NewReader(raw))
					return nil
				case "outer_late_error":
					return errors.New("private final close canary")
				case "outer_late_cancel":
					cancel()
					return nil
				case "outer_panic":
					panic("private final close canary")
				case "outer_panic_nil":
					panic(nil)
				case "reader_error_swallowed", "reader_panic", "reader_panic_nil", "typed_nil", "nil_reader", "zero_progress", "invalid_read_count", "extra_byte", "last_byte_then_error", "cancel_at_eof":
					return nil
				}
				return readErr
			})
			if err == nil || got != nil || strings.Contains(err.Error(), "canary") {
				t.Fatal("incomplete/late source failure issued observation", err)
			}
			if strings.HasPrefix(mode, "outer_") && !completed {
				t.Fatal("outer failure fixture did not first complete all original bytes")
			}
		})
	}
}

func TestBackupDependenciesActiveReadCanceledAndJoined(t *testing.T) {
	for _, mode := range []string{"return_active", "concurrent_consume", "reentrant_consume"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			started, done := make(chan struct{}), make(chan struct{})
			launched := false
			defer func() {
				cancel()
				if launched {
					<-done
				}
			}()
			source := backupDependencyTestSource("rule", "old", 1, 2, []byte("x"))
			got, err := ObserveBackupDependencies(ctx, source, BackupDependencyLimits{1, time.Second}, func(scope context.Context, consume func(io.Reader) error) error {
				if mode == "reentrant_consume" {
					return consume(backupDependencyReaderFunc(func([]byte) (int, error) { _ = consume(bytes.NewReader([]byte("x"))); return 0, io.EOF }))
				}
				launched = true
				go func() {
					defer close(done)
					_ = consume(backupDependencyReaderFunc(func([]byte) (int, error) { close(started); <-scope.Done(); return 0, scope.Err() }))
				}()
				select {
				case <-started:
				case <-done:
					return ErrBackupDependencyRead
				case <-time.After(time.Second):
					cancel()
					return ErrBackupDependencyRead
				}
				if mode == "concurrent_consume" {
					_ = consume(bytes.NewReader([]byte("x")))
				}
				return nil // Deliberately leave a borrowed read active.
			})
			if err == nil || got != nil {
				t.Fatal("detached/reentrant source produced observation", err)
			}
			if launched {
				select {
				case <-started:
				default:
					t.Fatal("actual read barrier not reached")
				}
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("active source was not joined")
				}
			}
		})
	}
}

func TestBackupDependenciesReaderScopeClosedAfterReturn(t *testing.T) {
	raw := []byte("original opaque")
	source := backupDependencyTestSource("rule", "old", 1, 2, raw)
	var retained func(io.Reader) error
	got, err := ObserveBackupDependencies(t.Context(), source, BackupDependencyLimits{source.Bytes, time.Second}, func(_ context.Context, consume func(io.Reader) error) error {
		retained = consume
		return consume(bytes.NewReader(raw))
	})
	if err != nil || got == nil {
		t.Fatal("source fixture", err)
	}
	called := false
	err = retained(backupDependencyReaderFunc(func([]byte) (int, error) { called = true; return 0, io.EOF }))
	if !errors.Is(err, ErrBackupDependencyClosed) || called {
		t.Fatal("expired callback borrowed a new source")
	}
	// A forbidden call made after return cannot retroactively revoke an already
	// observed immutable fact. It cannot read anything or mint another fact.
}

type backupDependencyRepeatedReader struct {
	remaining  int64
	maxRequest int
}

func (r *backupDependencyRepeatedReader) Read(p []byte) (int, error) {
	r.maxRequest = max(r.maxRequest, len(p))
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := min(int64(len(p)), r.remaining)
	for i := range int(n) {
		p[i] = 'x'
	}
	r.remaining -= n
	return int(n), nil
}

func TestBackupDependenciesLargeOpaqueFullyReadWithoutBodyAccumulation(t *testing.T) {
	const count = 24 << 20
	h := sha256.New()
	_, err := io.Copy(h, &backupDependencyRepeatedReader{remaining: count})
	if err != nil {
		t.Fatal(err)
	}
	source := BackupDependencySource{Category: "rule", OrganizationID: 1, RowID: 2, Version: "original-old", SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: count}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	reader := &backupDependencyRepeatedReader{remaining: count}
	got, err := ObserveBackupDependencies(t.Context(), source, BackupDependencyLimits{count, time.Second}, func(_ context.Context, consume func(io.Reader) error) error { return consume(reader) })
	runtime.ReadMemStats(&after)
	if err != nil || got == nil || got.Classification() != BackupDependenciesOpaque || got.Reason() != "codec_byte_limit" || reader.remaining != 0 || reader.maxRequest > 64<<10 || after.TotalAlloc-before.TotalAlloc > 2<<20 {
		t.Fatal("opaque stream was truncated/buffered/claimed interpreted", err)
	}
	called := false
	got, err = ObserveBackupDependencies(t.Context(), source, BackupDependencyLimits{count - 1, time.Second}, func(context.Context, func(io.Reader) error) error { called = true; return nil })
	if !errors.Is(err, ErrBackupDependencyLimit) || got != nil || called {
		t.Fatal("source budget was silently truncated", err)
	}
}

func TestBackupDependenciesInputBoundsBeforeSource(t *testing.T) {
	for _, mode := range []string{"nil_context", "canceled", "nil_callback", "category", "organization", "row", "long_version", "invalid_version_utf8", "bad_hash", "negative_bytes", "negative_limit", "large_limit", "zero_timeout", "large_timeout"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			source := backupDependencyTestSource("rule", "old", 1, 2, nil)
			limits := BackupDependencyLimits{0, time.Second}
			called := false
			read := func(context.Context, func(io.Reader) error) error { called = true; return nil }
			switch mode {
			case "nil_context":
				ctx = nil
			case "canceled":
				cancel()
			case "nil_callback":
				read = nil
			case "category":
				source.Category = "arbitrary"
			case "organization":
				source.OrganizationID = 0
			case "row":
				source.RowID = 0
			case "long_version":
				source.Version = strings.Repeat("x", 129)
			case "invalid_version_utf8":
				source.Version = string([]byte{0xff})
			case "bad_hash":
				source.SHA256 = strings.Repeat("A", 64)
			case "negative_bytes":
				source.Bytes = -1
			case "negative_limit":
				limits.MaxBytes = -1
			case "large_limit":
				limits.MaxBytes = BackupDependencyMaxBytes + 1
			case "zero_timeout":
				limits.Timeout = 0
			case "large_timeout":
				limits.Timeout = BackupDependencyMaxTimeout + 1
			}
			got, err := ObserveBackupDependencies(ctx, source, limits, read)
			if got != nil || err == nil || called {
				t.Fatal("invalid finite input reached source", err)
			}
		})
	}
}
