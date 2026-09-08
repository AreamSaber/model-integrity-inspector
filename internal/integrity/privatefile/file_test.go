//go:build windows || linux

package privatefile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func privateDir(t *testing.T) string {
	t.Helper()
	path := newTestDirectory(t)
	if err := protectTestDirectory(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func testLimits(max int64) Limits { return Limits{MaxBytes: max, Timeout: time.Minute} }

func testProduce(data []byte) func(context.Context, io.Writer) error {
	return func(_ context.Context, w io.Writer) error {
		_, err := w.Write(data)
		return err
	}
}

func writeTestFile(ctx context.Context, path string, data []byte, limit int64) error {
	_, err := WriteNew(ctx, path, testLimits(limit), testProduce(data))
	return err
}

func readTestFile(ctx context.Context, path string, limit int64) ([]byte, error) {
	var data bytes.Buffer
	_, err := Read(ctx, path, testLimits(limit), func(_ context.Context, r io.Reader) error {
		_, err := io.Copy(&data, r)
		return err
	})
	if err != nil {
		return nil, err
	}
	return data.Bytes(), nil
}

func assertEntries(t *testing.T, dir string, expected int) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != expected {
		t.Fatalf("unexpected private entries: %d, %v", len(entries), err)
	}
}

func TestStreamingLargeFileAndHash(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "large.backup")
	const size = (32 << 20) + 17
	chunk := bytes.Repeat([]byte{0x19, 0xA2, 0xB3, 0x44}, chunkBytes/4)
	want := sha256.New()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	written, err := WriteNew(t.Context(), path, testLimits(size), func(ctx context.Context, w io.Writer) error {
		if _, ok := w.(io.Closer); ok {
			t.Fatal("callback received file ownership")
		}
		for remaining := size; remaining > 0; {
			data := chunk[:min(remaining, len(chunk))]
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if _, err := w.Write(data); err != nil {
				return err
			}
			_, _ = want.Write(data)
			remaining -= len(data)
		}
		return nil
	})
	if err != nil || !written.Published || written.Size != size || written.SHA256 != hex.EncodeToString(want.Sum(nil)) {
		t.Fatal("large streaming write", written, err)
	}
	got := sha256.New()
	read, err := Read(t.Context(), path, testLimits(size), func(_ context.Context, r io.Reader) error {
		if _, ok := r.(io.Closer); ok {
			t.Fatal("callback received close capability")
		}
		_, err := io.CopyBuffer(got, r, chunk)
		return err
	})
	if err != nil || read.Published || read.Size != size || read.SHA256 != written.SHA256 || hex.EncodeToString(got.Sum(nil)) != written.SHA256 {
		t.Fatal("large streaming read", read, err)
	}
	runtime.ReadMemStats(&after)
	if after.TotalAlloc-before.TotalAlloc > 8<<20 {
		t.Fatal("streaming 32 MiB allocated storage proportional to full file")
	}
	assertEntries(t, dir, 1)
}

func TestNoReplaceAndConcurrentPublication(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "one.backup")
	const attempts = 8
	results := make(chan error, attempts)
	var group sync.WaitGroup
	for range attempts {
		group.Go(func() { results <- writeTestFile(t.Context(), path, []byte("complete"), 100) })
	}
	group.Wait()
	close(results)
	var success int
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrExists) {
			t.Fatal("unexpected concurrent result", err)
		}
	}
	if success != 1 {
		t.Fatal("not exactly one publisher", success)
	}
	if err := writeTestFile(t.Context(), path, []byte("must not replace"), 100); !errors.Is(err, ErrExists) {
		t.Fatal("existing destination replaced", err)
	}
	got, err := readTestFile(t.Context(), path, 100)
	if err != nil || string(got) != "complete" {
		t.Fatal("existing complete destination changed", err)
	}
	assertEntries(t, dir, 1)
}

func TestLimitsIncompleteAndSwallowedErrors(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "input")
	if err := writeTestFile(t.Context(), path, []byte("12345"), 5); err != nil {
		t.Fatal(err)
	}
	for _, limits := range []Limits{{}, {-1, time.Second}, {MaxBytes + 1, time.Second}, {5, 0}, {5, MaxTimeout + 1}} {
		if _, err := Read(t.Context(), path, limits, func(context.Context, io.Reader) error { t.Fatal("invalid limits callback"); return nil }); !errors.Is(err, ErrLimit) {
			t.Fatal("invalid read limits", err)
		}
		if _, err := WriteNew(t.Context(), filepath.Join(dir, "invalid"), limits, testProduce([]byte("x"))); !errors.Is(err, ErrLimit) {
			t.Fatal("invalid write limits", err)
		}
	}
	if _, err := readTestFile(t.Context(), path, 4); !errors.Is(err, ErrLimit) {
		t.Fatal("source size limit", err)
	}
	if _, err := Read(t.Context(), path, testLimits(5), func(context.Context, io.Reader) error { return nil }); !errors.Is(err, ErrIncomplete) {
		t.Fatal("unconsumed source accepted", err)
	}
	if _, err := WriteNew(t.Context(), filepath.Join(dir, "swallowed"), testLimits(1), func(_ context.Context, w io.Writer) error {
		_, _ = w.Write([]byte("too much"))
		return nil
	}); !errors.Is(err, ErrLimit) {
		t.Fatal("swallowed limit accepted", err)
	}
	if err := writeTestFile(t.Context(), filepath.Join(dir, "empty"), nil, 1); !errors.Is(err, ErrLimit) {
		t.Fatal("empty output accepted", err)
	}
	assertEntries(t, dir, 1)
}

func TestCancellationDeadlineAndCallbackError(t *testing.T) {
	dir := privateDir(t)
	for _, mode := range []string{"before", "during", "deadline", "callback", "publication"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			limits := testLimits(100)
			if mode == "before" {
				cancel()
			}
			if mode == "deadline" {
				limits.Timeout = 25 * time.Millisecond
			}
			var hooks *writeHooks
			if mode == "publication" {
				hooks = &writeHooks{beforePublish: cancel}
			}
			result, err := writeNew(ctx, filepath.Join(dir, mode), limits, func(ctx context.Context, w io.Writer) error {
				_, _ = w.Write([]byte("complete"))
				if mode == "during" {
					cancel()
					_, _ = w.Write([]byte("ignored canceled write"))
				}
				if mode == "deadline" {
					<-ctx.Done()
				}
				if mode == "callback" {
					return errors.New("synthetic-secret-and-path-should-not-leak")
				}
				return nil
			}, hooks)
			want := ErrCanceled
			if mode == "callback" {
				want = ErrCallback
			}
			if !errors.Is(err, want) || result.Published {
				t.Fatal("incorrect failed receipt", result, err)
			}
			assertEntries(t, dir, 0)
		})
	}
}

func TestPostPublicationFailureNeverDeletesDestination(t *testing.T) {
	for _, mode := range []string{"cancel", "close"} {
		t.Run(mode, func(t *testing.T) {
			dir := privateDir(t)
			path := filepath.Join(dir, "complete")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			hooks := &writeHooks{afterPublish: func(_ *os.File, f *os.File) {
				if mode == "cancel" {
					cancel()
				} else if err := f.Close(); err != nil {
					t.Fatal("test close", err)
				}
			}}
			result, err := writeNew(ctx, path, testLimits(100), testProduce([]byte("complete")), hooks)
			want := ErrUnavailable
			if mode == "cancel" {
				want = ErrCanceled
			}
			if !result.Published || result.Size != 8 || !errors.Is(err, want) {
				t.Fatal("publication not accurately reported", result, err)
			}
			got, err := readTestFile(t.Context(), path, 100)
			if err != nil || string(got) != "complete" {
				t.Fatal("published destination lost", err)
			}
			assertEntries(t, dir, 1)
		})
	}
}

func TestRetainedCapabilitiesAndCanceledRead(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "source")
	var retainedWriter io.Writer
	if _, err := WriteNew(t.Context(), path, testLimits(100), func(_ context.Context, w io.Writer) error {
		retainedWriter = w
		_, err := w.Write([]byte("source"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := retainedWriter.Write([]byte("late")); !errors.Is(err, ErrClosed) {
		t.Fatal("retained writer usable", err)
	}
	var retainedReader io.Reader
	if _, err := Read(t.Context(), path, testLimits(100), func(_ context.Context, r io.Reader) error {
		retainedReader = r
		_, err := io.Copy(io.Discard, r)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := retainedReader.Read(make([]byte, 1)); !errors.Is(err, ErrClosed) {
		t.Fatal("retained reader usable", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if _, err := Read(ctx, path, testLimits(100), func(_ context.Context, r io.Reader) error {
		cancel()
		_, _ = r.Read(make([]byte, 1))
		return nil
	}); !errors.Is(err, ErrCanceled) {
		t.Fatal("swallowed canceled read accepted", err)
	}
}

func TestPathAndHardlinkBoundaries(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "source")
	for _, invalid := range []string{"", "relative", "https://example.invalid/data", path + "\x00", dir, filepath.Join(dir, "missing"), path + string(filepath.Separator) + ".."} {
		if _, err := readTestFile(t.Context(), invalid, 100); err == nil || strings.Contains(err.Error(), dir) {
			t.Fatal("invalid path accepted or leaked")
		}
	}
	if err := writeTestFile(t.Context(), path, []byte("source"), 100); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "hardlink")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readTestFile(t.Context(), path, 100); !errors.Is(err, ErrUnsafe) {
		t.Fatal("hardlinked source accepted", err)
	}
	if err := writeTestFile(t.Context(), link, []byte("replacement"), 100); !errors.Is(err, ErrExists) {
		t.Fatal("hardlinked destination replaced", err)
	}
	assertEntries(t, dir, 2)
}

func TestNilCallbacksAndCanceledContexts(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "source")
	if _, err := Read(t.Context(), path, testLimits(100), nil); !errors.Is(err, ErrCallback) {
		t.Fatal(err)
	}
	if _, err := WriteNew(t.Context(), path, testLimits(100), nil); !errors.Is(err, ErrCallback) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, candidate := range []context.Context{nil, ctx} {
		if _, err := Read(candidate, path, testLimits(100), func(context.Context, io.Reader) error { t.Fatal("canceled read callback"); return nil }); !errors.Is(err, ErrCanceled) {
			t.Fatal(err)
		}
		if _, err := WriteNew(candidate, path, testLimits(100), testProduce([]byte("data"))); !errors.Is(err, ErrCanceled) {
			t.Fatal(err)
		}
	}
	assertEntries(t, dir, 0)
}

func TestPanicInvalidatesWriterAndCleansPrivateStaging(t *testing.T) {
	dir := privateDir(t)
	var retained io.Writer
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected trusted callback panic")
			}
		}()
		_, _ = WriteNew(t.Context(), filepath.Join(dir, "panic"), testLimits(100), func(_ context.Context, w io.Writer) error {
			retained = w
			_, _ = w.Write([]byte("not published"))
			panic("test-only trusted callback failure")
		})
	}()
	if retained == nil {
		t.Fatal("callback not exercised")
	}
	if _, err := retained.Write([]byte("late")); !errors.Is(err, ErrClosed) {
		t.Fatal("panic retained writer usable", err)
	}
	assertEntries(t, dir, 0)
}
