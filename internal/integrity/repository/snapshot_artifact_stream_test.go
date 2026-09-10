//nolint:errorlint // Exact sentinel identity is the non-leaking protocol under test; wrappers are forbidden.
package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func snapshotArtifactTestHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func snapshotArtifactTestSource(body []byte) (snapshotArtifactDescriptor, snapshotArtifactFetch) {
	descriptor := snapshotArtifactDescriptor{"rule", "opaque.1", snapshotArtifactTestHash(body), 1, 2, int64(len(body))}
	return descriptor, func(_ context.Context, offset, size int64) ([]byte, error) {
		if offset >= int64(len(body)) {
			return []byte{}, nil
		}
		return bytes.Clone(body[offset:min(offset+size, int64(len(body)))]), nil
	}
}

type snapshotArtifactWriterFunc func([]byte) (int, error)

func (f snapshotArtifactWriterFunc) Write(p []byte) (int, error) { return f(p) }

func snapshotArtifactTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestSnapshotArtifactStreamRawBoundedCopyAndLateCapability(t *testing.T) {
	body := bytes.Repeat([]byte("\xff{opaque:\r\n模板}"), 10000)
	d, fetch := snapshotArtifactTestSource(body)
	var calls, writes int
	var retained snapshotArtifactCopy
	var written bytes.Buffer
	var borrowed []byte
	err := snapshotArtifactConsume(snapshotArtifactTestContext(t), d, func(ctx context.Context, offset, size int64) ([]byte, error) {
		calls++
		if size > snapshotArtifactChunkBytes {
			t.Fatal("unbounded fetch")
		}
		if offset != int64(calls-1)*snapshotArtifactChunkBytes && offset != int64(len(body)) {
			t.Fatal("non-sequential source")
		}
		return fetch(ctx, offset, size)
	}, func(_ context.Context, got snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
		if got != d {
			t.Fatal("identity rewritten")
		}
		retained = copy
		return copy(snapshotArtifactWriterFunc(func(p []byte) (int, error) {
			if len(p) > snapshotArtifactChunkBytes {
				t.Fatal("unbounded write")
			}
			writes++
			borrowed = p
			return written.Write(p)
		}))
	})
	if err != nil || !bytes.Equal(written.Bytes(), body) || calls != writes+1 || calls < 3 {
		t.Fatal("raw copy failed", err, calls, writes)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("borrowed chunk not erased")
	}
	before := calls
	if err := retained(io.Discard); err != errSnapshotArtifactClosed || calls != before {
		t.Fatal("late capability performed I/O", err)
	}
}

func TestSnapshotArtifactStreamFailuresAreClosedAndSticky(t *testing.T) {
	canary := errors.New("private-source-path-and-token-canary")
	for _, test := range []struct {
		name   string
		want   error
		change func(*snapshotArtifactDescriptor, *snapshotArtifactFetch)
		sink   snapshotArtifactSink
	}{
		{"not-consumed", errSnapshotArtifactIncomplete, nil, func(context.Context, snapshotArtifactDescriptor, snapshotArtifactCopy) error { return nil }},
		{"sink-error", errSnapshotArtifactCallback, nil, func(context.Context, snapshotArtifactDescriptor, snapshotArtifactCopy) error { return canary }},
		{"sink-panic", errSnapshotArtifactCallback, nil, func(context.Context, snapshotArtifactDescriptor, snapshotArtifactCopy) error { panic(canary) }},
		{"panic-after-copy", errSnapshotArtifactCallback, nil, func(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
			_ = copy(io.Discard)
			panic(canary)
		}},
		{"nil-writer-swallowed", errSnapshotArtifactCallback, nil, func(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
			_ = copy(nil)
			return nil
		}},
		{"short-swallowed", errSnapshotArtifactCallback, nil, func(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
			_ = copy(snapshotArtifactWriterFunc(func(p []byte) (int, error) { return len(p) - 1, nil }))
			return nil
		}},
		{"invalid-large-n", errSnapshotArtifactCallback, nil, func(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
			_ = copy(snapshotArtifactWriterFunc(func(p []byte) (int, error) { return len(p) + 1, nil }))
			return nil
		}},
		{"invalid-negative-n", errSnapshotArtifactCallback, nil, func(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
			_ = copy(snapshotArtifactWriterFunc(func([]byte) (int, error) { return -1, nil }))
			return nil
		}},
		{"writer-error-swallowed", errSnapshotArtifactCallback, nil, func(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
			_ = copy(snapshotArtifactWriterFunc(func([]byte) (int, error) { return 0, canary }))
			return nil
		}},
		{"writer-panic-swallowed", errSnapshotArtifactCallback, nil, func(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
			_ = copy(snapshotArtifactWriterFunc(func([]byte) (int, error) { panic(canary) }))
			return nil
		}},
		{"duplicate-swallowed", errSnapshotArtifactConsumed, nil, func(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
			_ = copy(io.Discard)
			_ = copy(io.Discard)
			return nil
		}},
		{"reentrant-swallowed", errSnapshotArtifactConsumed, nil, func(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
			_ = copy(snapshotArtifactWriterFunc(func(p []byte) (int, error) { _ = copy(io.Discard); return len(p), nil }))
			return nil
		}},
		{"wrong-hash-swallowed", errSnapshotArtifactInvalid, func(d *snapshotArtifactDescriptor, _ *snapshotArtifactFetch) { d.sha256 = strings.Repeat("0", 64) }, nil},
		{"short-source-swallowed", errSnapshotArtifactInvalid, func(d *snapshotArtifactDescriptor, _ *snapshotArtifactFetch) { d.bytes++ }, nil},
		{"trailing-source-swallowed", errSnapshotArtifactInvalid, func(d *snapshotArtifactDescriptor, _ *snapshotArtifactFetch) { d.bytes-- }, nil},
		{"late-fetch-error-swallowed", ErrUnavailable, func(_ *snapshotArtifactDescriptor, f *snapshotArtifactFetch) {
			original := *f
			*f = func(ctx context.Context, offset, size int64) ([]byte, error) {
				if offset > 0 {
					return nil, canary
				}
				return original(ctx, offset, size)
			}
		}, nil},
		{"fetch-panic-swallowed", errSnapshotArtifactCallback, func(_ *snapshotArtifactDescriptor, f *snapshotArtifactFetch) {
			*f = func(context.Context, int64, int64) ([]byte, error) { panic(canary) }
		}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, fetch := snapshotArtifactTestSource(bytes.Repeat([]byte("opaque-not-json"), 8000))
			if test.change != nil {
				test.change(&d, &fetch)
			}
			sink := test.sink
			if sink == nil {
				sink = func(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
					_ = copy(io.Discard)
					return nil
				}
			}
			if err := snapshotArtifactConsume(snapshotArtifactTestContext(t), d, fetch, sink); err != test.want || strings.Contains(fmt.Sprint(err), "canary") {
				t.Fatal("wrong closed result", err, test.want)
			}
		})
	}
}

func TestSnapshotArtifactStreamAsyncReturnIsJoinedAndRejected(t *testing.T) {
	d, fetch := snapshotArtifactTestSource([]byte("opaque-private-bytes"))
	var writerFinished atomic.Bool
	var retained snapshotArtifactCopy
	err := snapshotArtifactConsume(snapshotArtifactTestContext(t), d, fetch, func(ctx context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
		retained = copy
		started := make(chan struct{})
		go func() {
			_ = copy(snapshotArtifactWriterFunc(func(p []byte) (int, error) {
				close(started)
				<-ctx.Done()
				writerFinished.Store(true)
				return len(p), nil
			}))
		}()
		<-started
		return nil
	})
	if err != errSnapshotArtifactIncomplete || !writerFinished.Load() {
		t.Fatal("detached copy escaped", err)
	}
	if err := retained(io.Discard); err != errSnapshotArtifactClosed {
		t.Fatal(err)
	}
}

func TestSnapshotArtifactStreamAsyncStartAfterReturnNeverReads(t *testing.T) {
	d, fetch := snapshotArtifactTestSource([]byte("private"))
	start, result := make(chan struct{}), make(chan error, 1)
	var reads atomic.Int32
	err := snapshotArtifactConsume(snapshotArtifactTestContext(t), d, func(ctx context.Context, offset, size int64) ([]byte, error) {
		reads.Add(1)
		return fetch(ctx, offset, size)
	}, func(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
		go func() { <-start; result <- copy(io.Discard) }()
		return nil
	})
	close(start)
	if err != errSnapshotArtifactIncomplete || <-result != errSnapshotArtifactClosed || reads.Load() != 0 {
		t.Fatal("late async start used transaction", err)
	}
}

func TestSnapshotArtifactStreamExactChunkBoundariesAndEOFFailure(t *testing.T) {
	for _, size := range []int{1, snapshotArtifactChunkBytes - 1, snapshotArtifactChunkBytes, snapshotArtifactChunkBytes + 1, 2 * snapshotArtifactChunkBytes} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			d, fetch := snapshotArtifactTestSource(bytes.Repeat([]byte("x"), size))
			calls := 0
			err := snapshotArtifactConsume(snapshotArtifactTestContext(t), d, func(ctx context.Context, offset, size int64) ([]byte, error) {
				calls++
				return fetch(ctx, offset, size)
			}, snapshotArtifactTestDiscard)
			if err != nil || calls != (size+snapshotArtifactChunkBytes-1)/snapshotArtifactChunkBytes+1 {
				t.Fatal("chunk/EOF boundary", err, calls)
			}
			var written int
			err = snapshotArtifactConsume(snapshotArtifactTestContext(t), d, func(ctx context.Context, offset, size int64) ([]byte, error) {
				if offset == d.bytes {
					return nil, errors.New("private EOF failure")
				}
				return fetch(ctx, offset, size)
			}, func(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
				_ = copy(snapshotArtifactWriterFunc(func(p []byte) (int, error) { written += len(p); return len(p), nil }))
				return nil
			})
			if err != ErrUnavailable || written != size {
				t.Fatal("EOF failure returned success after staging", err, written)
			}
		})
	}
}

func TestSnapshotArtifactStreamConcurrentDuplicatePoisonsFirst(t *testing.T) {
	d, fetch := snapshotArtifactTestSource([]byte("opaque"))
	err := snapshotArtifactConsume(snapshotArtifactTestContext(t), d, fetch, func(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
		started, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() {
			finished <- copy(snapshotArtifactWriterFunc(func(p []byte) (int, error) { close(started); <-release; return len(p), nil }))
		}()
		<-started
		if got := copy(io.Discard); got != errSnapshotArtifactConsumed {
			t.Errorf("concurrent duplicate: %v", got)
		}
		close(release)
		if got := <-finished; got != errSnapshotArtifactConsumed {
			t.Errorf("first copy ignored sticky failure: %v", got)
		}
		return nil
	})
	if err != errSnapshotArtifactConsumed {
		t.Fatal(err)
	}
}

func TestSnapshotArtifactStreamCancellationAndGuards(t *testing.T) {
	d, fetch := snapshotArtifactTestSource([]byte("opaque"))
	ctx, cancel := context.WithCancel(snapshotArtifactTestContext(t))
	if err := snapshotArtifactConsume(ctx, d, fetch, func(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
		_ = copy(snapshotArtifactWriterFunc(func(p []byte) (int, error) { cancel(); return len(p), nil }))
		return nil
	}); err != ErrUnavailable {
		t.Fatal(err)
	}
	var missingContext context.Context
	for _, err := range []error{
		snapshotArtifactConsume(missingContext, d, fetch, func(context.Context, snapshotArtifactDescriptor, snapshotArtifactCopy) error { return nil }),
		snapshotArtifactConsume(context.Background(), d, nil, func(context.Context, snapshotArtifactDescriptor, snapshotArtifactCopy) error { return nil }),
		snapshotArtifactConsume(context.Background(), d, fetch, nil),
	} {
		if err != ErrConfiguration {
			t.Fatal(err)
		}
	}
}
