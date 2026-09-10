package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

const snapshotArtifactChunkBytes = 64 << 10

// A copy is borrowed for exactly one synchronous sink invocation. The writer
// must follow io.Writer's contract and be cooperative with cancellation. The
// sink owns private staging only; it must not publish until the ENTIRE snapshot
// coordinator (including transaction completion) succeeds.
type snapshotArtifactCopy func(io.Writer) error
type snapshotArtifactSink func(context.Context, snapshotArtifactDescriptor, snapshotArtifactCopy) error
type snapshotArtifactFetch func(context.Context, int64, int64) ([]byte, error)

func (snapshotArtifactCopy) String() string               { return "[private snapshot artifact copy]" }
func (v snapshotArtifactCopy) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (v snapshotArtifactCopy) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (snapshotArtifactCopy) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (snapshotArtifactCopy) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

// No lock is held across SQL, a sink, or Write: reentrant/duplicate calls fail
// immediately instead of deadlocking. Failure is sticky even if a sink swallows
// an error. The fetch capability is erased on close, including panic paths.
type snapshotArtifactStream struct {
	mu                                sync.Mutex
	ctx                               context.Context
	descriptor                        snapshotArtifactDescriptor
	fetch                             snapshotArtifactFetch
	started, active, complete, closed bool
	failure                           error
	done                              chan struct{}
}

func (*snapshotArtifactStream) String() string               { return "[private snapshot artifact stream]" }
func (v *snapshotArtifactStream) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (v *snapshotArtifactStream) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (*snapshotArtifactStream) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (*snapshotArtifactStream) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

func snapshotArtifactConsume(ctx context.Context, descriptor snapshotArtifactDescriptor, fetch snapshotArtifactFetch, sink snapshotArtifactSink) error {
	if ctx == nil || fetch == nil || sink == nil || descriptor.bytes < 1 {
		return ErrConfiguration
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	stream := &snapshotArtifactStream{ctx: child, descriptor: descriptor, fetch: fetch}
	callbackErr := snapshotArtifactInvoke(child, descriptor, stream.copy, sink)
	stream.mu.Lock()
	// Close BEFORE waiting, rejecting newly admitted copies. An operation already
	// admitted by check may finish; join below keeps it within Consume's lifetime.
	// A copy still active at callback return is a lifecycle violation.
	stream.closed, stream.fetch = true, nil
	if callbackErr != nil {
		stream.failLocked(errSnapshotArtifactCallback)
	}
	if stream.active || !stream.started || !stream.complete {
		stream.failLocked(errSnapshotArtifactIncomplete)
	}
	done, active := stream.done, stream.active
	stream.mu.Unlock()
	cancel()
	if active {
		// An arbitrary Go callback cannot be forcibly preempted. Joining here
		// guarantees no detached writer remains at return; a noncooperative
		// writer can delay return beyond the deadline and is outside this API.
		<-done
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	return stream.failure
}

func snapshotArtifactInvoke(ctx context.Context, descriptor snapshotArtifactDescriptor, copy snapshotArtifactCopy, sink snapshotArtifactSink) (err error) {
	defer func() {
		if recover() != nil {
			err = errSnapshotArtifactCallback
		}
	}()
	return sink(ctx, descriptor, copy)
}

func (s *snapshotArtifactStream) failLocked(err error) {
	if s.failure == nil {
		s.failure = err
	}
}

func (s *snapshotArtifactStream) check() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errSnapshotArtifactClosed
	}
	if s.failure != nil {
		return s.failure
	}
	if s.ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *snapshotArtifactStream) copy(dst io.Writer) (err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errSnapshotArtifactClosed
	}
	if s.started {
		s.failLocked(errSnapshotArtifactConsumed)
		s.mu.Unlock()
		return errSnapshotArtifactConsumed
	}
	s.started, s.active, s.done = true, true, make(chan struct{})
	fetch := s.fetch
	s.mu.Unlock()
	defer func() {
		if recover() != nil {
			err = errSnapshotArtifactCallback
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if err != nil {
			s.failLocked(err)
		}
		s.active, s.complete = false, err == nil && s.failure == nil && !s.closed
		if s.failure != nil {
			err = s.failure
		}
		close(s.done)
	}()
	if dst == nil {
		return errSnapshotArtifactCallback
	}
	hash := sha256.New()
	for offset := int64(0); offset < s.descriptor.bytes; {
		if err = s.check(); err != nil {
			return err
		}
		size := min(int64(snapshotArtifactChunkBytes), s.descriptor.bytes-offset)
		chunk, fetchErr := fetch(s.ctx, offset, size)
		if fetchErr != nil {
			clear(chunk)
			return ErrUnavailable
		}
		if int64(len(chunk)) != size {
			clear(chunk)
			return errSnapshotArtifactInvalid
		}
		if err = s.check(); err != nil {
			clear(chunk)
			return err
		}
		// Hash the exact source bytes, never a normalized/runtime-decoded body.
		_, _ = hash.Write(chunk)
		n, writeErr := snapshotArtifactWrite(dst, chunk)
		clear(chunk)
		if writeErr != nil || n != int(size) {
			return errSnapshotArtifactCallback
		}
		offset += size
	}
	if err = s.check(); err != nil {
		return err
	}
	// The bounded metadata size is not trusted as an EOF assertion.
	trailing, fetchErr := fetch(s.ctx, s.descriptor.bytes, 1)
	trailingSize := len(trailing)
	clear(trailing)
	if fetchErr != nil {
		return ErrUnavailable
	}
	if trailingSize != 0 || hex.EncodeToString(hash.Sum(nil)) != s.descriptor.sha256 {
		return errSnapshotArtifactInvalid
	}
	return s.check()
}

// Recover at the narrow boundary as well so even panic paths erase chunk data.
func snapshotArtifactWrite(dst io.Writer, chunk []byte) (n int, err error) {
	defer func() {
		if recover() != nil {
			err = errSnapshotArtifactCallback
		}
	}()
	return dst.Write(chunk)
}
