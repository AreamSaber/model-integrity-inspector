package privatefile

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"
)

const MaxBackupWorkspaceEntries = 65536

// MaxBytes is the shared logical content/spool-file size budget, NOT physical
// allocated clusters, filesystem metadata, free-space reservation or capacity
// proof. Empty objects still consume MaxEntries. No files are replaced/refunded.
type BackupWorkspaceLimits struct {
	MaxBytes   int64
	MaxEntries int
	Timeout    time.Duration
}

type BackupObjectLimits struct {
	MaxBytes   int64
	AllowEmpty bool
}

// Metadata is explicit, bounded and pathless. It is a byte observation, not
// authentication, database readiness, a publication or restore authorization.
type BackupObjectInfo struct {
	Size   int64
	SHA256 string
}

type BackupWorkspaceReceipt struct {
	Objects int
	Bytes   int64
}

type BackupWorkspace struct{ state *backupWorkspaceState }
type BackupObject struct{ entry *backupWorkspaceEntry }

type backupWorkspaceEntry struct {
	owner *backupWorkspaceState
	name  string
	id    os.FileInfo
	info  BackupObjectInfo
	ready bool
}

type backupWorkspaceNative interface {
	create(string) (*os.File, error)
	open(string, bool) (*os.File, error)
	check(*os.File, string, os.FileInfo) error
	inspect(map[string]*backupWorkspaceEntry, int64) error
	remove(*os.File, string) error
	cleanup(map[string]*backupWorkspaceEntry) error
}

type backupWorkspaceState struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	native  backupWorkspaceNative
	limits  BackupWorkspaceLimits
	entries map[string]*backupWorkspaceEntry
	bytes   int64
	err     error
	closed  bool
	active  chan struct{}
	hooks   *backupWorkspaceHooks
}

// Native handles are available only to deterministic package-local tests.
type backupWorkspaceHooks struct {
	beforeObjectClose func(*os.File)
	beforeCleanup     func(backupWorkspaceNative)
}

func (BackupWorkspace) String() string                      { return "[private backup workspace]" }
func (v BackupWorkspace) Format(s fmt.State, _ rune)        { _, _ = io.WriteString(s, v.String()) }
func (v BackupWorkspace) LogValue() slog.Value              { return slog.StringValue(v.String()) }
func (BackupWorkspace) MarshalJSON() ([]byte, error)        { return nil, ErrUnsafe }
func (BackupWorkspace) MarshalYAML() (any, error)           { return nil, ErrUnsafe }
func (BackupObject) String() string                         { return "[private backup workspace object]" }
func (v BackupObject) Format(s fmt.State, _ rune)           { _, _ = io.WriteString(s, v.String()) }
func (v BackupObject) LogValue() slog.Value                 { return slog.StringValue(v.String()) }
func (BackupObject) MarshalJSON() ([]byte, error)           { return nil, ErrUnsafe }
func (BackupObject) MarshalYAML() (any, error)              { return nil, ErrUnsafe }
func (BackupObjectInfo) String() string                     { return "[private backup object observation]" }
func (v BackupObjectInfo) Format(s fmt.State, _ rune)       { _, _ = io.WriteString(s, v.String()) }
func (v BackupObjectInfo) LogValue() slog.Value             { return slog.StringValue(v.String()) }
func (BackupObjectInfo) MarshalJSON() ([]byte, error)       { return nil, ErrUnsafe }
func (BackupObjectInfo) MarshalYAML() (any, error)          { return nil, ErrUnsafe }
func (BackupWorkspaceReceipt) String() string               { return "[private backup workspace completion]" }
func (v BackupWorkspaceReceipt) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (v BackupWorkspaceReceipt) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (BackupWorkspaceReceipt) MarshalJSON() ([]byte, error) { return nil, ErrUnsafe }
func (BackupWorkspaceReceipt) MarshalYAML() (any, error)    { return nil, ErrUnsafe }

func backupWorkspaceCall(fn func() error) (err error) {
	returned := false
	defer func() {
		if !returned {
			_ = recover() // Also closes panic(nil) under legacy panicnil settings.
			err = ErrCallback
		}
	}()
	err = fn()
	returned = true
	return err
}

// WithBackupWorkspace owns private, bounded, re-readable scratch objects. The
// trusted callback must propagate external source/AEAD errors and withhold ALL
// publication until this call succeeds, including final cleanup/close. This
// primitive does not publish anything, execute SQL, or validate an archive.
//
// Callbacks/IO must cooperate with context. Detached work is forbidden: a live
// operation at callback return fails the workspace, is canceled and joined;
// arbitrary blocking callback/kernel code cannot be forcibly interrupted.
func WithBackupWorkspace(ctx context.Context, parent string, limits BackupWorkspaceLimits, use func(context.Context, *BackupWorkspace) error) (BackupWorkspaceReceipt, error) {
	return withBackupWorkspace(ctx, parent, limits, use, nil)
}

func withBackupWorkspace(ctx context.Context, parent string, limits BackupWorkspaceLimits, use func(context.Context, *BackupWorkspace) error, hooks *backupWorkspaceHooks) (receipt BackupWorkspaceReceipt, finalErr error) {
	if ctx == nil || ctx.Err() != nil {
		return receipt, ErrCanceled
	}
	if limits.MaxBytes < 0 || limits.MaxBytes > MaxBytes || limits.MaxEntries < 1 || limits.MaxEntries > MaxBackupWorkspaceEntries || limits.Timeout <= 0 || limits.Timeout > MaxTimeout {
		return receipt, ErrLimit
	}
	if use == nil {
		return receipt, ErrCallback
	}
	if _, _, err := splitPath(parent); err != nil {
		return receipt, err
	}
	bounded, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()
	native, err := newBackupWorkspaceNative(bounded, parent)
	if err != nil {
		return receipt, err
	}
	s := &backupWorkspaceState{ctx: bounded, cancel: cancel, native: native, limits: limits, entries: make(map[string]*backupWorkspaceEntry), hooks: hooks}
	defer func() {
		if recover() != nil {
			finalErr = ErrCallback
		}
		s.mu.Lock()
		if finalErr != nil && s.err == nil {
			s.err = finalErr
		}
		s.closed = true
		active := s.active
		if active != nil {
			if s.err == nil {
				s.err = ErrCallback
			}
			cancel()
		}
		s.mu.Unlock()
		if active != nil {
			<-active
		}
		// Closure is fenced before the final inspection: no escaped goroutine
		// can begin another operation while we inspect or delete these files.
		s.mu.Lock()
		failed := s.err != nil
		s.mu.Unlock()
		if !failed {
			if err := native.inspect(s.entries, limits.MaxBytes); err != nil {
				_ = s.fail(err)
			}
		}
		if hooks != nil && hooks.beforeCleanup != nil {
			if err := backupWorkspaceCall(func() error { hooks.beforeCleanup(native); return nil }); err != nil {
				_ = s.fail(err)
			}
		}
		if err := native.cleanup(s.entries); err != nil {
			_ = s.fail(err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if bounded.Err() != nil && s.err == nil {
			s.err = ErrCanceled
		}
		finalErr = s.err
		if finalErr != nil {
			receipt = BackupWorkspaceReceipt{}
		} else {
			receipt = BackupWorkspaceReceipt{Objects: len(s.entries), Bytes: s.bytes}
		}
		for _, entry := range s.entries {
			entry.id = nil
		}
		s.entries = nil
		s.native = nil
	}()
	callbackErr := backupWorkspaceCall(func() error { return use(bounded, &BackupWorkspace{state: s}) })
	if callbackErr != nil {
		return receipt, s.fail(ErrCallback)
	}
	return receipt, nil // The owner finalizer alone can issue a completion receipt.
}

func (s *backupWorkspaceState) checkLocked() error {
	if s.closed {
		return ErrClosed
	}
	if s.err != nil {
		return s.err
	}
	if s.ctx.Err() != nil {
		s.err = ErrCanceled
		return s.err
	}
	return nil
}
func (s *backupWorkspaceState) fail(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err == nil {
		s.err = err
	}
	return s.err
}
func (w BackupWorkspace) begin() (*backupWorkspaceState, error) {
	s := w.state
	if s == nil {
		return nil, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkLocked(); err != nil {
		return nil, err
	}
	if s.active != nil {
		s.err = ErrCallback
		return nil, s.err
	}
	s.active = make(chan struct{})
	return s, nil
}
func (s *backupWorkspaceState) end() {
	s.mu.Lock()
	close(s.active)
	s.active = nil
	s.mu.Unlock()
}

func (o BackupObject) Info() (BackupObjectInfo, error) {
	if o.entry == nil || o.entry.owner == nil {
		return BackupObjectInfo{}, ErrClosed
	}
	s := o.entry.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkLocked(); err != nil {
		return BackupObjectInfo{}, err
	}
	if !o.entry.ready || s.entries[o.entry.name] != o.entry {
		s.err = ErrUnsafe
		return BackupObjectInfo{}, s.err
	}
	return o.entry.info, nil
}

func (w BackupWorkspace) Put(limits BackupObjectLimits, produce func(context.Context, io.Writer) error) (object BackupObject, finalErr error) {
	s, err := w.begin()
	if err != nil {
		return object, err
	}
	defer s.end()
	defer func() {
		if recover() != nil {
			finalErr = ErrCallback
		}
		if finalErr != nil {
			finalErr = s.fail(finalErr)
			object = BackupObject{}
		}
	}()
	if limits.MaxBytes < 0 || limits.MaxBytes > MaxBytes || limits.MaxBytes == 0 && !limits.AllowEmpty {
		return object, ErrLimit
	}
	if produce == nil {
		return object, ErrCallback
	}
	if len(s.entries) >= s.limits.MaxEntries {
		return object, ErrLimit
	}
	if err := s.native.inspect(s.entries, s.limits.MaxBytes); err != nil {
		return object, err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return object, ErrUnavailable
	}
	name := "object-" + hex.EncodeToString(random[:]) + ".spool"
	f, err := s.native.create(name)
	if err != nil {
		return object, err
	}
	entry := &backupWorkspaceEntry{owner: s, name: name}
	s.mu.Lock()
	s.entries[name] = entry
	s.mu.Unlock()
	defer func() {
		if f != nil {
			if err := f.Close(); err != nil && finalErr == nil {
				finalErr = ErrUnavailable
				object = BackupObject{}
				_ = s.fail(finalErr)
			}
		}
	}()
	entry.id, err = f.Stat()
	if err != nil {
		return object, ErrUnavailable
	}
	if err := s.native.check(f, name, entry.id); err != nil {
		return object, err
	}
	stream := &stream{ctx: s.ctx, file: f, sum: sha256.New(), limit: min(limits.MaxBytes, s.limits.MaxBytes-s.bytes)}
	defer stream.invalidate()
	borrowed := &backupWorkspaceBorrow{owner: s, stream: stream}
	callbackErr := backupWorkspaceCall(func() error { return produce(s.ctx, backupWorkspaceWriter{borrowed}) })
	borrowed.finish()
	result, err := stream.finish(callbackErr)
	s.bytes += result.Size
	if err != nil {
		return object, err
	}
	if result.Size == 0 && !limits.AllowEmpty {
		return object, ErrLimit
	}
	if err := f.Sync(); err != nil {
		return object, ErrUnavailable
	}
	if err := s.native.check(f, name, entry.id); err != nil {
		return object, err
	}
	after, err := f.Stat()
	if err != nil || after.Size() != result.Size {
		return object, ErrUnsafe
	}
	entry.id = after
	if s.hooks != nil && s.hooks.beforeObjectClose != nil {
		if err := backupWorkspaceCall(func() error { s.hooks.beforeObjectClose(f); return nil }); err != nil {
			return object, err
		}
	}
	if err := f.Close(); err != nil {
		return object, ErrUnavailable
	}
	// Avoid treating this intentional successful close as a final close error.
	f = nil
	s.mu.Lock()
	err = s.checkLocked()
	if err == nil {
		entry.info = BackupObjectInfo{result.Size, result.SHA256}
		entry.ready = true
	}
	s.mu.Unlock()
	if err != nil {
		return object, err
	}
	return BackupObject{entry}, nil
}

// Read borrows a bounded stream from the original, sealed object generation.
// Success requires full consumption, exact EOF, hash, size, identity, permission
// and final-close checks. Read may be repeated, but never concurrently/reentrantly.
func (w BackupWorkspace) Read(object BackupObject, consume func(context.Context, io.Reader) error) (info BackupObjectInfo, finalErr error) {
	s, err := w.begin()
	if err != nil {
		return info, err
	}
	defer s.end()
	defer func() {
		if recover() != nil {
			finalErr = ErrCallback
		}
		if finalErr != nil {
			finalErr = s.fail(finalErr)
			info = BackupObjectInfo{}
		}
	}()
	entry := object.entry
	if entry == nil || entry.owner != s || !entry.ready || s.entries[entry.name] != entry {
		return info, ErrUnsafe
	}
	if consume == nil {
		return info, ErrCallback
	}
	if err := s.native.inspect(s.entries, s.limits.MaxBytes); err != nil {
		return info, err
	}
	f, err := s.native.open(entry.name, false)
	if err != nil {
		return info, err
	}
	defer func() {
		if f != nil {
			if err := f.Close(); err != nil && finalErr == nil {
				finalErr = ErrUnavailable
			}
		}
	}()
	if err := s.native.check(f, entry.name, entry.id); err != nil {
		return info, err
	}
	before, err := f.Stat()
	if err != nil || before.Size() != entry.info.Size || !before.ModTime().Equal(entry.id.ModTime()) {
		return info, ErrUnsafe
	}
	stream := &stream{ctx: s.ctx, file: f, sum: sha256.New(), limit: entry.info.Size}
	defer stream.invalidate()
	borrowed := &backupWorkspaceBorrow{owner: s, stream: stream}
	callbackErr := backupWorkspaceCall(func() error { return consume(s.ctx, backupWorkspaceReader{borrowed}) })
	borrowed.finish()
	result, err := stream.finish(callbackErr)
	if err != nil {
		return info, err
	}
	if result.Size != entry.info.Size {
		return info, ErrIncomplete
	}
	if result.SHA256 != entry.info.SHA256 {
		return info, ErrUnsafe
	}
	var extra [1]byte
	if n, err := f.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return info, ErrUnsafe
	}
	after, err := f.Stat()
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || !os.SameFile(before, after) {
		return info, ErrUnsafe
	}
	if err := s.native.check(f, entry.name, entry.id); err != nil {
		return info, err
	}
	if s.hooks != nil && s.hooks.beforeObjectClose != nil {
		if err := backupWorkspaceCall(func() error { s.hooks.beforeObjectClose(f); return nil }); err != nil {
			return info, err
		}
	}
	if err := f.Close(); err != nil {
		return info, ErrUnavailable
	}
	f = nil
	if err := s.native.inspect(s.entries, s.limits.MaxBytes); err != nil {
		return info, err
	}
	s.mu.Lock()
	err = s.checkLocked()
	s.mu.Unlock()
	if err != nil {
		return info, err
	}
	return entry.info, nil
}

type backupWorkspaceBorrow struct {
	owner  *backupWorkspaceState
	stream *stream
	mu     sync.Mutex
	closed bool
	active chan struct{}
}
type backupWorkspaceWriter struct{ b *backupWorkspaceBorrow }
type backupWorkspaceReader struct{ b *backupWorkspaceBorrow }

func (b *backupWorkspaceBorrow) enter() error {
	b.owner.mu.Lock()
	err := b.owner.checkLocked()
	b.owner.mu.Unlock()
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return b.owner.fail(ErrClosed)
	}
	if b.active != nil {
		return b.owner.fail(ErrCallback)
	}
	b.active = make(chan struct{})
	return nil
}
func (b *backupWorkspaceBorrow) leave() {
	b.mu.Lock()
	close(b.active)
	b.active = nil
	b.mu.Unlock()
}
func (b *backupWorkspaceBorrow) finish() {
	b.mu.Lock()
	b.closed = true
	active := b.active
	b.mu.Unlock()
	if active != nil {
		_ = b.owner.fail(ErrCallback)
		b.owner.cancel()
		<-active
	}
}
func (backupWorkspaceWriter) String() string               { return "[private backup workspace writer]" }
func (v backupWorkspaceWriter) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (v backupWorkspaceWriter) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (backupWorkspaceWriter) MarshalJSON() ([]byte, error) { return nil, ErrUnsafe }
func (backupWorkspaceWriter) MarshalYAML() (any, error)    { return nil, ErrUnsafe }
func (backupWorkspaceReader) String() string               { return "[private backup workspace reader]" }
func (v backupWorkspaceReader) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (v backupWorkspaceReader) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (backupWorkspaceReader) MarshalJSON() ([]byte, error) { return nil, ErrUnsafe }
func (backupWorkspaceReader) MarshalYAML() (any, error)    { return nil, ErrUnsafe }
func (w backupWorkspaceWriter) Write(p []byte) (int, error) {
	if err := w.b.enter(); err != nil {
		return 0, err
	}
	defer w.b.leave()
	n, err := (writer{w.b.stream}).Write(p)
	if err != nil {
		return n, w.b.owner.fail(err)
	}
	return n, nil
}
func (r backupWorkspaceReader) Read(p []byte) (int, error) {
	if err := r.b.enter(); err != nil {
		return 0, err
	}
	defer r.b.leave()
	n, err := (reader{r.b.stream}).Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, r.b.owner.fail(err)
	}
	return n, err
}
