// Package privatefile provides bounded streaming access to private local files.
// Callbacks are trusted internal code, never arbitrary user plugins. Paths,
// native handles and raw I/O errors are not returned to callers.
package privatefile

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

var (
	ErrUnsafe      = errors.New("MI_PRIVATE_FILE_UNSAFE")
	ErrPermissions = errors.New("MI_PRIVATE_FILE_PERMISSIONS")
	ErrUnavailable = errors.New("MI_PRIVATE_FILE_UNAVAILABLE")
	ErrExists      = errors.New("MI_PRIVATE_FILE_EXISTS")
	ErrLimit       = errors.New("MI_PRIVATE_FILE_LIMIT")
	ErrCanceled    = errors.New("MI_PRIVATE_FILE_CANCELED")
	ErrFilesystem  = errors.New("MI_PRIVATE_FILESYSTEM_UNSUPPORTED")
	ErrCallback    = errors.New("MI_PRIVATE_FILE_CALLBACK_FAILED")
	ErrIncomplete  = errors.New("MI_PRIVATE_FILE_INCOMPLETE")
	ErrClosed      = errors.New("MI_PRIVATE_FILE_CLOSED")
)

const (
	MaxBytes   int64 = 1 << 40
	MaxTimeout       = 24 * time.Hour
	chunkBytes       = 64 << 10
)

// Limits must be explicit. These hard limits are resource policies, not proven
// database capacities or guarantees that arbitrary callbacks/I/O can be preempted.
type Limits struct {
	MaxBytes int64
	Timeout  time.Duration
}

// Receipt contains no filesystem location. Published is meaningful for writes:
// a post-publication sync/close/deadline error can return Published=true. In that
// case a complete destination exists and is NEVER removed as error rollback.
type Receipt struct {
	Size      int64
	SHA256    string
	Published bool
}

func operation(ctx context.Context, limits Limits) (context.Context, context.CancelFunc, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, ErrCanceled
	}
	if limits.MaxBytes < 1 || limits.MaxBytes > MaxBytes || limits.Timeout <= 0 || limits.Timeout > MaxTimeout {
		return nil, nil, ErrLimit
	}
	bounded, cancel := context.WithTimeout(ctx, limits.Timeout)
	return bounded, cancel, nil
}

func splitPath(path string) (string, string, error) {
	if path == "" || len(path) > 4096 || !utf8.ValidString(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", "", ErrUnsafe
	}
	for _, r := range path {
		if r < 32 || r == 127 {
			return "", "", ErrUnsafe
		}
	}
	if strings.Contains(path, "://") {
		return "", "", ErrUnsafe
	}
	if err := validatePath(path); err != nil {
		return "", "", err
	}
	parent, name := filepath.Dir(path), filepath.Base(path)
	if parent == path || name == "." || name == ".." {
		return "", "", ErrUnsafe
	}
	return parent, name, nil
}

func verifyDirectoryPath(dir *os.File, path string) error {
	if err := validateDirectory(dir); err != nil {
		return err
	}
	current, err := openDirectory(path)
	if err != nil {
		return err
	}
	defer func() { _ = current.Close() }()
	pinned, err := dir.Stat()
	if err != nil {
		return ErrUnavailable
	}
	now, err := current.Stat()
	if err != nil || !os.SameFile(pinned, now) {
		return ErrUnsafe
	}
	return nil
}

// stream deliberately implements only Reader or Writer through separate wrappers.
// A mutex serializes callback operations and invalidation. Retaining a wrapper
// never grants ownership of the file and every operation after return fails.
type stream struct {
	mu     sync.Mutex
	ctx    context.Context
	file   *os.File
	sum    hash.Hash
	limit  int64
	size   int64
	closed atomic.Bool
	err    error
}

type reader struct{ s *stream }
type writer struct{ s *stream }

func (s *stream) check() error {
	if s.closed.Load() {
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

func (r reader) Read(p []byte) (int, error) {
	s := r.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if s.size == s.limit {
		return 0, io.EOF
	}
	n, err := s.file.Read(p[:min(int64(len(p)), int64(chunkBytes), s.limit-s.size)])
	if n > 0 {
		_, _ = s.sum.Write(p[:n])
		s.size += int64(n)
	}
	if s.closed.Load() {
		s.err = ErrClosed
	} else if s.ctx.Err() != nil {
		s.err = ErrCanceled
	} else if err != nil && !errors.Is(err, io.EOF) || n == 0 && err == nil {
		s.err = ErrUnavailable
	} else if errors.Is(err, io.EOF) && s.size != s.limit {
		s.err = ErrIncomplete
	}
	if s.err != nil {
		return n, s.err
	}
	return n, err
}

func (w writer) Write(p []byte) (int, error) {
	s := w.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(); err != nil {
		return 0, err
	}
	// Reject the entire write rather than silently truncate a caller's chunk.
	if int64(len(p)) > s.limit-s.size {
		s.err = ErrLimit
		return 0, s.err
	}
	var written int
	for written < len(p) {
		if s.closed.Load() {
			s.err = ErrClosed
			return written, s.err
		}
		if s.ctx.Err() != nil {
			s.err = ErrCanceled
			return written, s.err
		}
		end := min(written+chunkBytes, len(p))
		n, err := s.file.Write(p[written:end])
		if n > 0 {
			_, _ = s.sum.Write(p[written : written+n])
			s.size += int64(n)
			written += n
		}
		if err != nil || n == 0 {
			s.err = ErrUnavailable
			return written, s.err
		}
	}
	if s.closed.Load() {
		s.err = ErrClosed
		return written, s.err
	}
	if s.ctx.Err() != nil {
		s.err = ErrCanceled
		return written, s.err
	}
	return written, nil
}

func (s *stream) finish(callbackErr error) (Receipt, error) {
	s.closed.Store(true)
	s.mu.Lock()
	defer s.mu.Unlock()
	result := Receipt{Size: s.size, SHA256: hex.EncodeToString(s.sum.Sum(nil))}
	if s.err != nil {
		return result, s.err
	}
	if s.ctx.Err() != nil {
		return result, ErrCanceled
	}
	if callbackErr != nil {
		return result, ErrCallback
	}
	return result, nil
}

func (s *stream) invalidate() {
	s.closed.Store(true)
	s.mu.Lock()
	s.file = nil
	s.sum = nil
	s.mu.Unlock()
}

// Read streams the complete finite file from one no-follow regular-file handle.
// The callback must consume all bytes; success also requires final identity,
// length, timestamp, permissions and EOF checks. Unlike an authenticated archive
// decoder, this function cannot retract bytes already consumed by the callback.
// Use only with a trusted consumer that withholds publication until Read succeeds.
func Read(ctx context.Context, path string, limits Limits, consume func(context.Context, io.Reader) error) (Receipt, error) {
	ctx, cancel, err := operation(ctx, limits)
	if err != nil {
		return Receipt{}, err
	}
	defer cancel()
	if consume == nil {
		return Receipt{}, ErrCallback
	}
	parent, name, err := splitPath(path)
	if err != nil {
		return Receipt{}, err
	}
	dir, err := openDirectory(parent)
	if err != nil {
		return Receipt{}, err
	}
	defer func() { _ = dir.Close() }()
	f, err := openInput(dir, name)
	if err != nil {
		return Receipt{}, err
	}
	defer func() { _ = f.Close() }()
	if err := validateFile(f); err != nil {
		return Receipt{}, err
	}
	before, err := f.Stat()
	if err != nil {
		return Receipt{}, ErrUnavailable
	}
	if before.Size() < 1 || before.Size() > limits.MaxBytes {
		return Receipt{}, ErrLimit
	}
	s := &stream{ctx: ctx, file: f, sum: sha256.New(), limit: before.Size()}
	defer s.invalidate() // Invalidates even if trusted callback panics.
	result, err := s.finish(consume(ctx, reader{s}))
	if err != nil {
		return Receipt{}, err
	}
	if result.Size != before.Size() {
		return Receipt{}, ErrIncomplete
	}
	var extra [1]byte
	n, readErr := f.Read(extra[:])
	after, statErr := f.Stat()
	if n != 0 || !errors.Is(readErr, io.EOF) || statErr != nil || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return Receipt{}, ErrUnsafe
	}
	if err := validateFile(f); err != nil {
		return Receipt{}, err
	}
	if err := verifyDirectoryPath(dir, parent); err != nil {
		return Receipt{}, err
	}
	if err := f.Close(); err != nil {
		return Receipt{}, ErrUnavailable
	}
	if err := dir.Close(); err != nil {
		return Receipt{}, ErrUnavailable
	}
	if ctx.Err() != nil {
		return Receipt{}, ErrCanceled
	}
	return result, nil
}

// WriteNew requires an existing private parent. It stages a private file, hashes
// while streaming, syncs it and publishes with native atomic no-replace semantics.
// Cancellation is cooperative, including callback and per-chunk context checks;
// no promise is made to forcibly interrupt arbitrary callback code or kernel I/O.
func WriteNew(ctx context.Context, path string, limits Limits, produce func(context.Context, io.Writer) error) (Receipt, error) {
	return writeNew(ctx, path, limits, produce, nil)
}

// hooks are private deterministic test barriers. Exported operations never
// provide them, and the stream callbacks never receive native file handles.
type writeHooks struct {
	beforePublish func()
	afterPublish  func(*os.File, *os.File)
}

func writeNew(ctx context.Context, path string, limits Limits, produce func(context.Context, io.Writer) error, hooks *writeHooks) (result Receipt, resultErr error) {
	ctx, cancel, err := operation(ctx, limits)
	if err != nil {
		return Receipt{}, err
	}
	defer cancel()
	if produce == nil {
		return Receipt{}, ErrCallback
	}
	parent, name, err := splitPath(path)
	if err != nil {
		return Receipt{}, err
	}
	dir, err := openDirectory(parent)
	if err != nil {
		return Receipt{}, err
	}
	defer func() {
		if err := dir.Close(); err != nil && resultErr == nil {
			resultErr = ErrUnavailable
		}
		if ctx.Err() != nil && resultErr == nil {
			resultErr = ErrCanceled
		}
	}()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Receipt{}, ErrUnavailable
	}
	temp := ".mii-private-" + hex.EncodeToString(nonce[:]) + ".tmp"
	f, err := createTemp(dir, temp)
	if err != nil {
		return Receipt{}, err
	}
	defer func() {
		if !result.Published {
			// A cleanup error leaves private staging only. Never remove a final
			// destination or an entry whose identity differs from our handle.
			if err := removeTemp(dir, f, temp); err != nil && resultErr == nil {
				resultErr = err
			}
		}
		if err := f.Close(); err != nil && resultErr == nil {
			resultErr = ErrUnavailable
		}
	}()
	if err := validateFile(f); err != nil {
		return Receipt{}, err
	}
	s := &stream{ctx: ctx, file: f, sum: sha256.New(), limit: limits.MaxBytes}
	defer s.invalidate()
	result, err = s.finish(produce(ctx, writer{s}))
	if err != nil {
		return Receipt{}, err
	}
	if result.Size == 0 {
		return Receipt{}, ErrLimit
	}
	if err := f.Sync(); err != nil {
		return Receipt{}, ErrUnavailable
	}
	if hooks != nil && hooks.beforePublish != nil {
		hooks.beforePublish()
	}
	if err := validateFile(f); err != nil {
		return Receipt{}, err
	}
	info, err := f.Stat()
	if err != nil || info.Size() != result.Size {
		return Receipt{}, ErrUnsafe
	}
	if err := verifyDirectoryPath(dir, parent); err != nil {
		return Receipt{}, err
	}
	if ctx.Err() != nil {
		return Receipt{}, ErrCanceled
	}
	if err := publish(dir, f, temp, name); err != nil {
		return Receipt{}, err
	}
	result.Published = true
	if hooks != nil && hooks.afterPublish != nil {
		hooks.afterPublish(dir, f)
	}
	if err := syncDirectory(dir); err != nil {
		return result, err
	}
	if err := verifyDirectoryPath(dir, parent); err != nil {
		return result, err
	}
	if ctx.Err() != nil {
		return result, ErrCanceled
	}
	return result, nil
}
