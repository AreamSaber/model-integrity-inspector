package privatefile

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MaxSQLiteWorkspaceBytes is a scratch-space policy, not a database capacity
// claim. The main file and all temporary SQLite sidecars share this allowance.
const MaxSQLiteWorkspaceBytes = 2 * MaxBytes

// SQLiteLimits separates the final database budget from its temporary workspace.
// Check must be called between bounded SQLite steps. This capability cannot
// preempt SQLite, arbitrary callback code, or a blocking kernel operation.
type SQLiteLimits struct {
	MaxDatabaseBytes  int64
	MaxWorkspaceBytes int64
	Timeout           time.Duration
}

type sqliteStagingNative interface {
	databasePath() string
	inspect(maxDatabase, maxWorkspace int64, sealed bool) error
	seal() (*os.File, error)
	cleanup() error
}

// SQLiteTarget is a temporary path capability for trusted synchronous SQLite
// code, never HTTP input or an arbitrary plugin. Copies share one lifecycle.
// URI strings themselves cannot be revoked: callers MUST NOT retain them, pass
// them to detached work, or leave a SQLite connection/statement open on return.
type SQLiteTarget struct{ state *sqliteTargetState }

type sqliteTargetState struct {
	mu     sync.Mutex
	ctx    context.Context
	native sqliteStagingNative
	limits SQLiteLimits
	closed bool
	err    error
}

func (SQLiteTarget) String() string               { return "[protected SQLite target]" }
func (SQLiteTarget) GoString() string             { return "[protected SQLite target]" }
func (SQLiteTarget) LogValue() slog.Value         { return slog.StringValue("[protected SQLite target]") }
func (SQLiteTarget) MarshalJSON() ([]byte, error) { return nil, ErrUnsafe }
func (SQLiteTarget) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[protected SQLite target]")
}

func (s *sqliteTargetState) check() error {
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
	s.err = s.native.inspect(s.limits.MaxDatabaseBytes, s.limits.MaxWorkspaceBytes, false)
	return s.err
}

// Check verifies the same native workspace, permissions, and cumulative size.
// The first limit, cancellation, or native failure is sticky even if swallowed.
func (t SQLiteTarget) Check() error {
	if t.state == nil {
		return ErrClosed
	}
	t.state.mu.Lock()
	defer t.state.mu.Unlock()
	return t.state.check()
}

// URI returns an internally constructed, existing-file-only SQLite write URI.
func (t SQLiteTarget) URI() (string, error) { return t.uri(false) }

// ROURI returns a genuinely read-only URI. A read-only sql.TxOptions flag alone
// is not an OS read-only open in the pinned SQLite driver.
func (t SQLiteTarget) ROURI() (string, error) { return t.uri(true) }

func (t SQLiteTarget) uri(readOnly bool) (string, error) {
	if t.state == nil {
		return "", ErrClosed
	}
	s := t.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(); err != nil {
		return "", err
	}
	path := filepath.ToSlash(s.native.databasePath())
	if !strings.HasPrefix(path, "/") {
		path = "/" + path // Windows DOS path in an RFC 8089 file URI.
	}
	u := url.URL{Scheme: "file", Path: path}
	q := url.Values{"mode": {"rw"}}
	if readOnly {
		q.Set("mode", "ro")
		q.Set("_pragma", "query_only(1)")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (s *sqliteTargetState) finish() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		_ = s.check()
		s.closed = true
	}
	return s.err
}

// WithSQLiteStaging builds a temporary database through a strictly scoped path,
// then consumes its entire sealed main file. It never publishes a pathname.
//
// build owns correct SQLite finalization, all connection/statement closure,
// journal-mode consolidation, and read-only integrity/foreign-key validation.
// This file primitive does not assert that arbitrary bytes form a valid database.
// consume MUST withhold external publication until this whole call succeeds:
// final native rechecks, close, cleanup, or cancellation can still fail after it
// has consumed every byte. On any error the receipt is zero. A failed cleanup
// can leave a private orphan but never removes an unrecognized/replaced entry.
func WithSQLiteStaging(ctx context.Context, parent string, limits SQLiteLimits,
	build func(context.Context, *SQLiteTarget) error,
	consume func(context.Context, io.Reader) error,
) (receipt Receipt, finalErr error) {
	bounded, cancel, err := operation(ctx, Limits{MaxBytes: limits.MaxDatabaseBytes, Timeout: limits.Timeout})
	if err != nil {
		return Receipt{}, err
	}
	defer cancel()
	if limits.MaxWorkspaceBytes < limits.MaxDatabaseBytes || limits.MaxWorkspaceBytes > MaxSQLiteWorkspaceBytes {
		return Receipt{}, ErrLimit
	}
	if build == nil || consume == nil {
		return Receipt{}, ErrCallback
	}
	if _, _, err := splitPath(parent); err != nil {
		return Receipt{}, err
	}
	native, err := newSQLiteStaging(parent)
	if err != nil {
		return Receipt{}, err
	}
	s := &sqliteTargetState{ctx: bounded, native: native, limits: limits}
	defer func() {
		_ = s.finish()
		if err := native.cleanup(); finalErr == nil && err != nil {
			finalErr = err
		}
		if bounded.Err() != nil {
			finalErr = ErrCanceled
		}
		if finalErr != nil {
			receipt = Receipt{}
		}
	}()
	if bounded.Err() != nil {
		return Receipt{}, ErrCanceled
	}
	callbackErr := callSQLiteBuild(bounded, build, &SQLiteTarget{state: s})
	if err := s.finish(); err != nil {
		return Receipt{}, err
	}
	if callbackErr != nil {
		return Receipt{}, ErrCallback
	}
	if err := native.inspect(limits.MaxDatabaseBytes, limits.MaxWorkspaceBytes, true); err != nil {
		return Receipt{}, err
	}
	f, err := native.seal()
	if err != nil {
		return Receipt{}, err
	}
	return consumeSQLiteStaging(bounded, native, f, limits, consume)
}

func callSQLiteBuild(ctx context.Context, build func(context.Context, *SQLiteTarget) error, target *SQLiteTarget) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrCallback
		}
	}()
	return build(ctx, target)
}

func callSQLiteConsume(ctx context.Context, consume func(context.Context, io.Reader) error, r io.Reader) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrCallback
		}
	}()
	return consume(ctx, r)
}

func consumeSQLiteStaging(ctx context.Context, native sqliteStagingNative, f *os.File, limits SQLiteLimits,
	consume func(context.Context, io.Reader) error,
) (Receipt, error) {
	if ctx.Err() != nil {
		return Receipt{}, ErrCanceled
	}
	if err := native.inspect(limits.MaxDatabaseBytes, limits.MaxWorkspaceBytes, true); err != nil {
		return Receipt{}, err
	}
	before, err := f.Stat()
	if err != nil {
		return Receipt{}, ErrUnavailable
	}
	if before.Size() < 1 || before.Size() > limits.MaxDatabaseBytes {
		return Receipt{}, ErrLimit
	}
	s := &stream{ctx: ctx, file: f, sum: sha256.New(), limit: before.Size()}
	defer s.invalidate()
	callbackErr := callSQLiteConsume(ctx, consume, reader{s: s})
	receipt, err := s.finish(callbackErr)
	if err != nil {
		return Receipt{}, err
	}
	if receipt.Size != before.Size() {
		return Receipt{}, ErrIncomplete
	}
	var probe [1]byte
	if n, readErr := f.Read(probe[:]); n != 0 || !errors.Is(readErr, io.EOF) {
		return Receipt{}, ErrIncomplete
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return Receipt{}, ErrUnsafe
	}
	if err := native.inspect(limits.MaxDatabaseBytes, limits.MaxWorkspaceBytes, true); err != nil {
		return Receipt{}, err
	}
	if ctx.Err() != nil {
		return Receipt{}, ErrCanceled
	}
	return receipt, nil
}
