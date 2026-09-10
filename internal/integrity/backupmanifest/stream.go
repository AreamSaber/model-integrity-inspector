package backupmanifest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"
)

var (
	ErrCanceled = errors.New("MI_BACKUP_INVENTORY_CANCELED")
	ErrRead     = errors.New("MI_BACKUP_INVENTORY_READ_FAILED")
	ErrCallback = errors.New("MI_BACKUP_INVENTORY_CALLBACK_FAILED")
	ErrClosed   = errors.New("MI_BACKUP_INVENTORY_CLOSED")
)

const MaxStreamTimeout = 24 * time.Hour

// VerifyStream consumes an exact manifest inventory with bounded streaming I/O.
// read is trusted synchronous integration code: it must authenticate the whole
// archive (including its end marker and outer EOF) and return that result. An
// independent expected manifest identity/hash must have been checked with Decode.
// This function does not acquire a DB snapshot, establish provenance, extract
// files, or authorize restore. Its caller must withhold publication until BOTH
// archive authentication and this function (plus the outer file reader) succeed.
//
// read passes each authenticated entry's kind, opaque ID and finite plaintext
// reader to accept. Order is immaterial, but every planned entry, including the
// canonical manifest, must occur exactly once. Unknown entries are never read.
// Raw reader/callback errors and panics never escape. Swallowing an accept error
// cannot manufacture success. The borrowed function is invalid after read ends;
// neither callback nor input reader may retain work or run detached operations.
// Cancellation is cooperative, not preemption of arbitrary callbacks/kernel I/O.
func VerifyStream(ctx context.Context, m Manifest, timeout time.Duration, read func(context.Context, func(kind, id string, in io.Reader) error) error) (result error) {
	if ctx == nil || ctx.Err() != nil {
		return ErrCanceled
	}
	if timeout <= 0 || timeout > MaxStreamTimeout {
		return ErrLimit
	}
	if read == nil {
		return ErrCallback
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	entries, err := Entries(m)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ErrCanceled
	}
	s := &inventoryStream{ctx: ctx, expected: make(map[string]Entry, len(entries)), buffer: make([]byte, 64<<10)}
	for _, entry := range entries {
		s.expected[entry.File.EntryID] = entry
	}
	defer func() {
		if recover() != nil {
			result = ErrCallback
		}
		// All ordinary and panic paths invalidate the shared capability, even
		// if a caller copied the function value or swallowed its previous error.
		s.mu.Lock()
		s.closed = true
		clear(s.buffer)
		s.expected, s.buffer = nil, nil
		s.mu.Unlock()
	}()
	callbackErr := read(ctx, s.accept)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	switch {
	case s.err != nil:
		return s.err
	case ctx.Err() != nil:
		return ErrCanceled
	case callbackErr != nil:
		return ErrCallback
	case len(s.expected) != 0:
		return ErrMismatch
	default:
		return nil
	}
}

type inventoryStream struct {
	mu       sync.Mutex
	ctx      context.Context
	expected map[string]Entry
	buffer   []byte
	err      error
	closed   bool
}

func (s *inventoryStream) accept(kind, id string, in io.Reader) (result error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.err != nil {
		return s.err
	}
	defer func() {
		if recover() != nil {
			result = ErrRead
		}
		if result != nil {
			s.err = result
		}
	}()
	if s.ctx.Err() != nil {
		return ErrCanceled
	}
	want, exists := s.expected[id]
	if !exists || want.Kind != kind {
		return ErrMismatch
	}
	if in == nil {
		return ErrRead
	}
	sum := sha256.New()
	var size int64
	for {
		if s.ctx.Err() != nil {
			return ErrCanceled
		}
		// The extra byte detects growth and, at exact size, forces the reader
		// to process its real entry-end marker. Never synthesize EOF at limit.
		requested := min(int64(len(s.buffer)), want.File.Bytes-size+1)
		n, err := in.Read(s.buffer[:requested])
		if n < 0 || int64(n) > requested {
			return ErrRead
		}
		if s.ctx.Err() != nil {
			return ErrCanceled
		}
		if int64(n) > want.File.Bytes-size {
			return ErrMismatch
		}
		if n > 0 {
			_, _ = sum.Write(s.buffer[:n])
			size += int64(n)
		}
		if err == io.EOF { //nolint:errorlint // Reader must return the exact EOF sentinel; a joined I/O failure is not successful EOF.
			if size != want.File.Bytes || hex.EncodeToString(sum.Sum(nil)) != want.File.SHA256 {
				return ErrMismatch
			}
			delete(s.expected, id)
			return nil
		}
		if err != nil || n == 0 {
			return ErrRead
		}
	}
}
