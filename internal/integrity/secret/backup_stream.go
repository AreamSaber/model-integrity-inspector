package secret

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
)

type backupWriteState struct {
	mu        sync.Mutex
	closed    atomic.Bool
	stream    *backupIO
	cipher    *backupCipher
	limits    BackupLimits
	entries   int
	total     int64
	entryOpen bool
	seen      map[string]struct{}
	buffer    [backupChunkBytes]byte
}

type backupEntryWriter struct{ state *backupEntryWriteState }
type backupEntryWriteState struct {
	parent  *backupWriteState
	closed  atomic.Bool
	ordinal uint32
	size    int64
	used    int
}

func (backupEntryWriter) String() string               { return "[backup plaintext writer]" }
func (v backupEntryWriter) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (backupEntryWriter) MarshalJSON() ([]byte, error) { return nil, ErrSensitive }
func (v backupEntryWriter) LogValue() slog.Value       { return slog.StringValue(v.String()) }

func (s *backupWriteState) invalidate() {
	s.closed.Store(true)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cipher.destroy()
	clear(s.buffer[:])
	s.stream.writer = nil
}

// Seal streams authenticated entries to a trusted private staging destination.
// Callbacks and underlying I/O must cooperate with context: arbitrary blocking
// consumer code cannot be forcibly preempted. No destination is published here.
func (s *BackupSealer) Seal(ctx context.Context, scope BackupScope, limits BackupLimits, dst io.Writer, produce func(context.Context, *BackupArchiveWriter) error) (receipt BackupReceipt, result error) {
	defer func() {
		if recover() != nil {
			receipt = BackupReceipt{}
			result = ErrBackupConsumer
		}
	}()
	ctx, cancel, err := backupContext(ctx, scope, limits)
	if err != nil {
		return receipt, err
	}
	defer cancel()
	if s == nil || !versionPattern.MatchString(s.version) || dst == nil || produce == nil {
		return receipt, ErrBackupUnavailable
	}
	header, crypto, err := s.backupHeader(scope)
	if err != nil {
		return receipt, err
	}
	state := &backupWriteState{stream: &backupIO{ctx: ctx, writer: dst, sum: sha256.New(), limit: backupWireLimit(limits)}, cipher: crypto, limits: limits, seen: make(map[string]struct{})}
	defer state.invalidate()
	if err := state.stream.write(header); err != nil {
		return receipt, err
	}
	callbackErr := produce(ctx, &BackupArchiveWriter{state: state})
	state.closed.Store(true)
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := state.stream.check(); err != nil {
		return receipt, err
	}
	if callbackErr != nil || state.entryOpen {
		return receipt, ErrBackupConsumer
	}
	var final [12]byte
	// #nosec G115 -- entries advances only after MaxEntries <= 65536 validation.
	binary.BigEndian.PutUint32(final[:4], uint32(state.entries))
	// #nosec G115 -- total starts at zero and advances only within MaxBytes <= 1 TiB.
	binary.BigEndian.PutUint64(final[4:], uint64(state.total))
	if err := crypto.writeFrame(state.stream, backupFinal, 0, final[:], backupMaxFrames(limits)); err != nil {
		return receipt, err
	}
	if err := state.stream.check(); err != nil {
		return receipt, err
	}
	return BackupReceipt{Version: BackupFormatVersion, KeyVersion: s.version, ArchiveSHA256: hex.EncodeToString(state.stream.sum.Sum(nil)), Entries: state.entries, PlaintextBytes: state.total, ArchiveBytes: state.stream.size}, nil
}

// WriteEntry requires a synchronous producer and globally unique canonical ID.
// Empty entries count toward MaxEntries. Reentrant/concurrent entries fail the
// archive; copied handles share both the sticky failure and closed lifetime.
func (w *BackupArchiveWriter) WriteEntry(entry BackupEntry, produce func(context.Context, io.Writer) error) (result error) {
	defer func() {
		if recover() != nil {
			result = ErrBackupConsumer
			if w != nil && w.state != nil {
				s := w.state
				s.mu.Lock()
				result = s.stream.fail(ErrBackupConsumer)
				s.mu.Unlock()
			}
		}
	}()
	if w == nil || w.state == nil {
		return ErrBackupClosed
	}
	s := w.state
	body, err := s.beginEntry(entry, produce != nil)
	if err != nil {
		return err
	}
	defer func() {
		body.closed.Store(true)
		s.mu.Lock()
		clear(s.buffer[:])
		s.entryOpen = false
		s.mu.Unlock()
	}()
	callbackErr := produce(s.stream.ctx, backupEntryWriter{state: body})
	body.closed.Store(true)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.stream.check(); err != nil {
		return err
	}
	if s.closed.Load() {
		return s.stream.fail(ErrBackupClosed)
	}
	if callbackErr != nil {
		return s.stream.fail(ErrBackupConsumer)
	}
	if body.used > 0 {
		if err := body.flush(); err != nil {
			return err
		}
	}
	var end [8]byte
	// #nosec G115 -- size is a nonnegative subset of the checked archive total.
	binary.BigEndian.PutUint64(end[:], uint64(body.size))
	return s.cipher.writeFrame(s.stream, backupEnd, body.ordinal, end[:], backupMaxFrames(s.limits))
}

func (s *backupWriteState) beginEntry(entry BackupEntry, hasProducer bool) (*backupEntryWriteState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return nil, ErrBackupClosed
	}
	if err := s.stream.check(); err != nil {
		return nil, err
	}
	if s.entryOpen || !hasProducer {
		return nil, s.stream.fail(ErrBackupConsumer)
	}
	code, err := backupEntryCode(entry)
	if err != nil {
		return nil, s.stream.fail(err)
	}
	if _, exists := s.seen[entry.ID]; exists {
		return nil, s.stream.fail(ErrBackupInvalid)
	}
	if s.entries >= s.limits.MaxEntries {
		return nil, s.stream.fail(ErrBackupLimit)
	}
	// #nosec G115 -- entries is nonnegative and strictly below MaxEntries <= 65536.
	ordinal := uint32(s.entries + 1)
	var encoded [68]byte
	defer clear(encoded[:])
	encoded[0] = code
	// #nosec G115 -- backupEntryCode checked the canonical ID length is 1..64.
	encoded[1] = byte(len(entry.ID))
	copy(encoded[4:], entry.ID)
	if err := s.cipher.writeFrame(s.stream, backupBegin, ordinal, encoded[:], backupMaxFrames(s.limits)); err != nil {
		return nil, err
	}
	s.entries++
	s.seen[entry.ID] = struct{}{}
	s.entryOpen = true
	return &backupEntryWriteState{parent: s, ordinal: ordinal}, nil
}

func (w backupEntryWriter) Write(data []byte) (int, error) {
	if w.state == nil || w.state.parent == nil {
		return 0, ErrBackupClosed
	}
	e := w.state
	s := e.parent
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return 0, ErrBackupClosed
	}
	if e.closed.Load() {
		return 0, s.stream.fail(ErrBackupClosed)
	}
	if err := s.stream.check(); err != nil {
		return 0, err
	}
	if int64(len(data)) > s.limits.MaxBytes-s.total {
		return 0, s.stream.fail(ErrBackupLimit)
	}
	written := 0
	for len(data) > 0 {
		if e.closed.Load() || s.closed.Load() {
			return written, s.stream.fail(ErrBackupClosed)
		}
		if err := s.stream.check(); err != nil {
			return written, err
		}
		n := copy(s.buffer[e.used:], data)
		e.used += n
		e.size += int64(n)
		s.total += int64(n)
		written += n
		data = data[n:]
		if e.used == len(s.buffer) {
			if err := e.flush(); err != nil {
				return written, err
			}
		}
	}
	if e.closed.Load() || s.closed.Load() {
		return written, s.stream.fail(ErrBackupClosed)
	}
	if err := s.stream.check(); err != nil {
		return written, err
	}
	return written, nil
}

func (e *backupEntryWriteState) flush() error {
	s := e.parent
	if err := s.cipher.writeFrame(s.stream, backupData, e.ordinal, s.buffer[:e.used], backupMaxFrames(s.limits)); err != nil {
		return err
	}
	clear(s.buffer[:])
	e.used = 0
	return nil
}

type backupReadState struct {
	mu      sync.Mutex
	closed  atomic.Bool
	stream  *backupIO
	cipher  *backupCipher
	limits  BackupLimits
	entries int
	total   int64
	seen    map[string]struct{}
}
type backupEntryReader struct{ state *backupEntryReadState }
type backupEntryReadState struct {
	parent            *backupReadState
	closed            atomic.Bool
	ordinal           uint32
	size              int64
	offset, remaining int
	short, done       bool
}

func (backupEntryReader) String() string               { return "[backup plaintext reader]" }
func (v backupEntryReader) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (backupEntryReader) MarshalJSON() ([]byte, error) { return nil, ErrSensitive }
func (v backupEntryReader) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (s *backupReadState) invalidate() {
	s.closed.Store(true)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cipher.destroy()
	s.stream.reader = nil
}

// Open authenticates each chunk before a trusted consumer can read it, but the
// archive is NOT complete until final authentication, counts and actual EOF.
// Consumers must stage privately and withhold publication/DB execution until
// this call AND the outer privatefile.Read succeed. This is not a restore API.
func (o *BackupOpener) Open(ctx context.Context, scope BackupScope, limits BackupLimits, src io.Reader, consume func(context.Context, BackupEntry, io.Reader) error) (receipt BackupReceipt, result error) {
	defer func() {
		if recover() != nil {
			receipt = BackupReceipt{}
			result = ErrBackupConsumer
		}
	}()
	ctx, cancel, err := backupContext(ctx, scope, limits)
	if err != nil {
		return receipt, err
	}
	defer cancel()
	if o == nil || len(o.keys) == 0 || src == nil || consume == nil {
		return receipt, ErrBackupUnavailable
	}
	stream := &backupIO{ctx: ctx, reader: src, sum: sha256.New(), limit: backupWireLimit(limits)}
	var header [backupHeaderBytes]byte
	if err := stream.readFull(header[:]); err != nil {
		return receipt, err
	}
	crypto, version, err := o.openBackupHeader(scope, header[:])
	if err != nil {
		return receipt, err
	}
	s := &backupReadState{stream: stream, cipher: crypto, limits: limits, seen: make(map[string]struct{})}
	defer s.invalidate()
	for {
		entry, ordinal, done, err := s.nextEntry()
		if err != nil {
			return receipt, err
		}
		if done {
			return BackupReceipt{Version: BackupFormatVersion, KeyVersion: version, ArchiveSHA256: hex.EncodeToString(stream.sum.Sum(nil)), Entries: s.entries, PlaintextBytes: s.total, ArchiveBytes: stream.size}, nil
		}
		body := &backupEntryReadState{parent: s, ordinal: ordinal}
		if err := consumeBackupEntry(s, body, entry, consume); err != nil {
			return receipt, err
		}
	}
}

func (s *backupReadState) nextEntry() (BackupEntry, uint32, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kind, ordinal, data, err := s.cipher.readFrame(s.stream, backupMaxFrames(s.limits))
	if err != nil {
		return BackupEntry{}, 0, false, err
	}
	if kind == backupFinal {
		// #nosec G115 -- entries <= 65536 and total <= 1 TiB; both are nonnegative owned counters.
		if binary.BigEndian.Uint32(data[:4]) != uint32(s.entries) || binary.BigEndian.Uint64(data[4:]) != uint64(s.total) {
			return BackupEntry{}, 0, false, s.stream.fail(ErrBackupInvalid)
		}
		clear(s.cipher.buffer[:])
		if err := s.stream.requireEOF(); err != nil {
			return BackupEntry{}, 0, false, err
		}
		if err := s.stream.check(); err != nil {
			return BackupEntry{}, 0, false, err
		}
		s.closed.Store(true)
		return BackupEntry{}, 0, true, nil
	}
	// #nosec G115 -- entries <= 65536, so the expected next ordinal fits uint32.
	if kind != backupBegin || ordinal != uint32(s.entries+1) {
		return BackupEntry{}, 0, false, s.stream.fail(ErrBackupInvalid)
	}
	entry, err := decodeBackupEntry(data)
	clear(s.cipher.buffer[:])
	if err != nil {
		return BackupEntry{}, 0, false, s.stream.fail(err)
	}
	if s.entries >= s.limits.MaxEntries {
		return BackupEntry{}, 0, false, s.stream.fail(ErrBackupLimit)
	}
	if _, exists := s.seen[entry.ID]; exists {
		return BackupEntry{}, 0, false, s.stream.fail(ErrBackupInvalid)
	}
	s.entries++
	s.seen[entry.ID] = struct{}{}
	return entry, ordinal, false, nil
}

func decodeBackupEntry(data []byte) (BackupEntry, error) {
	if len(data) != 68 || data[0] < 1 || data[0] > 5 || data[1] < 1 || data[1] > 64 || data[2] != 0 || data[3] != 0 {
		return BackupEntry{}, ErrBackupInvalid
	}
	n := int(data[1])
	if !bytes.Equal(data[4+n:], make([]byte, 64-n)) {
		return BackupEntry{}, ErrBackupInvalid
	}
	kinds := [5]string{"database", "manifest", "report", "rule", "config"}
	entry := BackupEntry{Kind: kinds[data[0]-1], ID: string(data[4 : 4+n])}
	_, err := backupEntryCode(entry)
	return entry, err
}

func consumeBackupEntry(s *backupReadState, body *backupEntryReadState, entry BackupEntry, consume func(context.Context, BackupEntry, io.Reader) error) error {
	defer body.closed.Store(true)
	callbackErr := consume(s.stream.ctx, entry, backupEntryReader{state: body})
	body.closed.Store(true)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.stream.check(); err != nil {
		return err
	}
	if callbackErr != nil {
		return s.stream.fail(ErrBackupConsumer)
	}
	if body.remaining != 0 {
		return s.stream.fail(ErrBackupIncomplete)
	}
	if !body.done {
		err := body.next()
		if err == nil {
			return s.stream.fail(ErrBackupIncomplete)
		}
		if !errors.Is(err, io.EOF) {
			return err
		}
	}
	return s.stream.check()
}

func (r backupEntryReader) Read(out []byte) (int, error) {
	if r.state == nil || r.state.parent == nil {
		return 0, ErrBackupClosed
	}
	e := r.state
	s := e.parent
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return 0, ErrBackupClosed
	}
	if e.closed.Load() {
		return 0, s.stream.fail(ErrBackupClosed)
	}
	if err := s.stream.check(); err != nil {
		return 0, err
	}
	if len(out) == 0 {
		return 0, nil
	}
	if e.remaining == 0 {
		if e.done {
			return 0, io.EOF
		}
		if err := e.next(); err != nil {
			return 0, err
		}
	}
	if e.closed.Load() || s.closed.Load() {
		return 0, s.stream.fail(ErrBackupClosed)
	}
	if err := s.stream.check(); err != nil {
		return 0, err
	}
	n := copy(out, s.cipher.buffer[e.offset:e.offset+e.remaining])
	clear(s.cipher.buffer[e.offset : e.offset+n])
	e.offset += n
	e.remaining -= n
	return n, nil
}

func (e *backupEntryReadState) next() error {
	s := e.parent
	kind, ordinal, data, err := s.cipher.readFrame(s.stream, backupMaxFrames(s.limits))
	if err != nil {
		return err
	}
	if ordinal != e.ordinal {
		return s.stream.fail(ErrBackupInvalid)
	}
	switch kind {
	case backupData:
		if e.short {
			return s.stream.fail(ErrBackupInvalid)
		}
		if int64(len(data)) > s.limits.MaxBytes-s.total {
			return s.stream.fail(ErrBackupLimit)
		}
		e.short = len(data) < backupChunkBytes
		e.size += int64(len(data))
		s.total += int64(len(data))
		e.offset = 0
		e.remaining = len(data)
		return nil
	case backupEnd:
		// #nosec G115 -- size starts at zero and advances only under the 1 TiB archive limit.
		if binary.BigEndian.Uint64(data) != uint64(e.size) {
			return s.stream.fail(ErrBackupInvalid)
		}
		e.done = true
		clear(s.cipher.buffer[:])
		return io.EOF
	default:
		return s.stream.fail(ErrBackupInvalid)
	}
}
