package secret

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func backupFixture(t testing.TB) (*BackupSealer, *BackupOpener, BackupScope, BackupLimits) {
	t.Helper()
	s, o, err := testRing(t).NewBackupCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	return s, o, BackupScope{BackupID: 123, ManifestHash: strings.Repeat("a", 64)}, BackupLimits{MaxBytes: 64 << 20, MaxEntries: 4096, Timeout: time.Minute}
}
func backupBytes(t testing.TB, s *BackupSealer, scope BackupScope, limits BackupLimits, data ...[]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	_, err := s.Seal(context.Background(), scope, limits, &out, func(ctx context.Context, w *BackupArchiveWriter) error {
		for i, p := range data {
			if err := w.WriteEntry(BackupEntry{Kind: "database", ID: fmt.Sprintf("entry-%d", i)}, func(_ context.Context, w io.Writer) error { _, err := w.Write(p); return err }); err != nil {
				return err
			}
		}
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func consumeBackup(_ context.Context, _ BackupEntry, r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}

func TestBackupArchiveRoundTripBoundsAndIndependentRandomness(t *testing.T) {
	s, o, scope, limits := backupFixture(t)
	var data [][]byte
	for _, size := range []int{0, 1, backupChunkBytes - 1, backupChunkBytes, backupChunkBytes + 1} {
		data = append(data, bytes.Repeat([]byte{'x'}, size))
	}
	encoded := backupBytes(t, s, scope, limits, data...)
	again := backupBytes(t, s, scope, limits, data...)
	if bytes.Equal(encoded, again) || bytes.Equal(encoded[52:96], again[52:96]) || bytes.Equal(encoded[160:208], again[160:208]) {
		t.Fatal("archive randomness reused")
	}
	n := 0
	receipt, err := o.Open(t.Context(), scope, limits, bytes.NewReader(encoded), func(_ context.Context, entry BackupEntry, r io.Reader) error {
		got, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		if n >= len(data) || entry.ID != fmt.Sprintf("entry-%d", n) || !bytes.Equal(got, data[n]) {
			t.Fatal("authenticated entry changed")
		}
		n++
		return nil
	})
	sum := sha256.Sum256(encoded)
	if err != nil || n != len(data) || receipt.Entries != len(data) || receipt.ArchiveBytes != int64(len(encoded)) || receipt.PlaintextBytes != 3*backupChunkBytes+1 || receipt.ArchiveSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("archive completion mismatch", receipt, err)
	}
	empty := backupBytes(t, s, scope, limits)
	if receipt, err := o.Open(t.Context(), scope, limits, bytes.NewReader(empty), consumeBackup); err != nil || receipt.Entries != 0 || receipt.PlaintextBytes != 0 {
		t.Fatal("empty archive framing", err)
	}
}

func TestBackupPurposeIsolationExistingKeysAndHistoricalVersions(t *testing.T) {
	ring := testRing(t)
	s, o, scope, limits := backupFixture(t)
	set := ring.keys["one"]
	purposes := map[string][]byte{"secret-wrap": set.wrap, "secret-fingerprint": set.fingerprint, "audit-integrity": set.audit, "pagination-cursor": set.cursor, "probe-reproduction": set.probe, "response-evidence": set.evidence, "baseline-approval": set.baseline, "evidence-display": set.display, "derived-s1-authentication": set.derivedSource, "request-reproduction": set.requestReproduction}
	for purpose, actual := range purposes {
		expected, err := hkdf.Key(sha256.New, bytes.Repeat([]byte{0x17}, 32), nil, "mii/v1/"+purpose+"/one", 32)
		if err != nil || !bytes.Equal(actual, expected) || bytes.Equal(actual, set.backupWrap) {
			t.Fatal("existing purpose changed or backup key reused")
		}
		clear(expected)
		wrongPurpose := &BackupSealer{version: "one"}
		copy(wrongPurpose.key[:], actual)
		wrongArchive := backupBytes(t, wrongPurpose, scope, limits, []byte("synthetic"))
		called := false
		if _, err := o.Open(t.Context(), scope, limits, bytes.NewReader(wrongArchive), func(context.Context, BackupEntry, io.Reader) error { called = true; return nil }); err == nil || called {
			t.Fatal("backup accepted another purpose's wrapping key")
		}
	}
	encoded := backupBytes(t, s, scope, limits, []byte(canary))
	if bytes.Contains(encoded, []byte(canary)) {
		t.Fatal("plaintext archive leak")
	}
	newRing, err := NewKeyRing("two", map[string][]byte{"one": bytes.Repeat([]byte{0x17}, 32), "two": bytes.Repeat([]byte{0x91}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	_, historical, err := newRing.NewBackupCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := historical.Open(t.Context(), scope, limits, bytes.NewReader(encoded), consumeBackup); err != nil {
		t.Fatal("historical backup key rejected", err)
	}
	for _, masters := range []map[string][]byte{{"one": bytes.Repeat([]byte{1}, 32)}, {"one": bytes.Repeat([]byte{2}, 32)}} {
		wrong, err := NewKeyRing("one", masters)
		if err != nil {
			t.Fatal(err)
		}
		_, opened, err := wrong.NewBackupCapabilities()
		if err != nil {
			t.Fatal(err)
		}
		called := false
		if _, err := opened.Open(t.Context(), scope, limits, bytes.NewReader(encoded), func(context.Context, BackupEntry, io.Reader) error { called = true; return nil }); err == nil || called {
			t.Fatal("wrong key reached consumer")
		}
	}
	delete(o.keys, "one")
	if _, err := o.Open(t.Context(), scope, limits, bytes.NewReader(encoded), consumeBackup); err == nil {
		t.Fatal("missing key accepted")
	}
	sealer, opener, err := ring.NewBackupCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	clear(ring.keys["one"].backupWrap)
	encoded = backupBytes(t, sealer, scope, limits, []byte(canary))
	if _, err := opener.Open(t.Context(), scope, limits, bytes.NewReader(encoded), consumeBackup); err != nil {
		t.Fatal("capability retained KeyRing alias")
	}
}

func TestBackupHeadersScopeTamperAndTruncation(t *testing.T) {
	s, o, scope, limits := backupFixture(t)
	original := backupBytes(t, s, scope, limits, []byte("small"))
	for i := 0; i < backupHeaderBytes; i++ {
		bad := bytes.Clone(original)
		bad[i] ^= 0xff
		called := false
		if r, err := o.Open(t.Context(), scope, limits, bytes.NewReader(bad), func(context.Context, BackupEntry, io.Reader) error { called = true; return nil }); err == nil || called || r != (BackupReceipt{}) {
			t.Fatalf("header byte %d accepted", i)
		}
	}
	for _, changed := range []BackupScope{{BackupID: scope.BackupID + 1, ManifestHash: scope.ManifestHash}, {BackupID: scope.BackupID, ManifestHash: strings.Repeat("b", 64)}} {
		called := false
		if _, err := o.Open(t.Context(), changed, limits, bytes.NewReader(original), func(context.Context, BackupEntry, io.Reader) error { called = true; return nil }); err == nil || called {
			t.Fatal("self-authorized archive scope")
		}
	}
	for end := 0; end < len(original); end++ {
		if r, err := o.Open(t.Context(), scope, limits, bytes.NewReader(original[:end]), consumeBackup); err == nil || r != (BackupReceipt{}) {
			t.Fatalf("truncation %d accepted", end)
		}
	}
	for _, trailing := range [][]byte{{0}, original} {
		bad := append(bytes.Clone(original), trailing...)
		if _, err := o.Open(t.Context(), scope, limits, bytes.NewReader(bad), consumeBackup); err == nil {
			t.Fatal("trailing content accepted")
		}
	}
	for i := backupHeaderBytes; i < len(original); i++ {
		bad := bytes.Clone(original)
		bad[i] ^= 1
		if _, err := o.Open(t.Context(), scope, limits, bytes.NewReader(bad), consumeBackup); err == nil {
			t.Fatalf("record byte %d accepted", i)
		}
	}
}

type backupWriterFunc func([]byte) (int, error)

func (f backupWriterFunc) Write(p []byte) (int, error) { return f(p) }

type backupReaderFunc func([]byte) (int, error)

func (f backupReaderFunc) Read(p []byte) (int, error) { return f(p) }

func TestBackupIOAndCallbackErrorsRemainStickyAndSanitized(t *testing.T) {
	s, o, scope, limits := backupFixture(t)
	data := []byte(canary)
	encoded := backupBytes(t, s, scope, limits, data)
	for _, w := range []io.Writer{backupWriterFunc(func(p []byte) (int, error) { return len(p) - 1, nil }), backupWriterFunc(func(p []byte) (int, error) { return len(p), errors.New(canary) }), backupWriterFunc(func([]byte) (int, error) { return 0, nil }), backupWriterFunc(func([]byte) (int, error) { panic(canary) })} {
		r, err := s.Seal(t.Context(), scope, limits, w, func(_ context.Context, a *BackupArchiveWriter) error {
			return a.WriteEntry(BackupEntry{Kind: "database", ID: "entry"}, func(_ context.Context, w io.Writer) error { _, _ = w.Write(data); return nil })
		})
		if err == nil || r != (BackupReceipt{}) || strings.Contains(err.Error(), canary) {
			t.Fatal("writer fault escaped")
		}
	}
	for _, r := range []io.Reader{backupReaderFunc(func([]byte) (int, error) { return 0, nil }), backupReaderFunc(func(p []byte) (int, error) { p[0] = 1; return 1, errors.New(canary) }), backupReaderFunc(func([]byte) (int, error) { panic(canary) })} {
		if receipt, err := o.Open(t.Context(), scope, limits, r, consumeBackup); err == nil || receipt != (BackupReceipt{}) || strings.Contains(err.Error(), canary) {
			t.Fatal("reader fault escaped")
		}
	}
	for _, mode := range []string{"short_read", "error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			receipt, err := o.Open(t.Context(), scope, limits, bytes.NewReader(encoded), func(_ context.Context, _ BackupEntry, r io.Reader) error {
				if mode == "panic" {
					panic(canary)
				}
				if mode == "error" {
					return errors.New(canary)
				}
				var small [1]byte
				_, _ = r.Read(small[:])
				return nil
			})
			if err == nil || receipt != (BackupReceipt{}) || strings.Contains(err.Error(), canary) {
				t.Fatal("incomplete consumer succeeded")
			}
		})
	}
	limits.MaxBytes = 1
	if receipt, err := s.Seal(t.Context(), scope, limits, io.Discard, func(_ context.Context, a *BackupArchiveWriter) error {
		_ = a.WriteEntry(BackupEntry{Kind: "database", ID: "entry"}, func(_ context.Context, w io.Writer) error { _, _ = w.Write(data); return nil })
		return nil
	}); !errors.Is(err, ErrBackupLimit) || receipt != (BackupReceipt{}) {
		t.Fatal("swallowed write limit", err)
	}
	if receipt, err := o.Open(t.Context(), scope, limits, bytes.NewReader(encoded), func(_ context.Context, _ BackupEntry, r io.Reader) error { _, _ = io.Copy(io.Discard, r); return nil }); !errors.Is(err, ErrBackupLimit) || receipt != (BackupReceipt{}) {
		t.Fatal("swallowed read limit", err)
	}
}

func TestBackupCancellationIncludingFinalEOFAndInvalidLimits(t *testing.T) {
	s, o, scope, limits := backupFixture(t)
	encoded := backupBytes(t, s, scope, limits, []byte("x"))
	ctx, cancel := context.WithCancel(t.Context())
	if r, err := s.Seal(ctx, scope, limits, io.Discard, func(_ context.Context, a *BackupArchiveWriter) error {
		cancel()
		_ = a.WriteEntry(BackupEntry{Kind: "database", ID: "entry"}, func(context.Context, io.Writer) error { return nil })
		return nil
	}); !errors.Is(err, ErrBackupCanceled) || r != (BackupReceipt{}) {
		t.Fatal("swallowed cancellation", err)
	}
	ctx, cancel = context.WithCancel(t.Context())
	source := bytes.NewReader(encoded)
	reader := backupReaderFunc(func(p []byte) (int, error) {
		n, err := source.Read(p)
		if errors.Is(err, io.EOF) {
			cancel()
		}
		return n, err
	})
	if r, err := o.Open(ctx, scope, limits, reader, consumeBackup); !errors.Is(err, ErrBackupCanceled) || r != (BackupReceipt{}) {
		t.Fatal("EOF cancellation accepted", err)
	}
	for _, bad := range []BackupLimits{{}, {MaxBytes: BackupMaxBytes + 1, MaxEntries: 1, Timeout: time.Second}, {MaxBytes: 1, MaxEntries: BackupMaxEntries + 1, Timeout: time.Second}, {MaxBytes: 1, MaxEntries: 1, Timeout: BackupMaxTimeout + 1}} {
		if _, err := s.Seal(t.Context(), scope, bad, io.Discard, func(context.Context, *BackupArchiveWriter) error { return nil }); !errors.Is(err, ErrBackupLimit) {
			t.Fatal("invalid limits", err)
		}
	}
	limits.Timeout = time.Nanosecond
	if _, err := s.Seal(t.Context(), scope, limits, io.Discard, func(context.Context, *BackupArchiveWriter) error { time.Sleep(time.Millisecond); return nil }); !errors.Is(err, ErrBackupCanceled) {
		t.Fatal("deadline ignored", err)
	}
}

func TestBackupCanonicalIDsCopiesLifetimeAndReentrancy(t *testing.T) {
	s, o, scope, limits := backupFixture(t)
	for _, id := range []string{"", "../db", "a/b", "a\\b", "C:db", "UPPER", " a", "a.", "_a", "a\x00b", strings.Repeat("a", 65)} {
		if _, err := s.Seal(t.Context(), scope, limits, io.Discard, func(_ context.Context, a *BackupArchiveWriter) error {
			_ = a.WriteEntry(BackupEntry{Kind: "database", ID: id}, func(context.Context, io.Writer) error { return nil })
			return nil
		}); !errors.Is(err, ErrBackupInvalid) {
			t.Fatal("invalid entry identifier accepted")
		}
	}
	var outer *BackupArchiveWriter
	var borrowed io.Writer
	encoded := bytes.Buffer{}
	if _, err := s.Seal(t.Context(), scope, limits, &encoded, func(_ context.Context, a *BackupArchiveWriter) error {
		copy := *a
		outer = &copy
		return copy.WriteEntry(BackupEntry{Kind: "database", ID: "empty"}, func(_ context.Context, w io.Writer) error { borrowed = w; return nil })
	}); err != nil {
		t.Fatal(err)
	}
	if err := outer.WriteEntry(BackupEntry{Kind: "database", ID: "later"}, func(context.Context, io.Writer) error { return nil }); !errors.Is(err, ErrBackupClosed) {
		t.Fatal("copied archive writer survived")
	}
	if _, err := borrowed.Write([]byte("x")); !errors.Is(err, ErrBackupClosed) {
		t.Fatal("borrowed writer survived")
	}
	var input io.Reader
	if _, err := o.Open(t.Context(), scope, limits, bytes.NewReader(encoded.Bytes()), func(_ context.Context, _ BackupEntry, r io.Reader) error { input = r; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Read(make([]byte, 1)); !errors.Is(err, ErrBackupClosed) {
		t.Fatal("borrowed reader survived")
	}
	if _, err := s.Seal(t.Context(), scope, limits, io.Discard, func(_ context.Context, a *BackupArchiveWriter) error {
		_ = a.WriteEntry(BackupEntry{Kind: "database", ID: "outer"}, func(context.Context, io.Writer) error {
			_ = a.WriteEntry(BackupEntry{Kind: "database", ID: "inner"}, func(context.Context, io.Writer) error { return nil })
			return nil
		})
		return nil
	}); !errors.Is(err, ErrBackupConsumer) {
		t.Fatal("recursive entry was not sticky", err)
	}
	if _, err := s.Seal(t.Context(), scope, limits, io.Discard, func(_ context.Context, a *BackupArchiveWriter) error {
		for range 2 {
			_ = a.WriteEntry(BackupEntry{Kind: "database", ID: "same"}, func(context.Context, io.Writer) error { return nil })
		}
		return nil
	}); !errors.Is(err, ErrBackupInvalid) {
		t.Fatal("duplicate entry accepted", err)
	}
	for _, value := range []any{s, *s, o, *o, outer, *outer, borrowed, input, scope, BackupEntry{Kind: "database", ID: canary}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			got := fmt.Sprintf(format, value)
			if strings.Contains(got, canary) || strings.Contains(got, scope.ManifestHash) {
				t.Fatal("protected value formatting leak")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrSensitive) {
			t.Fatal("protected value serialized", err)
		}
		var logs bytes.Buffer
		slog.New(slog.NewJSONHandler(&logs, nil)).Info("safe", "value", value)
		if strings.Contains(logs.String(), canary) || strings.Contains(logs.String(), scope.ManifestHash) {
			t.Fatal("structured logging leak")
		}
	}
}

type backupPatternReader struct{ remaining int64 }

func (r *backupPatternReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := min(int64(len(p)), r.remaining)
	for i := range p[:n] {
		p[i] = byte(i % 251)
	}
	r.remaining -= n
	return int(n), nil
}

func TestBackupSyntheticLargeArchiveUsesBoundedMemory(t *testing.T) {
	s, o, scope, limits := backupFixture(t)
	const size = int64(32<<20) + 17
	file, err := os.CreateTemp(t.TempDir(), "encrypted-archive-")
	if err != nil {
		t.Fatal("create synthetic crypto test sink")
	}
	defer func() { _ = file.Close() }()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	originalHash, openedHash := sha256.New(), sha256.New()
	written, err := s.Seal(t.Context(), scope, limits, file, func(_ context.Context, a *BackupArchiveWriter) error {
		return a.WriteEntry(BackupEntry{Kind: "database", ID: "synthetic-db"}, func(_ context.Context, w io.Writer) error {
			_, err := io.Copy(io.MultiWriter(w, originalHash), &backupPatternReader{remaining: size})
			return err
		})
	})
	if err != nil || written.PlaintextBytes != size {
		t.Fatal("stream seal failed", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal("rewind encrypted test sink")
	}
	opened, err := o.Open(t.Context(), scope, limits, file, func(_ context.Context, _ BackupEntry, r io.Reader) error {
		_, err := io.Copy(openedHash, r)
		return err
	})
	runtime.ReadMemStats(&after)
	if err != nil || opened != written || !bytes.Equal(originalHash.Sum(nil), openedHash.Sum(nil)) || after.TotalAlloc-before.TotalAlloc > 8<<20 {
		t.Fatal("stream result or bounded allocation failed", err, after.TotalAlloc-before.TotalAlloc)
	}
}

// Independent record encoding below permits valid tags over malformed grammar,
// rather than mistaking only AEAD-bitflip tests for parser security coverage.
type backupTestFrame struct {
	kind  byte
	entry uint32
	data  []byte
}

func backupTestBegin(id string) []byte {
	if len(id) > 64 {
		panic("invalid test entry identifier")
	}
	data := make([]byte, 68)
	data[0] = 1
	// #nosec G115 -- Test helper rejects IDs longer than 64 above.
	data[1] = byte(len(id))
	copy(data[4:], id)
	return data
}
func backupTestLength(n uint64) []byte {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, n)
	return data
}
func backupTestFinal(entries uint32, size uint64) []byte {
	data := make([]byte, 12)
	binary.BigEndian.PutUint32(data[:4], entries)
	binary.BigEndian.PutUint64(data[4:], size)
	return data
}
func backupTestArchive(t testing.TB, s *BackupSealer, scope BackupScope, frames []backupTestFrame) []byte {
	t.Helper()
	header, c, err := s.backupHeader(scope)
	if err != nil {
		t.Fatal(err)
	}
	defer c.destroy()
	out := bytes.NewBuffer(bytes.Clone(header))
	for seq, f := range frames {
		var ordinal [8]byte
		binary.BigEndian.PutUint64(ordinal[:], uint64(seq/backupEpochRecords))
		hash := sha256.Sum256(header)
		info := append([]byte("mii/backup-data-epoch/v1\x00"), hash[:]...)
		info = append(info, ordinal[:]...)
		key, err := hkdf.Key(sha256.New, c.dek[:], nil, string(info), 32)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := gcm(key)
		clear(key)
		if err != nil {
			t.Fatal(err)
		}
		var frame [20]byte
		frame[0] = f.kind
		// #nosec G115 -- Fixed test frames are at most 65537 bytes, including the oversized negative.
		binary.BigEndian.PutUint32(frame[4:8], uint32(len(f.data)))
		binary.BigEndian.PutUint64(frame[8:16], uint64(seq))
		binary.BigEndian.PutUint32(frame[16:], f.entry)
		var nonce [12]byte
		copy(nonce[:4], []byte{'B', 'K', 'P', 1})
		binary.BigEndian.PutUint64(nonce[4:], uint64(seq))
		aad := append([]byte("mii/backup-record/v1\x00"), hash[:]...)
		aad = append(aad, frame[:]...)
		out.Write(frame[:])
		out.Write(aead.Seal(nil, nonce[:], f.data, aad))
	}
	return out.Bytes()
}

func TestBackupAuthenticatedMalformedGrammarRejected(t *testing.T) {
	s, o, scope, limits := backupFixture(t)
	begin := backupTestFrame{backupBegin, 1, backupTestBegin("entry")}
	data := backupTestFrame{backupData, 1, []byte("x")}
	end := backupTestFrame{backupEnd, 1, backupTestLength(1)}
	final := backupTestFrame{backupFinal, 0, backupTestFinal(1, 1)}
	for name, frames := range map[string][]backupTestFrame{
		"unknown": {{9, 1, []byte("x")}}, "data_without_begin": {data}, "end_without_begin": {end}, "nested": {begin, begin}, "empty_data": {begin, {backupData, 1, nil}},
		"wrong_entry": {begin, {backupData, 2, []byte("x")}}, "bad_end_size": {begin, data, {backupEnd, 1, backupTestLength(2)}, final}, "bad_final_size": {begin, data, end, {backupFinal, 0, backupTestFinal(1, 2)}}, "bad_final_count": {begin, data, end, {backupFinal, 0, backupTestFinal(2, 1)}},
		"short_then_more": {begin, data, data, end, final}, "early_final": {begin, final}, "duplicate_id": {begin, data, end, {backupBegin, 2, backupTestBegin("entry")}}, "uppercase_alias": {{backupBegin, 1, backupTestBegin("ENTRY")}}, "oversized": {begin, {backupData, 1, make([]byte, backupChunkBytes+1)}},
		"max_uint64_end": {begin, data, {backupEnd, 1, backupTestLength(^uint64(0))}, final}, "max_uint64_final": {begin, data, end, {backupFinal, 0, backupTestFinal(1, ^uint64(0))}}, "max_uint32_count": {begin, data, end, {backupFinal, 0, backupTestFinal(^uint32(0), 1)}},
	} {
		t.Run(name, func(t *testing.T) {
			encoded := backupTestArchive(t, s, scope, frames)
			if r, err := o.Open(t.Context(), scope, limits, bytes.NewReader(encoded), consumeBackup); err == nil || r != (BackupReceipt{}) {
				t.Fatal("authenticated invalid grammar accepted")
			}
		})
	}
}

func TestBackupEpochBoundaryIncludesEmptyEntryControlRecords(t *testing.T) {
	s, o, scope, limits := backupFixture(t)
	frames := make([]backupTestFrame, 0, 4101)
	for i := uint32(1); i <= 2050; i++ {
		frames = append(frames, backupTestFrame{backupBegin, i, backupTestBegin(fmt.Sprintf("entry-%d", i))}, backupTestFrame{backupEnd, i, backupTestLength(0)})
	}
	frames = append(frames, backupTestFrame{backupFinal, 0, backupTestFinal(2050, 0)})
	encoded := backupTestArchive(t, s, scope, frames)
	if r, err := o.Open(t.Context(), scope, limits, bytes.NewReader(encoded), consumeBackup); err != nil || r.Entries != 2050 {
		t.Fatal("independent epoch encoding rejected", err)
	}
	var produced bytes.Buffer
	sealed, err := s.Seal(t.Context(), scope, limits, &produced, func(_ context.Context, a *BackupArchiveWriter) error {
		for i := 0; i < 2050; i++ {
			if err := a.WriteEntry(BackupEntry{Kind: "config", ID: fmt.Sprintf("entry-%d", i)}, func(context.Context, io.Writer) error { return nil }); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal("production seal epoch boundary", err)
	}
	if opened, err := o.Open(t.Context(), scope, limits, bytes.NewReader(produced.Bytes()), consumeBackup); err != nil || opened != sealed {
		t.Fatal("production epoch round trip", err)
	}
	// Repeat and reorder whole authenticated frames around the key transition;
	// nonce and ordinal cannot be reset or replayed at an entry boundary.
	positions := []int{backupHeaderBytes}
	for i := 0; i < len(frames); i++ {
		positions = append(positions, positions[i]+20+len(frames[i].data)+16)
	}
	for _, index := range []int{4095, 4096, 4097} {
		bad := append([]byte{}, encoded[:positions[index]]...)
		bad = append(bad, encoded[positions[index]:positions[index+1]]...)
		bad = append(bad, encoded[positions[index]:]...)
		if _, err := o.Open(t.Context(), scope, limits, bytes.NewReader(bad), consumeBackup); err == nil {
			t.Fatal("epoch-boundary record replay accepted")
		}
		reordered := append([]byte{}, encoded[:positions[index]]...)
		reordered = append(reordered, encoded[positions[index+1]:positions[index+2]]...)
		reordered = append(reordered, encoded[positions[index]:positions[index+1]]...)
		reordered = append(reordered, encoded[positions[index+2]:]...)
		if _, err := o.Open(t.Context(), scope, limits, bytes.NewReader(reordered), consumeBackup); err == nil {
			t.Fatal("epoch-boundary record reorder accepted")
		}
	}
}

func TestBackupPanicDuringBeginAndRecoveredProducerCannotSucceed(t *testing.T) {
	s, _, scope, limits := backupFixture(t)
	done := make(chan error, 1)
	go func() {
		calls := 0
		writer := backupWriterFunc(func(p []byte) (int, error) {
			calls++
			if calls == 2 {
				panic(canary)
			}
			return len(p), nil
		})
		_, err := s.Seal(t.Context(), scope, limits, writer, func(_ context.Context, a *BackupArchiveWriter) error {
			return a.WriteEntry(BackupEntry{Kind: "database", ID: "entry"}, func(context.Context, io.Writer) error { return nil })
		})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrBackupConsumer) {
			t.Fatal("begin panic not sanitized", err)
		}
	case <-time.After(time.Second):
		t.Fatal("begin panic deadlocked archive invalidation")
	}
	var saved io.Writer
	receipt, err := s.Seal(t.Context(), scope, limits, io.Discard, func(_ context.Context, a *BackupArchiveWriter) error {
		func() {
			defer func() { _ = recover() }()
			_ = a.WriteEntry(BackupEntry{Kind: "database", ID: "entry"}, func(_ context.Context, w io.Writer) error { saved = w; _, _ = w.Write([]byte(canary)); panic(canary) })
		}()
		return nil
	})
	if !errors.Is(err, ErrBackupConsumer) || receipt != (BackupReceipt{}) {
		t.Fatal("recovered entry panic produced success receipt", err)
	}
	if _, err := saved.Write([]byte("x")); !errors.Is(err, ErrBackupClosed) {
		t.Fatal("panic left live writer")
	}
}

func TestBackupLegitimateShortReadsAndEOFWithBytes(t *testing.T) {
	s, o, scope, limits := backupFixture(t)
	encoded := backupBytes(t, s, scope, limits, bytes.Repeat([]byte("x"), backupChunkBytes+9))
	for _, withEOF := range []bool{false, true} {
		source := bytes.NewReader(encoded)
		reader := backupReaderFunc(func(p []byte) (int, error) {
			n, err := source.Read(p[:min(len(p), 7)])
			if withEOF && source.Len() == 0 && n > 0 {
				return n, io.EOF
			}
			return n, err
		})
		if _, err := o.Open(t.Context(), scope, limits, reader, consumeBackup); err != nil {
			t.Fatal("legal short reader rejected", err)
		}
	}
	source := bytes.NewReader(append(bytes.Clone(encoded), 1))
	reader := backupReaderFunc(func(p []byte) (int, error) {
		n, err := source.Read(p)
		if source.Len() == 0 && n > 0 {
			return n, io.EOF
		}
		return n, err
	})
	if _, err := o.Open(t.Context(), scope, limits, reader, consumeBackup); !errors.Is(err, ErrBackupInvalid) {
		t.Fatal("trailing byte plus EOF accepted", err)
	}
}

func TestBackupEmptyEntriesExactLimitsAndCanonicalChunks(t *testing.T) {
	s, o, scope, limits := backupFixture(t)
	limits.MaxEntries = 2
	limits.MaxBytes = 1
	encoded := backupBytes(t, s, scope, limits, nil, []byte("x"))
	if r, err := o.Open(t.Context(), scope, limits, bytes.NewReader(encoded), consumeBackup); err != nil || r.Entries != 2 || r.PlaintextBytes != 1 {
		t.Fatal("exact entry/byte bounds", err)
	}
	limits.MaxEntries = 1
	if _, err := o.Open(t.Context(), scope, limits, bytes.NewReader(encoded), consumeBackup); !errors.Is(err, ErrBackupLimit) {
		t.Fatal("empty entry not counted", err)
	}
	if r, err := s.Seal(t.Context(), scope, limits, io.Discard, func(_ context.Context, a *BackupArchiveWriter) error {
		for i := 0; i < 2; i++ {
			_ = a.WriteEntry(BackupEntry{Kind: "config", ID: fmt.Sprintf("empty-%d", i)}, func(context.Context, io.Writer) error { return nil })
		}
		return nil
	}); !errors.Is(err, ErrBackupLimit) || r != (BackupReceipt{}) {
		t.Fatal("swallowed empty entry count", err)
	}
	limits.MaxBytes = backupChunkBytes + 1
	var out bytes.Buffer
	if _, err := s.Seal(t.Context(), scope, limits, &out, func(_ context.Context, a *BackupArchiveWriter) error {
		return a.WriteEntry(BackupEntry{Kind: "database", ID: "bytewise"}, func(_ context.Context, w io.Writer) error {
			for i := 0; i < backupChunkBytes+1; i++ {
				if _, err := w.Write([]byte{1}); err != nil {
					return err
				}
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Open(t.Context(), scope, limits, bytes.NewReader(out.Bytes()), consumeBackup); err != nil {
		t.Fatal("bytewise writes did not canonicalize", err)
	}
}

func awaitBackupClosed(t *testing.T, closed *atomic.Bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !closed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("borrowed stream did not invalidate")
		}
		runtime.Gosched()
	}
}

func TestBackupInFlightIOCannotOutliveBorrowedCallback(t *testing.T) {
	s, o, scope, limits := backupFixture(t)
	t.Run("writer", func(t *testing.T) {
		blocked, release := make(chan struct{}), make(chan struct{})
		var released atomic.Bool
		defer func() {
			if released.CompareAndSwap(false, true) {
				close(release)
			}
		}()
		borrowed := make(chan *backupEntryWriteState, 1)
		writeDone := make(chan error, 1)
		sealDone := make(chan error, 1)
		calls := 0
		writer := backupWriterFunc(func(p []byte) (int, error) {
			calls++
			if calls == 5 {
				close(blocked)
				<-release
			}
			return len(p), nil
		})
		go func() {
			_, err := s.Seal(t.Context(), scope, limits, writer, func(_ context.Context, a *BackupArchiveWriter) error {
				return a.WriteEntry(BackupEntry{Kind: "database", ID: "entry"}, func(_ context.Context, w io.Writer) error {
					borrowed <- w.(backupEntryWriter).state
					go func() { _, err := w.Write(make([]byte, backupChunkBytes)); writeDone <- err }()
					<-blocked
					return nil
				})
			})
			sealDone <- err
		}()
		body := <-borrowed
		<-blocked
		awaitBackupClosed(t, &body.closed)
		if released.CompareAndSwap(false, true) {
			close(release)
		}
		if err := <-writeDone; !errors.Is(err, ErrBackupClosed) {
			t.Fatal("closed in-flight writer returned success", err)
		}
		if err := <-sealDone; !errors.Is(err, ErrBackupClosed) {
			t.Fatal("in-flight writer archive succeeded", err)
		}
	})
	t.Run("reader", func(t *testing.T) {
		encoded := backupBytes(t, s, scope, limits, make([]byte, backupChunkBytes))
		source := bytes.NewReader(encoded)
		blocked, release := make(chan struct{}), make(chan struct{})
		var released atomic.Bool
		defer func() {
			if released.CompareAndSwap(false, true) {
				close(release)
			}
		}()
		borrowed := make(chan *backupEntryReadState, 1)
		readDone := make(chan error, 1)
		openDone := make(chan error, 1)
		calls := 0
		reader := backupReaderFunc(func(p []byte) (int, error) {
			calls++
			if calls == 5 {
				close(blocked)
				<-release
			}
			return source.Read(p)
		})
		go func() {
			_, err := o.Open(t.Context(), scope, limits, reader, func(_ context.Context, _ BackupEntry, r io.Reader) error {
				borrowed <- r.(backupEntryReader).state
				go func() {
					out := []byte{99}
					n, err := r.Read(out)
					if n != 0 || out[0] != 99 {
						readDone <- errors.New("closed reader released bytes")
						return
					}
					readDone <- err
				}()
				<-blocked
				return nil
			})
			openDone <- err
		}()
		body := <-borrowed
		<-blocked
		awaitBackupClosed(t, &body.closed)
		if released.CompareAndSwap(false, true) {
			close(release)
		}
		if err := <-readDone; !errors.Is(err, ErrBackupClosed) {
			t.Fatal("closed in-flight reader returned bytes", err)
		}
		if err := <-openDone; !errors.Is(err, ErrBackupClosed) {
			t.Fatal("in-flight reader archive succeeded", err)
		}
	})
}
