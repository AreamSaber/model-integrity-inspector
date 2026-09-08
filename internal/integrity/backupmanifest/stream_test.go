package backupmanifest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func streamFixture(t *testing.T) (Manifest, []Entry, map[string][]byte) {
	t.Helper()
	m := fixture()
	payloads := map[string][]byte{}
	set := func(f *File) {
		payloads[f.EntryID] = []byte("actual-stream-for-" + f.EntryID)
		f.Bytes, f.SHA256 = int64(len(payloads[f.EntryID])), digest(payloads[f.EntryID])
	}
	set(&m.Database.File)
	set(&m.ConfigTemplate)
	for i := range m.Reports {
		set(&m.Reports[i].File)
	}
	for i := range m.Artifacts {
		set(&m.Artifacts[i].File)
	}
	data, _, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	payloads["backup-manifest"] = data
	entries, err := Entries(m)
	if err != nil {
		t.Fatal(err)
	}
	return m, entries, payloads
}

type inventoryReaderFunc func([]byte) (int, error)

func (f inventoryReaderFunc) Read(p []byte) (int, error) { return f(p) }

func TestVerifyStreamExactSetFailuresAndRetainedCapability(t *testing.T) {
	for _, mode := range []string{"valid", "reverse", "missing", "duplicate", "extra", "kind", "short", "long", "hash", "manifest", "unreadable", "stalled", "panic_reader", "bad_count", "joined_eof", "callback_error", "callback_panic", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			m, entries, payloads := streamFixture(t)
			if mode == "reverse" {
				slices.Reverse(entries)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var retained func(string, string, io.Reader) error
			readForbidden := inventoryReaderFunc(func([]byte) (int, error) {
				t.Error("unknown/closed entry reader was touched")
				return 0, io.EOF
			})
			err := VerifyStream(ctx, m, time.Second, func(_ context.Context, accept func(string, string, io.Reader) error) error {
				retained = accept
				for _, entry := range entries {
					id, kind := entry.File.EntryID, entry.Kind
					if mode == "missing" && kind == "config" {
						continue
					}
					payload := bytes.Clone(payloads[id])
					var in io.Reader = bytes.NewReader(payload)
					if kind == "database" {
						switch mode {
						case "kind":
							kind, in = "report", readForbidden
						case "short":
							in = bytes.NewReader(payload[:len(payload)-1])
						case "long":
							in = io.MultiReader(bytes.NewReader(payload), strings.NewReader("x"))
						case "hash":
							payload[0] ^= 1
						case "unreadable":
							in = inventoryReaderFunc(func([]byte) (int, error) { return 0, errors.New("sensitive reader detail") })
						case "stalled":
							in = inventoryReaderFunc(func([]byte) (int, error) { return 0, nil })
						case "panic_reader":
							in = inventoryReaderFunc(func([]byte) (int, error) { panic("sensitive reader detail") })
						case "bad_count":
							in = inventoryReaderFunc(func(p []byte) (int, error) { return len(p) + 1, nil })
						case "joined_eof":
							in = inventoryReaderFunc(func(p []byte) (int, error) { return copy(p, payload), errors.Join(io.EOF, errors.New("real failure")) })
						}
					}
					if mode == "manifest" && kind == "manifest" {
						payload[0] ^= 1
					}
					// Intentionally swallow every accept error. It must stay sticky.
					_ = accept(kind, id, in)
					if mode == "duplicate" && kind == "database" {
						_ = accept(kind, id, readForbidden)
					}
				}
				switch mode {
				case "extra":
					_ = accept("config", "unplanned", readForbidden)
				case "callback_error":
					return errors.New("sensitive callback detail")
				case "callback_panic":
					panic("sensitive callback detail")
				case "cancel":
					cancel()
				}
				return nil
			})
			want := ErrMismatch
			switch mode {
			case "valid", "reverse":
				want = nil
			case "unreadable", "stalled", "panic_reader", "bad_count", "joined_eof":
				want = ErrRead
			case "callback_error", "callback_panic":
				want = ErrCallback
			case "cancel":
				want = ErrCanceled
			}
			if !errors.Is(err, want) {
				t.Fatal("wrong closed inventory outcome", err, want)
			}
			if retained == nil || !errors.Is(retained("database", m.Database.File.EntryID, readForbidden), ErrClosed) {
				t.Fatal("borrowed function survived verification")
			}
		})
	}
}

func TestVerifyStreamRequiresRealEOFAndOwnsItsPlan(t *testing.T) {
	m, entries, payloads := streamFixture(t)
	readEnd := false
	err := VerifyStream(t.Context(), m, time.Second, func(_ context.Context, accept func(string, string, io.Reader) error) error {
		// Mutating the caller-owned manifest after entry validation cannot
		// change the verifier's owned expected inventory.
		m.Artifacts[0].File.SHA256 = strings.Repeat("0", 64)
		for _, e := range entries {
			source := bytes.NewReader(payloads[e.File.EntryID])
			in := inventoryReaderFunc(func(p []byte) (int, error) {
				n, err := source.Read(p)
				if err == io.EOF { //nolint:errorlint // Exact standard Reader EOF sentinel.
					readEnd = true
				}
				return n, err
			})
			readEnd = false
			if err := accept(e.Kind, e.File.EntryID, in); err != nil || !readEnd {
				t.Fatal("did not read the actual entry end", err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyStreamBoundsActualLargePayloadAllocationsAndReads(t *testing.T) {
	m, _, payloads := streamFixture(t)
	// Synthetic bytes, not a claimed valid database or capacity acceptance.
	large := bytes.Repeat([]byte{0x63}, 25<<20+17)
	m.Database.File.Bytes, m.Database.File.SHA256 = int64(len(large)), digest(large)
	payloads[m.Database.File.EntryID] = large
	data, _, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	payloads["backup-manifest"] = data
	entries, err := Entries(m)
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err = VerifyStream(t.Context(), m, 5*time.Second, func(_ context.Context, accept func(string, string, io.Reader) error) error {
		for _, e := range entries {
			r := bytes.NewReader(payloads[e.File.EntryID])
			if err := accept(e.Kind, e.File.EntryID, inventoryReaderFunc(func(p []byte) (int, error) {
				if len(p) > 64<<10 {
					t.Fatal("unbounded single read")
				}
				return r.Read(p)
			})); err != nil {
				return err
			}
		}
		return nil
	})
	runtime.ReadMemStats(&after)
	if err != nil || after.TotalAlloc-before.TotalAlloc > 4<<20 {
		t.Fatal("whole payload buffered or verification failed", after.TotalAlloc-before.TotalAlloc, err)
	}
}

func TestVerifyStreamRejectsInvalidInputsBeforeCallback(t *testing.T) {
	m, _, _ := streamFixture(t)
	called := false
	callback := func(context.Context, func(string, string, io.Reader) error) error { called = true; return nil }
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{nil, cancelled} {
		if !errors.Is(VerifyStream(ctx, m, time.Second, callback), ErrCanceled) {
			t.Fatal("invalid context accepted")
		}
	}
	for _, timeout := range []time.Duration{0, -1, MaxStreamTimeout + 1} {
		if !errors.Is(VerifyStream(t.Context(), m, timeout, callback), ErrLimit) {
			t.Fatal("invalid timeout accepted")
		}
	}
	if !errors.Is(VerifyStream(t.Context(), m, time.Second, nil), ErrCallback) {
		t.Fatal("nil callback accepted")
	}
	m.BackupID = 0
	if !errors.Is(VerifyStream(t.Context(), m, time.Second, callback), ErrInvalid) || called {
		t.Fatal("invalid input reached callback")
	}
}

func TestVerifyStreamCancellationDuringReadAndCallbackDeadline(t *testing.T) {
	m, entries, payloads := streamFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	err := VerifyStream(ctx, m, time.Second, func(_ context.Context, accept func(string, string, io.Reader) error) error {
		e := entries[0]
		_ = accept(e.Kind, e.File.EntryID, inventoryReaderFunc(func(p []byte) (int, error) {
			cancel()
			return copy(p, payloads[e.File.EntryID]), io.EOF
		}))
		return nil // A complete final read cannot override cancellation.
	})
	if !errors.Is(err, ErrCanceled) {
		t.Fatal("read cancellation was swallowed", err)
	}
	err = VerifyStream(t.Context(), m, 10*time.Millisecond, func(ctx context.Context, _ func(string, string, io.Reader) error) error {
		<-ctx.Done()
		return nil
	})
	if !errors.Is(err, ErrCanceled) {
		t.Fatal("callback exceeded the operation deadline", err)
	}
}
