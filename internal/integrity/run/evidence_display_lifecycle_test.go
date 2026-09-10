package run

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/evidencedisplay"
)

func TestEvidenceDisclosureValueCopyProtection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	releases := 0
	d := &Disclosure{disclosureState: &disclosureState{ctx: ctx, cancel: cancel, data: []byte("synthetic-private-disclosure"), release: func() { releases++ }}}
	copied := *d
	for _, value := range []any{d, copied} {
		if _, err := json.Marshal(value); !errors.Is(err, evidencedisplay.ErrSensitive) {
			t.Error("disclosure value can bypass protected JSON representation")
		}
		if text := fmt.Sprintf("%v %+v %#v", value, value, value); strings.Contains(text, "synthetic") || strings.Contains(text, "115 121 110") {
			t.Error("disclosure value can bypass protected formatting")
		}
		var log bytes.Buffer
		slog.New(slog.NewJSONHandler(&log, nil)).Info("protected", "value", value)
		if !strings.Contains(log.String(), "[protected evidence disclosure]") {
			t.Error("disclosure value does not retain protected logging")
		}
	}
	d.Close()
	copied.Close()
	if releases != 1 {
		t.Fatalf("copied disclosure released one admission slot %d times", releases)
	}
}

func TestEvidenceDisclosureDuplicateWriteDoesNotCancelActiveWriter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	releases := 0
	d := &Disclosure{disclosureState: &disclosureState{ctx: ctx, cancel: cancel, state: 1, release: func() { releases++ }}}
	copy := *d
	var sink bytes.Buffer
	if n, err := copy.WriteTo(ctx, &sink); n != 0 || !errors.Is(err, ErrEvidenceUnavailable) || sink.Len() != 0 {
		t.Fatal("duplicate writer accepted")
	}
	if ctx.Err() != nil || releases != 0 {
		t.Fatal("duplicate writer canceled or released the active writer")
	}
	copy.Close()
	if ctx.Err() == nil || releases != 0 {
		t.Fatal("explicit close must cancel but cannot release a writer-owned slot")
	}
	d.mu.Lock()
	d.finishLocked()
	d.mu.Unlock()
	copy.Close()
	if releases != 1 {
		t.Fatal("writer completion did not release exactly once")
	}
}

func TestEvidenceDisclosureCopiedConcurrentCloseAndZeroValues(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var releases atomic.Int32
	data := []byte("synthetic-private-disclosure")
	d := &Disclosure{disclosureState: &disclosureState{ctx: ctx, cancel: cancel, data: data, release: func() { releases.Add(1) }}}
	var workers sync.WaitGroup
	for range 16 {
		copy := *d
		workers.Go(func() { copy.Close() })
	}
	workers.Wait()
	if releases.Load() != 1 || ctx.Err() == nil || !bytes.Equal(data, make([]byte, len(data))) {
		t.Fatal("concurrent copied close did not release and clear exactly once")
	}
	for _, empty := range []*Disclosure{nil, {}, {disclosureState: &disclosureState{}}} {
		empty.Close()
		if n, err := empty.WriteTo(t.Context(), &bytes.Buffer{}); n != 0 || !errors.Is(err, ErrEvidenceUnavailable) {
			t.Fatal("zero disclosure accepted")
		}
	}
}
