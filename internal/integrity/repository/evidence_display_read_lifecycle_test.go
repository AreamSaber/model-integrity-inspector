package repository

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func displayReadLifecycleSource(t *testing.T) *DisplayReadSource {
	t.Helper()
	return &DisplayReadSource{displayReadSourceState: &displayReadSourceState{ctx: t.Context(), deadline: time.Now().Add(time.Minute), grant: new(atomic.Bool), snapshot: displayReadSnapshot{
		metadata: DisplayReadMetadata{Status: DisplayReadAvailable, PayloadHash: "private-source-lifecycle-marker"},
		record:   DisplayEvidenceRecord{Ciphertext: []byte("private-source-lifecycle-cipher"), Nonce: []byte("private-source-lifecycle-nonce")},
	}}}
}

func TestEvidenceDisplayReadLifecycleValueProtection(t *testing.T) {
	source := displayReadLifecycleSource(t)
	defer source.Close()
	permit := &DisclosurePermit{metadataDigest: "private-permit-lifecycle-marker", state: new(atomic.Int32)}
	for _, item := range []struct {
		name      string
		value     any
		protected string
	}{
		{"source-pointer", source, "[protected display read source]"},
		{"source-value", reflect.ValueOf(source).Elem().Interface(), "[protected display read source]"},
		{"permit-pointer", permit, "[private disclosure permit]"},
		{"permit-value", *permit, "[private disclosure permit]"},
	} {
		t.Run(item.name, func(t *testing.T) {
			if _, err := json.Marshal(item.value); !errors.Is(err, ErrEvidenceSerialization) {
				t.Error("value bypassed protected JSON error")
			}
			for _, format := range []string{"%v", "%+v", "%#v"} {
				if fmt.Sprintf(format, item.value) != item.protected {
					t.Error("value bypassed protected formatting")
				}
			}
			var output bytes.Buffer
			slog.New(slog.NewJSONHandler(&output, nil)).Info("protected", "value", item.value)
			if !strings.Contains(output.String(), item.protected) || strings.Contains(output.String(), "lifecycle-marker") {
				t.Error("value bypassed protected logging")
			}
		})
	}
}

func TestEvidenceDisplayReadLifecycleValueCloseIsShared(t *testing.T) {
	source := displayReadLifecycleSource(t)
	// Reflection exercises a real ordinary Go value copy without making the
	// intentionally unsafe pre-fix mutex copy prevent the red test from running.
	copied := reflect.New(reflect.TypeOf(source).Elem())
	copied.Elem().Set(reflect.ValueOf(source).Elem())
	clone := copied.Interface().(*DisplayReadSource)
	clone.Close()
	if meta := source.Metadata(); meta != (DisplayReadMetadata{}) {
		t.Error("copy Close did not close the original ownership state")
	}
	called := false
	if err := source.WithEnvelope(func(DisplayReadEnvelope) error { called = true; return nil }); !errors.Is(err, ErrDisplaySource) || called {
		t.Error("original borrowed already-cleared bytes after a copy closed")
	}
	source.Close()
	clone.Close()
}

func TestEvidenceDisplayReadLifecycleZeroSourceIsClosed(t *testing.T) {
	for name, source := range map[string]*DisplayReadSource{"nil": nil, "zero": {}, "empty-state": {displayReadSourceState: &displayReadSourceState{}}} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() != nil {
					t.Error("zero source panicked instead of rejecting")
				}
			}()
			called := false
			if err := source.WithEnvelope(func(DisplayReadEnvelope) error { called = true; return nil }); !errors.Is(err, ErrDisplaySource) || called {
				t.Error("zero source admitted an envelope")
			}
			if source.Metadata() != (DisplayReadMetadata{}) {
				t.Error("zero source invented metadata")
			}
			source.Close()
		})
	}
}

func TestEvidenceDisplayReadLifecycleConcurrentCopyCloseKeepsBorrowPrivate(t *testing.T) {
	source := displayReadLifecycleSource(t)
	copied := *source
	entered := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	var borrowed []byte
	go func() {
		result <- source.WithEnvelope(func(envelope DisplayReadEnvelope) error {
			borrowed = envelope.Record.Ciphertext
			close(entered)
			<-release
			if !bytes.Equal(borrowed, []byte("private-source-lifecycle-cipher")) {
				return ErrDisplaySource
			}
			return nil
		})
	}()
	<-entered
	copied.Close()
	meta := source.Metadata()
	err := copied.WithEnvelope(func(DisplayReadEnvelope) error { return nil })
	close(release)
	borrowError := <-result
	if meta != (DisplayReadMetadata{}) || !errors.Is(err, ErrDisplaySource) {
		t.Fatal("concurrent value Close did not share closed ownership")
	}
	if borrowError != nil {
		t.Fatal("Close altered a previously borrowed private clone")
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("borrowed clone was not cleared on return")
	}
	source.Close()
}
