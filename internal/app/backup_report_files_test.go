package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/report"
	"model-integrity-inspector.local/mii/internal/integrity/reportstorage"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

type backupReportFileWriterFunc func([]byte) (int, error)

func (f backupReportFileWriterFunc) Write(p []byte) (int, error) { return f(p) }

func backupReportFileTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func backupReportFileTestStore(t *testing.T) (*reportstorage.Store, string) {
	t.Helper()
	// Reuse the real store fixture pattern: it creates only this last private
	// directory, with its platform-native permissions, beneath an owned parent.
	directory := filepath.Join(t.TempDir(), "reports")
	store, err := reportstorage.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store, directory
}

func backupReportFileTestPut(t *testing.T, store *reportstorage.Store, format string, data []byte) reportstorage.Reference {
	t.Helper()
	ref, err := store.Put(backupReportFileTestContext(t), 17, format, data)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

// Actual S1 validation and all three real renderers, but no database job,
// authorization, publication or source-content regeneration in the copier.
func backupReportFileTestArtifacts(t *testing.T) map[string][]byte {
	t.Helper()
	now := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	versions := report.Versions{Rule: scoring.Version, Template: templates.BuiltinVersion, Scoring: scoring.Version, Tokenizer: tokenizer.BuiltinVersion}
	scope := report.Scope{ReportID: "31", OrganizationID: "17", RunID: "42", AnalysisRevision: 1, GeneratedAt: now, Versions: versions}
	input := report.Input{
		Run:     report.Run{ID: "42", TargetID: "51", Package: "standard", CreatedAt: now.Add(-time.Minute), FinishedAt: now, RequestCount: 1},
		Result:  report.Result{RunID: "42", AnalysisRevision: 1, Versions: versions, ExpectedSamples: 1, EvidenceGrade: "D", RiskLevel: "insufficient", Completeness: "insufficient", Limitations: []string{"MI_NO_VALID_SAMPLES", "MI_DEVELOPMENT_RULES_UNCALIBRATED"}},
		Samples: []report.Sample{{ID: "61", RunID: "42", ProbeInstanceID: "71", Family: "sequence", Language: "en-US", Validity: "NOT_APPLICABLE", RequestedMaxTokens: 256, TokenizerQuality: "unavailable"}},
	}
	snapshot, err := report.NewDevelopmentSnapshot(scope, input)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := report.Generate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	csv, err := report.GenerateCSV(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{"json": artifacts.JSON(), "html": artifacts.HTML(), "csv": csv.Bytes()}
}

func TestBackupReportFileActualRenderers(t *testing.T) {
	store, directory := backupReportFileTestStore(t)
	for format, original := range backupReportFileTestArtifacts(t) {
		t.Run(format, func(t *testing.T) {
			ref := backupReportFileTestPut(t, store, format, original)
			before, err := os.Stat(filepath.Join(directory, ref.Name()))
			if err != nil {
				t.Fatal(err)
			}
			var copied bytes.Buffer
			receipt, err := copyBackupReportFile(backupReportFileTestContext(t), store, ref, &copied)
			digest := sha256.Sum256(original)
			if err != nil || !bytes.Equal(copied.Bytes(), original) || receipt.organizationID != 17 || receipt.format != format || receipt.size != int64(len(original)) || receipt.hash != hex.EncodeToString(digest[:]) {
				t.Fatal("real artifact bytes/identity not copied exactly", err)
			}
			// Open another physical capability and use the real safe Read, not the
			// source slice retained by this fixture, to prove no source mutation.
			independent, err := reportstorage.Open(directory)
			if err != nil {
				t.Fatal(err)
			}
			read, readErr := independent.Read(backupReportFileTestContext(t), ref)
			closeErr := independent.Close()
			after, statErr := os.Stat(filepath.Join(directory, ref.Name()))
			if readErr != nil || closeErr != nil || statErr != nil || !bytes.Equal(read, original) || !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
				t.Fatal("copy changed source bytes/identity/metadata", readErr, closeErr, statErr)
			}
		})
	}
}

func TestBackupReportFileChunkBoundsAndOwnedClear(t *testing.T) {
	for _, size := range []int{1, backupReportFileChunkBytes - 1, backupReportFileChunkBytes, backupReportFileChunkBytes + 1, 2*backupReportFileChunkBytes + 37, reportstorage.MaxBytes} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			store, _ := backupReportFileTestStore(t)
			original := bytes.Repeat([]byte{0x69}, size)
			ref := backupReportFileTestPut(t, store, "json", original)
			var copied bytes.Buffer
			var views [][]byte
			writer := backupReportFileWriterFunc(func(p []byte) (int, error) {
				if len(p) == 0 || len(p) > backupReportFileChunkBytes || cap(p) != len(p) {
					t.Fatal("output chunk escaped its finite bound")
				}
				// Deliberately retain borrowed slices only as a synchronous
				// lifetime spy; a real sink MUST NOT retain or modify them.
				views = append(views, p)
				return copied.Write(p)
			})
			receipt, err := copyBackupReportFile(backupReportFileTestContext(t), store, ref, writer)
			if err != nil || receipt.size != int64(size) || !bytes.Equal(copied.Bytes(), original) || len(views) != (size+backupReportFileChunkBytes-1)/backupReportFileChunkBytes {
				t.Fatal("chunking changed/dropped bytes", err)
			}
			backupReportFileTestCleared(t, views)
			read, err := store.Read(backupReportFileTestContext(t), ref)
			if err != nil || !bytes.Equal(read, original) {
				t.Fatal("clearing owned read buffer changed source", err)
			}
		})
	}
}

func backupReportFileTestCleared(t *testing.T, views [][]byte) {
	t.Helper()
	for _, view := range views {
		for _, b := range view {
			if b != 0 {
				t.Fatal("borrowed source buffer survived return")
			}
		}
	}
}

func TestBackupReportFileSourceFailuresWriteNothing(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt", "oversized_file", "wrong_size", "wrong_hash", "wrong_org", "wrong_format", "unsafe_hash", "unsafe_format", "zero_org", "zero_size", "oversized_ref"} {
		t.Run(mode, func(t *testing.T) {
			store, directory := backupReportFileTestStore(t)
			original := bytes.Repeat([]byte{0x62}, 91)
			ref := backupReportFileTestPut(t, store, "json", original)
			path := filepath.Join(directory, ref.Name())
			switch mode {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "corrupt", "oversized_file":
				length := len(original)
				if mode == "oversized_file" {
					length++
				}
				if err := os.WriteFile(path, bytes.Repeat([]byte{0x63}, length), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong_size":
				ref.Size--
			case "wrong_hash":
				ref.Hash = strings.Repeat("a", 64)
			case "wrong_org":
				ref.OrganizationID++
			case "wrong_format":
				ref.Format = "csv"
			case "unsafe_hash":
				ref.Hash = "../../private-source-canary"
			case "unsafe_format":
				ref.Format = "../../private-source-canary"
			case "zero_org":
				ref.OrganizationID = 0
			case "zero_size":
				ref.Size = 0
			case "oversized_ref":
				ref.Size = reportstorage.MaxBytes + 1
			}
			calls := 0
			sink := backupReportFileWriterFunc(func(p []byte) (int, error) { calls++; return len(p), nil })
			receipt, err := copyBackupReportFile(backupReportFileTestContext(t), store, ref, sink)
			if err == nil || receipt != (backupReportFileReceipt{}) || calls != 0 || strings.Contains(err.Error(), "private-source-canary") {
				t.Fatal("source failure leaked bytes/receipt/details")
			}
		})
	}
}

func TestBackupReportFileNativeHardlinkRejection(t *testing.T) {
	store, directory := backupReportFileTestStore(t)
	original := []byte("original-single-identity")
	ref := backupReportFileTestPut(t, store, "json", original)
	alias := filepath.Join(filepath.Dir(directory), "report-hardlink")
	if err := os.Link(filepath.Join(directory, ref.Name()), alias); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	receipt, err := copyBackupReportFile(backupReportFileTestContext(t), store, ref, &out)
	if !errors.Is(err, reportstorage.ErrUnsafe) || receipt != (backupReportFileReceipt{}) || out.Len() != 0 {
		t.Fatal("copy bypassed real native link identity checks", err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	receipt, err = copyBackupReportFile(backupReportFileTestContext(t), store, ref, &out)
	if err != nil || receipt.size != int64(len(original)) || !bytes.Equal(out.Bytes(), original) {
		t.Fatal("removing only fixture alias did not preserve real source", err)
	}
}

func TestBackupReportFileReceiptClosedSerialization(t *testing.T) {
	receipt := backupReportFileReceipt{organizationID: 917281763, hash: "private-hash-canary", format: "private-format-canary", size: 51392741}
	for _, value := range []any{receipt, &receipt} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			if got := fmt.Sprintf(verb, value); got != receipt.String() {
				t.Fatal("receipt formatting was not closed")
			}
		}
		if data, err := json.Marshal(value); err == nil || data != nil {
			t.Fatal("receipt JSON escaped")
		}
		if data, err := yaml.Marshal(value); err == nil || data != nil {
			t.Fatal("receipt YAML escaped")
		}
		var output bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&output, nil))
		logger.Info("copy", "receipt", value)
		if strings.Contains(output.String(), "canary") || strings.Contains(output.String(), "917281763") || !strings.Contains(output.String(), receipt.String()) {
			t.Fatal("receipt logging escaped")
		}
	}
}

func TestBackupReportFilePreflightAndTypedNil(t *testing.T) {
	store, _ := backupReportFileTestStore(t)
	ref := backupReportFileTestPut(t, store, "json", []byte("source-owned"))
	ctx := backupReportFileTestContext(t)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	expired, stop := context.WithDeadline(ctx, time.Unix(1, 0))
	defer stop()
	var typedNil *bytes.Buffer
	var nilFunction backupReportFileWriterFunc
	for _, tc := range []struct {
		name  string
		ctx   context.Context
		store *reportstorage.Store
		sink  io.Writer
	}{
		{"nil_context", nil, store, io.Discard},
		{"no_deadline", context.WithoutCancel(t.Context()), store, io.Discard},
		{"canceled", canceled, store, io.Discard},
		{"expired", expired, store, io.Discard},
		{"nil_store", ctx, nil, io.Discard},
		{"zero_store", ctx, &reportstorage.Store{}, io.Discard},
		{"nil_sink", ctx, store, nil},
		{"typed_nil_sink", ctx, store, typedNil},
		{"nil_function_sink", ctx, store, nilFunction},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receipt, err := copyBackupReportFile(tc.ctx, tc.store, ref, tc.sink)
			if err == nil || receipt != (backupReportFileReceipt{}) {
				t.Fatal("invalid/canceled copy returned a receipt")
			}
		})
	}
}

// The Error method must never run, even indirectly through panic formatting.
type backupReportFilePrivateError struct{}

func (backupReportFilePrivateError) Error() string { panic("private-writer-error-canary") }

func TestBackupReportFileWriterFailuresZeroReceiptAndClear(t *testing.T) {
	for _, mode := range []string{"short_nil", "zero_nil", "negative", "oversized", "partial_error", "full_error", "panic", "cancel_after_first", "cancel_after_last"} {
		t.Run(mode, func(t *testing.T) {
			store, directory := backupReportFileTestStore(t)
			original := bytes.Repeat([]byte{0x79}, 2*backupReportFileChunkBytes+7)
			ref := backupReportFileTestPut(t, store, "html", original)
			ctx, cancel := context.WithCancel(backupReportFileTestContext(t))
			defer cancel()
			var views [][]byte
			var prefix bytes.Buffer
			calls := 0
			sink := backupReportFileWriterFunc(func(p []byte) (int, error) {
				views = append(views, p)
				calls++
				if mode == "cancel_after_first" || mode == "cancel_after_last" {
					n, err := prefix.Write(p)
					if mode == "cancel_after_first" || calls == 3 {
						cancel()
					}
					return n, err
				}
				if calls == 1 {
					return prefix.Write(p)
				}
				switch mode {
				case "short_nil":
					return prefix.Write(p[:len(p)-1])
				case "zero_nil":
					return 0, nil
				case "negative":
					return -1, nil
				case "oversized":
					return len(p) + 1, nil
				case "partial_error":
					n, _ := prefix.Write(p[:3])
					return n, backupReportFilePrivateError{}
				case "full_error":
					n, _ := prefix.Write(p)
					return n, backupReportFilePrivateError{}
				default:
					panic(backupReportFilePrivateError{})
				}
			})
			receipt, err := copyBackupReportFile(ctx, store, ref, sink)
			expectedCalls := 2
			switch mode {
			case "cancel_after_first":
				expectedCalls = 1
			case "cancel_after_last":
				expectedCalls = 3
			}
			if !errors.Is(err, errBackupReportFileCopy) || receipt != (backupReportFileReceipt{}) || calls != expectedCalls || prefix.Len() < backupReportFileChunkBytes || !bytes.Equal(prefix.Bytes(), original[:prefix.Len()]) {
				t.Fatal("late failure retried, lost prefix, or produced receipt", err)
			}
			if mode == "cancel_after_last" && !bytes.Equal(prefix.Bytes(), original) {
				t.Fatal("final cancellation did not exercise all accepted bytes")
			}
			backupReportFileTestCleared(t, views)
			independent, err := reportstorage.Open(directory)
			if err != nil {
				t.Fatal(err)
			}
			read, readErr := independent.Read(backupReportFileTestContext(t), ref)
			closeErr := independent.Close()
			if readErr != nil || closeErr != nil || !bytes.Equal(read, original) {
				t.Fatal("failure mutated the source", readErr, closeErr)
			}
		})
	}
}
