package tokenizer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func installedTestHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func installedTestArtifact(t *testing.T) (*Engine, *InstalledArtifact) {
	t.Helper()
	e, err := Load(builtinBytes, BuiltinHash)
	if err != nil {
		t.Fatal("load independent actual compiled tokenizer", err)
	}
	a, err := e.InstalledArtifact(t.Context())
	if err != nil {
		t.Fatal("export actual Engine resources", err)
	}
	return e, a
}

// Independent wire reader, not decodeInstalledParts. Pin field order, exact
// count and trailing EOF to avoid having encoder and decoder share an error.
func installedTestParts(t *testing.T, data []byte) [][]byte {
	t.Helper()
	r := bytes.NewReader(data)
	header := make([]byte, len("MII-TOKENIZER-INSTALLED-V1\n"))
	if _, err := io.ReadFull(r, header); err != nil || string(header) != "MII-TOKENIZER-INSTALLED-V1\n" {
		t.Fatal("carrier framing magic")
	}
	count, err := r.ReadByte()
	if err != nil || count != 5 {
		t.Fatal("carrier exact part count")
	}
	var parts [][]byte
	for _, expected := range []string{"implementation", "configuration", "cl100k_base", "o200k_base", "notices"} {
		var nameSize uint16
		if err := binary.Read(r, binary.BigEndian, &nameSize); err != nil || int(nameSize) != len(expected) {
			t.Fatal("independent resource name size")
		}
		name := make([]byte, nameSize)
		if _, err := io.ReadFull(r, name); err != nil || string(name) != expected {
			t.Fatal("resource order/name")
		}
		var size uint64
		if err := binary.Read(r, binary.BigEndian, &size); err != nil || size == 0 || size > 4<<20 {
			t.Fatal("independent resource size")
		}
		part := make([]byte, int(size))
		if _, err := io.ReadFull(r, part); err != nil {
			t.Fatal("truncated resource")
		}
		parts = append(parts, part)
	}
	if _, err := r.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatal("carrier trailing bytes")
	}
	return parts
}

func TestInstalledTokenizerArtifactGoldenFullResourcesAndRestoredCorpus(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	original, artifact := installedTestArtifact(t)
	data, ref := artifact.Bytes(), artifact.Ref()
	if ref.SchemaVersion != InstalledArtifactSchema || ref.Version != "1.0.0" || ref.Implementation != ImplementationVersion || ref.ConfigurationSHA256 != BuiltinHash || ref.Bytes != int64(len(data)) || ref.SHA256 != installedTestHash(data) || ref.SHA256 == ref.ConfigurationSHA256 {
		t.Fatal("carrier/config identities collapsed or incorrect")
	}
	// This new-format golden is pinned only after independently inspecting all
	// emitted resources below; it is not asserted to be a historical artifact.
	const golden = "4d17c03ccb0ea4fbbb122d1fc9091375b5c21a06958e8ef8967872641549675b"
	if ref.SHA256 != golden {
		t.Errorf("new complete carrier golden: hash=%s bytes=%d", ref.SHA256, ref.Bytes)
	}
	parts := installedTestParts(t, data)
	if len(parts[1]) != 1548 || !bytes.Equal(parts[1], builtinBytes) || installedTestHash(parts[1]) != "e63605c54793bca24d79c89ae4e0a66f37e4c8c5409cea795f52e63e7e5024ae" {
		t.Fatal("original configuration bytes/LF lost")
	}
	if len(parts[4]) != 2058 || installedTestHash(parts[4]) != "01e032a74984f7b521bbf668f26cb1a118cf75a662035015bdc893fbd05edebc" || !bytes.Contains(parts[4], []byte("Copyright (c) 2022 OpenAI, Shantanu Jain")) || !bytes.Contains(parts[4], []byte("Permission is hereby granted")) {
		t.Fatal("complete existing license notice omitted")
	}
	var metadata installedMetadata
	if err := json.Unmarshal(parts[0], &metadata); err != nil || metadata.CLPattern != clPattern || metadata.OPattern != oPattern || metadata.VisibleTextMode != "ordinary-visible-text" || metadata.RegexImplementation != "github.com/dlclark/regexp2/v2@v2.5.1" || metadata.MaxBPEWork != 4<<20 || metadata.MaxBPESpan != 1024 || metadata.ConcurrentBPE != 2 || metadata.RegexTimeoutMilliseconds != 100 {
		t.Fatal("actual MII implementation semantics omitted")
	}
	for i, expected := range []struct {
		count int
		hash  string
	}{{100256, "223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7"}, {199998, "446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d"}} {
		rows := bytes.Split(parts[2+i], []byte{'\n'})
		if len(rows) != expected.count+1 || len(rows[len(rows)-1]) != 0 || installedTestHash(parts[2+i]) != expected.hash {
			t.Fatal("official rank file bytes/count/digest do not match")
		}
		var sawNonUTF8Byte bool
		for rank, line := range rows[:len(rows)-1] {
			fields := bytes.Split(line, []byte{' '})
			if len(fields) != 2 || string(fields[1]) != strconv.Itoa(rank) {
				t.Fatal("independent rank/order parser")
			}
			piece, err := base64.StdEncoding.Strict().DecodeString(string(fields[0]))
			if err != nil || len(piece) == 0 || original.codecs[original.bundle.Encodings[i].ID].(*boundedBPE).ranks[string(piece)] != rank {
				t.Fatal("carrier did not preserve actual engine rank bytes")
			}
			if bytes.Equal(piece, []byte{0xff}) {
				sawNonUTF8Byte = true
			}
		}
		if !sawNonUTF8Byte {
			t.Fatal("fixture did not cover raw invalid-UTF8 token bytes")
		}
		t.Logf("independent official rank-file %d: bytes=%d rows=%d", i, len(parts[2+i]), expected.count)
	}
	verified, err := VerifyInstalledArtifact(t.Context(), data, ref)
	if err != nil {
		t.Fatal("verify full carrier", err)
	}
	restored, err := verified.NewEngine(t.Context())
	if err != nil || restored == original || restored.Hash() != original.Hash() {
		t.Fatal("restore independent actual archive engine", err)
	}
	fixtureData, err := os.ReadFile("testdata/reference_counts.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture referenceFixture
	if json.Unmarshal(fixtureData, &fixture) != nil || fixture.Reference != "openai/tiktoken@0.14.0" {
		t.Fatal("read existing official frozen corpus")
	}
	corpus := referenceCorpus()
	corpusBytes, err := json.Marshal(corpus)
	if err != nil || installedTestHash(corpusBytes) != fixture.CorpusSHA256 || len(corpus) != 759 || len(fixture.Counts) != len(corpus) {
		t.Fatal("official corpus identity changed")
	}
	// Explicitly use the engine reconstructed from ARCHIVED rank bytes, not
	// checkReferenceCounts (which internally calls NewBuiltin).
	for i, text := range corpus {
		for j, model := range []string{"gpt-4", "gpt-4o"} {
			got, err := restored.CountOutput(text, Selection{RequestedModel: model})
			if err != nil || got.Tokens == nil || *got.Tokens != fixture.Counts[i][j] || got.Quality != Exact {
				t.Fatalf("restored official corpus vector %d/%d mismatch", i, j)
			}
		}
	}
	for _, selection := range []Selection{{RequestedModel: "unknown"}, {StandardModel: "gpt-4o"}, {ReportedModel: "gpt-4o-variant"}} {
		want, err := original.CountOutput("short synthetic output", selection)
		if err != nil {
			t.Fatal(err)
		}
		got, err := restored.CountOutput("short synthetic output", selection)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("restored selection/quality/budget semantics drift")
		}
	}
	for _, model := range []string{"gpt-4o", "unknown-model"} {
		request := domain.NormalizedRequest{Model: model, Messages: []domain.NormalizedMessage{{Role: "user", Content: "hello world"}}, ResponseFormat: &domain.ResponseFormat{Type: "json_object"}}
		want, err := original.EstimateInput(request)
		if err != nil {
			t.Fatal(err)
		}
		got, err := restored.EstimateInput(request)
		if err != nil || !reflect.DeepEqual(got, want) || got.Quality == Exact {
			t.Fatal("restored input JSON framing/heuristic reserve drift")
		}
		if model == "gpt-4o" && (got.Tokens == nil || *got.Tokens != 18 || got.BudgetTokens != 23) {
			t.Fatal("known input framing must include JSON-object surcharge")
		}
	}
	if metadata.InputFraming != "role+content;4-per-message+3-reply-priming;+8-json-object;compatible-or-heuristic-never-exact" || !strings.Contains(metadata.BudgetSafety, "visible-bytes+3+4*messages+8") {
		t.Fatal("input framing/budget metadata is incomplete")
	}
}

func TestInstalledTokenizerArtifactOwnedNoDefaultFallback(t *testing.T) {
	original, first := installedTestArtifact(t)
	second, err := original.InstalledArtifact(t.Context())
	if err != nil || first.Ref() != second.Ref() || !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("map iteration changed deterministic carrier")
	}
	data := first.Bytes()
	verified, err := VerifyInstalledArtifact(t.Context(), data, first.Ref())
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 1
	copy := verified.Bytes()
	copy[len(copy)-1] ^= 1
	if !bytes.Equal(first.Bytes(), verified.Bytes()) {
		t.Fatal("verified carrier borrowed input/returned backing array")
	}
	restored, err := verified.NewEngine(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	delete(restored.codecs["cl100k_base"].(*boundedBPE).ranks, "!")
	again, err := verified.NewEngine(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, found := again.codecs["cl100k_base"].(*boundedBPE).ranks["!"]; !found {
		t.Fatal("restored engine shared map with earlier restore")
	}
	if _, found := original.codecs["cl100k_base"].(*boundedBPE).ranks["!"]; !found {
		t.Fatal("restored engine shared source map")
	}
	// Source mutation MUST break export: silently calling NewBuiltin or
	// tiktoken.Get here would export unrelated current default ranks instead.
	delete(original.codecs["cl100k_base"].(*boundedBPE).ranks, "!")
	if got, err := original.InstalledArtifact(t.Context()); !errors.Is(err, ErrInstalledArtifact) || got != nil {
		t.Fatal("export replaced actual damaged source with default resource")
	}
	// Even an already verified carrier rechecks its full private content on
	// restore; no cached builtin engine can ignore a damaged archive.
	verified.data[len(verified.data)-1] ^= 1
	if got, err := verified.NewEngine(t.Context()); !errors.Is(err, ErrInstalledArtifact) || got != nil {
		t.Fatal("restore ignored damaged actual carrier")
	}
}

func TestInstalledTokenizerArtifactRepresentationAndNilGuards(t *testing.T) {
	ref := InstalledRef{Version: "private-version-canary", SHA256: "private-hash-canary", Bytes: 987654321}
	a := InstalledArtifact{ref: ref, data: []byte("private-resource-canary")}
	for _, item := range []struct {
		input    any
		expected string
	}{{ref, "[private installed tokenizer reference]"}, {&ref, "[private installed tokenizer reference]"}, {a, "[private installed tokenizer artifact]"}, {&a, "[private installed tokenizer artifact]"}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if fmt.Sprintf(format, item.input) != item.expected {
				t.Fatal("ordinary format disclosed resource")
			}
		}
		if _, err := json.Marshal(item.input); !errors.Is(err, ErrInstalledArtifact) {
			t.Fatal("ordinary JSON exposed artifact")
		}
		if _, err := yaml.Marshal(item.input); err == nil {
			t.Fatal("ordinary YAML exposed artifact")
		}
		var out bytes.Buffer
		slog.New(slog.NewJSONHandler(&out, nil)).Info("artifact", "value", item.input)
		if strings.Contains(out.String(), "canary") || strings.Contains(out.String(), "987654321") || !strings.Contains(out.String(), item.expected) {
			t.Fatal("structured log disclosed resource")
		}
	}
	var missing *InstalledArtifact
	if missing.Ref() != (InstalledRef{}) || missing.Bytes() != nil {
		t.Fatal("nil artifact access")
	}
	if e, err := missing.NewEngine(context.Background()); !errors.Is(err, ErrInstalledArtifact) || e != nil {
		t.Fatal("nil artifact restored")
	}
	for _, e := range []*Engine{nil, {}} {
		if a, err := e.InstalledArtifact(context.Background()); !errors.Is(err, ErrInstalledArtifact) || a != nil {
			t.Fatal("nil/incomplete engine export")
		}
	}
}
