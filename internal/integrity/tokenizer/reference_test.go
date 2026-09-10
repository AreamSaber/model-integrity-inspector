package tokenizer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"os"
	"os/exec"
	"strings"
	"testing"
)

type referenceFixture struct {
	Reference    string     `json:"reference"`
	CorpusSHA256 string     `json:"corpus_sha256"`
	Counts       [][2]int64 `json:"counts"`
}

func referenceCorpus() []string {
	texts := []string{"hello world", "antidisestablishmentarianism", "お誕生日おめでとう", "中文标点，模型输出。", "I'm I'VE can't we'd don't", "\t\r\n  \n \t", "e\u0301 café naïve", "👨‍👩‍👧‍👦🏳️‍🌈👍🏽", "<|endoftext|> <|fim_prefix|>", "\u0000\u0001\u007f", "01234567890123456789", "{\"tag\":\"synthetic\",\"n\":123}\n"}
	fragments := []string{"Alpha", "beta", "'ll", "'s", " ", "\n", "\t", "42", "中文", "。", "日本語", "مرحبا", "हिन्दी", "é", "e\u0301", "👋🏽", "🦊", "{}", "[]", "_|", "/", "\r\n"}
	// #nosec G404 -- Fixed-seed synthetic differential corpus, not security randomness.
	rng := rand.New(rand.NewPCG(17, 42))
	for range 256 {
		var text strings.Builder
		for n := rng.IntN(40) + 1; n > 0; n-- {
			text.WriteString(fragments[rng.IntN(len(fragments))])
		}
		texts = append(texts, text.String())
	}
	for _, a := range fragments {
		for _, b := range fragments {
			texts = append(texts, a+b)
		}
	}
	texts = append(texts, "\r\n\t\r\n\t", "\n \n\n", " éé42", "'llé", "{}éé", "🦊हिन्दी", " 's中文é")
	return texts
}

func TestDifferentialOfficialTiktoken014(t *testing.T) {
	python := os.Getenv("MII_TOKENIZER_REFERENCE_PYTHON")
	if python == "" {
		t.Skip("optional official tiktoken 0.14.0 oracle not configured; deterministic published vectors still run")
	}
	corpus := referenceCorpus()
	data, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G204 G702 -- Explicit operator-selected local Python test oracle, never runtime/user input.
	command := exec.CommandContext(t.Context(), python, "testdata/reference.py")
	command.Stdin = bytes.NewReader(data)
	output, err := command.Output()
	if err != nil {
		t.Fatal("official tokenizer reference failed")
	}
	var expected [][2]int64
	if json.Unmarshal(output, &expected) != nil || len(expected) != len(corpus) {
		t.Fatal("invalid oracle result")
	}
	if os.Getenv("MII_TOKENIZER_EXPORT_FIXTURE") == "1" {
		sum := sha256.Sum256(data)
		fixture, err := json.Marshal(referenceFixture{Reference: "openai/tiktoken@0.14.0", CorpusSHA256: hex.EncodeToString(sum[:]), Counts: expected})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("ORACLE_FIXTURE:%s", fixture)
	}
	checkReferenceCounts(t, corpus, expected)
}

func TestFrozenOfficialReferenceCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/reference_counts.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture referenceFixture
	if json.Unmarshal(data, &fixture) != nil || fixture.Reference != "openai/tiktoken@0.14.0" {
		t.Fatal("invalid frozen reference fixture")
	}
	corpus := referenceCorpus()
	canonical, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	if hex.EncodeToString(sum[:]) != fixture.CorpusSHA256 || len(fixture.Counts) != len(corpus) {
		t.Fatal("corpus changed without official reference regeneration")
	}
	checkReferenceCounts(t, corpus, fixture.Counts)
}

func checkReferenceCounts(t *testing.T, corpus []string, expected [][2]int64) {
	t.Helper()
	e := testEngine(t)
	for i, text := range corpus {
		for j, model := range []string{"gpt-4", "gpt-4o"} {
			got, err := e.CountOutput(text, Selection{RequestedModel: model})
			if err != nil || got.Quality != Exact || got.Tokens == nil || *got.Tokens != expected[i][j] {
				t.Errorf("differential fixture %d encoding %d: got %+v expected count %d; no content logged", i, j, got, expected[i][j])
			}
		}
	}
}
