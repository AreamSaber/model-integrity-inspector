package tokenizer

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"sync"

	tiktoken "github.com/tiktoken-go/tokenizer"
)

const BuiltinVersion = "1.0.0"
const ImplementationVersion = "mii-bpe-v1+github.com/tiktoken-go/tokenizer@v0.8.1"
const BuiltinHash = "e63605c54793bca24d79c89ae4e0a66f37e4c8c5409cea795f52e63e7e5024ae"

//go:embed builtin.json
var builtinBytes []byte

var ErrBundle = errors.New("MI_TOKENIZER_BUNDLE_INVALID")

type encodingArtifact struct {
	ID     string `json:"id"`
	Tokens int    `json:"tokens"`
	SHA256 string `json:"sha256"`
}
type modelBinding struct {
	Name     string `json:"name"`
	Encoding string `json:"encoding"`
}
type bundle struct {
	Version        string             `json:"version"`
	Implementation string             `json:"implementation"`
	Reference      string             `json:"reference"`
	Encodings      []encodingArtifact `json:"encodings"`
	Models         []modelBinding     `json:"models"`
	Families       []modelBinding     `json:"families"`
}

type Engine struct {
	bundle bundle
	hash   string
	codecs map[string]counter
	work   chan struct{}
}

var builtinOnce sync.Once
var builtinEngine *Engine
var builtinError error

// NewBuiltin verifies the controlled configuration and reconstructs each
// official rank-file digest from the compiled vocabulary before first use.
// No network, cache directory, user-supplied artifact path or model download is
// involved. The returned engine is immutable and safe for concurrent callers.
func NewBuiltin() (*Engine, error) {
	builtinOnce.Do(func() { builtinEngine, builtinError = Load(builtinBytes, BuiltinHash) })
	return builtinEngine, builtinError
}

func (e *Engine) Version() string { return e.bundle.Version }
func (e *Engine) Hash() string    { return e.hash }

// Load only accepts this binary's frozen canonical bundle and its independently
// supplied expected digest. Updating aliases/quality or artifacts requires a
// reviewed new release, not a catalog record's claimed tokenizer quality.
func Load(data []byte, expectedHash string) (*Engine, error) {
	if len(data) > 32<<10 || expectedHash != BuiltinHash {
		return nil, ErrBundle
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != expectedHash {
		return nil, ErrBundle
	}
	var b bundle
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&b) != nil {
		return nil, ErrBundle
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) || b.Version != BuiltinVersion || b.Implementation != ImplementationVersion || len(b.Encodings) != 2 {
		return nil, ErrBundle
	}
	canonical, err := json.Marshal(b)
	if err != nil || !bytes.Equal(append(canonical, '\n'), data) {
		return nil, ErrBundle
	}
	e := &Engine{bundle: b, hash: expectedHash, codecs: map[string]counter{}, work: make(chan struct{}, 2)}
	for _, artifact := range b.Encodings {
		codec, err := tiktoken.Get(tiktoken.Encoding(artifact.ID))
		if err != nil {
			return nil, ErrBundle
		}
		ranks, err := loadVocabulary(codec, artifact)
		if err != nil {
			return nil, ErrBundle
		}
		bounded, err := newBoundedBPE(artifact.ID, ranks)
		if err != nil {
			return nil, ErrBundle
		}
		e.codecs[artifact.ID] = bounded
	}
	return e, nil
}

func verifyVocabulary(codec tiktoken.Codec, artifact encodingArtifact) error {
	_, err := loadVocabulary(codec, artifact)
	return err
}

func loadVocabulary(codec tiktoken.Codec, artifact encodingArtifact) (map[string]int, error) {
	if artifact.Tokens < 1 || artifact.Tokens > 200000 {
		return nil, ErrBundle
	}
	ranks := make(map[string]int, artifact.Tokens)
	h := sha256.New()
	for rank := 0; rank < artifact.Tokens; rank++ {
		piece, err := codec.Decode([]uint{uint(rank)})
		if err != nil || len(piece) == 0 || len(piece) > 1024 {
			return nil, ErrBundle
		}
		ranks[piece] = rank
		// .tiktoken files are rank-ordered base64(bytes), one space, decimal
		// rank, LF. Token bytes may individually be invalid UTF-8: do not
		// normalize them while verifying the original artifact.
		_, _ = io.WriteString(h, base64.StdEncoding.EncodeToString([]byte(piece)))
		_, _ = io.WriteString(h, " "+strconv.Itoa(rank)+"\n")
	}
	if hex.EncodeToString(h.Sum(nil)) != artifact.SHA256 {
		return nil, ErrBundle
	}
	return ranks, nil
}
