package bundle

import (
	"bytes"
	"errors"
	"sync"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
	"model-integrity-inspector.local/mii/internal/integrity/analyzer"
)

var ErrImmutable = errors.New("MI_RUNTIME_BUNDLE_IMMUTABLE")

// RuntimeRef is an S1 identity projection, NOT a mintable publication capability.
type RuntimeRef struct {
	Version, SHA256, SchemaVersion, Implementation string
	ScoringHash, TokenRulesHash                    string
	Template, Tokenizer                            ArtifactRef
}

type Runtime struct {
	ref    RuntimeRef
	engine *analyzer.Engine
}

func (r *Runtime) Ref() RuntimeRef {
	if r == nil {
		return RuntimeRef{}
	}
	return r.ref
}
func (r *Runtime) Analyze(batch *features.Batch) (analyzer.Document, error) {
	if r == nil || r.engine == nil || batch == nil {
		return analyzer.Document{}, ErrIntegrity
	}
	templateHash, tokenizerHash := batch.ArtifactHashes()
	if templateHash != r.ref.Template.SHA256 || tokenizerHash != r.ref.Tokenizer.SHA256 {
		return analyzer.Document{}, ErrIntegrity
	}
	return r.engine.Analyze(batch)
}

// Resolver is a bounded process-local installed-code registry. It does not
// replace durable tenant version immutability or production release admission.
// Only the builtin and validated DEVELOPMENT candidates are resolvable here.
type Resolver struct {
	mu       sync.Mutex
	runtimes map[string]*Runtime
	builtin  []byte
}

const MaxRuntimeVersions = 64

func NewResolver() (*Resolver, error) {
	installed, err := Builtin()
	if err != nil {
		return nil, err
	}
	m, err := defaultManifest()
	if err != nil {
		return nil, err
	}
	tokens, err := tokenrisk.NewDevelopment(m.TokenRisk)
	if err != nil {
		return nil, ErrIntegrity
	}
	scores, err := scoring.NewDevelopment(m.Scoring, tokens)
	if err != nil {
		return nil, ErrIntegrity
	}
	runtime, err := makeRuntime(m, BuiltinHash, m.SchemaVersion, tokens, scores)
	if err != nil {
		return nil, err
	}
	return &Resolver{runtimes: map[string]*Runtime{BuiltinVersion: runtime}, builtin: installed.RuleBytes()}, nil
}

func makeRuntime(m Manifest, hash, schema string, tokens *tokenrisk.Engine, scores *scoring.Engine) (*Runtime, error) {
	engine, err := analyzer.NewDevelopment(tokens, scores)
	if err != nil {
		return nil, ErrIntegrity
	}
	return &Runtime{ref: RuntimeRef{m.Version, hash, schema, DevelopmentImplementation, scores.Hash(), tokens.Hash(), m.Template, m.Tokenizer}, engine: engine}, nil
}

func (r *Resolver) Resolve(data []byte, expectedHash string) (*Runtime, error) {
	if r == nil || r.runtimes == nil || len(data) > MaxArtifactBytes {
		return nil, ErrIntegrity
	}
	if expectedHash == BuiltinHash {
		if !bytes.Equal(data, r.builtin) {
			return nil, ErrIntegrity
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.runtimes[BuiltinVersion], nil
	}
	a, err := DecodeRuleArtifact(data, expectedHash)
	if err != nil {
		return nil, err
	}
	tokens, scores, err := a.kernels()
	if err != nil {
		return nil, err
	}
	runtime, err := makeRuntime(a.Manifest, expectedHash, a.SchemaVersion, tokens, scores)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if old := r.runtimes[a.Manifest.Version]; old != nil {
		if old.ref.SHA256 != expectedHash {
			return nil, ErrImmutable
		}
		return old, nil
	}
	if len(r.runtimes) >= MaxRuntimeVersions {
		return nil, ErrIntegrity
	}
	r.runtimes[a.Manifest.Version] = runtime
	return runtime, nil
}
