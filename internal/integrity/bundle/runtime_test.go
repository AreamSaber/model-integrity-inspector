package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
)

func candidate(t *testing.T, version string) RuleArtifact {
	t.Helper()
	a, err := DevelopmentArtifact(version)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func canonicalCandidate(t *testing.T, a RuleArtifact) ([]byte, string) {
	t.Helper()
	data, hash, err := a.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return data, hash
}

func TestRuleArtifactCanonicalAndClosedImplementations(t *testing.T) {
	a := candidate(t, "1.0.0-dev.2")
	data, hash := canonicalCandidate(t, a)
	decoded, err := DecodeRuleArtifact(data, hash)
	if err != nil {
		t.Fatal(err)
	}
	copy, copyHash := canonicalCandidate(t, decoded)
	if !bytes.Equal(data, copy) || hash != copyHash || hash == BuiltinHash {
		t.Fatal("canonical identity lost")
	}
	for name, change := range map[string]func(*RuleArtifact){
		"schema":              func(a *RuleArtifact) { a.SchemaVersion = "mii.unknown.v1" },
		"implementation":      func(a *RuleArtifact) { a.Implementation = "arbitrary.plugin" },
		"published":           func(a *RuleArtifact) { a.Manifest.Status = "published" },
		"builtin-alias":       func(a *RuleArtifact) { a.Manifest.Version = BuiltinVersion },
		"version-mismatch":    func(a *RuleArtifact) { a.Manifest.Scoring.Version = "1.0.0-dev.3" },
		"generator":           func(a *RuleArtifact) { a.Manifest.GeneratorVersion = "arbitrary" },
		"features":            func(a *RuleArtifact) { a.Manifest.FeatureVersion = "arbitrary" },
		"structure":           func(a *RuleArtifact) { a.Manifest.StructureVersion = "arbitrary" },
		"behavior":            func(a *RuleArtifact) { a.Manifest.BehaviorVersion = "arbitrary" },
		"template-hash":       func(a *RuleArtifact) { a.Manifest.Template.SHA256 = strings.Repeat("0", 64) },
		"template-version":    func(a *RuleArtifact) { a.Manifest.Template.Version = "2.0.0" },
		"tokenizer-hash":      func(a *RuleArtifact) { a.Manifest.Tokenizer.SHA256 = strings.Repeat("0", 64) },
		"tokenizer-version":   func(a *RuleArtifact) { a.Manifest.Tokenizer.Version = "unknown" },
		"behavior-minima":     func(a *RuleArtifact) { a.Manifest.BehaviorMinimums[0] = 1 },
		"hypothesis-omission": func(a *RuleArtifact) { a.Manifest.PairedMetrics = a.Manifest.PairedMetrics[:1] },
		"hypothesis-alpha":    func(a *RuleArtifact) { a.Manifest.PairedAlpha = .5 },
		"limitations":         func(a *RuleArtifact) { a.Manifest.Limitations = nil },
		"token-range":         func(a *RuleArtifact) { a.Manifest.TokenRisk.RobustCV = 999 },
		"score-range":         func(a *RuleArtifact) { a.Manifest.Scoring.NoBaselineFactor = 1 },
		"weight":              func(a *RuleArtifact) { a.Manifest.Scoring.OverallWeights[0] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			a := candidate(t, "1.0.0-dev.2")
			change(&a)
			raw, err := json.Marshal(a)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeRuleArtifact(raw, digest(raw)); !errors.Is(err, ErrIntegrity) {
				t.Fatal("unsupported artifact accepted", err)
			}
		})
	}
	a.Manifest.TokenRisk.RobustCV = math.NaN()
	if _, _, err := a.Canonical(); !errors.Is(err, ErrIntegrity) {
		t.Fatal("NaN accepted")
	}
	if _, err := DevelopmentArtifact(BuiltinVersion); !errors.Is(err, ErrIntegrity) {
		t.Fatal("builtin version rebound")
	}
	if _, err := DevelopmentArtifact("1.0.0"); !errors.Is(err, ErrIntegrity) {
		t.Fatal("formal version accepted as development")
	}
}

func TestRuleArtifactRejectsUntrustedJSONAndByteAbuse(t *testing.T) {
	data, hash := canonicalCandidate(t, candidate(t, "1.0.0-dev.2"))
	if _, err := DecodeRuleArtifact(data, strings.Repeat("a", 64)); !errors.Is(err, ErrIntegrity) {
		t.Fatal("wrong hash accepted")
	}
	if _, err := DecodeRuleArtifact(data, strings.ToUpper(hash)); !errors.Is(err, ErrIntegrity) {
		t.Fatal("noncanonical hash accepted")
	}
	for name, raw := range map[string][]byte{
		"top-duplicate":    bytes.Replace(data, []byte(`"schema_version":`), []byte(`"schema_version":"mii.rule-artifact.v1","schema_version":`), 1),
		"nested-duplicate": bytes.Replace(data, []byte(`"RobustCV":0.1`), []byte(`"RobustCV":0.1,"RobustCV":0.1`), 1),
		"case-alias":       bytes.Replace(data, []byte(`"RobustCV":`), []byte(`"robustcv":`), 1),
		"unknown-trust":    bytes.Replace(data, []byte(`"implementation":`), []byte(`"calibrated":true,"implementation":`), 1),
		"unknown-secret":   bytes.Replace(data, []byte(`"RobustCV":`), []byte(`"private_body":"S2_SENTINEL_MUST_NOT_ECHO","RobustCV":`), 1),
		"null":             []byte("null"), "array": []byte("[]"), "missing": []byte("{}"),
		"trailing": append(bytes.Clone(data), []byte("{}")...), "whitespace": append(bytes.Clone(data), '\n'),
		"invalid-utf8": append(bytes.Clone(data), 0xff), "giant-utf8": []byte(strings.Repeat("密", MaxArtifactBytes/3+1)),
		"bad-number": bytes.Replace(data, []byte(`"RobustCV":0.1`), []byte(`"RobustCV":1e9999`), 1),
		"malformed":  []byte(`{"schema_version":`),
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(raw, data) {
				t.Fatal("mutation missed source")
			}
			_, err := DecodeRuleArtifact(raw, digest(raw))
			if !errors.Is(err, ErrIntegrity) || strings.Contains(err.Error(), "S2_SENTINEL") {
				t.Fatal("untrusted JSON accepted or leaked", err)
			}
		})
	}
}

func TestResolverImmutableBoundedAndConcurrent(t *testing.T) {
	r, err := NewResolver()
	if err != nil {
		t.Fatal(err)
	}
	installed, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := r.Resolve(installed.RuleBytes(), BuiltinHash)
	if err != nil || legacy.Ref().Version != BuiltinVersion || legacy.Ref().SHA256 != BuiltinHash {
		t.Fatal("builtin unresolved", err)
	}
	a := candidate(t, "1.0.0-dev.2")
	data, hash := canonicalCandidate(t, a)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			runtime, err := r.Resolve(data, hash)
			if err != nil || runtime.Ref().SHA256 != hash {
				t.Error("concurrent resolution", err)
			}
		})
	}
	wg.Wait()
	a.Manifest.TokenRisk.RobustCV = .01
	tokens, err := tokenrisk.NewDevelopment(a.Manifest.TokenRisk)
	if err != nil {
		t.Fatal(err)
	}
	a.Manifest.Scoring.TokenRulesHash = tokens.Hash()
	conflict, conflictHash := canonicalCandidate(t, a)
	if _, err := r.Resolve(conflict, conflictHash); !errors.Is(err, ErrImmutable) {
		t.Fatal("same version mutable", err)
	}
	data[0] = 'x'
	if _, err := r.Resolve(data, hash); !errors.Is(err, ErrIntegrity) {
		t.Fatal("mutated bytes accepted")
	}
	ref := legacy.Ref()
	ref.SHA256 = "changed"
	if legacy.Ref().SHA256 != BuiltinHash {
		t.Fatal("reference mutation")
	}
	for n := 3; n <= MaxRuntimeVersions; n++ {
		data, hash := canonicalCandidate(t, candidate(t, fmt.Sprintf("1.0.0-dev.%d", n)))
		if _, err := r.Resolve(data, hash); err != nil {
			t.Fatal(err)
		}
	}
	data, hash = canonicalCandidate(t, candidate(t, "2.0.0-dev.1"))
	if _, err := r.Resolve(data, hash); !errors.Is(err, ErrIntegrity) {
		t.Fatal("unbounded registry")
	}
	for _, resolver := range []*Resolver{nil, {}} {
		if _, err := resolver.Resolve(data, hash); !errors.Is(err, ErrIntegrity) {
			t.Fatal("zero resolver")
		}
	}
	for _, runtime := range []*Runtime{nil, {}} {
		if _, err := runtime.Analyze(&features.Batch{}); !errors.Is(err, ErrIntegrity) {
			t.Fatal("zero runtime")
		}
		if runtime.Ref() != (RuntimeRef{}) {
			t.Fatal("zero ref")
		}
	}
	if _, err := legacy.Analyze(nil); !errors.Is(err, ErrIntegrity) {
		t.Fatal("nil batch")
	}
	if _, err := legacy.Analyze(&features.Batch{}); !errors.Is(err, ErrIntegrity) {
		t.Fatal("unbound batch")
	}
	if _, err := r.Resolve([]byte("{}"), BuiltinHash); !errors.Is(err, ErrIntegrity) {
		t.Fatal("builtin hash without bytes")
	}
}

func FuzzRuleArtifactDecoder(f *testing.F) {
	a, err := DevelopmentArtifact("1.0.0-dev.2")
	if err != nil {
		f.Fatal(err)
	}
	seed, _, err := a.Canonical()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"schema_version":"unknown","calibrated":true}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := DecodeRuleArtifact(data, digest(data))
		if err != nil {
			return
		}
		canonical, hash, err := decoded.Canonical()
		if err != nil || !bytes.Equal(canonical, data) || hash != digest(data) || decoded.Manifest.Status != "development_uncalibrated" || decoded.Manifest.Version == BuiltinVersion {
			t.Fatal("decoder escaped canonical development domain")
		}
	})
}
