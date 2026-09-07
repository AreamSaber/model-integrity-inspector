package features

import (
	"errors"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func TestOpaqueRuntimeInjectionRetainsLifetimeAndArtifactBinding(t *testing.T) {
	f := newFixture(t, nil)
	batch, err := f.builder.Build(f.input)
	if err != nil {
		t.Fatal(err)
	}
	templateHash, tokenHash := batch.ArtifactHashes()
	if templateHash != templates.BuiltinHash || tokenHash != tokenizer.BuiltinHash {
		t.Fatal("artifact hashes not bound")
	}
	rules := tokenrisk.Parameters()
	rules.Version = "1.0.0-dev.2"
	rules.BootstrapReplicates = 128
	engine, err := tokenrisk.NewDevelopment(rules)
	if err != nil {
		t.Fatal(err)
	}
	var escaped OpaqueTokenInput
	if err := batch.WithTokenInput(func(input OpaqueTokenInput) error {
		escaped = input
		if _, err := input.AnalyzeWith(nil); !errors.Is(err, ErrConfiguration) {
			t.Fatal("nil engine")
		}
		result, err := input.AnalyzeWith(engine)
		if err != nil || result.Version != rules.Version || result.RulesHash != engine.Hash() {
			t.Fatal("selected runtime not used", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := escaped.AnalyzeWith(engine); !errors.Is(err, ErrConfiguration) {
		t.Fatal("expired opaque input usable")
	}
	if _, err := (OpaqueTokenInput{}).AnalyzeWith(engine); !errors.Is(err, ErrConfiguration) {
		t.Fatal("zero opaque input usable")
	}
	var empty *Batch
	a, b := empty.ArtifactHashes()
	if a != "" || b != "" {
		t.Fatal("nil batch artifacts")
	}
}
