package analyzer

import (
	"errors"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
)

func TestRuntimeRejectsEmptyOrMixedKernels(t *testing.T) {
	tokens, err := tokenrisk.NewDevelopment(tokenrisk.Parameters())
	if err != nil {
		t.Fatal(err)
	}
	scores, err := scoring.NewDevelopment(scoring.Parameters(), tokens)
	if err != nil {
		t.Fatal(err)
	}
	otherRules := tokenrisk.Parameters()
	otherRules.Version = "1.0.0-dev.2"
	other, err := tokenrisk.NewDevelopment(otherRules)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range []struct {
		t *tokenrisk.Engine
		s *scoring.Engine
	}{{nil, scores}, {tokens, nil}, {&tokenrisk.Engine{}, scores}, {tokens, &scoring.Engine{}}, {other, scores}} {
		if _, err := NewDevelopment(pair.t, pair.s); !errors.Is(err, ErrInput) {
			t.Fatal("mixed/empty kernels accepted")
		}
	}
	for _, engine := range []*Engine{nil, {}} {
		if _, err := engine.Analyze(&features.Batch{}); !errors.Is(err, ErrInput) {
			t.Fatal("empty analyzer")
		}
	}
	if _, err := Analyze(nil); !errors.Is(err, ErrInput) {
		t.Fatal("nil legacy input")
	}
	engine, err := NewDevelopment(tokens, scores)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Analyze(&features.Batch{}); err == nil {
		t.Fatal("unbound feature batch accepted")
	}
}
