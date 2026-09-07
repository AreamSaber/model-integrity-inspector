package analyzer

import (
	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
)

// Engine executes only a coherent pair of immutable development kernels. It
// is not authorization to load evidence or publish/calibrate a rule release.
type Engine struct {
	tokens *tokenrisk.Engine
	scores *scoring.Engine
}

func NewDevelopment(tokens *tokenrisk.Engine, scores *scoring.Engine) (*Engine, error) {
	if tokens == nil || tokens.Hash() == "" || scores == nil || scores.Hash() == "" || scores.Rules().TokenVersion != tokens.Rules().Version || scores.Rules().TokenRulesHash != tokens.Hash() {
		return nil, ErrInput
	}
	return &Engine{tokens: tokens, scores: scores}, nil
}

func (e *Engine) Analyze(batch *features.Batch) (Document, error) {
	if e == nil || e.tokens == nil || e.scores == nil {
		return Document{}, ErrInput
	}
	return e.analyze(batch)
}
