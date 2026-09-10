package scoring

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
)

var ErrRules = errors.New("MI_SCORING_RULES_UNSUPPORTED")

// Engine contains only validated development parameters. Neither an Engine nor
// its hash authenticates observations, approves a release, or enables A/B.
type Engine struct {
	rules  Rules
	hash   string
	tokens *tokenrisk.Engine
}

func NewDevelopment(r Rules, tokens *tokenrisk.Engine) (*Engine, error) {
	base := Parameters()
	if tokens == nil || tokens.Hash() == "" || r.Version != tokens.Rules().Version || r.TokenVersion != tokens.Rules().Version || r.TokenRulesHash != tokens.Hash() || !finite(r.StableFraction) || r.StableFraction < .8 || r.StableFraction > 1 || !finite(r.NoBaselineFactor) || r.NoBaselineFactor < .1 || r.NoBaselineFactor > .8 || !finite(r.MissingDimensionFactor) || r.MissingDimensionFactor < .1 || r.MissingDimensionFactor > .75 {
		return nil, ErrRules
	}
	if r.Version == Version && r != base {
		return nil, ErrRules
	}
	allowed := base
	allowed.Version, allowed.TokenVersion, allowed.TokenRulesHash = r.Version, r.TokenVersion, r.TokenRulesHash
	allowed.StableFraction, allowed.NoBaselineFactor, allowed.MissingDimensionFactor = r.StableFraction, r.NoBaselineFactor, r.MissingDimensionFactor
	if r != allowed {
		return nil, ErrRules
	}
	data, err := json.Marshal(r)
	if err != nil {
		return nil, ErrRules
	}
	hash := sha256.Sum256(data)
	return &Engine{rules: r, hash: hex.EncodeToString(hash[:]), tokens: tokens}, nil
}

func builtinEngine() *Engine {
	tokens, _ := tokenrisk.NewDevelopment(tokenrisk.Parameters())
	return &Engine{rules: Parameters(), hash: RulesHash(), tokens: tokens}
}
func (e *Engine) Rules() Rules {
	if e == nil {
		return Rules{}
	}
	return e.rules
}
func (e *Engine) Hash() string {
	if e == nil {
		return ""
	}
	return e.hash
}
func (e *Engine) Analyze(input Input) (Result, error) {
	if e == nil || e.hash == "" || e.tokens == nil {
		return Result{}, ErrRules
	}
	return e.analyze(input, releasePolicy{})
}
