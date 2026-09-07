package tokenrisk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
)

var ErrRules = errors.New("MI_TOKEN_RULES_UNSUPPORTED")
var developmentVersion = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})-dev\.([1-9][0-9]{0,5})$`)

// Engine is an immutable development configuration, not a release approval or
// proof that input observations originated from a trusted source.
type Engine struct {
	rules Rules
	hash  string
}

// NewDevelopment admits only this implementation's finite development knobs.
// All other fields, including weights, sample minima and evidence caps, remain
// frozen. A changed parameter set cannot impersonate the original version.
func NewDevelopment(r Rules) (*Engine, error) {
	base := Parameters()
	if !developmentVersion.MatchString(r.Version) || !finite(r.RobustCV) || r.RobustCV < .01 || r.RobustCV > .20 || !finite(r.UsageDirectionFraction) || r.UsageDirectionFraction < .8 || r.UsageDirectionFraction > 1 || r.BootstrapReplicates < 128 || r.BootstrapReplicates > 4096 || r.BootstrapReplicates&(r.BootstrapReplicates-1) != 0 {
		return nil, ErrRules
	}
	if r.Version == Version && r != base {
		return nil, ErrRules
	}
	allowed := base
	allowed.Version, allowed.RobustCV, allowed.UsageDirectionFraction, allowed.BootstrapReplicates = r.Version, r.RobustCV, r.UsageDirectionFraction, r.BootstrapReplicates
	if r != allowed {
		return nil, ErrRules
	}
	return &Engine{rules: r, hash: hashRules(r)}, nil
}

func hashRules(r Rules) string {
	data, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
func builtinEngine() *Engine { return &Engine{rules: Parameters(), hash: RulesHash()} }
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
	if e == nil || e.hash == "" {
		return Result{}, ErrRules
	}
	return e.analyze(input)
}
