package scoring

import (
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/behavior"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func finite(n float64) bool     { return !math.IsNaN(n) && !math.IsInf(n, 0) }
func unit(n float64) bool       { return finite(n) && n >= 0 && n <= 1 }
func score(n float64) bool      { return finite(n) && n >= 0 && n <= 100 }
func number(n float64) *float64 { return &n }
func copyNumber(n *float64) *float64 {
	if n == nil {
		return nil
	}
	return number(*n)
}
func ratio(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}
func identifier(s string, max int) bool {
	return len(s) > 0 && len(s) <= max && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n\t ")
}
func positiveID(s string) bool {
	n, err := strconv.ParseInt(s, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == s
}
func auxiliary(s Observation) bool { return s.AuxiliaryOnly || s.Family == "self_report" }
func included(s Observation) bool  { return s.Included && !auxiliary(s) }
func behaviorFamily(s string) bool {
	return slices.Contains([]string{"format", "neutral", "differential", "style"}, s)
}
func observed(s ObservationState) bool { return s != Unobserved }
func validState(s ObservationState) bool {
	return slices.Contains([]ObservationState{Unobserved, Normal, Anomalous, Missing, Invalid}, s)
}

func (e *Engine) validate(input Input) (map[string]Observation, error) {
	if len(input.Samples) > MaxSamples {
		return nil, ErrLimit
	}
	if input.ExpectedSamples < 0 || input.ExpectedSamples > MaxSamples || input.ExpectedSamples < len(input.Samples) {
		return nil, ErrInput
	}
	byID := make(map[string]Observation, len(input.Samples))
	valid := 0
	for _, s := range input.Samples {
		if !positiveID(s.SampleID) || !identifier(s.Language, 32) || !identifier(s.TemplateID, 128) || !identifier(s.ClusterID, 128) || !slices.Contains([]string{"sequence", "jsonl", "format", "neutral", "differential", "style", "self_report"}, s.Family) {
			return nil, ErrInput
		}
		if _, exists := byID[s.SampleID]; exists {
			return nil, ErrInput
		}
		if s.Tokenizer != "" && !slices.Contains([]tokenizer.Quality{tokenizer.Exact, tokenizer.Compatible, tokenizer.Heuristic, tokenizer.Unavailable}, s.Tokenizer) {
			return nil, ErrInput
		}
		if s.Protocol != nil {
			for _, v := range []ObservationState{s.Protocol.Usage, s.Protocol.HTTP, s.Protocol.ModelEcho, s.Protocol.Finish, s.Protocol.Termination} {
				if !validState(v) {
					return nil, ErrInput
				}
			}
		}
		byID[s.SampleID] = s
		if included(s) {
			valid++
		}
	}
	if input.Behavior != nil {
		b := input.Behavior
		if len(b.Samples)+len(b.Auxiliary) > MaxSamples || len(b.Patterns) > MaxSamples*4 {
			return nil, ErrLimit
		}
		if b.Version != behavior.Version || b.RuleStatus != "development_uncalibrated" {
			return nil, ErrInput
		}
		seen := map[string]bool{}
		for _, set := range [][]behavior.Features{b.Samples, b.Auxiliary} {
			for _, f := range set {
				s, exists := byID[f.SampleID]
				if !exists || seen[f.SampleID] || f.Version != behavior.Version || len(f.Evidence) > 16 || !slices.Contains([]behavior.State{behavior.Analyzed, behavior.Excluded, behavior.Auxiliary}, f.State) {
					return nil, ErrInput
				}
				seen[f.SampleID] = true
				if f.State == behavior.Analyzed && (!included(s) || !behaviorFamily(s.Family)) {
					return nil, ErrInput
				}
				if !slices.Contains([]behavior.ContractState{behavior.Matches, behavior.Deviates, behavior.ContractNotApplicable}, f.Contract) || !slices.Contains([]behavior.CueClass{behavior.CueNotApplicable, behavior.NoCue, behavior.RefusalLike}, f.Refusal) || !slices.Contains([]behavior.CueClass{behavior.CueNotApplicable, behavior.NoCue, behavior.IdentityLike}, f.Identity) {
					return nil, ErrInput
				}
				for _, e := range f.Evidence {
					if e.SampleID != f.SampleID || !identifier(e.NormalizedSHA256, 64) || e.StartByte < 0 || e.EndByte < e.StartByte || e.EndByte > behavior.MaxTextBytes {
						return nil, ErrInput
					}
				}
			}
		}
		evidenceCount := 0
		for _, p := range b.Patterns {
			evidenceCount += len(p.Evidence)
			if evidenceCount > MaxSamples*16 {
				return nil, ErrLimit
			}
			if len(p.Evidence) > MaxSamples || len(p.Coverage) > 7 || !slices.Contains([]behavior.PatternState{behavior.StablePattern, behavior.InsufficientPattern}, p.State) {
				return nil, ErrInput
			}
			for _, e := range p.Evidence {
				if !seen[e.SampleID] {
					return nil, ErrInput
				}
			}
		}
	}
	if input.Tokens != nil {
		t := input.Tokens
		if t.Version != e.rules.TokenVersion || t.RulesHash != e.rules.TokenRulesHash || !t.Development || t.Calibrated || t.ExpectedSamples != input.ExpectedSamples || t.ValidSamples != valid || t.FinalSamples < valid || t.FinalSamples > len(input.Samples) || t.ObservedLogicalSamples < t.FinalSamples || t.ObservedLogicalSamples > len(input.Samples) || t.IgnoredAttempts < 0 || t.DuplicateFinals < 0 || t.MissingFinals != t.ObservedLogicalSamples-t.FinalSamples {
			return nil, ErrInput
		}
		if len(t.Series) > tokenrisk.MaxSeries || len(t.Plateaus) > MaxSamples || len(t.Token.Limitations) > 128 || len(t.Response.Limitations) > 128 {
			return nil, ErrLimit
		}
		rules := e.tokens.Rules()
		if !validAggregate(t.Token, []string{"plateau", "termination", "usage", "stream_difference"}, rules.TokenWeights) || !validAggregate(t.Response, []string{"sse_termination", "fixed_suffix", "metadata_consistency", "protocol_anomaly"}, rules.ResponseWeights) {
			return nil, ErrInput
		}
		for _, series := range t.Series {
			if len(series.Tiers) > MaxSamples || !identifier(series.Family, 64) {
				return nil, ErrInput
			}
			for _, tier := range series.Tiers {
				if tier.Samples < 0 || tier.Samples > valid || !finite(tier.RobustCV) || tier.RobustCV < 0 {
					return nil, ErrInput
				}
			}
		}
		for _, list := range [][]string{t.Token.Limitations, t.Response.Limitations} {
			for _, code := range list {
				if !identifier(code, 128) || !strings.HasPrefix(code, "MI_") {
					return nil, ErrInput
				}
			}
		}
		for _, p := range t.Plateaus {
			if !score(p.Strength) || len(p.SampleIDs) > MaxSamples {
				return nil, ErrInput
			}
			for _, id := range p.SampleIDs {
				s, exists := byID[strconv.FormatInt(id, 10)]
				if !exists || !included(s) || s.Family != p.Family {
					return nil, ErrInput
				}
			}
		}
	}
	return byID, nil
}

func validAggregate(a tokenrisk.Aggregate, names []string, weights [4]float64) bool {
	if len(a.Components) != 4 || a.Strength != nil && !score(*a.Strength) {
		return false
	}
	weight, total := 0.0, 0.0
	for i, c := range a.Components {
		if c.Name != names[i] || c.Weight != weights[i] || !score(c.Strength) || !unit(c.EffectiveWeight) {
			return false
		}
		if c.Available {
			weight += c.Weight
			total += c.Weight * c.Strength
		} else if c.EffectiveWeight != 0 {
			return false
		}
	}
	if (weight == 0) != (a.Strength == nil) {
		return false
	}
	for _, c := range a.Components {
		if c.Available && math.Abs(c.EffectiveWeight-c.Weight/weight) > 1e-9 {
			return false
		}
	}
	// Upstream may cap a strength, but may never exceed its weighted evidence.
	return a.Strength == nil || *a.Strength <= total/weight+1e-9
}
