package scoring

import (
	"math"
	"slices"
	"sort"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

// Analyze has no configurable trust flags or arbitrary score inputs. Its caller
// must assemble the projections from the authenticated immutable Run snapshot.
func Analyze(input Input) (Result, error) {
	return builtinEngine().Analyze(input)
}

func (e *Engine) analyze(input Input, policy releasePolicy) (Result, error) {
	byID, err := e.validate(input)
	if err != nil {
		return Result{}, err
	}
	rules := e.rules
	out := Result{Version: rules.Version, RulesHash: e.hash, Development: !policy.calibrated(e.hash), Calibrated: policy.calibrated(e.hash), ExpectedSamples: input.ExpectedSamples, Completeness: "COMPLETE", EvidenceGrade: "D", RiskLevel: "insufficient", Conclusion: "INSUFFICIENT_EVIDENCE", Limitations: []string{"MI_BASELINE_UNAVAILABLE", "MI_GATEWAY_EVIDENCE_UNAVAILABLE"}}
	if !out.Calibrated {
		out.Limitations = append(out.Limitations, "MI_DEVELOPMENT_RULES_UNCALIBRATED")
	}
	families := map[string]bool{}
	for _, s := range input.Samples {
		if included(s) {
			out.ValidSamples++
			families[s.Family] = true
		}
	}
	out.IndependentFamilies = len(families)
	var support map[string]*familySupport
	out.Prompt, support, err = e.prompt(input, byID)
	if err != nil {
		return Result{}, err
	}
	out.StableHitFamilies = e.stableFamilies(support)
	if input.Tokens != nil {
		out.TokenRulesHash = input.Tokens.RulesHash
		out.Token = fromTokenAggregate(input.Tokens.Token)
		out.Response = fromTokenAggregate(input.Tokens.Response)
	} else {
		out.Token = missingDimension("MI_TOKEN_AGGREGATE_UNAVAILABLE")
		out.Response = missingDimension("MI_RESPONSE_AGGREGATE_UNAVAILABLE")
	}
	out.Protocol = e.protocolRisk(input, out.ValidSamples)
	out.Overall = Dimension{Components: []Component{}, Limitations: []string{}}
	for i, item := range []struct {
		name string
		d    Dimension
	}{{"prompt", out.Prompt}, {"token", out.Token}, {"response", out.Response}, {"protocol_and_evidence", out.Protocol}} {
		out.Overall.Components = append(out.Overall.Components, Component{Name: item.name, Score: copyNumber(item.d.Score), Weight: rules.OverallWeights[i]})
		if item.d.Limited {
			out.Completeness = "PARTIAL"
			for _, code := range item.d.Limitations {
				out.Limitations = appendCode(out.Limitations, code)
			}
		}
	}
	combine(&out.Overall)
	if out.Overall.Score != nil {
		*out.Overall.Score = math.Round(*out.Overall.Score)
	}
	if input.Partial || len(input.Samples) < input.ExpectedSamples || input.Tokens != nil && input.Tokens.Partial {
		out.Completeness = "PARTIAL"
		out.Limitations = appendCode(out.Limitations, "MI_PARTIAL_RESULT")
	}
	out.Confidence = e.confidence(input, support, out.Completeness == "PARTIAL", policy)
	for _, code := range out.Confidence.Limitations {
		out.Limitations = appendCode(out.Limitations, code)
	}
	if out.ValidSamples == 0 {
		out.Overall.Score = nil
		out.Completeness = "INSUFFICIENT"
		out.Limitations = appendCode(out.Limitations, "MI_NO_VALID_SAMPLES")
	} else if out.ValidSamples < rules.MinimumValid || criticalFraction(input) < rules.MinimumCriticalFraction || out.Overall.Score == nil {
		out.Completeness = "INSUFFICIENT"
		out.Limitations = appendCode(out.Limitations, "MI_CRITICAL_EVIDENCE_INSUFFICIENT")
	} else {
		out.RiskLevel = e.level(*out.Overall.Score)
		if hasAnomaly(out) {
			out.EvidenceGrade = "C"
			out.Conclusion = "OBSERVED_ANOMALY_REQUIRES_REVIEW"
		} else {
			out.Conclusion = "NO_OBVIOUS_ANOMALY_OBSERVED"
		}
		// A cannot be produced here: no verified gateway evidence capability.
		// A future authenticated calibration admission may enable statistical B.
		if policy.calibrated(e.hash) && out.Completeness == "COMPLETE" && out.Confidence.Score >= int(rules.HighEvidenceConfidence) && (out.StableHitFamilies >= rules.MinimumHitFamilies && *out.Overall.Score >= rules.HighEvidenceRisk || !hasAnomaly(out)) {
			out.EvidenceGrade = "B"
		}
	}
	if out.Completeness != "COMPLETE" {
		out.Overall.Limited = true
		out.Overall.Limitations = appendCode(out.Overall.Limitations, "MI_RESULT_INCOMPLETE")
	}
	sort.Strings(out.Limitations)
	return out, nil
}

func fromTokenAggregate(a tokenrisk.Aggregate) Dimension {
	d := Dimension{Score: copyNumber(a.Strength), Limited: a.Limited, Limitations: append([]string{}, a.Limitations...), Components: []Component{}}
	for _, c := range a.Components {
		part := Component{Name: c.Name, Weight: c.Weight, EffectiveWeight: c.EffectiveWeight}
		if c.Available {
			part.Score = number(c.Strength)
		}
		d.Components = append(d.Components, part)
	}
	return d
}

func missingDimension(reason string) Dimension {
	return Dimension{Components: []Component{}, Limited: true, Limitations: []string{reason}}
}
func hasAnomaly(r Result) bool {
	for _, d := range []Dimension{r.Prompt, r.Token, r.Response, r.Protocol} {
		if d.Score != nil && *d.Score > 0 {
			return true
		}
	}
	return false
}
func level(n float64) string {
	return builtinEngine().level(n)
}
func (e *Engine) level(n float64) string {
	for i, v := range e.rules.Bands {
		if n < v {
			return []string{"low", "attention", "medium", "high"}[i]
		}
	}
	return "severe_black_box_statistical_judgment"
}

func (e *Engine) protocolRisk(input Input, valid int) Dimension {
	rules := e.rules
	d := Dimension{Components: make([]Component, 6), Limitations: []string{"MI_PROTOCOL_SCORE_NOT_PROVIDER_MISCONDUCT"}}
	for i, name := range []string{"usage_quality", "http_content_type", "model_echo", "finish_reason", "tokenizer_unavailable", "valid_sample_rate"} {
		d.Components[i] = Component{Name: name, Weight: rules.ProtocolWeights[i]}
	}
	aux := 0
	for _, s := range input.Samples {
		if auxiliary(s) {
			aux++
			continue
		}
		if s.Protocol != nil {
			for i, value := range []ObservationState{s.Protocol.Usage, s.Protocol.HTTP, s.Protocol.ModelEcho, s.Protocol.Finish} {
				if observed(value) {
					d.Components[i].Applicable++
					if value != Normal {
						d.Components[i].Positive++
					}
				}
			}
		}
		if s.Tokenizer != "" {
			d.Components[4].Applicable++
			if s.Tokenizer == tokenizer.Unavailable {
				d.Components[4].Positive++
			}
		}
	}
	d.Components[5].Applicable = input.ExpectedSamples - aux
	d.Components[5].Positive = d.Components[5].Applicable - valid
	for i := range d.Components {
		c := &d.Components[i]
		if c.Applicable > 0 {
			c.Score = number(100 * ratio(c.Positive, c.Applicable))
		}
	}
	combine(&d)
	return d
}

func criticalFraction(input Input) float64 {
	valid, critical := 0, 0
	for _, s := range input.Samples {
		if included(s) {
			valid++
			if s.Protocol != nil && s.Protocol.HTTP == Normal && s.Protocol.Finish == Normal && s.Protocol.Termination == Normal {
				critical++
			}
		}
	}
	return ratio(critical, valid)
}

func (e *Engine) confidence(input Input, support map[string]*familySupport, partial bool, policy releasePolicy) Confidence {
	rules := e.rules
	c := Confidence{BaselineFactor: rules.NoBaselineFactor, Limitations: []string{"MI_BASELINE_UNAVAILABLE"}}
	valid, aux := 0, 0
	quality, applicable := 0.0, 0.0
	groups := map[string]map[string]bool{}
	for _, s := range input.Samples {
		if auxiliary(s) {
			aux++
			continue
		}
		if !included(s) {
			continue
		}
		valid++
		if groups[s.Family] == nil {
			groups[s.Family] = map[string]bool{}
		}
		groups[s.Family][s.ClusterID] = true
		tokenQuality := 0.0
		switch s.Tokenizer {
		case tokenizer.Exact:
			tokenQuality = 1
		case tokenizer.Compatible:
			tokenQuality = rules.CompatibleQuality
		case tokenizer.Heuristic:
			tokenQuality = rules.HeuristicQuality
			c.Limitations = appendCode(c.Limitations, "MI_TOKENIZER_HEURISTIC_LIMIT")
		default:
			c.Limitations = appendCode(c.Limitations, "MI_TOKENIZER_UNAVAILABLE")
		}
		termination, usage := 0.0, 0.0
		if s.Protocol != nil {
			if s.Protocol.Termination == Normal && s.Protocol.Finish == Normal {
				termination = 1
			}
			if s.Protocol.Usage == Normal {
				usage = 1
			}
		}
		quality += rules.QualityWeights[0]*termination + rules.QualityWeights[1]*usage + rules.QualityWeights[2]*tokenQuality
		if s.ReasoningUnseparated {
			c.Limitations = appendCode(c.Limitations, "MI_REASONING_UNSEPARATED")
		} else {
			applicable++
		}
	}
	c.SampleFactor = ratio(valid, input.ExpectedSamples-aux)
	if valid > 0 {
		c.EvidenceQualityFactor = quality / float64(valid)
		c.ApplicabilityFactor = applicable / float64(valid)
	}
	// Floating-point addition is order-sensitive. Keep identical observations
	// byte-reproducible across raw/derived paths and independent process runs.
	families := make([]string, 0, len(groups))
	for family := range groups {
		families = append(families, family)
	}
	slices.Sort(families)
	for _, family := range families {
		clusters := groups[family]
		consistency := 0.0
		if f := support[family]; f != nil && f.applicable > 0 {
			fraction := ratio(f.positive, f.applicable)
			consistency = math.Max(fraction, 1-fraction)
		} else if input.Tokens != nil {
			for _, s := range input.Tokens.Series {
				if s.Family == family {
					for _, tier := range s.Tiers {
						if tier.Samples > 0 {
							consistency = math.Max(consistency, 1/(1+tier.RobustCV))
						}
					}
				}
			}
		}
		c.RepeatabilityFactor += math.Min(1, float64(len(clusters))/float64(rules.MinimumFamilyClusters)) * consistency
	}
	if len(groups) > 0 {
		c.RepeatabilityFactor /= float64(len(groups))
	}
	if c.RepeatabilityFactor < 1 {
		c.Limitations = appendCode(c.Limitations, "MI_REPLICATION_OR_CONSISTENCY_LIMIT")
	}
	if c.SampleFactor < 1 {
		c.Limitations = appendCode(c.Limitations, "MI_VALID_SAMPLE_COVERAGE_LIMIT")
	}
	if criticalFraction(input) < rules.MinimumCriticalFraction {
		c.Limitations = appendCode(c.Limitations, "MI_CRITICAL_EVIDENCE_INSUFFICIENT")
	}
	if partial {
		c.ApplicabilityFactor *= rules.MissingDimensionFactor
		c.Limitations = appendCode(c.Limitations, "MI_PARTIAL_CONFIDENCE_LIMIT")
	}
	value := 100 * c.SampleFactor * c.RepeatabilityFactor * c.EvidenceQualityFactor * c.BaselineFactor * c.ApplicabilityFactor
	if partial {
		value = math.Min(value, rules.PartialConfidenceCeiling)
	}
	if !policy.calibrated(e.hash) {
		value = math.Min(value, rules.DevelopmentConfidenceCeiling)
		c.Limitations = appendCode(c.Limitations, "MI_UNCALIBRATED_CONFIDENCE_LIMIT")
	}
	if input.Tokens != nil && (input.Tokens.Token.Limited || input.Tokens.Response.Limited) {
		c.Limitations = appendCode(c.Limitations, "MI_UPSTREAM_AGGREGATE_LIMITATIONS")
		// Do not re-cap/reweight Token or Response strengths. Preserve their
		// limitations above and deny a high-confidence presentation here.
		value = math.Min(value, rules.PartialConfidenceCeiling)
	}
	c.Score = int(math.Round(value))
	slices.Sort(c.Limitations)
	return c
}
