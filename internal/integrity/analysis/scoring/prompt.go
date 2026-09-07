package scoring

import (
	"math"
	"slices"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/behavior"
)

type familySupport struct {
	applicable, positive int
	clusters             map[string]bool
	hitClusters          map[string]bool
}

func behaviorEligible(f behavior.Features, s Observation) bool {
	return included(s) && behaviorFamily(s.Family) && f.State == behavior.Analyzed && f.RegistryMatch
}

func prompt(input Input, byID map[string]Observation) (Dimension, map[string]*familySupport, error) {
	rules := Parameters()
	d := Dimension{Components: make([]Component, 5), Limitations: []string{"MI_BASELINE_UNAVAILABLE"}}
	for i, name := range []string{"format_contract", "stable_unknown_affix", "neutral_refusal", "identity_style", "trusted_baseline_difference"} {
		d.Components[i] = Component{Name: name, Weight: rules.PromptWeights[i]}
	}
	families := map[string]*familySupport{}
	if input.Behavior == nil {
		combine(&d)
		return d, families, nil
	}
	features := map[string]behavior.Features{}
	for _, f := range input.Behavior.Samples {
		if behaviorEligible(f, byID[f.SampleID]) {
			features[f.SampleID] = f
		}
	}
	stableIDs, err := stableAffixes(input.Behavior.Patterns, features, byID)
	if err != nil {
		return Dimension{}, nil, err
	}
	anyHit, nonIdentityHit := false, false
	for id, f := range features {
		s := byID[id]
		if families[s.Family] == nil {
			families[s.Family] = &familySupport{clusters: map[string]bool{}, hitClusters: map[string]bool{}}
		}
		family := families[s.Family]
		applicable := false
		if f.Contract != behavior.ContractNotApplicable {
			applicable = true
			d.Components[0].Applicable++
			d.Components[1].Applicable++
			if f.Contract == behavior.Deviates {
				d.Components[0].Positive++
			}
			if stableIDs[id] {
				d.Components[1].Positive++
			}
		}
		if f.Refusal != behavior.CueNotApplicable {
			applicable = true
			d.Components[2].Applicable++
			if f.Refusal == behavior.RefusalLike {
				d.Components[2].Positive++
			}
		}
		if f.Identity != behavior.CueNotApplicable {
			applicable = true
			d.Components[3].Applicable++
			if f.Identity == behavior.IdentityLike {
				d.Components[3].Positive++
			}
		}
		if !applicable {
			continue
		}
		family.applicable++
		family.clusters[s.ClusterID] = true
		hit := f.Contract == behavior.Deviates || stableIDs[id] || f.Refusal == behavior.RefusalLike || f.Identity == behavior.IdentityLike
		if hit {
			anyHit = true
			family.positive++
			family.hitClusters[s.ClusterID] = true
		}
		if f.Refusal == behavior.RefusalLike || f.Identity != behavior.IdentityLike && (f.Contract == behavior.Deviates || stableIDs[id]) {
			nonIdentityHit = true
		}
	}
	for i := range d.Components {
		c := &d.Components[i]
		if c.Applicable > 0 {
			c.Score = number(100 * ratio(c.Positive, c.Applicable))
		}
	}
	combine(&d)
	stable := stableFamilies(families)
	if anyHit && !nonIdentityHit {
		capDimension(&d, rules.WeakCeiling, "MI_IDENTITY_STYLE_ONLY")
	}
	if stable == 0 && anyHit {
		capDimension(&d, rules.WeakCeiling, "MI_BEHAVIOR_REPEATABILITY_INSUFFICIENT")
	} else if anyHit && stable < rules.MinimumHitFamilies {
		capDimension(&d, rules.SingleFamilyCeiling, "MI_BEHAVIOR_INDEPENDENT_FAMILIES_INSUFFICIENT")
	}
	return d, families, nil
}

func stableFamilies(families map[string]*familySupport) int {
	n := 0
	rules := Parameters()
	for _, f := range families {
		if f.positive >= rules.MinimumFamilyHits && len(f.hitClusters) >= rules.MinimumFamilyClusters && ratio(f.positive, f.applicable) >= rules.StableFraction {
			n++
		}
	}
	return n
}

// Pattern state is cross-checked against its linked eligible sample evidence;
// unlinked caller-declared counts never establish repeated-affix support.
func stableAffixes(patterns []behavior.Pattern, features map[string]behavior.Features, observations map[string]Observation) (map[string]bool, error) {
	ids := map[string]bool{}
	for _, p := range patterns {
		if p.Kind != behavior.Prefix && p.Kind != behavior.Suffix {
			continue
		}
		if p.State != behavior.StablePattern {
			continue
		}
		matches, denom := map[string]int{}, map[string]int{}
		seen := map[string]bool{}
		for id, f := range features {
			if f.Contract != behavior.ContractNotApplicable {
				denom[observations[id].Family]++
			}
		}
		for _, e := range p.Evidence {
			f, exists := features[e.SampleID]
			if !exists || seen[e.SampleID] || f.Contract == behavior.ContractNotApplicable || e.Kind != p.Kind || e.NormalizedSHA256 != p.NormalizedSHA256 || !e.Candidate || !slices.Contains(f.Evidence, e) {
				return nil, ErrInput
			}
			seen[e.SampleID] = true
			matches[observations[e.SampleID].Family]++
		}
		qualifying := map[string]bool{}
		for family, n := range matches {
			if n >= behavior.MinimumFamilyMatches && ratio(n, denom[family]) >= behavior.MinimumRepeatFraction {
				qualifying[family] = true
			}
		}
		templates, languages := map[string]bool{}, map[string]bool{}
		for id := range seen {
			s := observations[id]
			if qualifying[s.Family] {
				templates[s.TemplateID] = true
				languages[s.Language] = true
			}
		}
		if len(qualifying) < behavior.MinimumFamilies || len(templates) < behavior.MinimumTemplates || len(languages) < behavior.MinimumLanguages || p.FamilyCount != len(qualifying) || p.TemplateCount != len(templates) || p.LanguageCount != len(languages) {
			return nil, ErrInput
		}
		for id := range seen {
			ids[id] = true
		}
	}
	return ids, nil
}

func combine(d *Dimension) {
	weight, total := 0.0, 0.0
	for _, c := range d.Components {
		if c.Score != nil {
			weight += c.Weight
			total += *c.Score * c.Weight
		} else {
			d.Limited = true
		}
	}
	if weight > 0 {
		d.Score = number(math.Max(0, math.Min(100, total/weight)))
		for i := range d.Components {
			if d.Components[i].Score != nil {
				d.Components[i].EffectiveWeight = d.Components[i].Weight / weight
			}
		}
	} else {
		d.Limited = true
		d.Limitations = appendCode(d.Limitations, "MI_NO_ANALYZABLE_COMPONENTS")
	}
	if d.Limited {
		d.Limitations = appendCode(d.Limitations, "MI_COMPONENTS_MISSING_RENORMALIZED")
	}
}

func capDimension(d *Dimension, limit float64, code string) {
	d.Limited = true
	d.Limitations = appendCode(d.Limitations, code)
	if d.Score != nil {
		*d.Score = math.Min(*d.Score, limit)
	}
}
func appendCode(values []string, code string) []string {
	if !slices.Contains(values, code) {
		return append(values, code)
	}
	return values
}
