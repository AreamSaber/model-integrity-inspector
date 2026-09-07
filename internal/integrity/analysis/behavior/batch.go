package behavior

import (
	"sort"
	"strings"
)

// These deliberately conservative development rules are NOT calibrated risk
// thresholds. Stable means repeated normalized text, not hidden instructions.
const MinimumFamilies = 2
const MinimumTemplates = 3
const MinimumLanguages = 2
const MinimumFamilyMatches = 3
const MinimumRepeatFraction = 0.8

type PatternState string

const (
	StablePattern       PatternState = "cross_family_repeat"
	InsufficientPattern PatternState = "insufficient_coverage"
)

type FamilyCoverage struct {
	Family            Family  `json:"family"`
	ApplicableSamples int     `json:"applicable_samples"`
	MatchedSamples    int     `json:"matched_samples"`
	Fraction          float64 `json:"fraction"`
}

type Pattern struct {
	Kind             EvidenceKind     `json:"kind"`
	NormalizedSHA256 string           `json:"normalized_sha256"`
	State            PatternState     `json:"state"`
	FamilyCount      int              `json:"qualifying_family_count"`
	TemplateCount    int              `json:"qualifying_template_count"`
	LanguageCount    int              `json:"qualifying_language_count"`
	Coverage         []FamilyCoverage `json:"coverage"`
	Evidence         []Evidence       `json:"evidence"`
	Alternatives     []string         `json:"alternatives"`
}

type Batch struct {
	Version    string     `json:"version"`
	RuleStatus string     `json:"rule_status"`
	Samples    []Features `json:"samples"`
	Auxiliary  []Features `json:"auxiliary_samples"`
	Patterns   []Pattern  `json:"patterns"`
}

type batchItem struct {
	sample   Sample
	features Features
	spec     templateSpec
	eligible bool
}

func (e *Engine) items(samples []Sample) ([]batchItem, error) {
	if len(samples) > MaxSamples {
		return nil, ErrLimit
	}
	seen := make(map[int64]bool, len(samples))
	bytes := 0
	// Check the complete resource budget before performing analyses.
	for _, sample := range samples {
		if seen[sample.ID] {
			return nil, ErrInput
		}
		seen[sample.ID] = true
		if _, err := validate(sample); err != nil {
			return nil, err
		}
		bytes += len(sample.Contract.Expected) + len(sample.Contract.Key)
		for _, variable := range sample.Variables {
			bytes += len(variable)
		}
		for _, attempt := range sample.Attempts {
			bytes += len(attempt.Content)
		}
		if bytes > MaxBatchBytes {
			return nil, ErrLimit
		}
	}
	items := make([]batchItem, 0, len(samples))
	for _, sample := range samples {
		features, err := e.Analyze(sample)
		if err != nil {
			return nil, err
		}
		spec := templateSpec{}
		if e != nil {
			spec = e.templates[sample.Template]
		}
		eligible := features.State == Analyzed && features.RegistryMatch && (!spec.builtin || builtinContractBound(sample, spec))
		items = append(items, batchItem{sample: sample, features: features, spec: spec, eligible: eligible})
	}
	return items, nil
}

// The caller still must bind these records to the immutable request plan.
// This additional guard prevents arbitrary expected text from masquerading as
// one of the fixed builtin marker experiments during statistical aggregation.
func builtinContractBound(sample Sample, spec templateSpec) bool {
	has := func(value string) bool {
		for _, variable := range sample.Variables {
			if value == variable {
				return true
			}
		}
		return false
	}
	switch spec.family {
	case NeutralFamily:
		return neutralContractBound(sample)
	case FormatFamily:
		if spec.variant == 3 {
			return sample.Contract.Kind == JSONField && has(sample.Contract.Expected) && has(sample.Contract.Key)
		}
		return sample.Contract.Kind == Exact && has(sample.Contract.Expected)
	case DifferentialFamily:
		return sample.Contract.Kind == Exact && has(sample.Contract.Expected)
	case StyleFamily:
		return sample.Contract.Kind == NoContract
	default:
		return false
	}
}

func evidenceApplicable(item batchItem, kind EvidenceKind) bool {
	if !item.eligible {
		return false
	}
	switch kind {
	case Prefix, Suffix:
		return item.features.Contract != ContractNotApplicable
	case Refusal:
		return item.features.Refusal != CueNotApplicable
	case Identity:
		return item.features.Identity != CueNotApplicable
	default:
		return false
	}
}

func (e *Engine) AnalyzeBatch(samples []Sample) (Batch, error) {
	items, err := e.items(samples)
	if err != nil {
		return Batch{}, err
	}
	out := Batch{Version: Version, RuleStatus: "development_uncalibrated", Samples: make([]Features, 0, len(items)), Auxiliary: []Features{}, Patterns: []Pattern{}}
	type patternKey struct {
		kind EvidenceKind
		hash string
	}
	type matched struct {
		item     batchItem
		evidence Evidence
	}
	groups := map[patternKey][]matched{}
	for _, item := range items {
		if item.features.State == Auxiliary {
			out.Auxiliary = append(out.Auxiliary, item.features)
		} else {
			out.Samples = append(out.Samples, item.features)
		}
		seen := map[patternKey]bool{}
		for _, evidence := range item.features.Evidence {
			key := patternKey{evidence.Kind, evidence.NormalizedSHA256}
			if evidence.Candidate && !seen[key] && evidenceApplicable(item, evidence.Kind) {
				groups[key] = append(groups[key], matched{item, evidence})
				seen[key] = true
			}
		}
	}
	keys := make([]patternKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].kind != keys[j].kind {
			return keys[i].kind < keys[j].kind
		}
		return keys[i].hash < keys[j].hash
	})
	for _, key := range keys {
		pattern := Pattern{Kind: key.kind, NormalizedSHA256: key.hash, State: InsufficientPattern, Coverage: []FamilyCoverage{}, Evidence: []Evidence{}, Alternatives: []string{"ordinary_model_style_or_common_training", "normalized_repeat_is_not_injection_proof", "public_development_templates_not_independent_content_safety_approval"}}
		hits, denominators := map[Family]int{}, map[Family]int{}
		for _, match := range groups[key] {
			hits[match.item.spec.family]++
			pattern.Evidence = append(pattern.Evidence, match.evidence)
		}
		for _, item := range items {
			if evidenceApplicable(item, key.kind) {
				denominators[item.spec.family]++
			}
		}
		families := make([]Family, 0, len(denominators))
		for family := range denominators {
			families = append(families, family)
		}
		sort.Slice(families, func(i, j int) bool { return families[i] < families[j] })
		qualifying := map[Family]bool{}
		for _, family := range families {
			fraction := float64(hits[family]) / float64(denominators[family])
			pattern.Coverage = append(pattern.Coverage, FamilyCoverage{family, denominators[family], hits[family], fraction})
			if hits[family] >= MinimumFamilyMatches && fraction >= MinimumRepeatFraction {
				qualifying[family] = true
			}
		}
		templates, languages := map[TemplateRef]bool{}, map[string]bool{}
		for _, match := range groups[key] {
			if qualifying[match.item.spec.family] {
				templates[match.item.sample.Template] = true
				languages[match.item.spec.language] = true
			}
		}
		pattern.FamilyCount, pattern.TemplateCount, pattern.LanguageCount = len(qualifying), len(templates), len(languages)
		if len(qualifying) >= MinimumFamilies && len(templates) >= MinimumTemplates && len(languages) >= MinimumLanguages {
			pattern.State = StablePattern
		}
		sort.Slice(pattern.Evidence, func(i, j int) bool {
			return strings.Compare(pattern.Evidence[i].SampleID, pattern.Evidence[j].SampleID) < 0
		})
		out.Patterns = append(out.Patterns, pattern)
	}
	return out, nil
}
