package behavior

import (
	"math"
	"sort"
)

type Metric string

const (
	ContractDeviation   Metric = "contract_deviation"
	ExtraAffix          Metric = "extra_affix"
	NeutralRefusal      Metric = "neutral_refusal_like"
	UnsolicitedIdentity Metric = "unsolicited_identity_like"
)

const MinimumDescriptivePairs = 6 // Development rule; not a power calculation.

type PairState string

const (
	PairAvailable     PairState = "descriptive_available"
	PairInsufficient  PairState = "insufficient_pairs"
	PairUninformative PairState = "no_discordant_pairs"
)

type PairEvidence struct {
	PairSHA256      string `json:"pair_sha256"`
	ControlSampleID string `json:"a_sample_id"`
	VariantSampleID string `json:"b_sample_id"`
	ControlPositive bool   `json:"a_positive"`
	VariantPositive bool   `json:"b_positive"`
}

type PairExclusion struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type Difference struct {
	Version         string          `json:"version"`
	RuleStatus      string          `json:"rule_status"`
	Metric          Metric          `json:"metric"`
	State           PairState       `json:"state"`
	CompletePairs   int             `json:"complete_pairs"`
	ExcludedPairs   int             `json:"excluded_pairs"`
	UnpairedSamples int             `json:"unpaired_samples"`
	ControlPositive int             `json:"a_positive"`
	VariantPositive int             `json:"b_positive"`
	ControlOnly     int             `json:"a_only_positive"`
	VariantOnly     int             `json:"b_only_positive"`
	RiskDifference  *float64        `json:"paired_rate_difference_b_minus_a"`
	ExactTwoSidedP  *float64        `json:"exact_two_sided_p"`
	Test            string          `json:"test"`
	Multiplicity    string          `json:"multiplicity"`
	Exclusions      []PairExclusion `json:"exclusions"`
	Pairs           []PairEvidence  `json:"pairs"`
	Alternatives    []string        `json:"alternatives"`
}

// PairedDifference uses one logical sample per arm and pair_id. It refuses to
// pick a convenient duplicate arm, and does not mix incomparable conditions.
// The p-value is the exact paired binary sign/McNemar test on discordant pairs;
// paired rate difference is reported even with small n, but never as a risk score.
func (e *Engine) PairedDifference(samples []Sample, metric Metric) (Difference, error) {
	switch metric {
	case ContractDeviation, ExtraAffix, NeutralRefusal, UnsolicitedIdentity:
	default:
		return Difference{}, ErrInput
	}
	items, err := e.items(samples)
	if err != nil {
		return Difference{}, err
	}
	return pairedItems(items, metric), nil
}

func pairedItems(items []batchItem, metric Metric) Difference {
	out := Difference{Version: Version, RuleStatus: "development_uncalibrated", Metric: metric, State: PairInsufficient, Test: "exact_paired_binomial_discordance", Multiplicity: "uncorrected_exploratory_no_fdr_claim", Exclusions: []PairExclusion{}, Pairs: []PairEvidence{}, Alternatives: []string{"paired_conditions_require_immutable_plan_binding", "pairs_must_be_independent_experimental_units", "public_development_templates_not_independent_content_safety_approval", "no_causal_or_injection_conclusion"}}
	groups := map[string][]batchItem{}
	for _, item := range items {
		if item.sample.Pair.ID == "" {
			out.UnpairedSamples++
		} else {
			groups[item.sample.Pair.ID] = append(groups[item.sample.Pair.ID], item)
		}
	}
	ids := make([]string, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	exclusions := map[string]int{}
	languageContrast := false
	for _, id := range ids {
		group := groups[id]
		if len(group) != 2 {
			if len(group) < 2 {
				exclusions["incomplete_pair"]++
			} else {
				exclusions["duplicate_pair_arm"]++
			}
			out.ExcludedPairs++
			continue
		}
		a, b := group[0], group[1]
		if a.sample.Pair.Arm == b.sample.Pair.Arm {
			exclusions["duplicate_pair_arm"]++
			out.ExcludedPairs++
			continue
		}
		if a.sample.Pair.Arm == Variant {
			a, b = b, a
		}
		if !comparable(a, b) {
			exclusions["incomparable_pair_conditions"]++
			out.ExcludedPairs++
			continue
		}
		av, aok := metricValue(a, metric)
		bv, bok := metricValue(b, metric)
		if !aok || !bok {
			exclusions["excluded_or_not_applicable_arm"]++
			out.ExcludedPairs++
			continue
		}
		if a.sample.Pair.Contrast == LanguageContrast {
			languageContrast = true
		}
		out.CompletePairs++
		if av {
			out.ControlPositive++
		}
		if bv {
			out.VariantPositive++
		}
		if av && !bv {
			out.ControlOnly++
		}
		if bv && !av {
			out.VariantOnly++
		}
		out.Pairs = append(out.Pairs, PairEvidence{digest("pair_id", id), a.features.SampleID, b.features.SampleID, av, bv})
	}
	reasons := make([]string, 0, len(exclusions))
	for reason := range exclusions {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	for _, reason := range reasons {
		out.Exclusions = append(out.Exclusions, PairExclusion{reason, exclusions[reason]})
	}
	if languageContrast {
		out.Alternatives = append(out.Alternatives, "language_capability_difference_not_hidden_instruction_evidence")
	}
	if out.CompletePairs > 0 {
		effect := float64(out.VariantPositive-out.ControlPositive) / float64(out.CompletePairs)
		p := exactDiscordance(out.ControlOnly, out.VariantOnly)
		out.RiskDifference, out.ExactTwoSidedP = &effect, &p
		if out.CompletePairs >= MinimumDescriptivePairs {
			out.State = PairAvailable
		}
		if out.ControlOnly+out.VariantOnly == 0 {
			out.State = PairUninformative
			out.Alternatives = append(out.Alternatives, "no_discordance_is_not_proof_of_equivalence")
		}
	}
	if out.CompletePairs < MinimumDescriptivePairs {
		out.Alternatives = append(out.Alternatives, "small_sample_low_power")
	}
	return out
}

func comparable(a, b batchItem) bool {
	if a.sample.Pair.ComparableSHA256 != b.sample.Pair.ComparableSHA256 || a.sample.Pair.Contrast != b.sample.Pair.Contrast || a.spec.family != b.spec.family || a.sample.Template.SHA256 != b.sample.Template.SHA256 || a.sample.Template.Version != b.sample.Template.Version || a.sample.Contract != b.sample.Contract {
		return false
	}
	if a.sample.Pair.Contrast == SurfaceContrast && a.spec.language != b.spec.language {
		return false
	}
	if a.sample.Pair.Contrast == LanguageContrast && a.spec.language == b.spec.language {
		return false
	}
	av, bv := append([]string(nil), a.sample.Variables...), append([]string(nil), b.sample.Variables...)
	sort.Strings(av)
	sort.Strings(bv)
	if len(av) != len(bv) {
		return false
	}
	for i := range av {
		if av[i] != bv[i] {
			return false
		}
	}
	return true
}

func metricValue(item batchItem, metric Metric) (bool, bool) {
	if !item.eligible {
		return false, false
	}
	switch metric {
	case ContractDeviation:
		return item.features.Contract == Deviates, item.features.Contract != ContractNotApplicable
	case ExtraAffix:
		return item.features.PrefixBytes > 0 || item.features.SuffixBytes > 0, item.features.Contract != ContractNotApplicable
	case NeutralRefusal:
		return item.features.Refusal == RefusalLike, item.features.Refusal != CueNotApplicable
	case UnsolicitedIdentity:
		return item.features.Identity == IdentityLike, item.features.Identity != CueNotApplicable
	default:
		return false, false
	}
}

func exactDiscordance(aOnly, bOnly int) float64 {
	n := aOnly + bOnly
	if n == 0 {
		return 1
	}
	k := aOnly
	if bOnly < k {
		k = bOnly
	}
	// MaxSamples bounds n <= 256, so this recurrence neither overflows nor
	// underflows. It computes 2*P[Binomial(n,0.5)<=min(discordant counts)].
	term := math.Ldexp(1, -n)
	sum := term
	for j := 1; j <= k; j++ {
		term *= float64(n-j+1) / float64(j)
		sum += term
	}
	return math.Min(1, 2*sum)
}
