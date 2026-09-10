package scoring

import (
	"math"
	"sort"
)

// Hypothesis IDs identify the entire preplanned family, including tests that
// could not be performed. Effect is descriptive and never a p-value substitute.
type Hypothesis struct {
	ID             string
	PValue, Effect *float64
}

type AdjustedHypothesis struct {
	ID                        string
	PValue, AdjustedP, Effect *float64
	Reject                    bool
}

type FDRResult struct {
	Method             string
	Alpha              float64
	FamilySize, Tested int
	Tests              []AdjustedHypothesis
	Limitations        []string
}

// BenjaminiHochberg computes monotone BH adjusted p-values. Nil tests remain
// nil in the result but count in m (equivalently their unknown p is 1).
// FDR control requires valid tests plus independence/positive dependence;
// arbitrary dependence and selective reporting do not inherit that guarantee.
// Reject concerns a statistical null only, never a risk or evidence grade.
func BenjaminiHochberg(family []Hypothesis, alpha float64) (FDRResult, error) {
	if len(family) > MaxHypotheses {
		return FDRResult{}, ErrLimit
	}
	if !unit(alpha) || alpha == 0 {
		return FDRResult{}, ErrInput
	}
	out := FDRResult{Method: "benjamini_hochberg", Alpha: alpha, FamilySize: len(family), Tests: make([]AdjustedHypothesis, len(family)), Limitations: []string{"MI_BH_DEPENDENCE_ASSUMPTION", "MI_PREPLANNED_FAMILY_REQUIRED", "MI_P_VALUE_NOT_RISK"}}
	seen := map[string]bool{}
	indices := []int{}
	for i, h := range family {
		if !identifier(h.ID, 128) || seen[h.ID] || h.PValue != nil && !unit(*h.PValue) || h.Effect != nil && !finite(*h.Effect) || h.PValue != nil && h.Effect == nil {
			return FDRResult{}, ErrInput
		}
		seen[h.ID] = true
		out.Tests[i] = AdjustedHypothesis{ID: h.ID, PValue: copyNumber(h.PValue), Effect: copyNumber(h.Effect)}
		if h.PValue != nil {
			indices = append(indices, i)
		}
	}
	out.Tested = len(indices)
	sort.SliceStable(indices, func(i, j int) bool { return *family[indices[i]].PValue < *family[indices[j]].PValue })
	next := 1.0
	for rank := len(indices); rank > 0; rank-- {
		i := indices[rank-1]
		next = math.Min(next, *family[i].PValue*float64(len(family))/float64(rank))
		out.Tests[i].AdjustedP = number(next)
		out.Tests[i].Reject = next <= alpha
	}
	return out, nil
}
