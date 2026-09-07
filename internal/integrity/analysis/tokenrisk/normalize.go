package tokenrisk

import (
	"encoding/hex"
	"math"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func identifier(s string, max int) bool {
	return len(s) > 0 && len(s) <= max && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}
func digest(s string) bool {
	if len(s) != 64 {
		return false
	}
	value, err := hex.DecodeString(s)
	return err == nil && len(value) == 32 && strings.ToLower(s) == s
}
func finite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }
func usable(s Sample) bool {
	return !s.AuxiliaryOnly && s.Family != "self_report" && (s.Validity == Valid || s.Validity == ValidWithWarning)
}
func countable(s Sample) bool {
	return usable(s) && s.Local.Tokens != nil && s.Local.Quality != tokenizer.Unavailable && !slices.Contains(s.Structure.Warnings, "MI_TERMINATION_NOT_APPLICABLE")
}
func tokens(s Sample) float64 {
	if s.Local.Tokens == nil {
		return 0
	}
	return float64(*s.Local.Tokens)
}
func sameSeed(left, right *int64) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}
func ladder(s Sample) bool { return s.Family == "sequence" || s.Family == "jsonl" }

func validateSample(s Sample) bool {
	if !slices.Contains([]string{"sequence", "jsonl", "format", "neutral", "differential", "style", "self_report"}, s.Family) {
		return false
	}
	if s.ID <= 0 || s.AttemptID <= 0 || s.FinalAttemptID <= 0 || s.AttemptNumber < 1 || s.AttemptNumber > 8 || !identifier(s.Family, 64) || !identifier(s.Language, 32) || !identifier(s.TemplateID, 128) || !identifier(s.TemplateVersion, 64) || !identifier(s.ConditionID, 256) || !digest(s.SeriesID) || !identifier(s.GroupID, 128) || s.Variant < 1 || s.Variant > 32 || s.Repetition < 0 || s.Repetition > 64 || s.RequestedMaxTokens < 1 || s.RequestedMaxTokens > 10000000 {
		return false
	}
	if s.Validity != Valid && s.Validity != ValidWithWarning && s.Validity != InvalidRetryable && s.Validity != InvalidProtocol && s.Validity != InvalidSafetyLimit && s.Validity != NotApplicable {
		return false
	}
	if !usable(s) {
		return true
	}
	if s.Local.Quality != tokenizer.Exact && s.Local.Quality != tokenizer.Compatible && s.Local.Quality != tokenizer.Heuristic && s.Local.Quality != tokenizer.Unavailable {
		return false
	}
	if s.Local.Tokens != nil && (*s.Local.Tokens < 0 || *s.Local.Tokens > tokenizer.MaxTextBytes) {
		return false
	}
	if s.Local.Quality != tokenizer.Unavailable && (!identifier(s.Local.TokenizerID, 128) || !identifier(s.Local.TokenizerVersion, 128)) {
		return false
	}
	for _, list := range [][]string{s.Local.Warnings, s.Structure.Warnings, s.Structure.TerminationHints} {
		if len(list) > 16 {
			return false
		}
		for _, value := range list {
			if !identifier(value, 128) {
				return false
			}
		}
	}
	for _, value := range []string{s.Local.BundleVersion, s.Local.SelectedBy, s.Usage.Warning, s.Usage.Band, s.Usage.EvidenceCeiling, s.Structure.Version, s.Structure.FinishReason} {
		if value != "" && !identifier(value, 128) {
			return false
		}
	}
	if s.Local.BundleHash != "" && !digest(s.Local.BundleHash) {
		return false
	}
	if (s.ProtocolAnomaly && !s.ProtocolChecked) || (s.SuffixFingerprint != "" && !s.SuffixChecked) {
		return false
	}
	if s.Local.Scope != "visible_output" || (s.Local.Quality == tokenizer.Unavailable) != (s.Local.Tokens == nil) || !finite(s.Usage.RelativeError) || s.Usage.RelativeError < 0 || s.Usage.Direction < -1 || s.Usage.Direction > 1 || len(s.Structure.TerminationHints) > 16 || len(s.Structure.Warnings) > 16 || (s.SuffixFingerprint != "" && !digest(s.SuffixFingerprint)) {
		return false
	}
	if s.Structure.StructureComplete && s.Structure.HardTruncation || s.Structure.CompleteEarlyStop && s.Structure.HardTruncation {
		return false
	}
	return true
}

func (e *Engine) normalize(input Input) ([]Sample, Result, error) {
	r := Result{Version: e.rules.Version, RulesHash: e.hash, Development: true, Calibrated: false, Partial: input.Partial, Warnings: []string{"MI_DEVELOPMENT_RULES_UNCALIBRATED", "MI_MULTIPLE_COMPARISONS_EXPLORATORY", "MI_BASELINE_UNAVAILABLE"}, Series: []Series{}, Plateaus: []Plateau{}}
	if input.OrganizationID <= 0 || input.RunID <= 0 || input.ExpectedSamples < 0 || input.ExpectedSamples > MaxSamples || (input.DeclaredModelOutputLimit != nil && (*input.DeclaredModelOutputLimit < 1 || *input.DeclaredModelOutputLimit > 10000000)) {
		return nil, r, ErrInput
	}
	if len(input.Samples) > MaxObservations {
		return nil, r, ErrLimit
	}
	finalIDs := map[int64]int64{}
	attemptOwners := map[int64]int64{}
	finals := map[int64]Sample{}
	series := map[string]Sample{}
	for _, s := range input.Samples {
		if !validateSample(s) {
			return nil, r, ErrInput
		}
		if owner, ok := attemptOwners[s.AttemptID]; ok && owner != s.ID {
			return nil, r, ErrInput
		}
		attemptOwners[s.AttemptID] = s.ID
		if existing, ok := finalIDs[s.ID]; ok && existing != s.FinalAttemptID {
			return nil, r, ErrInput
		}
		finalIDs[s.ID] = s.FinalAttemptID
		if len(finalIDs) > MaxSamples {
			return nil, r, ErrLimit
		}
		if s.AttemptID != s.FinalAttemptID {
			r.IgnoredAttempts++
			continue
		}
		if existing, ok := finals[s.ID]; ok {
			if !reflect.DeepEqual(existing, s) {
				return nil, r, ErrInput
			}
			r.DuplicateFinals++
			continue
		}
		if existing, ok := series[s.SeriesID]; ok && (existing.Family != s.Family || existing.Language != s.Language || existing.Variant != s.Variant || existing.TemplateID != s.TemplateID || existing.TemplateVersion != s.TemplateVersion) {
			return nil, r, ErrInput
		}
		series[s.SeriesID] = s
		if len(series) > MaxSeries {
			return nil, r, ErrLimit
		}
		finals[s.ID] = s
	}
	r.ObservedLogicalSamples = len(finalIDs)
	r.FinalSamples = len(finals)
	r.MissingFinals = len(finalIDs) - len(finals)
	r.ExpectedSamples = input.ExpectedSamples
	if r.ExpectedSamples == 0 {
		r.ExpectedSamples = len(finalIDs)
	}
	if r.ExpectedSamples < len(finalIDs) {
		return nil, r, ErrInput
	}
	if r.ExpectedSamples > r.FinalSamples || r.MissingFinals > 0 {
		r.Partial = true
		r.Warnings = append(r.Warnings, "MI_FINAL_SAMPLES_MISSING")
	}
	ids := make([]int64, 0, len(finals))
	for id := range finals {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	result := make([]Sample, 0, len(ids))
	families := map[string]bool{}
	network, observed := 0, 0
	for _, id := range ids {
		s := finals[id]
		result = append(result, s)
		if !s.AuxiliaryOnly && s.Family != "self_report" {
			observed++
			if s.NetworkFailure {
				network++
			}
		}
		if usable(s) {
			r.ValidSamples++
			families[s.Family] = true
		}
	}
	r.IndependentFamilies = len(families)
	if r.ValidSamples < observed {
		r.Partial = true
		r.Warnings = append(r.Warnings, "MI_VALID_SAMPLES_INCOMPLETE")
	}
	r.NetworkErrorRate = ratio(network, observed)
	r.SSEAttributionFactor = 1
	if r.NetworkErrorRate > e.rules.NetworkErrorThreshold {
		r.SSEAttributionFactor = e.rules.NetworkAttributionFactor
		r.Warnings = append(r.Warnings, "MI_NETWORK_ERRORS_REDUCE_ATTRIBUTION")
	}
	return result, r, nil
}
