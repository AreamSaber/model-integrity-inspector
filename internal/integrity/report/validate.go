package report

import (
	"encoding/json"
	"math"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func id(s string) bool {
	if len(s) < 1 || len(s) > 19 {
		return false
	}
	n, e := strconv.ParseInt(s, 10, 64)
	return e == nil && n > 0 && strconv.FormatInt(n, 10) == s
}
func hash(s string) bool         { return len(s) == 64 && hashPattern.MatchString(s) }
func one(s, options string) bool { return slices.Contains(strings.Fields(options), s) }
func number(n float64, low, high float64) bool {
	return !math.IsNaN(n) && !math.IsInf(n, 0) && n >= low && n <= high
}
func score(n *float64) bool                   { return n == nil || number(*n, 0, 100) }
func count(n *int64) bool                     { return n == nil || *n >= 0 && *n <= 9007199254740991 }
func stamp(t time.Time) bool                  { return !t.IsZero() && t.Year() >= 2000 && t.Year() <= 9999 }
func before(a, b time.Time) bool              { return !a.After(b) }
func optional(s *string, options string) bool { return s == nil || one(*s, options) }
func validVersions(v Versions) bool {
	return v.Rule == scoring.Version && v.Scoring == scoring.Version && v.Template == templates.BuiltinVersion && v.Tokenizer == tokenizer.BuiltinVersion
}

const families = "sequence jsonl format neutral differential style self_report"
const validities = "VALID VALID_WITH_WARNING INVALID_RETRYABLE INVALID_PROTOCOL INVALID_SAFETY_LIMIT NOT_APPLICABLE"
const statisticNames = "format_contract stable_unknown_affix neutral_refusal identity_style trusted_baseline_difference plateau termination usage stream_difference sse_termination fixed_suffix metadata_consistency protocol_anomaly usage_quality http_content_type model_echo finish_reason tokenizer_unavailable valid_sample_rate"
const codes = `MI_BASELINE_UNAVAILABLE MI_GATEWAY_EVIDENCE_UNAVAILABLE MI_DEVELOPMENT_RULES_UNCALIBRATED MI_MULTIPLE_COMPARISONS_EXPLORATORY MI_COMPONENTS_MISSING_RENORMALIZED MI_NO_ANALYZABLE_COMPONENTS MI_SINGLE_TIER_LIMIT MI_VALID_SAMPLES_INSUFFICIENT MI_TOKENIZER_HEURISTIC_ONLY MI_TOKENIZER_HEURISTIC_LIMIT MI_TOKENIZER_UNAVAILABLE MI_REASONING_UNSEPARATED MI_NATURAL_EOS_ALTERNATIVE MI_PARTIAL_RESULT MI_INDEPENDENT_GROUPS_INSUFFICIENT MI_BOOTSTRAP_GROUPS_INSUFFICIENT MI_DECLARED_MODEL_OUTPUT_LIMIT MI_STREAM_MODES_NOT_COMPARABLE MI_USAGE_INSUFFICIENT MI_PAIRED_SAMPLES_INSUFFICIENT MI_BEHAVIOR_INDEPENDENT_FAMILIES_INSUFFICIENT MI_BEHAVIOR_REPEATABILITY_INSUFFICIENT MI_IDENTITY_STYLE_ONLY MI_PARTIAL_CONFIDENCE_LIMIT MI_UNCALIBRATED_CONFIDENCE_LIMIT MI_REPLICATION_OR_CONSISTENCY_LIMIT MI_VALID_SAMPLE_COVERAGE_LIMIT MI_CRITICAL_EVIDENCE_INSUFFICIENT MI_NO_VALID_SAMPLES MI_UPSTREAM_AGGREGATE_LIMITATIONS MI_PROTOCOL_SCORE_NOT_PROVIDER_MISCONDUCT MI_RESULT_INCOMPLETE MI_FINAL_SAMPLES_MISSING MI_VALID_SAMPLES_INCOMPLETE MI_NETWORK_ERRORS_REDUCE_ATTRIBUTION MI_TOKEN_AGGREGATE_UNAVAILABLE MI_RESPONSE_AGGREGATE_UNAVAILABLE MI_BH_DEPENDENCE_ASSUMPTION MI_PREPLANNED_FAMILY_REQUIRED MI_P_VALUE_NOT_RISK MI_ANALYSIS_LIMITATION_UNAVAILABLE ordinary_model_variation capability_or_protocol_limits`
const additionalCodes = `MI_BOOTSTRAP_UNAVAILABLE MI_HIGH_TIER_SAMPLES_INSUFFICIENT MI_LADDER_PAIRS_INCOMPLETE MI_LENGTH_FAR_BELOW_REQUEST MI_MODE_TIER_COVERAGE_INSUFFICIENT MI_NORMAL_GROWTH_WITHIN_INTERVAL MI_STOP_WITH_INCOMPLETE_STRUCTURE MI_STREAM_PAIRS_INCOMPLETE MI_STREAM_PAIRS_INSUFFICIENT MI_STREAM_TERMINATOR_MISSING MI_STREAM_TIER_COVERAGE_INSUFFICIENT MI_STREAM_VARIATION_ALTERNATIVE MI_TERMINATION_NOT_APPLICABLE MI_USAGE_SAMPLES_INSUFFICIENT MI_FEATURE_ATTEMPT_UNCERTAIN MI_FEATURE_AUXILIARY_ONLY MI_FEATURE_BEHAVIOR_INVALID MI_FEATURE_BEHAVIOR_LIMIT MI_FEATURE_BINDING_INVALID MI_FEATURE_CONTRACT_UNSUPPORTED MI_FEATURE_EVIDENCE_MISSING MI_FEATURE_FINAL_ATTEMPT_INVALID MI_FEATURE_FINAL_ATTEMPT_MISSING MI_FEATURE_PLAN_REDUCED MI_FEATURE_PROTOCOL_INVALID MI_FEATURE_PROTOCOL_WARNING_UNKNOWN MI_FEATURE_SAFETY_LIMIT MI_FEATURE_STRUCTURE_INVALID MI_FEATURE_STRUCTURE_LIMIT MI_FEATURE_TERMINATION_NOT_APPLICABLE MI_FEATURE_TOKENIZER_APPROXIMATE MI_FEATURE_TOKENIZER_LIMIT`
const protocolCodes = `MI_USAGE_UNAVAILABLE MI_USAGE_INVALID MI_PROTOCOL_OBJECT_MISSING MI_PROTOCOL_MODEL_CHANGED_WITHIN_STREAM MI_PROTOCOL_USAGE_CHANGED_WITHIN_STREAM MI_PROTOCOL_USAGE_TOTAL_MISMATCH MI_PROTOCOL_REASONING_EXCEEDS_COMPLETION MI_PROTOCOL_FINISH_REASON_UNKNOWN MI_PROTOCOL_FINISH_REASON_CONFLICT MI_PROTOCOL_MODEL_MISSING MI_PROTOCOL_FINISH_REASON_MISSING MI_PROTOCOL_EMPTY_CONTENT MI_PROTOCOL_USAGE_MISSING MI_PROTOCOL_FIRST_EVENT_TIMEOUT MI_PROTOCOL_STREAM_IDLE_TIMEOUT MI_PROTOCOL_STREAM_EOF_BEFORE_DONE MI_PROTOCOL_UNTERMINATED_EVENT MI_PROTOCOL_STREAM_MALFORMED_EVENT MI_PROTOCOL_CONTENT_AFTER_FINISH MI_PROTOCOL_LOCAL_TOKENIZER_APPROXIMATE`

func codeSet(values []string) bool {
	if len(values) > 128 {
		return false
	}
	seen := map[string]bool{}
	for _, s := range values {
		if len(s) > 128 || !one(s, codes+" "+additionalCodes+" "+protocolCodes) || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}
func refs(values []string, samples map[string]Sample) bool {
	if len(values) > MaxSamples {
		return false
	}
	seen := map[string]bool{}
	for _, s := range values {
		if _, ok := samples[s]; !ok || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

// A preflight walks only our acyclic owned input type, before any JSON clone.
// Conservative accounting includes field/element overhead and UTF-8 bytes.
func bounded(v reflect.Value, budget *int, depth int) bool {
	if depth > 24 || *budget < 0 {
		return false
	}
	*budget -= 32
	if v.Kind() == reflect.Pointer {
		return v.IsNil() || bounded(v.Elem(), budget, depth+1)
	}
	if v.Type() == reflect.TypeFor[time.Time]() {
		return true
	}
	switch v.Kind() {
	case reflect.String:
		s := v.String()
		if len(s) > 4096 || !utf8.ValidString(s) {
			return false
		}
		*budget -= len(s) * 6
	case reflect.Slice:
		if v.Len() > 2048 {
			return false
		}
		for i := 0; i < v.Len(); i++ {
			if !bounded(v.Index(i), budget, depth+1) {
				return false
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !bounded(v.Field(i), budget, depth+1) {
				return false
			}
		}
	case reflect.Float64:
		if !number(v.Float(), -1e16, 1e16) {
			return false
		}
	}
	return *budget >= 0
}

func NewDevelopmentSnapshot(scope Scope, input Input) (*Snapshot, error) {
	budget := MaxInputBytes
	if !bounded(reflect.ValueOf(input), &budget, 0) {
		return nil, ErrLimit
	}
	if !id(scope.ReportID) || !id(scope.OrganizationID) || !id(scope.RunID) || scope.AnalysisRevision != 1 || !stamp(scope.GeneratedAt) || !validVersions(scope.Versions) {
		return nil, ErrInput
	}
	if err := validate(scope, input); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, ErrInput
	}
	if len(raw) > MaxInputBytes {
		return nil, ErrLimit
	}
	var owned Input
	if json.Unmarshal(raw, &owned) != nil {
		return nil, ErrInput
	}
	normalize(&owned)
	doc := document{SchemaVersion: SchemaVersion, CanonicalVersion: CanonicalVersion, ReportID: scope.ReportID, OrganizationID: scope.OrganizationID, RunID: scope.RunID, AnalysisRevision: scope.AnalysisRevision, GeneratedAt: scope.GeneratedAt.UTC(), ObservationMode: "blackbox", Development: true, Calibrated: false, ContentState: "redacted", Input: owned, Review: nil, ReviewState: "not_included", Disclaimer: Disclaimer, DevelopmentNotice: DevelopmentNotice, Recommendations: []string{"MI_REVIEW_OBSERVED_EVIDENCE", "MI_REPEAT_WITH_TRUSTED_BASELINE"}}
	return &Snapshot{doc: doc}, nil
}

func validate(scope Scope, in Input) error {
	r := in.Result
	u := in.Run
	if u.ID != scope.RunID || !id(u.TargetID) || !one(u.Package, "quick standard deep custom") || !stamp(u.CreatedAt) || !stamp(u.FinishedAt) || !before(u.CreatedAt, u.FinishedAt) || !before(u.FinishedAt, scope.GeneratedAt) || u.StartedAt != nil && (!stamp(*u.StartedAt) || !before(u.CreatedAt, *u.StartedAt) || !before(*u.StartedAt, u.FinishedAt)) || u.RequestCount < 0 || u.RequestCount > 100000 || !count(&u.TokenCount) || !count(u.EstimatedCostMicros) {
		return ErrInput
	}
	if r.RunID != scope.RunID || r.AnalysisRevision != scope.AnalysisRevision || r.Versions != scope.Versions || r.ExpectedSamples < 1 || r.ExpectedSamples > MaxSamples || len(in.Samples) != r.ExpectedSamples || len(in.Findings) > MaxFindings || r.ValidSamples < 0 || r.ValidSamples > r.ExpectedSamples || r.Confidence < 0 || r.Confidence > 74 || !one(r.EvidenceGrade, "C D") || !one(r.RiskLevel, "low watch medium high critical insufficient") || !one(r.Completeness, "full partial insufficient") || r.Completeness != "full" && r.Confidence > 59 || !codeSet(r.Limitations) {
		return ErrInput
	}
	for _, n := range []*float64{r.OverallRisk, r.PromptRisk, r.TokenRisk, r.ResponseRisk, r.EvidenceRisk} {
		if !score(n) {
			return ErrInput
		}
	}
	if r.ValidSamples == 0 && (r.OverallRisk != nil || r.Completeness != "insufficient" || r.EvidenceGrade != "D" || r.RiskLevel != "insufficient") {
		return ErrInput
	}
	if r.Completeness == "insufficient" && (r.EvidenceGrade != "D" || r.RiskLevel != "insufficient") {
		return ErrInput
	}
	if r.Completeness != "insufficient" {
		if r.OverallRisk == nil || r.RiskLevel != riskLevel(*r.OverallRisk) {
			return ErrInput
		}
	}
	samples := map[string]Sample{}
	ordinals := map[int]bool{}
	attempts := map[string]bool{}
	included := 0
	for _, s := range in.Samples {
		if !id(s.ID) || s.RunID != scope.RunID || !id(s.ProbeInstanceID) || ordinals[s.Ordinal] || s.Ordinal < 0 || s.Ordinal >= r.ExpectedSamples || !one(s.Family, families) || !one(s.Language, "en-US zh-CN") || !one(s.Validity, validities) || s.RequestedMaxTokens < 1 || s.RequestedMaxTokens > 10000000 || !count(s.LocalCompletionTokens) || !count(s.ReportedCompletionTokens) || !one(s.TokenizerQuality, "exact compatible heuristic unavailable") || !codeSet(s.Limitations) {
			return ErrInput
		}
		if _, ok := samples[s.ID]; ok {
			return ErrInput
		}
		samples[s.ID] = s
		ordinals[s.Ordinal] = true
		if s.TokenizerQuality == "unavailable" {
			if s.LocalCompletionTokens != nil || s.TokenizerID != "" {
				return ErrInput
			}
		} else if s.LocalCompletionTokens == nil || !one(s.TokenizerID, "cl100k_base o200k_base unicode-byte-heuristic") {
			return ErrInput
		}
		if s.Included {
			included++
			if s.AuxiliaryOnly || s.Family == "self_report" || !one(s.Validity, "VALID VALID_WITH_WARNING") {
				return ErrInput
			}
		}
		if !optional(s.FinishReason, "STOP LENGTH CONTENT_FILTER TOOL_CALL CLIENT_CANCEL CLIENT_LIMIT ERROR UNKNOWN") || !optional(s.Contract, "matches deviates not_applicable") || !optional(s.RefusalClass, "no_cue refusal_like not_applicable") || !optional(s.IdentityClass, "no_cue self_identity_like not_applicable") || s.ResponseHash != nil && !hash(*s.ResponseHash) || len(s.Attempts) > 3 {
			return ErrInput
		}
		numbers := map[int]bool{}
		finalFound := s.FinalAttemptID == nil
		for _, a := range s.Attempts {
			if !id(a.ID) || attempts[a.ID] || numbers[a.AttemptNo] || a.AttemptNo < 1 || a.AttemptNo > 3 || !one(a.Validity, validities) || !count(a.PromptTokens) || !count(a.CompletionTokens) || !count(a.TotalTokens) || !count(a.DurationMS) || a.HTTPStatus != nil && (*a.HTTPStatus < 100 || *a.HTTPStatus > 599) || !optional(a.ErrorCode, "MI_EXECUTION_ERROR MI_AUTH_FAILED MI_MODEL_NOT_FOUND MI_PROTOCOL_UNSUPPORTED MI_RATE_LIMITED MI_TIMEOUT MI_NETWORK_FAILED MI_NETWORK_TEMPORARY MI_SERVICE_UNAVAILABLE MI_CLIENT_SAFETY_LIMIT MI_EVIDENCE_LIMIT MI_SAFETY_REFUSAL MI_EXECUTION_TARGET_STALE MI_EXECUTION_CIRCUIT_OPEN MI_UNCERTAIN_ATTEMPT MI_CONNECTION_RESET MI_EXECUTION_BUDGET_EXCEEDED MI_EXECUTION_CANCELLED") {
				return ErrInput
			}
			attempts[a.ID] = true
			numbers[a.AttemptNo] = true
			if a.StartedAt != nil && (!stamp(*a.StartedAt) || !before(u.CreatedAt, *a.StartedAt) || !before(*a.StartedAt, u.FinishedAt)) || a.FinishedAt != nil && (!stamp(*a.FinishedAt) || !before(u.CreatedAt, *a.FinishedAt) || !before(*a.FinishedAt, u.FinishedAt)) || a.StartedAt != nil && a.FinishedAt != nil && !before(*a.StartedAt, *a.FinishedAt) {
				return ErrInput
			}
			if s.FinalAttemptID != nil && a.ID == *s.FinalAttemptID {
				finalFound = true
			}
		}
		if !finalFound || s.FinalAttemptID != nil && !id(*s.FinalAttemptID) {
			return ErrInput
		}
	}
	if included != r.ValidSamples {
		return ErrInput
	}
	findings := map[string]bool{}
	for _, f := range in.Findings {
		dimension := map[string]*float64{"prompt": r.PromptRisk, "token": r.TokenRisk, "response": r.ResponseRisk, "evidence": r.EvidenceRisk}[f.Category]
		category := f.Category
		if category == "evidence" {
			category = "protocol"
		}
		if !id(f.ID) || findings[f.ID] || f.RunID != scope.RunID || f.AnalysisRevision != scope.AnalysisRevision || dimension == nil || f.RuleID != "development.aggregate."+category || f.RuleVersion != scope.Versions.Scoring || !one(f.Severity, "low medium high") || !number(f.RiskScore, 0, 100) || f.RiskScore != *dimension || f.Confidence != r.Confidence || f.EvidenceGrade != r.EvidenceGrade || !codeSet(f.Alternatives) || !refs(f.SampleRefs, samples) || len(f.Statistics) > 32 {
			return ErrInput
		}
		findings[f.ID] = true
		names := map[string]bool{}
		for _, s := range f.Statistics {
			if !one(s.Name, statisticNames) || names[s.Name] || s.Unit != "risk_index" || !score(s.Actual) {
				return ErrInput
			}
			names[s.Name] = true
		}
	}
	return validateStatistics(r, samples)
}

func validateStatistics(r Result, samples map[string]Sample) error {
	if t := r.Token; t != nil {
		if len(t.Tiers) > 512 || len(t.Plateaus) > 512 || t.UsageSamples < 0 || t.UsageSamples > r.ExpectedSamples || t.StreamPairs < 0 || t.StreamPairs > r.ExpectedSamples/2 || !codeSet(t.Limitations) || (t.UsageSamples == 0) != (t.UsageMedianError == nil) || (t.StreamPairs == 0) != (t.StreamMedianDifference == nil) {
			return ErrInput
		}
		if t.UsageMedianError != nil && !number(*t.UsageMedianError, 0, 1e6) || t.StreamMedianDifference != nil && !number(*t.StreamMedianDifference, -1e6, 1e6) {
			return ErrInput
		}
		seen := map[string]bool{}
		for _, v := range t.Tiers {
			key := v.SeriesID + "/" + strconv.FormatInt(v.RequestedMaxTokens, 10)
			if !hash(v.SeriesID) || seen[key] || !one(v.Family, families) || !one(v.Language, "en-US zh-CN") || v.RequestedMaxTokens < 1 || v.RequestedMaxTokens > 1e7 || v.Samples < 1 || v.Samples > r.ExpectedSamples || !number(v.Median, 0, 1e7) || !number(v.MAD, 0, 1e7) || !number(v.RobustCV, 0, 1e7) {
				return ErrInput
			}
			seen[key] = true
		}
		plateaus := map[string]bool{}
		for _, p := range t.Plateaus {
			key := p.SeriesID + "/" + strconv.FormatInt(p.LowRequested, 10) + "/" + strconv.FormatInt(p.HighRequested, 10)
			if !hash(p.SeriesID) || plateaus[key] || !one(p.Family, families) || p.LowRequested < 1 || p.HighRequested <= p.LowRequested || p.HighRequested > 1e7 || !number(p.GrowthRatio, 0, 1e7) || !number(p.Strength, 0, 100) || p.IndependentGroups < 0 || p.IndependentGroups > r.ExpectedSamples || !codeSet(p.Limitations) || !refs(p.SampleRefs, samples) || (p.Lower == nil) != (p.Upper == nil) || p.Lower != nil && (!number(*p.Lower, -1e7, 1e7) || !number(*p.Upper, -1e7, 1e7) || *p.Lower > *p.Upper) {
				return ErrInput
			}
			plateaus[key] = true
			for _, ref := range p.SampleRefs {
				if samples[ref].Family != p.Family {
					return ErrInput
				}
			}
		}
	}
	if b := r.Behavior; b != nil {
		if b.AnalyzedSamples < 0 || b.AuxiliarySamples < 0 || b.AnalyzedSamples+b.AuxiliarySamples > r.ExpectedSamples || len(b.Patterns) > 2048 || len(b.Differences) > 4 || !codeSet(b.Limitations) {
			return ErrInput
		}
		patterns := map[string]bool{}
		for _, p := range b.Patterns {
			key := p.Kind + "/" + p.Fingerprint
			if !one(p.Kind, "extra_prefix extra_suffix refusal_like self_identity_like") || !hash(p.Fingerprint) || patterns[key] || !one(p.State, "cross_family_repeat insufficient_coverage") || p.FamilyCount < 0 || p.FamilyCount > 7 || p.TemplateCount < 0 || p.TemplateCount > r.ExpectedSamples || p.LanguageCount < 0 || p.LanguageCount > 2 || !refs(p.SampleRefs, samples) {
				return ErrInput
			}
			patterns[key] = true
		}
		metrics := map[string]bool{}
		for _, d := range b.Differences {
			if !one(d.Metric, "contract_deviation extra_affix neutral_refusal_like unsolicited_identity_like") || metrics[d.Metric] || !one(d.State, "descriptive_available insufficient_pairs no_discordant_pairs") || d.Pairs < 0 || d.Pairs > r.ExpectedSamples/2 || d.EffectSize != nil && !number(*d.EffectSize, -1, 1) || d.PValue != nil && !number(*d.PValue, 0, 1) || d.AdjustedP != nil && !number(*d.AdjustedP, 0, 1) {
				return ErrInput
			}
			metrics[d.Metric] = true
		}
	}
	return nil
}

func normalize(in *Input) {
	in.Run.CreatedAt = in.Run.CreatedAt.UTC()
	in.Run.FinishedAt = in.Run.FinishedAt.UTC()
	if in.Run.StartedAt != nil {
		v := in.Run.StartedAt.UTC()
		in.Run.StartedAt = &v
	}
	sort.Slice(in.Samples, func(i, j int) bool { return in.Samples[i].Ordinal < in.Samples[j].Ordinal })
	for i := range in.Samples {
		s := &in.Samples[i]
		sort.Strings(s.Limitations)
		sort.Slice(s.Attempts, func(i, j int) bool { return s.Attempts[i].AttemptNo < s.Attempts[j].AttemptNo })
		for j := range s.Attempts {
			a := &s.Attempts[j]
			if a.StartedAt != nil {
				v := a.StartedAt.UTC()
				a.StartedAt = &v
			}
			if a.FinishedAt != nil {
				v := a.FinishedAt.UTC()
				a.FinishedAt = &v
			}
		}
		if s.Attempts == nil {
			s.Attempts = []Attempt{}
		}
		if s.Limitations == nil {
			s.Limitations = []string{}
		}
	}
	sort.Slice(in.Findings, func(i, j int) bool {
		a, _ := strconv.ParseInt(in.Findings[i].ID, 10, 64)
		b, _ := strconv.ParseInt(in.Findings[j].ID, 10, 64)
		return a < b
	})
	for i := range in.Findings {
		f := &in.Findings[i]
		sort.Strings(f.Alternatives)
		sort.Strings(f.SampleRefs)
		sort.Slice(f.Statistics, func(i, j int) bool { return f.Statistics[i].Name < f.Statistics[j].Name })
		if f.Alternatives == nil {
			f.Alternatives = []string{}
		}
		if f.SampleRefs == nil {
			f.SampleRefs = []string{}
		}
		if f.Statistics == nil {
			f.Statistics = []Statistic{}
		}
	}
	if in.Findings == nil {
		in.Findings = []Finding{}
	}
	if in.Result.Limitations == nil {
		in.Result.Limitations = []string{}
	}
	sort.Strings(in.Result.Limitations)
	normalizeStatistics(&in.Result)
}

// The current frozen scoring bands govern labels, not a second scoring pass.
func riskLevel(n float64) string {
	for i, v := range scoring.Parameters().Bands {
		if n < v {
			return []string{"low", "watch", "medium", "high"}[i]
		}
	}
	return "critical"
}
