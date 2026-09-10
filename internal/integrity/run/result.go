package run

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/behavior"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
	"model-integrity-inspector.local/mii/internal/integrity/analyzer"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func resultScore(n float64) bool { return !math.IsNaN(n) && !math.IsInf(n, 0) && n >= 0 && n <= 100 }
func decimal(id int64) string    { return strconv.FormatInt(id, 10) }

type ResultView struct {
	RunID string `json:"run_id"`
	ResultSummary
	Versions           VersionsView          `json:"versions"`
	ExpectedSamples    int                   `json:"expected_samples"`
	ValidSamples       int                   `json:"valid_samples"`
	PromptRisk         *float64              `json:"prompt_risk"`
	TokenRisk          *float64              `json:"token_risk"`
	ResponseRisk       *float64              `json:"response_risk"`
	EvidenceRisk       *float64              `json:"evidence_risk"`
	AlgorithmRiskLevel string                `json:"algorithm_risk_level"`
	ObservationMode    string                `json:"observation_mode"`
	Published          bool                  `json:"published"`
	Development        bool                  `json:"development"`
	Calibrated         bool                  `json:"calibrated"`
	CreatedAt          time.Time             `json:"created_at"`
	Limitations        []string              `json:"limitations"`
	Recommendations    []string              `json:"recommendations"`
	TokenAnalysis      *TokenAnalysisView    `json:"token_analysis,omitempty"`
	BehaviorAnalysis   *BehaviorAnalysisView `json:"behavior_analysis,omitempty"`
}
type TokenTierView struct {
	SeriesID           string  `json:"series_id"`
	Family             string  `json:"family"`
	Language           string  `json:"language"`
	RequestedMaxTokens int64   `json:"requested_max_tokens"`
	Samples            int     `json:"samples"`
	Median             float64 `json:"median"`
	MAD                float64 `json:"mad"`
	RobustCV           float64 `json:"robust_cv"`
}
type TokenPlateauView struct {
	SeriesID          string   `json:"series_id"`
	Family            string   `json:"family"`
	LowRequested      int64    `json:"low_requested"`
	HighRequested     int64    `json:"high_requested"`
	GrowthRatio       float64  `json:"growth_ratio"`
	Strength          float64  `json:"strength"`
	Candidate         bool     `json:"candidate"`
	Limited           bool     `json:"limited"`
	Lower             *float64 `json:"lower"`
	Upper             *float64 `json:"upper"`
	Paired            bool     `json:"paired"`
	IndependentGroups int      `json:"independent_groups"`
	Limitations       []string `json:"limitations"`
	SampleRefs        []string `json:"sample_refs"`
}
type TokenAnalysisView struct {
	Tiers                          []TokenTierView    `json:"tiers"`
	Plateaus                       []TokenPlateauView `json:"plateaus"`
	UsageSamples                   int                `json:"usage_samples"`
	UsageMedianRelativeError       float64            `json:"usage_median_relative_error"`
	StreamPairs                    int                `json:"stream_pairs"`
	StreamMedianRelativeDifference float64            `json:"stream_median_relative_difference"`
	Limitations                    []string           `json:"limitations"`
}
type PatternView struct {
	Kind          string   `json:"kind"`
	Fingerprint   string   `json:"fingerprint"`
	State         string   `json:"state"`
	FamilyCount   int      `json:"family_count"`
	TemplateCount int      `json:"template_count"`
	LanguageCount int      `json:"language_count"`
	SampleRefs    []string `json:"sample_refs"`
}
type DifferenceView struct {
	Metric     string   `json:"metric"`
	State      string   `json:"state"`
	Pairs      int      `json:"pairs"`
	EffectSize *float64 `json:"effect_size"`
	PValue     *float64 `json:"p_value"`
	AdjustedP  *float64 `json:"adjusted_p"`
}
type BehaviorAnalysisView struct {
	AnalyzedSamples  int              `json:"analyzed_samples"`
	AuxiliarySamples int              `json:"auxiliary_samples"`
	Patterns         []PatternView    `json:"patterns"`
	Differences      []DifferenceView `json:"differences"`
	Limitations      []string         `json:"limitations"`
}
type StatisticView struct {
	Name   string   `json:"name"`
	Actual *float64 `json:"actual"`
	Unit   string   `json:"unit"`
}
type FindingView struct {
	ID                      string          `json:"id"`
	RunID                   string          `json:"run_id"`
	AnalysisRevision        int             `json:"analysis_revision"`
	Category                string          `json:"category"`
	RuleID                  string          `json:"rule_id"`
	RuleVersion             string          `json:"rule_version"`
	Title                   string          `json:"title"`
	Summary                 string          `json:"summary"`
	Severity                string          `json:"severity"`
	RiskScore               float64         `json:"risk_score"`
	Confidence              int             `json:"confidence"`
	EvidenceGrade           string          `json:"evidence_grade"`
	Statistics              []StatisticView `json:"statistics"`
	AlternativeExplanations []string        `json:"alternative_explanations"`
	SampleRefs              []string        `json:"sample_refs"`
}
type SampleView struct {
	ID                       string   `json:"id"`
	RunID                    string   `json:"run_id"`
	ProbeInstanceID          string   `json:"probe_instance_id"`
	Ordinal                  int      `json:"ordinal"`
	Family                   string   `json:"family"`
	Language                 string   `json:"language"`
	Validity                 string   `json:"validity"`
	FinalAttemptID           *string  `json:"final_attempt_id"`
	Included                 bool     `json:"included"`
	AuxiliaryOnly            bool     `json:"auxiliary_only"`
	RequestedMaxTokens       int      `json:"requested_max_tokens"`
	LocalCompletionTokens    *int64   `json:"local_completion_tokens"`
	ReportedCompletionTokens *int64   `json:"reported_completion_tokens"`
	TokenizerID              string   `json:"tokenizer_id"`
	TokenizerQuality         string   `json:"tokenizer_quality"`
	Stream                   bool     `json:"stream"`
	FinishReason             *string  `json:"finish_reason"`
	StructureComplete        *bool    `json:"structure_complete"`
	HardTruncation           *bool    `json:"hard_truncation"`
	Contract                 *string  `json:"contract"`
	RefusalClass             *string  `json:"refusal_class"`
	IdentityClass            *string  `json:"identity_class"`
	ContentState             string   `json:"content_state"`
	ResponseHash             *string  `json:"response_hash"`
	Limitations              []string `json:"limitations"`
}
type AttemptView struct {
	ID               string     `json:"id"`
	AttemptNo        int        `json:"attempt_no"`
	Validity         string     `json:"validity"`
	ErrorCode        *string    `json:"error_code"`
	HTTPStatus       *int       `json:"http_status"`
	PromptTokens     *int64     `json:"prompt_tokens"`
	CompletionTokens *int64     `json:"completion_tokens"`
	TotalTokens      *int64     `json:"total_tokens"`
	DurationMS       *int64     `json:"duration_ms"`
	StartedAt        *time.Time `json:"started_at"`
	FinishedAt       *time.Time `json:"finished_at"`
	ContentState     string     `json:"content_state"`
}
type SampleDetail struct {
	Sample   SampleView    `json:"sample"`
	Attempts []AttemptView `json:"attempts"`
}

// strictDocument rejects unknown fields, duplicate/case-aliased keys, oversized
// strings/collections, excessive nesting and trailing documents before decoding.
func strictDocument(raw string, limit int, out any) error {
	if len(raw) < 2 || len(raw) > limit || !utf8.ValidString(raw) {
		return repository.ErrResultDocument
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	tokens := 0
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 || tokens > 200000 {
			return repository.ErrResultDocument
		}
		tokens++
		token, err := decoder.Token()
		if err != nil {
			return repository.ErrResultDocument
		}
		switch v := token.(type) {
		case string:
			if len(v) > 4096 {
				return repository.ErrResultDocument
			}
		case json.Delim:
			switch v {
			case '{':
				seen := map[string]bool{}
				for decoder.More() {
					key, err := decoder.Token()
					if err != nil {
						return repository.ErrResultDocument
					}
					name, ok := key.(string)
					if !ok || len(name) > 128 || seen[strings.ToLower(name)] {
						return repository.ErrResultDocument
					}
					seen[strings.ToLower(name)] = true
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
				end, err := decoder.Token()
				if err != nil || end != json.Delim('}') {
					return repository.ErrResultDocument
				}
			case '[':
				for decoder.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
				end, err := decoder.Token()
				if err != nil || end != json.Delim(']') {
					return repository.ErrResultDocument
				}
			default:
				return repository.ErrResultDocument
			}
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return repository.ErrResultDocument
	}
	decoder = json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return repository.ErrResultDocument
	}
	return nil
}

var resultHash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var validities = []string{"VALID", "VALID_WITH_WARNING", "INVALID_RETRYABLE", "INVALID_PROTOCOL", "INVALID_SAFETY_LIMIT", "NOT_APPLICABLE"}

func isHash(s string) bool        { return resultHash.MatchString(s) }
func boundedCount(n *int64) bool  { return n == nil || *n >= 0 && *n <= 9007199254740991 }
func finiteNumber(n float64) bool { return !math.IsNaN(n) && !math.IsInf(n, 0) }
func sameScore(a, b *float64) bool {
	return a == nil && b == nil || a != nil && b != nil && resultScore(*a) && *a == *b
}
func familyName(s string) bool {
	return slices.Contains([]string{"sequence", "jsonl", "format", "neutral", "differential", "style", "self_report"}, s)
}

func decodePublished(data repository.PublishedRead) (analyzer.Document, error) {
	var d analyzer.Document
	if err := strictDocument(data.Result.ConclusionJSON, 4<<20, &d); err != nil {
		return d, err
	}
	r, f, score := data.Run, d.Features, d.Scores
	if r.RuleBundleVersion != scoring.Version || r.TemplateBundleVersion != templates.BuiltinVersion || r.TokenizerBundleVersion != tokenizer.BuiltinVersion {
		return d, repository.ErrResultDocument
	}
	// Supported versions come from the installed implementation, never a stored
	// `Calibrated` or `Development` assertion. A future release needs a resolver.
	if d.SchemaVersion != analyzer.SchemaVersion || f.Version != features.Version || score.Version != scoring.Version || r.ScoringVersion != scoring.Version || score.RulesHash != scoring.RulesHash() || d.Tokens.Version != tokenrisk.Version || d.Tokens.RulesHash != tokenrisk.RulesHash() || d.Behavior.Version != behavior.Version || f.OrganizationID != decimal(r.OrganizationID) || f.RunID != decimal(r.ID) || f.ManifestHash != r.ManifestHash || !isHash(f.ManifestHash) || len(f.Samples) != len(data.Samples) || f.Expected != len(data.Samples) || f.Expected < 1 || f.Expected > 512 || f.Included < 0 || f.Included > f.Expected || f.Excluded != f.Expected-f.Included || score.ValidSamples != f.Included || score.ExpectedSamples != f.Expected || f.Included > r.ValidSampleCount {
		return d, repository.ErrResultDocument
	}
	stored := data.Result
	if f.Included == 0 && (stored.OverallRisk != nil || stored.Completeness != "INSUFFICIENT" || stored.EvidenceGrade != "D" || stored.RiskLevel != "insufficient") {
		return d, repository.ErrResultDocument
	}
	if !stored.IsPublished || stored.AnalysisRevision != 1 || stored.OrganizationID != r.OrganizationID || stored.RunID != r.ID || stored.Confidence != float64(score.Confidence.Score) || stored.EvidenceGrade != score.EvidenceGrade || stored.RiskLevel != score.RiskLevel || stored.Completeness != score.Completeness {
		return d, repository.ErrResultDocument
	}
	for i, v := range []*float64{score.Prompt.Score, score.Token.Score, score.Response.Score, score.Protocol.Score, score.Overall.Score} {
		if !sameScore(v, []*float64{stored.PromptRisk, stored.TokenRisk, stored.ResponseRisk, stored.EvidenceRisk, stored.OverallRisk}[i]) {
			return d, repository.ErrResultDocument
		}
	}
	if _, err := summary(1, stored.OverallRisk, stored.Confidence, stored.RiskLevel, stored.EvidenceGrade, stored.Completeness); err != nil {
		return d, err
	}
	rows := map[string]repository.ResultSampleRecord{}
	for _, row := range data.Samples {
		if row.ID <= 0 || row.OrganizationID != r.OrganizationID || row.RunID != r.ID || row.ProbeInstanceID <= 0 || row.CompletedAt == nil {
			return d, repository.ErrResultDocument
		}
		rows[decimal(row.ID)] = row
	}
	seen, ordinals := map[string]bool{}, map[int]bool{}
	included := 0
	for _, sample := range f.Samples {
		row, ok := rows[sample.SampleID]
		if !ok || seen[sample.SampleID] || ordinals[sample.Ordinal] || sample.Ordinal != row.Ordinal || sample.Ordinal < 0 || sample.Ordinal >= f.Expected || !derivedValidity(row.Validity, sample) || !slices.Contains(validities, sample.Validity) || row.FinalAttemptID != nil && sample.AttemptNumber != row.AttemptCount || row.FinalAttemptID == nil && sample.AttemptNumber != 0 || !familyName(sample.Family) || !slices.Contains([]string{"en-US", "zh-CN"}, sample.Language) || sample.RequestedMaxTokens < 1 || sample.RequestedMaxTokens > 10000000 {
			return d, repository.ErrResultDocument
		}
		seen[sample.SampleID] = true
		ordinals[sample.Ordinal] = true
		if (row.FinalAttemptID == nil) != (sample.AttemptID == "") || row.FinalAttemptID != nil && sample.AttemptID != decimal(*row.FinalAttemptID) {
			return d, repository.ErrResultDocument
		}
		if sample.Included {
			included++
			if sample.AuxiliaryOnly || sample.Family == "self_report" || sample.Validity != "VALID" && sample.Validity != "VALID_WITH_WARNING" {
				return d, repository.ErrResultDocument
			}
		}
		if sample.Local != nil {
			local := sample.Local
			if !slices.Contains([]tokenizer.Quality{tokenizer.Exact, tokenizer.Compatible, tokenizer.Heuristic, tokenizer.Unavailable}, local.Quality) || !boundedCount(local.Tokens) || (local.Quality == tokenizer.Unavailable) != (local.Tokens == nil) || !slices.Contains([]string{"", "cl100k_base", "o200k_base", "unicode-byte-heuristic"}, local.TokenizerID) {
				return d, repository.ErrResultDocument
			}
		}
		if sample.Usage != nil && !boundedCount(sample.Usage.ReportedCompletion) {
			return d, repository.ErrResultDocument
		}
		if sample.Structure != nil && !slices.Contains([]string{"STOP", "LENGTH", "CONTENT_FILTER", "TOOL_CALL", "CLIENT_CANCEL", "CLIENT_LIMIT", "ERROR", "UNKNOWN"}, sample.Structure.FinishReason) {
			return d, repository.ErrResultDocument
		}
		if b := sample.Behavior; b != nil {
			if b.SampleID != sample.SampleID || !slices.Contains([]behavior.ContractState{behavior.Matches, behavior.Deviates, behavior.ContractNotApplicable}, b.Contract) || !slices.Contains([]behavior.CueClass{behavior.NoCue, behavior.RefusalLike, behavior.CueNotApplicable}, b.Refusal) || !slices.Contains([]behavior.CueClass{behavior.NoCue, behavior.IdentityLike, behavior.CueNotApplicable}, b.Identity) || b.ResponseSHA256 != "" && !isHash(b.ResponseSHA256) {
				return d, repository.ErrResultDocument
			}
		}
	}
	if included != f.Included {
		return d, repository.ErrResultDocument
	}
	return d, nil
}

func derivedValidity(persisted string, f features.SampleFeature) bool {
	if f.Validity == persisted {
		return true
	}
	if f.Validity == "NOT_APPLICABLE" && !f.Included && (slices.Contains(f.Limitations, "MI_FEATURE_EVIDENCE_MISSING") || slices.Contains(f.Limitations, "MI_FEATURE_TERMINATION_NOT_APPLICABLE")) {
		return true
	}
	if f.Validity == "INVALID_RETRYABLE" && !f.Included && slices.Contains(f.Limitations, "MI_FEATURE_ATTEMPT_UNCERTAIN") {
		return true
	}
	if persisted != "VALID" && persisted != "VALID_WITH_WARNING" {
		return false
	}
	if f.Validity == "VALID_WITH_WARNING" && f.Protocol != nil && f.Protocol.State == "valid_with_warning" {
		return true
	}
	if f.Validity == "INVALID_PROTOCOL" && !f.Included && slices.Contains(f.Limitations, "MI_FEATURE_PROTOCOL_INVALID") {
		return true
	}
	if f.Validity == "INVALID_SAFETY_LIMIT" && !f.Included {
		for _, code := range []string{"MI_FEATURE_TOKENIZER_LIMIT", "MI_FEATURE_STRUCTURE_INVALID", "MI_FEATURE_STRUCTURE_LIMIT"} {
			if slices.Contains(f.Limitations, code) {
				return true
			}
		}
	}
	return false
}

// Unknown future codes are represented by a fixed marker, never echoed. This
// avoids treating a string in an otherwise typed persisted document as S1.
func safeCodes(values []string) []string {
	known := strings.Fields(`MI_BASELINE_UNAVAILABLE MI_GATEWAY_EVIDENCE_UNAVAILABLE MI_DEVELOPMENT_RULES_UNCALIBRATED MI_MULTIPLE_COMPARISONS_EXPLORATORY MI_COMPONENTS_MISSING_RENORMALIZED MI_NO_ANALYZABLE_COMPONENTS MI_SINGLE_TIER_LIMIT MI_VALID_SAMPLES_INSUFFICIENT MI_TOKENIZER_HEURISTIC_ONLY MI_TOKENIZER_HEURISTIC_LIMIT MI_TOKENIZER_UNAVAILABLE MI_REASONING_UNSEPARATED MI_NATURAL_EOS_ALTERNATIVE MI_PARTIAL_RESULT MI_INDEPENDENT_GROUPS_INSUFFICIENT MI_BOOTSTRAP_GROUPS_INSUFFICIENT MI_DECLARED_MODEL_OUTPUT_LIMIT MI_STREAM_MODES_NOT_COMPARABLE MI_USAGE_INSUFFICIENT MI_PAIRED_SAMPLES_INSUFFICIENT MI_BEHAVIOR_INDEPENDENT_FAMILIES_INSUFFICIENT MI_BEHAVIOR_REPEATABILITY_INSUFFICIENT MI_IDENTITY_STYLE_ONLY MI_PARTIAL_CONFIDENCE_LIMIT MI_UNCALIBRATED_CONFIDENCE_LIMIT MI_REPLICATION_OR_CONSISTENCY_LIMIT MI_VALID_SAMPLE_COVERAGE_LIMIT MI_CRITICAL_EVIDENCE_INSUFFICIENT MI_NO_VALID_SAMPLES MI_UPSTREAM_AGGREGATE_LIMITATIONS MI_PROTOCOL_SCORE_NOT_PROVIDER_MISCONDUCT MI_RESULT_INCOMPLETE MI_FINAL_SAMPLES_MISSING MI_VALID_SAMPLES_INCOMPLETE MI_NETWORK_ERRORS_REDUCE_ATTRIBUTION MI_TOKEN_AGGREGATE_UNAVAILABLE MI_RESPONSE_AGGREGATE_UNAVAILABLE MI_TOKENIZER_UNAVAILABLE MI_BH_DEPENDENCE_ASSUMPTION MI_PREPLANNED_FAMILY_REQUIRED MI_P_VALUE_NOT_RISK ordinary_model_variation capability_or_protocol_limits`)
	known = append(known, strings.Fields(`MI_BOOTSTRAP_UNAVAILABLE MI_HIGH_TIER_SAMPLES_INSUFFICIENT MI_LADDER_PAIRS_INCOMPLETE MI_LENGTH_FAR_BELOW_REQUEST MI_MODE_TIER_COVERAGE_INSUFFICIENT MI_NORMAL_GROWTH_WITHIN_INTERVAL MI_STOP_WITH_INCOMPLETE_STRUCTURE MI_STREAM_PAIRS_INCOMPLETE MI_STREAM_PAIRS_INSUFFICIENT MI_STREAM_TERMINATOR_MISSING MI_STREAM_TIER_COVERAGE_INSUFFICIENT MI_STREAM_VARIATION_ALTERNATIVE MI_TERMINATION_NOT_APPLICABLE MI_USAGE_SAMPLES_INSUFFICIENT MI_FEATURE_ATTEMPT_UNCERTAIN MI_FEATURE_AUXILIARY_ONLY MI_FEATURE_BEHAVIOR_INVALID MI_FEATURE_BEHAVIOR_LIMIT MI_FEATURE_BINDING_INVALID MI_FEATURE_CONTRACT_UNSUPPORTED MI_FEATURE_EVIDENCE_MISSING MI_FEATURE_FINAL_ATTEMPT_INVALID MI_FEATURE_FINAL_ATTEMPT_MISSING MI_FEATURE_PLAN_REDUCED MI_FEATURE_PROTOCOL_INVALID MI_FEATURE_PROTOCOL_WARNING_UNKNOWN MI_FEATURE_SAFETY_LIMIT MI_FEATURE_STRUCTURE_INVALID MI_FEATURE_STRUCTURE_LIMIT MI_FEATURE_TERMINATION_NOT_APPLICABLE MI_FEATURE_TOKENIZER_APPROXIMATE MI_FEATURE_TOKENIZER_LIMIT`)...)
	known = append(known, strings.Fields(`MI_USAGE_UNAVAILABLE MI_USAGE_INVALID MI_PROTOCOL_OBJECT_MISSING MI_PROTOCOL_MODEL_CHANGED_WITHIN_STREAM MI_PROTOCOL_USAGE_CHANGED_WITHIN_STREAM MI_PROTOCOL_USAGE_TOTAL_MISMATCH MI_PROTOCOL_REASONING_EXCEEDS_COMPLETION MI_PROTOCOL_FINISH_REASON_UNKNOWN MI_PROTOCOL_FINISH_REASON_CONFLICT MI_PROTOCOL_MODEL_MISSING MI_PROTOCOL_FINISH_REASON_MISSING MI_PROTOCOL_EMPTY_CONTENT MI_PROTOCOL_USAGE_MISSING MI_PROTOCOL_FIRST_EVENT_TIMEOUT MI_PROTOCOL_STREAM_IDLE_TIMEOUT MI_PROTOCOL_STREAM_EOF_BEFORE_DONE MI_PROTOCOL_UNTERMINATED_EVENT MI_PROTOCOL_STREAM_MALFORMED_EVENT MI_PROTOCOL_CONTENT_AFTER_FINISH MI_PROTOCOL_LOCAL_TOKENIZER_APPROXIMATE`)...)
	out := []string{}
	for _, code := range values {
		if !slices.Contains(known, code) {
			code = "MI_ANALYSIS_LIMITATION_UNAVAILABLE"
		}
		if !slices.Contains(out, code) {
			out = append(out, code)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Service) resultData(ctx context.Context, orgID, runID int64, revision int, evidence bool, sampleID int64) (repository.PublishedRead, analyzer.Document, error) {
	tenant, err := s.tenant(ctx, orgID)
	if err != nil {
		return repository.PublishedRead{}, analyzer.Document{}, err
	}
	data, err := tenant.ReadPublishedResult(runID, revision, evidence, sampleID)
	if err != nil {
		return data, analyzer.Document{}, err
	}
	doc, err := decodePublished(data)
	return data, doc, err
}

func (s *Service) Result(ctx context.Context, orgID, runID int64, revision int, statistics bool) (ResultView, error) {
	data, doc, err := s.resultData(ctx, orgID, runID, revision, statistics, 0)
	if err != nil {
		return ResultView{}, err
	}
	r := data.Result
	summary, err := summary(revision, r.OverallRisk, r.Confidence, r.RiskLevel, r.EvidenceGrade, r.Completeness)
	if err != nil {
		return ResultView{}, err
	}
	view := ResultView{RunID: decimal(runID), ResultSummary: summary, Versions: VersionsView{data.Run.RuleBundleVersion, data.Run.TemplateBundleVersion, data.Run.ScoringVersion, data.Run.TokenizerBundleVersion}, PromptRisk: r.PromptRisk, TokenRisk: r.TokenRisk, ResponseRisk: r.ResponseRisk, EvidenceRisk: r.EvidenceRisk, AlgorithmRiskLevel: r.RiskLevel, ObservationMode: "blackbox", Published: true, Development: true, Calibrated: false, CreatedAt: r.CreatedAt, Limitations: safeCodes(doc.Scores.Limitations), Recommendations: []string{"MI_REVIEW_OBSERVED_EVIDENCE", "MI_REPEAT_WITH_TRUSTED_BASELINE"}}
	view.ExpectedSamples, view.ValidSamples = doc.Scores.ExpectedSamples, doc.Scores.ValidSamples
	if statistics {
		view.TokenAnalysis, view.BehaviorAnalysis, err = statisticsViews(doc)
		if err != nil {
			return ResultView{}, err
		}
	}
	return view, nil
}

func statisticsViews(d analyzer.Document) (*TokenAnalysisView, *BehaviorAnalysisView, error) {
	t := d.Tokens
	b := d.Behavior
	if len(t.Series) > 64 || len(t.Plateaus) > 512 || len(b.Patterns) > 2048 || len(b.Samples)+len(b.Auxiliary) > d.Features.Expected || len(d.Differences) > 4 || len(d.Multiplicity.Tests) > 4 {
		return nil, nil, repository.ErrResultDocument
	}
	ids := map[string]string{}
	for _, s := range d.Features.Samples {
		ids[s.SampleID] = s.Family
	}
	tokens := &TokenAnalysisView{Tiers: []TokenTierView{}, Plateaus: []TokenPlateauView{}, UsageSamples: t.Usage.IncludedSamples, UsageMedianRelativeError: t.Usage.MedianRelativeError, StreamPairs: t.Stream.Pairs, StreamMedianRelativeDifference: t.Stream.MedianRelativeDifference, Limitations: safeCodes(append(append([]string{}, t.Token.Limitations...), t.Response.Limitations...))}
	if t.Usage.IncludedSamples < 0 || t.Usage.IncludedSamples > d.Features.Expected || t.Usage.Samples < 0 || t.Usage.Samples > d.Features.Expected || t.Stream.Pairs < 0 || t.Stream.Pairs > d.Features.Expected || !finiteNumber(t.Usage.MedianRelativeError) || math.Abs(t.Usage.MedianRelativeError) > 1000000 || !finiteNumber(t.Stream.MedianRelativeDifference) || math.Abs(t.Stream.MedianRelativeDifference) > 1000000 {
		return nil, nil, repository.ErrResultDocument
	}
	for _, series := range t.Series {
		if !isHash(series.ID) || !familyName(series.Family) || !slices.Contains([]string{"en-US", "zh-CN"}, series.Language) || len(series.Tiers) > 512 {
			return nil, nil, repository.ErrResultDocument
		}
		for _, tier := range series.Tiers {
			if len(tokens.Tiers) >= 512 {
				return nil, nil, repository.ErrResultDocument
			}
			if tier.RequestedMaxTokens < 1 || tier.RequestedMaxTokens > 10000000 || tier.Samples < 1 || tier.Samples > d.Features.Expected || !finiteNumber(tier.Median) || tier.Median < 0 || tier.Median > 10000000 || !finiteNumber(tier.MAD) || tier.MAD < 0 || tier.MAD > 10000000 || !finiteNumber(tier.RobustCV) || tier.RobustCV < 0 || tier.RobustCV > 10000000 {
				return nil, nil, repository.ErrResultDocument
			}
			tokens.Tiers = append(tokens.Tiers, TokenTierView{series.ID, series.Family, series.Language, tier.RequestedMaxTokens, tier.Samples, tier.Median, tier.MAD, tier.RobustCV})
		}
	}
	for _, p := range t.Plateaus {
		if !isHash(p.SeriesID) || !familyName(p.Family) || !resultScore(p.Strength) || !finiteNumber(p.GrowthRatio) || p.GrowthRatio < 0 || p.GrowthRatio > 10000000 || p.Low.RequestedMaxTokens < 1 || p.High.RequestedMaxTokens <= p.Low.RequestedMaxTokens || p.High.RequestedMaxTokens > 10000000 || len(p.SampleIDs) > 512 || p.DifferenceCI.Units < 0 || p.DifferenceCI.Units > 512 {
			return nil, nil, repository.ErrResultDocument
		}
		view := TokenPlateauView{SeriesID: p.SeriesID, Family: p.Family, LowRequested: p.Low.RequestedMaxTokens, HighRequested: p.High.RequestedMaxTokens, GrowthRatio: p.GrowthRatio, Strength: p.Strength, Candidate: p.Candidate, Limited: p.Limited, Paired: p.DifferenceCI.Paired, IndependentGroups: p.DifferenceCI.Units, Limitations: safeCodes(p.Limitations), SampleRefs: []string{}}
		if p.DifferenceCI.Available {
			if !finiteNumber(p.DifferenceCI.Lower) || !finiteNumber(p.DifferenceCI.Upper) || p.DifferenceCI.Lower > p.DifferenceCI.Upper || math.Abs(p.DifferenceCI.Lower) > 10000000 || math.Abs(p.DifferenceCI.Upper) > 10000000 {
				return nil, nil, repository.ErrResultDocument
			}
			lo, hi := p.DifferenceCI.Lower, p.DifferenceCI.Upper
			view.Lower, view.Upper = &lo, &hi
		}
		for _, id := range p.SampleIDs {
			if ids[decimal(id)] != p.Family {
				return nil, nil, repository.ErrResultDocument
			}
			if !slices.Contains(view.SampleRefs, decimal(id)) {
				view.SampleRefs = append(view.SampleRefs, decimal(id))
			}
		}
		tokens.Plateaus = append(tokens.Plateaus, view)
	}
	behaviors := &BehaviorAnalysisView{Patterns: []PatternView{}, Differences: []DifferenceView{}, Limitations: []string{"MI_DEVELOPMENT_RULES_UNCALIBRATED", "MI_P_VALUE_NOT_RISK", "MI_BASELINE_UNAVAILABLE"}}
	behaviorSeen := map[string]bool{}
	for _, sample := range b.Samples {
		if _, ok := ids[sample.SampleID]; !ok || behaviorSeen[sample.SampleID] || !slices.Contains([]behavior.State{behavior.Analyzed, behavior.Excluded}, sample.State) {
			return nil, nil, repository.ErrResultDocument
		}
		behaviorSeen[sample.SampleID] = true
		if sample.State == behavior.Analyzed {
			behaviors.AnalyzedSamples++
		}
	}
	for _, sample := range b.Auxiliary {
		if _, ok := ids[sample.SampleID]; !ok || behaviorSeen[sample.SampleID] || sample.State != behavior.Auxiliary {
			return nil, nil, repository.ErrResultDocument
		}
		behaviorSeen[sample.SampleID] = true
	}
	behaviors.AuxiliarySamples = len(b.Auxiliary)
	for _, p := range b.Patterns {
		if !slices.Contains([]behavior.EvidenceKind{behavior.Prefix, behavior.Suffix, behavior.Refusal, behavior.Identity}, p.Kind) || !isHash(p.NormalizedSHA256) || !slices.Contains([]behavior.PatternState{behavior.StablePattern, behavior.InsufficientPattern}, p.State) || p.FamilyCount < 0 || p.FamilyCount > 7 || p.TemplateCount < 0 || p.TemplateCount > 512 || p.LanguageCount < 0 || p.LanguageCount > 2 || len(p.Evidence) > 512 {
			return nil, nil, repository.ErrResultDocument
		}
		view := PatternView{Kind: string(p.Kind), Fingerprint: p.NormalizedSHA256, State: string(p.State), FamilyCount: p.FamilyCount, TemplateCount: p.TemplateCount, LanguageCount: p.LanguageCount, SampleRefs: []string{}}
		for _, e := range p.Evidence {
			if _, ok := ids[e.SampleID]; !ok {
				return nil, nil, repository.ErrResultDocument
			}
			if !slices.Contains(view.SampleRefs, e.SampleID) {
				view.SampleRefs = append(view.SampleRefs, e.SampleID)
			}
		}
		behaviors.Patterns = append(behaviors.Patterns, view)
	}
	adjusted := map[string]*float64{}
	metrics := []behavior.Metric{behavior.ContractDeviation, behavior.ExtraAffix, behavior.NeutralRefusal, behavior.UnsolicitedIdentity}
	for _, h := range d.Multiplicity.Tests {
		_, duplicate := adjusted[h.ID]
		if !slices.Contains(metrics, behavior.Metric(h.ID)) || duplicate || h.AdjustedP != nil && (!finiteNumber(*h.AdjustedP) || *h.AdjustedP < 0 || *h.AdjustedP > 1) {
			return nil, nil, repository.ErrResultDocument
		}
		adjusted[h.ID] = h.AdjustedP
	}
	differenceSeen := map[behavior.Metric]bool{}
	for _, diff := range d.Differences {
		if !slices.Contains(metrics, diff.Metric) || differenceSeen[diff.Metric] || !slices.Contains([]behavior.PairState{behavior.PairAvailable, behavior.PairInsufficient, behavior.PairUninformative}, diff.State) || diff.CompletePairs < 0 || diff.CompletePairs > d.Features.Expected {
			return nil, nil, repository.ErrResultDocument
		}
		differenceSeen[diff.Metric] = true
		if diff.RiskDifference != nil && (!finiteNumber(*diff.RiskDifference) || math.Abs(*diff.RiskDifference) > 1) || diff.ExactTwoSidedP != nil && (!finiteNumber(*diff.ExactTwoSidedP) || *diff.ExactTwoSidedP < 0 || *diff.ExactTwoSidedP > 1) {
			return nil, nil, repository.ErrResultDocument
		}
		behaviors.Differences = append(behaviors.Differences, DifferenceView{string(diff.Metric), string(diff.State), diff.CompletePairs, diff.RiskDifference, diff.ExactTwoSidedP, adjusted[string(diff.Metric)]})
	}
	return tokens, behaviors, nil
}

func (s *Service) Findings(ctx context.Context, orgID, runID int64, revision int, page repository.ListOptions) ([]FindingView, error) {
	if page.Limit < 1 || page.Limit > 100 || page.AfterID < 0 {
		return nil, ErrInvalid
	}
	data, doc, err := s.resultData(ctx, orgID, runID, revision, true, 0)
	if err != nil {
		return nil, err
	}
	return findingsViews(data, doc, orgID, runID, revision, page)
}

func findingsViews(data repository.PublishedRead, doc analyzer.Document, orgID, runID int64, revision int, page repository.ListOptions) ([]FindingView, error) {
	items := []FindingView{}
	ids := map[string]bool{}
	for _, sample := range data.Samples {
		ids[decimal(sample.ID)] = true
	}
	for _, row := range data.Findings {
		category := row.Category
		categoryView := category
		if category == "protocol" {
			categoryView = "evidence"
		}
		dimensions := map[string]scoring.Dimension{"prompt": doc.Scores.Prompt, "token": doc.Scores.Token, "response": doc.Scores.Response, "protocol": doc.Scores.Protocol}
		dimension, ok := dimensions[category]
		if !ok || row.ID <= 0 || row.OrganizationID != orgID || row.RunID != runID || row.AnalysisRevision != revision || row.Type != "development_aggregate" || row.RuleID != "development.aggregate."+category || row.RuleVersion != scoring.Version || !slices.Contains([]string{"low", "medium", "high"}, row.Severity) || !resultScore(row.RiskScore) || dimension.Score == nil || row.RiskScore != *dimension.Score || row.Confidence != data.Result.Confidence || row.EvidenceGrade != data.Result.EvidenceGrade {
			return nil, repository.ErrResultDocument
		}
		var stats scoring.Dimension
		var refs, alternatives []string
		if strictDocument(row.StatisticsJSON, 64<<10, &stats) != nil || !reflect.DeepEqual(stats, dimension) || strictDocument(row.SampleRefs, 64<<10, &refs) != nil || strictDocument(row.AlternativeExplanations, 64<<10, &alternatives) != nil || len(refs) > 512 || len(alternatives) > 32 {
			return nil, repository.ErrResultDocument
		}
		seen := map[string]bool{}
		for _, id := range refs {
			if !ids[id] || seen[id] {
				return nil, repository.ErrResultDocument
			}
			seen[id] = true
		}
		view := FindingView{ID: decimal(row.ID), RunID: decimal(runID), AnalysisRevision: revision, Category: categoryView, RuleID: row.RuleID, RuleVersion: row.RuleVersion, Title: "Development " + category + " observation", Summary: "Observed deviations are not proof of provider misconduct. References identify contributing observations, not independent positive findings.", Severity: row.Severity, RiskScore: row.RiskScore, Confidence: int(row.Confidence), EvidenceGrade: row.EvidenceGrade, Statistics: []StatisticView{}, AlternativeExplanations: safeCodes(alternatives), SampleRefs: refs}
		for _, part := range stats.Components {
			if !slices.Contains([]string{"format_contract", "stable_unknown_affix", "neutral_refusal", "identity_style", "trusted_baseline_difference", "plateau", "termination", "usage", "stream_difference", "sse_termination", "fixed_suffix", "metadata_consistency", "protocol_anomaly", "usage_quality", "http_content_type", "model_echo", "finish_reason", "tokenizer_unavailable", "valid_sample_rate"}, part.Name) || part.Score != nil && !resultScore(*part.Score) {
				return nil, repository.ErrResultDocument
			}
			view.Statistics = append(view.Statistics, StatisticView{part.Name, part.Score, "risk_index"})
		}
		if row.ID > page.AfterID && len(items) < page.Limit {
			items = append(items, view)
		}
	}
	return items, nil
}

func sampleView(runID int64, row repository.ResultSampleRecord, f features.SampleFeature) SampleView {
	view := SampleView{ID: f.SampleID, RunID: decimal(runID), ProbeInstanceID: decimal(row.ProbeInstanceID), Ordinal: f.Ordinal, Family: f.Family, Language: f.Language, Validity: f.Validity, Included: f.Included, AuxiliaryOnly: f.AuxiliaryOnly, RequestedMaxTokens: f.RequestedMaxTokens, TokenizerQuality: "unavailable", Stream: f.Stream, ContentState: "redacted", Limitations: safeCodes(f.Limitations)}
	if f.Protocol != nil {
		view.Limitations = safeCodes(append(slices.Clone(f.Limitations), f.Protocol.Warnings...))
	}
	if row.FinalAttemptID != nil {
		id := decimal(*row.FinalAttemptID)
		view.FinalAttemptID = &id
	}
	if f.Local != nil {
		view.LocalCompletionTokens = f.Local.Tokens
		view.TokenizerID = f.Local.TokenizerID
		view.TokenizerQuality = string(f.Local.Quality)
	}
	if f.Usage != nil {
		view.ReportedCompletionTokens = f.Usage.ReportedCompletion
	}
	if f.Structure != nil {
		view.FinishReason = &f.Structure.FinishReason
		view.StructureComplete = &f.Structure.StructureComplete
		view.HardTruncation = &f.Structure.HardTruncation
	}
	if f.Behavior != nil {
		contract, refusal, identity := string(f.Behavior.Contract), string(f.Behavior.Refusal), string(f.Behavior.Identity)
		view.Contract, view.RefusalClass, view.IdentityClass = &contract, &refusal, &identity
		if f.Behavior.ResponseSHA256 != "" {
			view.ResponseHash = &f.Behavior.ResponseSHA256
		}
	}
	return view
}

func (s *Service) Samples(ctx context.Context, orgID, runID int64, revision int, page repository.ListOptions) ([]SampleView, error) {
	if page.Limit < 1 || page.Limit > 100 || page.AfterID < 0 {
		return nil, ErrInvalid
	}
	data, doc, err := s.resultData(ctx, orgID, runID, revision, true, 0)
	if err != nil {
		return nil, err
	}
	features := map[string]features.SampleFeature{}
	for _, f := range doc.Features.Samples {
		features[f.SampleID] = f
	}
	items := []SampleView{}
	for _, row := range data.Samples {
		if row.ID > page.AfterID && len(items) < page.Limit {
			items = append(items, sampleView(runID, row, features[decimal(row.ID)]))
		}
	}
	return items, nil
}

func (s *Service) Sample(ctx context.Context, orgID, runID, sampleID int64, revision int) (SampleDetail, error) {
	data, doc, err := s.resultData(ctx, orgID, runID, revision, true, sampleID)
	if err != nil {
		return SampleDetail{}, err
	}
	out := SampleDetail{Attempts: []AttemptView{}}
	for _, row := range data.Samples {
		if row.ID == sampleID {
			for _, f := range doc.Features.Samples {
				if f.SampleID == decimal(sampleID) {
					out.Sample = sampleView(runID, row, f)
				}
			}
		}
	}
	if out.Sample.ID == "" {
		return out, repository.ErrNotFound
	}
	out.Attempts, err = attemptsViews(data.Attempts, orgID, runID, sampleID)
	if err != nil {
		return SampleDetail{}, err
	}
	return out, nil
}

func attemptsViews(rows []repository.ResultAttemptRecord, orgID, runID, sampleID int64) ([]AttemptView, error) {
	items := []AttemptView{}
	for _, a := range rows {
		if a.ID <= 0 || a.OrganizationID != orgID || a.RunID != runID || a.LogicalSampleID != sampleID || a.AttemptNo < 1 || a.AttemptNo > 3 || !slices.Contains(validities, a.Validity) || a.HTTPStatus != nil && (*a.HTTPStatus < 100 || *a.HTTPStatus > 599) || !boundedCount(a.PromptTokens) || !boundedCount(a.CompletionTokens) || !boundedCount(a.TotalTokens) || !boundedCount(a.DurationMS) {
			return nil, repository.ErrResultDocument
		}
		code := attemptErrorCode(a.ErrorCode)
		items = append(items, AttemptView{decimal(a.ID), a.AttemptNo, a.Validity, code, a.HTTPStatus, a.PromptTokens, a.CompletionTokens, a.TotalTokens, a.DurationMS, a.StartedAt, a.FinishedAt, "redacted"})
	}
	return items, nil
}

func attemptErrorCode(stored *string) *string {
	// Successful attempts historically stored a non-NULL empty string. Empty
	// and NULL both mean no error, including VALID_WITH_WARNING observations.
	if stored == nil || *stored == "" {
		return nil
	}
	value := "MI_EXECUTION_ERROR"
	if slices.Contains([]string{"MI_AUTH_FAILED", "MI_MODEL_NOT_FOUND", "MI_PROTOCOL_UNSUPPORTED", "MI_RATE_LIMITED", "MI_TIMEOUT", "MI_NETWORK_TEMPORARY", "MI_SERVICE_UNAVAILABLE", "MI_CLIENT_SAFETY_LIMIT", "MI_EVIDENCE_LIMIT", "MI_SAFETY_REFUSAL", "MI_EXECUTION_TARGET_STALE", "MI_EXECUTION_CIRCUIT_OPEN", "MI_UNCERTAIN_ATTEMPT", "MI_CONNECTION_RESET", "MI_EXECUTION_BUDGET_EXCEEDED", "MI_EXECUTION_CANCELLED"}, *stored) {
		value = *stored
	}
	return &value
}
