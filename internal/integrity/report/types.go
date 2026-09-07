package report

import (
	"errors"
	"time"
)

const SchemaVersion = "mii.report.v1"
const CanonicalVersion = "mii.report.canonical-json.v1"
const MaxSamples = 512
const MaxFindings = 256
const MaxInputBytes = 4 << 20
const MaxOutputBytes = 16 << 20

const Disclaimer = "本报告基于指定时间、接口、参数和样本的可观测行为生成。除非存在直接网关证据，否则异常代表风险或统计迹象，不等同于对供应商内部配置或主观行为的确定性证明。"
const DevelopmentNotice = "未校准的开发规则；仅提供 C/D 级行为迹象或信息不足。机器发布不代表人工审核批准，风险指数不是供应商欺诈概率。"

var ErrInput = errors.New("MI_REPORT_INPUT_INVALID")
var ErrLimit = errors.New("MI_REPORT_RESOURCE_LIMIT")
var ErrRender = errors.New("MI_REPORT_RENDER_FAILED")

type Versions struct {
	Rule      string `json:"rule_bundle"`
	Template  string `json:"template_bundle"`
	Scoring   string `json:"scoring"`
	Tokenizer string `json:"tokenizer_bundle"`
}

// Scope is supplied by the authorized report job, never by a public request
// body. Validation binds supplied projections; it does not authenticate a DB,
// caller, signature or independent review. ReportID identifies this snapshot.
type Scope struct {
	ReportID, OrganizationID, RunID string
	AnalysisRevision                int
	GeneratedAt                     time.Time
	Versions                        Versions
}

// These report-owned S1 types deliberately contain no endpoint, credentials,
// prompt, response body, arbitrary display title, URL, HTML or storage path.
// The application adapter maps already validated public read projections.
type Input struct {
	Run      Run       `json:"run"`
	Result   Result    `json:"result"`
	Findings []Finding `json:"findings"`
	Samples  []Sample  `json:"samples"`
}
type Run struct {
	ID                  string     `json:"id"`
	TargetID            string     `json:"target_id"`
	Package             string     `json:"package"`
	CreatedAt           time.Time  `json:"created_at"`
	StartedAt           *time.Time `json:"started_at"`
	FinishedAt          time.Time  `json:"finished_at"`
	RequestCount        int64      `json:"request_count"`
	TokenCount          int64      `json:"token_count"`
	EstimatedCostMicros *int64     `json:"estimated_cost_micros"`
}
type Result struct {
	RunID            string              `json:"run_id"`
	AnalysisRevision int                 `json:"analysis_revision"`
	Versions         Versions            `json:"versions"`
	ExpectedSamples  int                 `json:"expected_samples"`
	ValidSamples     int                 `json:"valid_samples"`
	OverallRisk      *float64            `json:"overall_risk"`
	PromptRisk       *float64            `json:"prompt_risk"`
	TokenRisk        *float64            `json:"token_risk"`
	ResponseRisk     *float64            `json:"response_risk"`
	EvidenceRisk     *float64            `json:"evidence_risk"`
	Confidence       int                 `json:"confidence"`
	EvidenceGrade    string              `json:"evidence_grade"`
	RiskLevel        string              `json:"risk_level"`
	Completeness     string              `json:"completeness"`
	Limitations      []string            `json:"limitations"`
	Token            *TokenStatistics    `json:"token_statistics"`
	Behavior         *BehaviorStatistics `json:"behavior_statistics"`
}
type Statistic struct {
	Name   string   `json:"name"`
	Actual *float64 `json:"actual"`
	Unit   string   `json:"unit"`
}
type Finding struct {
	ID               string      `json:"id"`
	RunID            string      `json:"run_id"`
	AnalysisRevision int         `json:"analysis_revision"`
	Category         string      `json:"category"`
	RuleID           string      `json:"rule_id"`
	RuleVersion      string      `json:"rule_version"`
	Severity         string      `json:"severity"`
	RiskScore        float64     `json:"risk_score"`
	Confidence       int         `json:"confidence"`
	EvidenceGrade    string      `json:"evidence_grade"`
	Statistics       []Statistic `json:"statistics"`
	Alternatives     []string    `json:"alternative_explanations"`
	SampleRefs       []string    `json:"sample_refs"`
}
type Sample struct {
	ID                       string    `json:"id"`
	RunID                    string    `json:"run_id"`
	ProbeInstanceID          string    `json:"probe_instance_id"`
	Ordinal                  int       `json:"ordinal"`
	Family                   string    `json:"family"`
	Language                 string    `json:"language"`
	Validity                 string    `json:"validity"`
	Included                 bool      `json:"included"`
	AuxiliaryOnly            bool      `json:"auxiliary_only"`
	RequestedMaxTokens       int       `json:"requested_max_tokens"`
	LocalCompletionTokens    *int64    `json:"local_completion_tokens"`
	ReportedCompletionTokens *int64    `json:"reported_completion_tokens"`
	TokenizerID              string    `json:"tokenizer_id"`
	TokenizerQuality         string    `json:"tokenizer_quality"`
	Stream                   bool      `json:"stream"`
	FinishReason             *string   `json:"finish_reason"`
	StructureComplete        *bool     `json:"structure_complete"`
	HardTruncation           *bool     `json:"hard_truncation"`
	Contract                 *string   `json:"contract"`
	RefusalClass             *string   `json:"refusal_class"`
	IdentityClass            *string   `json:"identity_class"`
	ResponseHash             *string   `json:"response_hash"`
	FinalAttemptID           *string   `json:"final_attempt_id"`
	Limitations              []string  `json:"limitations"`
	Attempts                 []Attempt `json:"attempts"`
}
type Attempt struct {
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
}

type TokenStatistics struct {
	Tiers                  []Tier    `json:"tiers"`
	Plateaus               []Plateau `json:"plateaus"`
	UsageSamples           int       `json:"usage_samples"`
	UsageMedianError       *float64  `json:"usage_median_relative_error"`
	StreamPairs            int       `json:"stream_pairs"`
	StreamMedianDifference *float64  `json:"stream_median_relative_difference"`
	Limitations            []string  `json:"limitations"`
}
type Tier struct {
	SeriesID           string  `json:"series_id"`
	Family             string  `json:"family"`
	Language           string  `json:"language"`
	RequestedMaxTokens int64   `json:"requested_max_tokens"`
	Samples            int     `json:"samples"`
	Median             float64 `json:"median"`
	MAD                float64 `json:"mad"`
	RobustCV           float64 `json:"robust_cv"`
}
type Plateau struct {
	SeriesID          string   `json:"series_id"`
	Family            string   `json:"family"`
	LowRequested      int64    `json:"low_requested"`
	HighRequested     int64    `json:"high_requested"`
	GrowthRatio       float64  `json:"growth_ratio"`
	Strength          float64  `json:"strength"`
	Candidate         bool     `json:"candidate"`
	Limited           bool     `json:"limited"`
	Paired            bool     `json:"paired"`
	Lower             *float64 `json:"lower"`
	Upper             *float64 `json:"upper"`
	IndependentGroups int      `json:"independent_groups"`
	Limitations       []string `json:"limitations"`
	SampleRefs        []string `json:"sample_refs"`
}
type BehaviorStatistics struct {
	AnalyzedSamples  int          `json:"analyzed_samples"`
	AuxiliarySamples int          `json:"auxiliary_samples"`
	Patterns         []Pattern    `json:"patterns"`
	Differences      []Difference `json:"differences"`
	Limitations      []string     `json:"limitations"`
}
type Pattern struct {
	Kind          string   `json:"kind"`
	Fingerprint   string   `json:"fingerprint"`
	State         string   `json:"state"`
	FamilyCount   int      `json:"family_count"`
	TemplateCount int      `json:"template_count"`
	LanguageCount int      `json:"language_count"`
	SampleRefs    []string `json:"sample_refs"`
}
type Difference struct {
	Metric     string   `json:"metric"`
	State      string   `json:"state"`
	Pairs      int      `json:"pairs"`
	EffectSize *float64 `json:"effect_size"`
	PValue     *float64 `json:"p_value"`
	AdjustedP  *float64 `json:"adjusted_p"`
}

type document struct {
	SchemaVersion    string    `json:"schema_version"`
	CanonicalVersion string    `json:"canonical_version"`
	ReportID         string    `json:"report_id"`
	OrganizationID   string    `json:"organization_id"`
	RunID            string    `json:"run_id"`
	AnalysisRevision int       `json:"analysis_revision"`
	GeneratedAt      time.Time `json:"generated_at"`
	ObservationMode  string    `json:"observation_mode"`
	Development      bool      `json:"development"`
	Calibrated       bool      `json:"calibrated"`
	ContentState     string    `json:"content_state"`
	Input
	Review            *struct{} `json:"review"`
	ReviewState       string    `json:"review_state"`
	Disclaimer        string    `json:"disclaimer"`
	DevelopmentNotice string    `json:"development_notice"`
	Recommendations   []string  `json:"recommendations"`
}

// Snapshot and Artifacts own their memory. No mutable projection/bytes escape.
type Snapshot struct{ doc document }
type Artifacts struct {
	json, html                      []byte
	contentHash, jsonHash, htmlHash string
}

func (a *Artifacts) JSON() []byte {
	if a == nil {
		return nil
	}
	return append([]byte(nil), a.json...)
}
func (a *Artifacts) HTML() []byte {
	if a == nil {
		return nil
	}
	return append([]byte(nil), a.html...)
}
func (a *Artifacts) ContentHash() string {
	if a == nil {
		return ""
	}
	return a.contentHash
}
func (a *Artifacts) JSONFileHash() string {
	if a == nil {
		return ""
	}
	return a.jsonHash
}
func (a *Artifacts) HTMLFileHash() string {
	if a == nil {
		return ""
	}
	return a.htmlHash
}
func (a *Artifacts) SchemaVersion() string {
	if a == nil {
		return ""
	}
	return SchemaVersion
}
