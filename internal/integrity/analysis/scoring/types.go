// Package scoring combines body-free, internally verified feature projections.
// It authenticates neither a caller nor a database row. Never bind Input to HTTP.
package scoring

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/behavior"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

const Version = "1.0.0-dev.1"
const MaxSamples = 512
const MaxHypotheses = 256

var ErrInput = errors.New("MI_SCORING_INPUT_INVALID")
var ErrLimit = errors.New("MI_SCORING_RESOURCE_LIMIT")

type ObservationState string

const (
	Unobserved ObservationState = "unobserved"
	Normal     ObservationState = "normal"
	Anomalous  ObservationState = "anomalous"
	Missing    ObservationState = "missing"
	Invalid    ObservationState = "invalid"
)

// Missing means checked and absent; Unobserved means no measurement was made.
// Termination is the final protocol event, not whether generation was long.
type ProtocolObservation struct {
	Usage, HTTP, ModelEcho, Finish, Termination ObservationState
}

type Observation struct {
	SampleID, Family, Language, TemplateID, ClusterID string
	Included, AuxiliaryOnly                           bool
	Protocol                                          *ProtocolObservation
	Tokenizer                                         tokenizer.Quality
	ReasoningUnseparated                              bool
}

// Input is a trusted Worker assembly boundary, not an externally attestable
// certificate. Versions/hashes only prevent accidental incompatible mixing.
// No field can assert trusted baseline, calibration, or gateway verification.
type Input struct {
	ExpectedSamples int
	Partial         bool
	Samples         []Observation
	Behavior        *behavior.Batch
	Tokens          *tokenrisk.Result
}

type Rules struct {
	Version                                                                                            string
	BehaviorVersion, TokenVersion, TokenRulesHash                                                      string
	PatternMinimumFamilies, PatternMinimumTemplates, PatternMinimumLanguages, PatternMinimumFamilyHits int
	PatternRepeatFraction                                                                              float64
	PromptWeights                                                                                      [5]float64
	OverallWeights                                                                                     [4]float64
	ProtocolWeights                                                                                    [6]float64
	MinimumValid, MinimumFamilyHits, MinimumFamilyClusters, MinimumHitFamilies                         int
	StableFraction, WeakCeiling, SingleFamilyCeiling                                                   float64
	PartialConfidenceCeiling, DevelopmentConfidenceCeiling                                             float64
	NoBaselineFactor, CompatibleQuality, HeuristicQuality                                              float64
	MissingDimensionFactor, MinimumCriticalFraction                                                    float64
	QualityWeights                                                                                     [3]float64
	Bands                                                                                              [4]float64
	HighEvidenceRisk, HighEvidenceConfidence                                                           float64
}

func Parameters() Rules {
	return Rules{Version: Version, BehaviorVersion: behavior.Version, TokenVersion: tokenrisk.Version, TokenRulesHash: tokenrisk.RulesHash(), PatternMinimumFamilies: behavior.MinimumFamilies, PatternMinimumTemplates: behavior.MinimumTemplates, PatternMinimumLanguages: behavior.MinimumLanguages, PatternMinimumFamilyHits: behavior.MinimumFamilyMatches, PatternRepeatFraction: behavior.MinimumRepeatFraction, PromptWeights: [5]float64{.30, .25, .20, .10, .15}, OverallWeights: [4]float64{.40, .35, .15, .10}, ProtocolWeights: [6]float64{.20, .15, .10, .15, .15, .25},
		MinimumValid: 6, MinimumFamilyHits: 3, MinimumFamilyClusters: 3, MinimumHitFamilies: 2, StableFraction: .8, WeakCeiling: 39, SingleFamilyCeiling: 69,
		PartialConfidenceCeiling: 59, DevelopmentConfidenceCeiling: 74, NoBaselineFactor: .8, CompatibleQuality: .9, HeuristicQuality: .4,
		MissingDimensionFactor: .75, MinimumCriticalFraction: .5, QualityWeights: [3]float64{.4, .3, .3}, Bands: [4]float64{20, 40, 70, 90}, HighEvidenceRisk: 60, HighEvidenceConfidence: 75}
}

func RulesHash() string {
	data, _ := json.Marshal(Parameters())
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

type Component struct {
	Name                 string   `json:"name"`
	Score                *float64 `json:"score"`
	Weight               float64  `json:"weight"`
	EffectiveWeight      float64  `json:"effective_weight"`
	Applicable, Positive int
}

type Dimension struct {
	Score       *float64    `json:"score"`
	Components  []Component `json:"components"`
	Limited     bool        `json:"limited"`
	Limitations []string    `json:"limitations"`
}

type Confidence struct {
	Score                                                                                         int `json:"score"`
	SampleFactor, RepeatabilityFactor, EvidenceQualityFactor, BaselineFactor, ApplicabilityFactor float64
	Limitations                                                                                   []string `json:"limitations"`
}

type Result struct {
	Version, RulesHash, TokenRulesHash                                    string
	Development, Calibrated                                               bool
	ExpectedSamples, ValidSamples, IndependentFamilies, StableHitFamilies int
	Prompt, Token, Response, Protocol                                     Dimension
	Overall                                                               Dimension
	Confidence                                                            Confidence
	Completeness, EvidenceGrade, RiskLevel, Conclusion                    string
	Limitations                                                           []string
}

// The only current policy is development. Future release admission must live
// inside this package, validate immutable calibration/held-out artifact scope,
// and mint this private capability. Exporting a caller-supplied boolean or
// arbitrary implementation interface would not establish that trust boundary.
type releasePolicy struct {
	calibration *verifiedCalibration
}
type verifiedCalibration struct{ rulesHash string }

func (p releasePolicy) calibrated() bool {
	return p.calibration != nil && p.calibration.rulesHash == RulesHash()
}
