// Package tokenrisk computes development-only aggregate evidence strengths.
// Its inputs contain identifiers and derived features, never request/response text.
package tokenrisk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/structure"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

const Version = "1.0.0-dev.1"
const MaxSamples = 512
const MaxObservations = 4096
const MaxSeries = 64

var ErrInput = errors.New("MI_TOKEN_AGGREGATE_INPUT_INVALID")
var ErrLimit = errors.New("MI_TOKEN_AGGREGATE_RESOURCE_LIMIT")

type Validity string

const (
	Valid              Validity = "VALID"
	ValidWithWarning   Validity = "VALID_WITH_WARNING"
	InvalidRetryable   Validity = "INVALID_RETRYABLE"
	InvalidProtocol    Validity = "INVALID_PROTOCOL"
	InvalidSafetyLimit Validity = "INVALID_SAFETY_LIMIT"
	NotApplicable      Validity = "NOT_APPLICABLE"
)

type Sample struct {
	ID, AttemptID, FinalAttemptID                               int64
	AttemptNumber                                               int
	Validity                                                    Validity
	Family, Language, TemplateID, TemplateVersion               string
	Variant                                                     int
	ConditionID, SeriesID, GroupID                              string
	Repetition                                                  int
	Seed                                                        *int64
	RequestedMaxTokens                                          int64
	Stream, AuxiliaryOnly, NetworkFailure, ReasoningUnseparated bool
	Local                                                       tokenizer.Estimate
	Usage                                                       tokenizer.UsageComparison
	Structure                                                   structure.Features
	ProtocolChecked, ProtocolAnomaly                            bool
	SuffixChecked                                               bool
	// Derived by the controlled fingerprint analyzer; never raw suffix text.
	SuffixFingerprint string
}

type Input struct {
	OrganizationID, RunID int64
	Samples               []Sample
	ExpectedSamples       int
	Partial               bool
	// A declared model limit can only LOWER strength; it grants no trust.
	DeclaredModelOutputLimit *int64
}

// No caller-toggled "trusted baseline" flag exists. A verified immutable M5
// resolver capability must be designed/injected before baseline support exists.
type Rules struct {
	Version                                                                              string `json:"version"`
	MinTierSamples, MinHighSamples, MinUsageSamples, MinPairs                            int
	TierRatio, GrowthRatio, PlateauRatio, RobustCV, UsageDirectionFraction, StreamEffect float64
	BootstrapReplicates                                                                  int
	Alpha, NormalResponsiveness, NaturalEOSFraction                                      float64
	MinIndependentGroups, MinBootstrapGroups, MinStreamTiers                             int
	MinTerminationSamples, MinSSESamples, MinSuffixSamples, MinProtocolSamples           int
	UsageExactMismatch, UsageHeuristicMismatch, UsageStrengthRange                       float64
	StreamIntervalEffect, DeclaredLimitTolerance, SuffixFraction                         float64
	NetworkErrorThreshold, NetworkAttributionFactor                                      float64
	StrengthBase, StrengthScale, WeakCeiling, PartialCeiling                             float64
	TokenWeights, ResponseWeights                                                        [4]float64
}

func Parameters() Rules {
	return Rules{Version: Version, MinTierSamples: 3, MinHighSamples: 6, MinUsageSamples: 6, MinPairs: 3, TierRatio: 1.5, GrowthRatio: 1.2, PlateauRatio: 0.7, RobustCV: 0.10, UsageDirectionFraction: 0.8, StreamEffect: 0.20, BootstrapReplicates: 1024, Alpha: 0.05, NormalResponsiveness: 0.5, NaturalEOSFraction: 0.5,
		MinIndependentGroups: 3, MinBootstrapGroups: 2, MinStreamTiers: 2, MinTerminationSamples: 6, MinSSESamples: 3, MinSuffixSamples: 6, MinProtocolSamples: 3,
		UsageExactMismatch: 0.15, UsageHeuristicMismatch: 0.30, UsageStrengthRange: 0.35, StreamIntervalEffect: 0.1, DeclaredLimitTolerance: 0.1, SuffixFraction: 0.8,
		NetworkErrorThreshold: 0.20, NetworkAttributionFactor: 0.5, StrengthBase: 60, StrengthScale: 40, WeakCeiling: 39, PartialCeiling: 59,
		TokenWeights: [4]float64{0.45, 0.20, 0.20, 0.15}, ResponseWeights: [4]float64{0.35, 0.25, 0.25, 0.15}}
}
func RulesHash() string {
	data, _ := json.Marshal(Parameters())
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

type Interval struct {
	Lower, Upper      float64
	Available, Paired bool
	Units, Replicates int
	Method            string
}
type Tier struct {
	RequestedMaxTokens                                                                                              int64
	Samples, IndependentGroups                                                                                      int
	Median, MAD, RobustCV, IncompleteRate, AbnormalSupportRate, NaturalEOSRate, HeuristicRate, ReasoningUnknownRate float64
}

// ModeTier retains the diagnostic arms without demanding three repetitions
// independently in each arm. The frozen minimum applies to the pooled tier.
type ModeTier struct {
	Nonstream, Stream        Tier
	Covered, Comparable      bool
	RelativeMedianDifference float64
}
type Plateau struct {
	SeriesID, Family, Language                    string
	Variant                                       int
	Low, High                                     Tier
	LowModes, HighModes                           ModeTier
	GrowthRatio, CombinedRobustCV, Responsiveness float64
	DifferenceCI                                  Interval
	Candidate                                     bool
	Strength                                      float64
	Limited                                       bool
	Limitations                                   []string
	SampleIDs                                     []int64
}
type Series struct {
	ID, Family, Language          string
	TokenizerID, TokenizerVersion string
	Variant                       int
	Tiers                         []Tier
	Modes                         []ModeTier
}
type UsageResult struct {
	Available, Candidate                                       bool
	Samples, Positive, Negative, Consistent, IndependentGroups int
	Direction                                                  int
	MedianRelativeError, ConsistentFraction, Strength          float64
	HeuristicSamples, SkippedReasoning                         int
	IncludedSamples                                            int
	Limited                                                    bool
	Limitations                                                []string
}
type StreamResult struct {
	Available, Candidate                             bool
	Pairs, Unmatched, Ambiguous, SeedMismatch, Tiers int
	MedianRelativeDifference, Strength               float64
	DifferenceCI                                     Interval
	Limited                                          bool
	Limitations                                      []string
}
type Component struct {
	Name                              string
	Available                         bool
	Strength, Weight, EffectiveWeight float64
}
type Aggregate struct {
	Strength    *float64
	Components  []Component
	Limited     bool
	Limitations []string
}
type Result struct {
	Version, RulesHash                                                                                                   string
	Development, Calibrated                                                                                              bool
	ObservedLogicalSamples, FinalSamples, ValidSamples, IgnoredAttempts, DuplicateFinals, MissingFinals, ExpectedSamples int
	IndependentFamilies                                                                                                  int
	Series                                                                                                               []Series
	Plateaus                                                                                                             []Plateau
	Usage                                                                                                                UsageResult
	Stream                                                                                                               StreamResult
	NetworkErrorRate, SSEAttributionFactor                                                                               float64
	Token, Response                                                                                                      Aggregate
	Partial                                                                                                              bool
	Warnings                                                                                                             []string
}
