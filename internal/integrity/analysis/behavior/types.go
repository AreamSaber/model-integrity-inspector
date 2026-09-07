// Package behavior extracts bounded behavioral features, never risk scores.
// It has no network, persistence, secret, or model-judging dependencies.
package behavior

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const Version = "1.0.0-dev.1"
const MaxTextBytes = 64 << 10
const MaxSamples = 512
const MaxAttempts = 8
const MaxBatchBytes = 8 << 20

var ErrInput = errors.New("MI_BEHAVIOR_INPUT_INVALID")
var ErrLimit = errors.New("MI_BEHAVIOR_RESOURCE_LIMIT")

type ContractKind string

const (
	NoContract ContractKind = "none"
	Exact      ContractKind = "exact"
	JSONField  ContractKind = "json_single_field"
)

type Contract struct {
	Kind     ContractKind
	Expected string `json:"-"`
	Key      string `json:"-"`
}

type TemplateRef struct{ ID, Version, SHA256 string }
type Family string

const (
	FormatFamily       Family = "format"
	NeutralFamily      Family = "neutral"
	DifferentialFamily Family = "differential"
	StyleFamily        Family = "style"
	SelfReportFamily   Family = "self_report"
)

type Validity string

const (
	Valid                 Validity = "VALID"
	ValidWithWarning      Validity = "VALID_WITH_WARNING"
	InvalidRetryable      Validity = "INVALID_RETRYABLE"
	InvalidProtocol       Validity = "INVALID_PROTOCOL"
	InvalidSafetyLimit    Validity = "INVALID_SAFETY_LIMIT"
	NotApplicableValidity Validity = "NOT_APPLICABLE"
)

type Attempt struct {
	ID       int64
	Number   int
	Validity Validity
	Content  string `json:"-"`
}

type Arm string

const (
	Control Arm = "A"
	Variant Arm = "B"
)

type Contrast string

const (
	SurfaceContrast  Contrast = "surface"
	LanguageContrast Contrast = "language"
)

// ComparableSHA256 must bind fixed request settings and semantic task identity,
// excluding only the planned irrelevant variable. The caller derives it from
// the frozen experiment plan, not the response. No baseline trust is inferred.
type Pair struct {
	ID               string
	Arm              Arm
	Contrast         Contrast
	ComparableSHA256 string
}

type Sample struct {
	ID                int64
	Template          TemplateRef
	Contract          Contract
	Variables         []string  `json:"-"`
	Attempts          []Attempt `json:"-"`
	FinalAttemptID    int64
	Pair              Pair
	SensitiveTask     bool
	IdentityRequested bool
	AuxiliaryOnly     bool
}

// Input values are ephemeral S2 data. Accidental formatting/JSON logging cannot
// serialize the response, expected marker, or random variables.
func (Sample) String() string                 { return "[behavior sample input]" }
func (s Sample) Format(w fmt.State, _ rune)   { _, _ = io.WriteString(w, s.String()) }
func (Sample) MarshalJSON() ([]byte, error)   { return []byte(`"[behavior sample input]"`), nil }
func (Attempt) String() string                { return "[behavior attempt input]" }
func (a Attempt) Format(w fmt.State, _ rune)  { _, _ = io.WriteString(w, a.String()) }
func (Attempt) MarshalJSON() ([]byte, error)  { return []byte(`"[behavior attempt input]"`), nil }
func (Contract) String() string               { return "[behavior contract input]" }
func (c Contract) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, c.String()) }
func (Contract) MarshalJSON() ([]byte, error) { return []byte(`"[behavior contract input]"`), nil }

type State string

const (
	Analyzed  State = "analyzed"
	Excluded  State = "excluded"
	Auxiliary State = "auxiliary_only"
)

type ContractState string

const (
	Matches               ContractState = "matches"
	Deviates              ContractState = "deviates"
	ContractNotApplicable ContractState = "not_applicable"
)

type CueClass string

const (
	CueNotApplicable CueClass = "not_applicable"
	NoCue            CueClass = "no_cue"
	RefusalLike      CueClass = "refusal_like"
	IdentityLike     CueClass = "self_identity_like"
)

type EvidenceKind string

const (
	Prefix   EvidenceKind = "extra_prefix"
	Suffix   EvidenceKind = "extra_suffix"
	Refusal  EvidenceKind = "refusal_like"
	Identity EvidenceKind = "self_identity_like"
)

type Evidence struct {
	SampleID         string       `json:"sample_id"`
	StartByte        int          `json:"start_byte"`
	EndByte          int          `json:"end_byte"`
	Kind             EvidenceKind `json:"kind"`
	NormalizedSHA256 string       `json:"normalized_sha256"`
	InformativeRunes int          `json:"informative_runes"`
	Candidate        bool         `json:"repeat_candidate"`
	Suppression      string       `json:"suppression,omitempty"`
}

type Features struct {
	Version          string        `json:"version"`
	SampleID         string        `json:"sample_id"`
	State            State         `json:"state"`
	Reason           string        `json:"reason,omitempty"`
	RegistryMatch    bool          `json:"trusted_registry_match"`
	Contract         ContractState `json:"contract"`
	ContractReason   string        `json:"contract_reason,omitempty"`
	Anchor           string        `json:"anchor"`
	PrefixBytes      int           `json:"prefix_bytes"`
	SuffixBytes      int           `json:"suffix_bytes"`
	Refusal          CueClass      `json:"refusal_class"`
	Identity         CueClass      `json:"identity_class"`
	ResponseSHA256   string        `json:"response_sha256,omitempty"`
	NormalizedSHA256 string        `json:"normalized_sha256,omitempty"`
	Evidence         []Evidence    `json:"evidence"`
	Alternatives     []string      `json:"alternatives"`
}

type Engine struct{ templates map[TemplateRef]templateSpec }

var identifier = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,95}$`)
var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$`)
var pairPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
var markerPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)

func validHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == 32 && strings.ToLower(value) == value
}
func validRef(ref TemplateRef) bool {
	return len(ref.Version) <= 64 && identifier.MatchString(ref.ID) && versionPattern.MatchString(ref.Version) && validHash(ref.SHA256)
}

func validate(sample Sample) (Attempt, error) {
	if sample.ID <= 0 || sample.FinalAttemptID <= 0 || !validRef(sample.Template) || len(sample.Attempts) == 0 || len(sample.Attempts) > MaxAttempts || len(sample.Variables) > 16 {
		return Attempt{}, ErrInput
	}
	if len(sample.Contract.Expected) > 1024 || len(sample.Contract.Key) > 128 {
		return Attempt{}, ErrLimit
	}
	if !utf8.ValidString(sample.Contract.Expected) || !utf8.ValidString(sample.Contract.Key) {
		return Attempt{}, ErrInput
	}
	switch sample.Contract.Kind {
	case NoContract:
		if sample.Contract.Expected != "" || sample.Contract.Key != "" {
			return Attempt{}, ErrInput
		}
	case Exact:
		if sample.Contract.Expected == "" || sample.Contract.Key != "" {
			return Attempt{}, ErrInput
		}
	case JSONField:
		if sample.Contract.Expected == "" || sample.Contract.Key == "" {
			return Attempt{}, ErrInput
		}
	default:
		return Attempt{}, ErrInput
	}
	for _, variable := range sample.Variables {
		if !markerPattern.MatchString(variable) {
			return Attempt{}, ErrInput
		}
	}
	if sample.Pair.ID != "" {
		if !pairPattern.MatchString(sample.Pair.ID) || (sample.Pair.Arm != Control && sample.Pair.Arm != Variant) || (sample.Pair.Contrast != SurfaceContrast && sample.Pair.Contrast != LanguageContrast) || !validHash(sample.Pair.ComparableSHA256) {
			return Attempt{}, ErrInput
		}
	} else if sample.Pair.Arm != "" || sample.Pair.Contrast != "" || sample.Pair.ComparableSHA256 != "" {
		return Attempt{}, ErrInput
	}
	seenID, seenNumber := map[int64]bool{}, map[int]bool{}
	var selected Attempt
	for _, attempt := range sample.Attempts {
		if attempt.ID <= 0 || attempt.Number < 1 || attempt.Number > 64 || seenID[attempt.ID] || seenNumber[attempt.Number] {
			return Attempt{}, ErrInput
		}
		seenID[attempt.ID], seenNumber[attempt.Number] = true, true
		if len(attempt.Content) > MaxTextBytes {
			return Attempt{}, ErrLimit
		}
		if !utf8.ValidString(attempt.Content) {
			return Attempt{}, ErrInput
		}
		switch attempt.Validity {
		case Valid, ValidWithWarning, InvalidRetryable, InvalidProtocol, InvalidSafetyLimit, NotApplicableValidity:
		default:
			return Attempt{}, ErrInput
		}
		if attempt.ID == sample.FinalAttemptID {
			selected = attempt
		}
	}
	if selected.ID == 0 {
		return Attempt{}, ErrInput
	}
	return selected, nil
}

func freshFeatures(id int64) Features {
	return Features{Version: Version, SampleID: strconv.FormatInt(id, 10), State: Excluded, Contract: ContractNotApplicable, Anchor: "none", Refusal: CueNotApplicable, Identity: CueNotApplicable, Evidence: []Evidence{}, Alternatives: []string{}}
}
