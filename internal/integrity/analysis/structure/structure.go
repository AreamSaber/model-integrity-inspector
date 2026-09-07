// Package structure extracts bounded, content-free completeness features.
// It never scores risk or concludes that an upstream changed a request.
package structure

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

const Version = "1.0.0"
const MaxTextBytes = 1 << 20
const MaxLines = 10000
const MaxLineBytes = 64 << 10
const MaxDepth = 64

var ErrLimit = errors.New("MI_STRUCTURE_RESOURCE_LIMIT")
var ErrInput = errors.New("MI_STRUCTURE_INPUT_INVALID")

type Kind string

const (
	JSON     Kind = "json"
	JSONL    Kind = "jsonl"
	Sequence Kind = "sequence"
	Markdown Kind = "markdown"
	Text     Kind = "text"
)

type State string

const (
	Complete      State = "complete"
	Incomplete    State = "incomplete"
	Invalid       State = "invalid"
	Unknown       State = "unknown"
	NotApplicable State = "not_applicable"
)

type Contract struct {
	Kind           Kind
	SequencePrefix string `json:"-"`
	FirstNumber    int64
	ExpectedUnits  int64
	JSONNumberKey  string `json:"-"`
}

type Input struct {
	Content               string `json:"-"`
	Contract              Contract
	FinishReason          string
	RequestedMaxTokens    int64
	LocalCompletionTokens *int64
	TokenizerQuality      tokenizer.Quality
	Stream                bool
	StreamTerminated      bool
	ReasoningModel        bool
	ReasoningTokens       *int64
	Refusal               bool
	EndCause              string
}

// Protect S2 input if a caller accidentally passes it to a formatted logger.
func (Input) String() string                  { return "[structure analysis input]" }
func (v Input) Format(w fmt.State, _ rune)    { _, _ = io.WriteString(w, v.String()) }
func (Contract) String() string               { return "[structure contract]" }
func (v Contract) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }

type Features struct {
	Version                   string   `json:"version"`
	Kind                      Kind     `json:"kind"`
	VisibleBytes              int      `json:"visible_bytes"`
	VisibleRunes              int      `json:"visible_runes"`
	UTF8Valid                 bool     `json:"utf8_valid"`
	EndsAtUTF8Boundary        bool     `json:"ends_at_utf8_boundary"`
	Parse                     State    `json:"parse"`
	Brackets                  State    `json:"brackets"`
	Strings                   State    `json:"strings"`
	Numbering                 State    `json:"numbering"`
	LastUnit                  State    `json:"last_unit"`
	CodeFences                State    `json:"code_fences"`
	Sentence                  State    `json:"sentence"`
	StructureComplete         bool     `json:"structure_complete"`
	HardTruncation            bool     `json:"hard_truncation"`
	CompleteUnits             int64    `json:"complete_units"`
	TaskComplete              *bool    `json:"task_complete,omitempty"`
	ExpectedUnitsRemaining    *int64   `json:"expected_units_remaining,omitempty"`
	FinishReason              string   `json:"finish_reason"`
	NormalRequestedLimit      bool     `json:"normal_requested_limit"`
	CompleteEarlyStop         bool     `json:"complete_early_stop"`
	LengthComparisonAvailable bool     `json:"length_comparison_available"`
	LimitExceeded             bool     `json:"limit_exceeded"`
	TerminationHints          []string `json:"termination_hints"`
	Warnings                  []string `json:"warnings"`
}

func Analyze(input Input) (Features, error) {
	f := Features{Version: Version, Kind: input.Contract.Kind, VisibleBytes: len(input.Content), Parse: NotApplicable, Brackets: NotApplicable, Strings: NotApplicable, Numbering: NotApplicable, LastUnit: Unknown, CodeFences: NotApplicable, Sentence: NotApplicable, TerminationHints: []string{}, Warnings: []string{}}
	if !validContract(input.Contract) || input.RequestedMaxTokens < 0 || len(input.FinishReason) > 128 || len(input.EndCause) > 128 {
		return f, ErrInput
	}
	if len(input.Content) > MaxTextBytes {
		return limited(f)
	}
	f.UTF8Valid = utf8.ValidString(input.Content)
	f.EndsAtUTF8Boundary = endsAtUTF8Boundary(input.Content)
	if !f.UTF8Valid {
		f.Warnings = append(f.Warnings, "MI_STRUCTURE_INVALID_UTF8")
		f.HardTruncation = !f.EndsAtUTF8Boundary
		f.Parse = Invalid
		f.LastUnit = Invalid
		termination(input, &f)
		return f, nil
	}
	f.VisibleRunes = utf8.RuneCountInString(input.Content)
	trimmed := strings.TrimSpace(input.Content)
	if trimmed == "" {
		f.Parse = Incomplete
		f.LastUnit = Incomplete
		f.Warnings = append(f.Warnings, "MI_STRUCTURE_EMPTY_OUTPUT")
		taskProgress(input.Contract, &f)
		termination(input, &f)
		return f, nil
	}
	lines := strings.Split(input.Content, "\n")
	if len(lines) > MaxLines+1 {
		return limited(f)
	}
	for _, line := range lines {
		if len(line) > MaxLineBytes {
			return limited(f)
		}
	}
	var err error
	switch input.Contract.Kind {
	case JSON:
		err = analyzeJSON(trimmed, &f)
	case JSONL:
		err = analyzeJSONL(lines, input.Contract, &f)
	case Sequence:
		analyzeSequence(lines, input.Contract, &f)
	case Markdown:
		f.CodeFences = fenceState(lines)
		f.Sentence = sentenceState(trimmed)
		f.LastUnit = f.CodeFences
		f.StructureComplete = f.CodeFences == Complete
		f.HardTruncation = f.CodeFences == Incomplete
	case Text:
		f.Sentence = sentenceState(trimmed)
		f.LastUnit = f.Sentence
		// A fragment without final punctuation is not proof of truncation.
		f.StructureComplete = f.Sentence == Complete
	}
	if errors.Is(err, ErrLimit) {
		return limited(f)
	}
	if err != nil {
		return f, err
	}
	taskProgress(input.Contract, &f)
	termination(input, &f)
	return f, nil
}

func validContract(c Contract) bool {
	if c.Kind != JSON && c.Kind != JSONL && c.Kind != Sequence && c.Kind != Markdown && c.Kind != Text {
		return false
	}
	if c.FirstNumber < 0 || c.FirstNumber > 1000000 || c.ExpectedUnits < 0 || c.ExpectedUnits > 1000000 || len(c.SequencePrefix) > 128 || len(c.JSONNumberKey) > 64 ||
		!utf8.ValidString(c.SequencePrefix) || !utf8.ValidString(c.JSONNumberKey) || strings.ContainsAny(c.SequencePrefix, "\r\n\x00|") || strings.ContainsAny(c.JSONNumberKey, "\r\n\x00") {
		return false
	}
	return true
}
func limited(f Features) (Features, error) {
	f.StructureComplete = false
	f.LimitExceeded = true
	f.HardTruncation = false
	f.Warnings = append(f.Warnings, "MI_STRUCTURE_RESOURCE_LIMIT")
	return f, ErrLimit
}
func taskProgress(c Contract, f *Features) {
	if c.ExpectedUnits == 0 || (c.Kind != Sequence && c.Kind != JSONL) {
		return
	}
	done := f.StructureComplete && f.CompleteUnits >= c.ExpectedUnits
	remaining := max(c.ExpectedUnits-f.CompleteUnits, 0)
	f.TaskComplete = &done
	f.ExpectedUnitsRemaining = &remaining
}
func endsAtUTF8Boundary(s string) bool {
	if len(s) == 0 {
		return true
	}
	r, size := utf8.DecodeLastRuneInString(s)
	return r != utf8.RuneError || size > 1
}
