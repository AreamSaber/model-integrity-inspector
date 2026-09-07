package tokenizer

import (
	"errors"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

type Quality string

const (
	Exact       Quality = "exact"
	Compatible  Quality = "compatible"
	Heuristic   Quality = "heuristic"
	Unavailable Quality = "unavailable"
)

const MaxTextBytes = 1 << 20
const MaxBPEBytes = 64 << 10
const maxBPEWork = 4 << 20
const maxBPESpan = 1024

var ErrLimit = errors.New("MI_TOKENIZER_RESOURCE_LIMIT")
var ErrInput = errors.New("MI_TOKENIZER_INPUT_INVALID")

// Selection is model metadata only. It intentionally has no caller-provided
// tokenizer ID or quality. A reported model name is not an authenticity claim.
type Selection struct{ ReportedModel, RequestedModel, StandardModel string }

// Estimate never carries request/response text or the token sequence. Exact
// refers only to visible-text encoding under the frozen mapping, not proof of
// model identity, hidden reasoning, billable usage or chat message framing.
type Estimate struct {
	Tokens              *int64   `json:"tokens"`
	BudgetTokens        int64    `json:"budget_tokens"`
	BudgetSafetyApplied bool     `json:"budget_safety_applied"`
	Quality             Quality  `json:"quality"`
	TokenizerID         string   `json:"tokenizer_id"`
	TokenizerVersion    string   `json:"tokenizer_version"`
	BundleVersion       string   `json:"bundle_version"`
	BundleHash          string   `json:"bundle_hash"`
	SelectedBy          string   `json:"selected_by"`
	Scope               string   `json:"scope"`
	VisibleBytes        int      `json:"visible_bytes"`
	VisibleRunes        int      `json:"visible_runes"`
	Warnings            []string `json:"warnings"`
}

func (e *Engine) selection(s Selection) (string, Quality, string) {
	for i, name := range []string{s.ReportedModel, s.RequestedModel, s.StandardModel} {
		if name == "" || len(name) > 256 || !utf8.ValidString(name) {
			continue
		}
		selectedBy := []string{"reported_model", "requested_model", "standard_model"}[i]
		for _, binding := range e.bundle.Models {
			if name == binding.Name {
				quality := Exact
				if i == 2 {
					quality = Compatible
				}
				return binding.Encoding, quality, selectedBy
			}
		}
		best := modelBinding{}
		for _, binding := range e.bundle.Families {
			if len(name) > len(binding.Name) && strings.HasPrefix(name, binding.Name) && len(binding.Name) > len(best.Name) {
				best = binding
			}
		}
		if best.Name != "" {
			return best.Encoding, Compatible, selectedBy
		}
	}
	return "unicode-byte-heuristic", Heuristic, "heuristic"
}

func (e *Engine) emptyEstimate(scope string) Estimate {
	return Estimate{Quality: Unavailable, TokenizerVersion: ImplementationVersion, BundleVersion: e.bundle.Version, BundleHash: e.hash, Scope: scope, Warnings: []string{}}
}

// CountOutput treats special-token-looking output as literal visible text,
// equivalent to tiktoken.encode_ordinary, never as protocol control tokens.
func (e *Engine) CountOutput(text string, selection Selection) (Estimate, error) {
	return e.countOutput(text, selection, false)
}

func (e *Engine) countOutput(text string, selection Selection, forceHeuristic bool) (Estimate, error) {
	result := e.emptyEstimate("visible_output")
	result.VisibleBytes = len(text)
	if len(text) > MaxTextBytes {
		result.Warnings = append(result.Warnings, "MI_TOKENIZER_RESOURCE_LIMIT")
		return result, ErrLimit
	}
	if !utf8.ValidString(text) {
		result.Warnings = append(result.Warnings, "MI_TOKENIZER_INVALID_UTF8")
		return result, ErrInput
	}
	result.VisibleRunes = utf8.RuneCountInString(text)
	result.TokenizerID, result.Quality, result.SelectedBy = e.selection(selection)
	if result.Quality != Heuristic && (forceHeuristic || !bpeWithinBudget(text)) {
		result.Quality = Heuristic
		result.TokenizerID = "unicode-byte-heuristic"
		result.Warnings = append(result.Warnings, "MI_TOKENIZER_COMPLEXITY_FALLBACK")
	}
	var count int64
	if result.Quality == Heuristic {
		count = heuristicCount(text)
	} else {
		// Bound active allocation/CPU without changing counts/quality with
		// transient load. Waiting callers do not spawn background tokenizers.
		e.work <- struct{}{}
		value, err := e.codecs[result.TokenizerID].Count(text)
		<-e.work
		if err != nil {
			result.Quality = Unavailable
			if errors.Is(err, ErrLimit) {
				result.Warnings = append(result.Warnings, "MI_TOKENIZER_RESOURCE_LIMIT")
				return result, ErrLimit
			}
			result.Warnings = append(result.Warnings, "MI_TOKENIZER_FAILED")
			return result, ErrInput
		}
		count = int64(value)
	}
	result.Tokens = &count
	result.BudgetTokens = count
	if result.Quality != Exact {
		reserve := count
		if result.Quality == Heuristic {
			result.TokenizerVersion = "unicode-byte-v1"
			result.Warnings = append(result.Warnings, "MI_TOKENIZER_HEURISTIC_ONLY")
			// Unknown tokenization can split words into bytes. The displayed
			// estimate remains separate from a conservative byte-based reserve.
			reserve = max(reserve, int64(len(text)))
		}
		result.BudgetTokens = ceilSafety(reserve)
		result.BudgetSafetyApplied = true
	}
	return result, nil
}

func ceilSafety(tokens int64) int64 { return (tokens*5 + 3) / 4 }

// The upstream pure-Go BPE merge is quadratic in each regex piece. Bound both
// input and a conservative run-square work estimate BEFORE entering it. No
// goroutine continues computing after a timeout, and no partial count is exact.
func bpeWithinBudget(text string) bool {
	if len(text) > MaxBPEBytes {
		return false
	}
	lastSpace := false
	run, work := 0, 0
	for _, r := range text {
		space := unicode.IsSpace(r)
		if run > 0 && space != lastSpace {
			work += (run + 4) * (run + 4)
			run = 0
		}
		run += utf8.RuneLen(r)
		lastSpace = space
		if run > maxBPESpan || work > maxBPEWork {
			return false
		}
	}
	return work+(run+4)*(run+4) <= maxBPEWork
}

func heuristicCount(text string) int64 {
	var count, ascii int64
	for _, r := range text {
		if r < utf8.RuneSelf {
			ascii++
			continue
		}
		count += (ascii+3)/4 + 1
		ascii = 0
	}
	return count + (ascii+3)/4
}

// EstimateInput includes a versioned conservative framing estimate (four tokens
// per message plus three reply-priming tokens). This is never labeled exact;
// there is no claim to reproduce a provider's undisclosed message template.
func (e *Engine) EstimateInput(request domain.NormalizedRequest) (Estimate, error) {
	return e.EstimateInputFor(request, Selection{RequestedModel: request.Model})
}

func (e *Engine) EstimateInputFor(request domain.NormalizedRequest, selection Selection) (Estimate, error) {
	result := e.emptyEstimate("input")
	if selection.RequestedModel == "" {
		selection.RequestedModel = request.Model
	}
	if len(request.Messages) < 1 || len(request.Messages) > 64 || len(request.Model) == 0 || len(request.Model) > 256 {
		return result, ErrInput
	}
	// Tools/multimodal schemas are not part of NormalizedMessage in V1.0. Do
	// not quietly omit future prompt-bearing extensions from budget counting.
	for key, value := range request.ExtraAllowedParams {
		if key != "presence_penalty" && key != "frequency_penalty" {
			return result, ErrInput
		}
		number, ok := value.(float64)
		if !ok || math.IsNaN(number) || math.IsInf(number, 0) || number < -2 || number > 2 {
			return result, ErrInput
		}
	}
	parts := make([]string, 0, len(request.Messages)*2)
	totalBytes := 0
	for _, message := range request.Messages {
		if message.Role != "system" && message.Role != "developer" && message.Role != "user" && message.Role != "assistant" {
			return result, ErrInput
		}
		totalBytes += len(message.Role) + len(message.Content)
		if totalBytes > MaxTextBytes {
			return result, ErrLimit
		}
		if !utf8.ValidString(message.Content) {
			return result, ErrInput
		}
		parts = append(parts, message.Role, message.Content)
	}
	if request.ResponseFormat != nil && request.ResponseFormat.Type != "text" && request.ResponseFormat.Type != "json_object" {
		return result, ErrInput
	}
	count := 3 + int64(len(request.Messages))*4
	quality := Compatible
	warnings := []string{"MI_INPUT_FRAMING_ESTIMATED"}
	// Apply one aggregate work bound to the entire request, not a fresh BPE
	// allowance for each of up to 64 messages.
	forceHeuristic := !bpeWithinBudget(strings.Join(parts, " "))
	for _, part := range parts {
		piece, err := e.countOutput(part, selection, forceHeuristic)
		if err != nil {
			return result, err
		}
		count += *piece.Tokens
		result.TokenizerID = piece.TokenizerID
		result.TokenizerVersion = piece.TokenizerVersion
		result.SelectedBy = piece.SelectedBy
		result.VisibleRunes += piece.VisibleRunes
		if piece.Quality == Heuristic {
			quality = Heuristic
		}
		for _, warning := range piece.Warnings {
			if !contains(warnings, warning) {
				warnings = append(warnings, warning)
			}
		}
	}
	if request.ResponseFormat != nil && request.ResponseFormat.Type == "json_object" {
		count += 8
	}
	result.Tokens = &count
	result.Quality = quality
	result.VisibleBytes = totalBytes
	result.Warnings = warnings
	reserve := count
	if quality == Heuristic {
		result.TokenizerID = "unicode-byte-heuristic"
		result.TokenizerVersion = "unicode-byte-v1"
		reserve = max(reserve, int64(totalBytes)+3+int64(len(request.Messages))*4+8)
	}
	result.BudgetTokens = ceilSafety(reserve)
	result.BudgetSafetyApplied = true
	return result, nil
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
