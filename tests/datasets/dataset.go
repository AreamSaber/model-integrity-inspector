// Package datasets defines test-controller manifests and a separate, strictly
// typed detector input. It is test infrastructure, not a production dependency.
// Blind labels must additionally be held in a separate access-controlled process
// and filesystem: a Go type boundary cannot hide labels from a shared workspace.
package datasets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

const SchemaVersion = "1.0.0"
const MaxInputBytes = 16 << 20

type Split string

const (
	Development Split = "development"
	Calibration Split = "calibration"
	Regression  Split = "regression"
	Blind       Split = "blind"
	Gray        Split = "gray"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Input is the complete allowed detector boundary. It has neither expected
// classes, split names, lineage, scenario IDs, controller seeds nor outcomes.
// CaseID must be opaque and must not encode a class or scenario name.
type Input struct {
	SchemaVersion string   `json:"schema_version"`
	CaseID        string   `json:"case_id"`
	Samples       []Sample `json:"samples"`
}

type Sample struct {
	SampleID    string           `json:"sample_id"`
	ProbeFamily string           `json:"probe_family"`
	Language    string           `json:"language"`
	Request     RequestSnapshot  `json:"request"`
	Response    ResponseSnapshot `json:"response"`
	Tokenizer   Tokenizer        `json:"tokenizer"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type RequestSnapshot struct {
	Model           string    `json:"model"`
	Messages        []Message `json:"messages"`
	MaxOutputTokens int       `json:"max_output_tokens"`
	Stream          bool      `json:"stream"`
	Temperature     *float64  `json:"temperature,omitempty"`
	Seed            *int64    `json:"seed,omitempty"`
}

type ResponseSnapshot struct {
	HTTPStatus       int    `json:"http_status"`
	Content          string `json:"content"`
	ModelReported    string `json:"model_reported"`
	FinishReason     string `json:"finish_reason"`
	PromptTokens     *int64 `json:"prompt_tokens,omitempty"`
	CompletionTokens *int64 `json:"completion_tokens,omitempty"`
	TotalTokens      *int64 `json:"total_tokens,omitempty"`
	ReasoningTokens  *int64 `json:"reasoning_tokens,omitempty"`
	StreamTerminated *bool  `json:"stream_terminated,omitempty"`
	TransportError   string `json:"transport_error,omitempty"`
	DurationMS       int64  `json:"duration_ms"`
}

type Tokenizer struct {
	ID              string `json:"id"`
	Version         string `json:"version"`
	Quality         string `json:"quality"`
	LocalTokenCount *int64 `json:"local_token_count,omitempty"`
}

// Manifest is controller-side only. Do not mount it inside a blind detector
// process: lineage, coverage and even partition membership can disclose labels.
type Manifest struct {
	SchemaVersion  string    `json:"schema_version"`
	DatasetVersion string    `json:"dataset_version"`
	FrozenAt       string    `json:"frozen_at,omitempty"`
	Cases          []CaseRef `json:"cases"`
}

type CaseRef struct {
	CaseID      string   `json:"case_id"`
	Split       Split    `json:"split"`
	LineageID   string   `json:"lineage_id"`
	InputSHA256 string   `json:"input_sha256"`
	Coverage    []string `json:"coverage"`
}

// Label belongs in a separate owner-controlled label file. It never embeds a
// detector Input and must never be part of a server response or model prompt.
type Label struct {
	CaseID     string   `json:"case_id"`
	Conditions []string `json:"conditions"`
	Rationale  string   `json:"rationale"`
}

var RequiredCoverage = []string{
	"normal", "fixed_cap", "probabilistic_cap", "hidden_instruction", "stream_mutation", "usage_forgery",
	"natural_short_answer", "safety_refusal", "unknown_tokenizer", "reasoning_model", "high_network_error",
}

var validConditions = map[string]bool{
	"normal": true, "fixed_cap": true, "probabilistic_cap": true, "hidden_instruction": true,
	"stream_mutation": true, "usage_forgery": true, "natural_short_answer": true,
	"safety_refusal": true, "unknown_tokenizer": true, "reasoning_model": true,
	"high_network_error": true,
}

func validSplit(split Split) bool {
	return split == Development || split == Calibration || split == Regression || split == Blind || split == Gray
}

// DecodeInput rejects unknown fields at every nesting level and trailing JSON.
// It only reads the supplied reader; it does not discover or read label files.
func DecodeInput(reader io.Reader) (Input, error) {
	limited := &io.LimitedReader{R: reader, N: MaxInputBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var input Input
	if err := decoder.Decode(&input); err != nil {
		return Input{}, fmt.Errorf("detector input: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Input{}, errors.New("detector input must contain exactly one JSON object")
	}
	if limited.N == 0 {
		return Input{}, errors.New("detector input exceeds byte limit")
	}
	if err := ValidateInput(input); err != nil {
		return Input{}, err
	}
	return input, nil
}

func ValidateInput(input Input) error {
	if input.SchemaVersion != SchemaVersion || !identifierPattern.MatchString(input.CaseID) || len(input.Samples) == 0 || len(input.Samples) > 1000 {
		return errors.New("invalid detector input identity, schema or sample count")
	}
	seen := map[string]bool{}
	for _, sample := range input.Samples {
		if !identifierPattern.MatchString(sample.SampleID) || seen[sample.SampleID] || sample.ProbeFamily == "" || sample.Language == "" {
			return errors.New("invalid or duplicate sample identity")
		}
		seen[sample.SampleID] = true
		if sample.Request.Model == "" || sample.Request.MaxOutputTokens <= 0 || len(sample.Request.Messages) == 0 || len(sample.Request.Messages) > 256 {
			return errors.New("invalid request snapshot")
		}
		if sample.Response.HTTPStatus != 0 && (sample.Response.HTTPStatus < 100 || sample.Response.HTTPStatus > 599) || sample.Response.DurationMS < 0 {
			return errors.New("invalid response snapshot")
		}
		for _, count := range []*int64{sample.Response.PromptTokens, sample.Response.CompletionTokens, sample.Response.TotalTokens, sample.Response.ReasoningTokens, sample.Tokenizer.LocalTokenCount} {
			if count != nil && *count < 0 {
				return errors.New("negative token count")
			}
		}
		switch sample.Tokenizer.Quality {
		case "exact", "compatible", "heuristic":
			if sample.Tokenizer.ID == "" || sample.Tokenizer.Version == "" || sample.Tokenizer.LocalTokenCount == nil {
				return errors.New("available tokenizer requires identity, version and count")
			}
		case "unavailable":
			if sample.Tokenizer.LocalTokenCount != nil {
				return errors.New("unavailable tokenizer cannot claim a count")
			}
		default:
			return errors.New("invalid tokenizer quality")
		}
	}
	return nil
}

// Fingerprint hashes the canonical Go JSON encoding of samples, excluding the
// opaque case and sample IDs. Renaming a case cannot evade duplicate checking.
// This catches exact copies; semantic variants must share an owner-set lineage.
func Fingerprint(input Input) (string, error) {
	if err := ValidateInput(input); err != nil {
		return "", err
	}
	samples := append([]Sample(nil), input.Samples...)
	for index := range samples {
		samples[index].SampleID = ""
	}
	encoded, err := json.Marshal(samples)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func ValidateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != SchemaVersion || !identifierPattern.MatchString(manifest.DatasetVersion) || len(manifest.Cases) == 0 {
		return errors.New("invalid dataset manifest identity or empty cases")
	}
	if manifest.FrozenAt != "" {
		if _, err := time.Parse(time.RFC3339, manifest.FrozenAt); err != nil {
			return errors.New("frozen_at must be RFC3339")
		}
	}
	ids := map[string]bool{}
	lineages := map[string]Split{}
	fingerprints := map[string]string{}
	for _, item := range manifest.Cases {
		if !identifierPattern.MatchString(item.CaseID) || ids[item.CaseID] || !identifierPattern.MatchString(item.LineageID) || !validSplit(item.Split) || !hashPattern.MatchString(item.InputSHA256) {
			return errors.New("invalid or duplicate case identity, lineage, split or fingerprint")
		}
		ids[item.CaseID] = true
		if previous, ok := lineages[item.LineageID]; ok && previous != item.Split {
			return fmt.Errorf("lineage %s crosses dataset partitions", item.LineageID)
		}
		lineages[item.LineageID] = item.Split
		if previous, ok := fingerprints[item.InputSHA256]; ok {
			return fmt.Errorf("duplicate input content for cases %s and %s", previous, item.CaseID)
		}
		fingerprints[item.InputSHA256] = item.CaseID
		coverage := map[string]bool{}
		for _, condition := range item.Coverage {
			if !validConditions[condition] || coverage[condition] {
				return errors.New("unknown or repeated coverage condition")
			}
			coverage[condition] = true
		}
		if len(coverage) == 0 {
			return errors.New("case requires controller-side coverage metadata")
		}
	}
	return nil
}

// ValidateCoverage is an explicit release-dataset readiness check, not a metric.
// Small development examples are intentionally not release-complete datasets.
func ValidateCoverage(manifest Manifest, split Split) error {
	if err := ValidateManifest(manifest); err != nil {
		return err
	}
	if !validSplit(split) {
		return errors.New("unknown partition")
	}
	coverage := map[string]bool{}
	for _, item := range manifest.Cases {
		if item.Split == split {
			for _, condition := range item.Coverage {
				coverage[condition] = true
			}
		}
	}
	for _, condition := range RequiredCoverage {
		if !coverage[condition] {
			return fmt.Errorf("partition %s lacks %s coverage", split, condition)
		}
	}
	return nil
}

// ValidatePartition checks a mounted input set against its controller manifest.
// Labels are not needed or read to verify hashes and partition separation.
func ValidatePartition(manifest Manifest, split Split, inputs []Input) error {
	if err := ValidateManifest(manifest); err != nil {
		return err
	}
	if !validSplit(split) {
		return errors.New("unknown partition")
	}
	expected := map[string]string{}
	for _, item := range manifest.Cases {
		if item.Split == split {
			expected[item.CaseID] = item.InputSHA256
		}
	}
	if len(expected) == 0 || len(inputs) != len(expected) {
		return errors.New("partition input count mismatch or empty partition")
	}
	seen := map[string]bool{}
	for _, input := range inputs {
		hash, err := Fingerprint(input)
		if err != nil {
			return err
		}
		if seen[input.CaseID] || expected[input.CaseID] != hash {
			return errors.New("input is duplicated, changed or belongs to another partition")
		}
		seen[input.CaseID] = true
	}
	return nil
}

// ValidateLabels is for the scoring controller after detector results are
// sealed. It cannot prove filesystem access isolation or genuine blind testing.
func ValidateLabels(manifest Manifest, split Split, labels []Label) error {
	if err := ValidateManifest(manifest); err != nil {
		return err
	}
	if !validSplit(split) {
		return errors.New("unknown partition")
	}
	expected := map[string]CaseRef{}
	for _, item := range manifest.Cases {
		if item.Split == split {
			expected[item.CaseID] = item
		}
	}
	if len(expected) == 0 || len(labels) != len(expected) {
		return errors.New("label count mismatch or empty partition")
	}
	seen := map[string]bool{}
	for _, label := range labels {
		item, exists := expected[label.CaseID]
		if !exists || seen[label.CaseID] || len(label.Conditions) == 0 || label.Rationale == "" {
			return errors.New("invalid, duplicate or cross-partition label")
		}
		seen[label.CaseID] = true
		conditions := map[string]bool{}
		for _, condition := range label.Conditions {
			if !validConditions[condition] || conditions[condition] {
				return errors.New("unknown or repeated label condition")
			}
			conditions[condition] = true
		}
		if len(conditions) != len(item.Coverage) {
			return errors.New("labels do not match controller coverage")
		}
		for _, condition := range item.Coverage {
			if !conditions[condition] {
				return errors.New("labels do not match controller coverage")
			}
		}
		if conditions["normal"] && (conditions["fixed_cap"] || conditions["probabilistic_cap"] || conditions["hidden_instruction"] || conditions["stream_mutation"] || conditions["usage_forgery"]) {
			return errors.New("normal label contradicts positive mutation label")
		}
	}
	return nil
}
