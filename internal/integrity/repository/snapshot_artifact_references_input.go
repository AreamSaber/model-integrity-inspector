package repository

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"unicode/utf8"
)

// Configuration context is distinct from the actual estimator implementation
// and encoding. Its SHA is not an implementation/carrier/parameter hash.
type snapshotReferenceInputTokenizer struct {
	configurationVersion, configurationHash string
	implementation, encoding                string
}

func (snapshotReferenceInputTokenizer) String() string {
	return "[private input tokenizer observation]"
}
func (v snapshotReferenceInputTokenizer) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, v.String())
}
func (v snapshotReferenceInputTokenizer) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (snapshotReferenceInputTokenizer) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (snapshotReferenceInputTokenizer) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

const snapshotReferenceInputBPE = "mii-bpe-v1+github.com/tiktoken-go/tokenizer@v0.8.1"

func snapshotReferenceInputString(object map[string]json.RawMessage, key string, empty bool) (string, bool, error) {
	if !snapshotKeyExactNames(object, key) {
		return "", false, errSnapshotReferenceInvalid
	}
	raw, present := object[key]
	if !present {
		return "", false, nil
	}
	value, ok := snapshotKeyJSONString(raw)
	if !ok || !empty && value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
		return "", true, errSnapshotReferenceInvalid
	}
	return value, true, nil
}

// This observes the historical writer's metadata, not counts, canonical
// tokenizer data or MAC authenticity. Repository permits storage-only manifests
// with omitted metadata; missing/unknown remains incomplete, never defaulted.
func snapshotReferenceInputEstimate(sample map[string]json.RawMessage, configurationVersion, configurationHash string) (snapshotReferenceInputTokenizer, bool, bool, error) {
	zero := snapshotReferenceInputTokenizer{}
	if !snapshotKeyExactNames(sample, "input_estimate") {
		return zero, false, false, errSnapshotReferenceInvalid
	}
	raw, present := sample["input_estimate"]
	if !present {
		return zero, false, true, nil
	}
	object, ok := snapshotKeyObject(raw)
	if !ok {
		return zero, false, false, errSnapshotReferenceInvalid
	}
	version, hasVersion, err := snapshotReferenceInputString(object, "bundle_version", false)
	if err != nil || hasVersion && version != configurationVersion {
		return zero, false, false, errSnapshotReferenceInvalid
	}
	hash, hasHash, err := snapshotReferenceInputString(object, "bundle_hash", false)
	if err != nil || hasHash && (!executionHash.MatchString(hash) || hash != configurationHash) {
		return zero, false, false, errSnapshotReferenceInvalid
	}
	implementation, hasImplementation, err := snapshotReferenceInputString(object, "tokenizer_version", true)
	if err != nil {
		return zero, false, false, err
	}
	encoding, hasEncoding, err := snapshotReferenceInputString(object, "tokenizer_id", true)
	if err != nil {
		return zero, false, false, err
	}
	quality, hasQuality, err := snapshotReferenceInputString(object, "quality", true)
	if err != nil {
		return zero, false, false, err
	}
	// Unknown declarations are kept verbatim, not implicitly admitted as today's
	// installed resource. A pair of known, contradictory declarations is invalid.
	knownBPEEncoding := encoding == "cl100k_base" || encoding == "o200k_base"
	heuristicEncoding := encoding == "unicode-byte-heuristic"
	knownBPE := implementation == snapshotReferenceInputBPE
	heuristic := implementation == "unicode-byte-v1"
	if (knownBPE && heuristicEncoding) || (heuristic && knownBPEEncoding) ||
		(hasQuality && quality == "heuristic" && (knownBPE || knownBPEEncoding)) ||
		(hasQuality && (quality == "compatible" || quality == "exact") && (heuristic || heuristicEncoding)) {
		return zero, false, false, errSnapshotReferenceInvalid
	}
	complete := hasVersion && hasHash && hasImplementation && hasEncoding && hasQuality &&
		((knownBPE && knownBPEEncoding && quality == "compatible") || (heuristic && heuristicEncoding && quality == "heuristic"))
	// Container context comes from this SAME original manifest, not a default
	// resource. Missing nested declarations remain incomplete; no implementation
	// or encoding is supplied in their place. This also prevents incomplete refs
	// under different original configurations from being flattened together.
	input := snapshotReferenceInputTokenizer{configurationVersion, configurationHash, implementation, encoding}
	return input, hasVersion || hasHash || hasImplementation || hasEncoding, !complete, nil
}
