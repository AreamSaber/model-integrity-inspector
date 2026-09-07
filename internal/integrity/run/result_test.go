package run

import (
	"errors"
	"math"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/behavior"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/structure"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func TestResultStrictDocumentResourceAndSchemaBounds(t *testing.T) {
	type document struct {
		Value string `json:"value"`
	}
	for name, raw := range map[string]string{
		"unknown": `{"prompt":"PRIVATE_BODY"}`, "duplicate": `{"value":"a","value":"b"}`,
		"case_duplicate": `{"value":"a","Value":"b"}`, "trailing": `{"value":"a"}{}`,
		"bad_utf8":    "{\"value\":\"" + string([]byte{255}) + "\"}",
		"long_string": `{"value":"` + strings.Repeat("x", 4097) + `"}`,
		"long_key":    `{"` + strings.Repeat("x", 129) + `":0}`,
		"deep":        strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66),
		"many_values": "[" + strings.Repeat("0,", 200001) + "0]",
		"truncated":   `{"value":`, "invalid_number": `{"value":NaN}`,
	} {
		t.Run(name, func(t *testing.T) {
			var out document
			if err := strictDocument(raw, 4<<20, &out); !errors.Is(err, repository.ErrResultDocument) {
				t.Fatal("malformed document accepted", err)
			}
		})
	}
	var out document
	if err := strictDocument(`{"value":"bounded"}`, 64, &out); err != nil || out.Value != "bounded" {
		t.Fatal("valid document rejected", err)
	}
	if err := strictDocument(`{"value":"bounded"}`, 10, &out); !errors.Is(err, repository.ErrResultDocument) {
		t.Fatal("outer byte limit ignored")
	}
}

func TestResultPublishedBindingAndClosedProjection(t *testing.T) {
	for _, name := range []string{"unknown_field", "org", "run", "manifest", "sample", "duplicate_sample", "final_attempt", "ordinal", "included", "quality", "tokenizer_id", "finish", "family", "language", "score", "version", "rules_hash", "unpublished"} {
		t.Run(name, func(t *testing.T) {
			data, d := reviewPublished(t)
			sample := &d.Features.Samples[0]
			switch name {
			case "org":
				d.Features.OrganizationID = "999"
			case "run":
				d.Features.RunID = "999"
			case "manifest":
				d.Features.ManifestHash = strings.Repeat("b", 64)
			case "sample":
				sample.SampleID = "999"
			case "duplicate_sample":
				d.Features.Samples = append(d.Features.Samples, *sample)
			case "final_attempt":
				sample.AttemptID = "99"
			case "ordinal":
				sample.Ordinal = 1
			case "included":
				sample.Included = true
			case "quality":
				sample.Local = &tokenizer.Estimate{Quality: "PRIVATE_BODY"}
			case "tokenizer_id":
				sample.Local = &tokenizer.Estimate{Quality: tokenizer.Unavailable, TokenizerID: "PRIVATE_BODY"}
			case "finish":
				sample.Structure = &structure.Features{FinishReason: "PRIVATE_BODY"}
			case "family":
				sample.Family = "PRIVATE_BODY"
			case "language":
				sample.Language = "PRIVATE_BODY"
			case "score":
				value := 8.0
				data.Result.OverallRisk = &value
			case "version":
				d.Scores.Version = "future.calibrated"
			case "rules_hash":
				d.Scores.RulesHash = strings.Repeat("b", 64)
			case "unpublished":
				data.Result.IsPublished = false
			}
			reviewDocument(t, &data, d)
			if name == "unknown_field" {
				data.Result.ConclusionJSON = strings.TrimSuffix(data.Result.ConclusionJSON, "}") + `,"response_body":"PRIVATE_BODY"}`
			}
			if _, err := decodePublished(data); !errors.Is(err, repository.ErrResultDocument) {
				t.Fatal("unbound or untrusted published field accepted", err)
			}
		})
	}
	// Display text is selected from a closed code table, not arbitrary stored
	// prose nor a syntactically plausible MI_* string containing S2 data.
	codes := safeCodes([]string{"PRIVATE_BODY", "MI_PRIVATE_BODY", "PRIVATE_BODY"})
	if len(codes) != 1 || codes[0] != "MI_ANALYSIS_LIMITATION_UNAVAILABLE" {
		t.Fatal("untrusted diagnostic reflected")
	}
}

func TestResultDerivedMissingEvidenceIsNotHealthy(t *testing.T) {
	data, d := reviewPublished(t)
	data.Samples[0].Validity = "VALID"
	d.Features.Samples[0].Limitations = []string{"MI_FEATURE_EVIDENCE_MISSING"}
	reviewDocument(t, &data, d)
	if _, err := decodePublished(data); err != nil {
		t.Fatal("legitimate derived missing evidence rejected", err)
	}
	if derivedValidity("VALID", features.SampleFeature{Validity: "NOT_APPLICABLE"}) {
		t.Fatal("unexplained validity downgrade accepted")
	}
	if derivedValidity("INVALID_PROTOCOL", features.SampleFeature{Validity: "VALID", Included: true}) {
		t.Fatal("invalid evidence upgraded to valid")
	}
}

func TestResultHistoryClosedVersionsAndSummaryLimits(t *testing.T) {
	data, _ := reviewPublished(t)
	if _, err := historyItem(data.Run); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"PRIVATE_BODY", "", strings.Repeat("x", 129)} {
		row := data.Run
		row.RuleBundleVersion = version
		if _, err := historyItem(row); !errors.Is(err, repository.ErrResultDocument) {
			t.Fatal("history returned unsupported version")
		}
	}
	data.Run.Status = ""
	if _, err := historyItem(data.Run); !errors.Is(err, repository.ErrResultDocument) {
		t.Fatal("empty status accepted")
	}
	for _, confidence := range []float64{math.NaN(), math.Inf(1), -1, 59.5, 75} {
		if _, err := summary(1, nil, confidence, "insufficient", "D", "INSUFFICIENT"); !errors.Is(err, repository.ErrResultDocument) {
			t.Fatal("invalid confidence accepted")
		}
	}
	for _, grade := range []string{"A", "B", "F"} {
		if _, err := summary(1, nil, 0, "insufficient", grade, "INSUFFICIENT"); !errors.Is(err, repository.ErrResultDocument) {
			t.Fatal("unsupported grade accepted")
		}
	}
}

func TestResultStatisticsRejectInflatedDenominatorsAndUnknownReferences(t *testing.T) {
	for _, name := range []string{"extra_samples", "foreign_sample", "foreign_auxiliary", "invalid_state", "duplicate_metric", "usage_denominator", "nonfinite_usage"} {
		t.Run(name, func(t *testing.T) {
			_, d := reviewPublished(t)
			switch name {
			case "extra_samples":
				d.Behavior.Samples = []behavior.Features{{SampleID: "4", State: behavior.Analyzed}, {SampleID: "4", State: behavior.Analyzed}}
			case "foreign_sample":
				d.Behavior.Samples = []behavior.Features{{SampleID: "999", State: behavior.Analyzed}}
			case "foreign_auxiliary":
				d.Behavior.Auxiliary = []behavior.Features{{SampleID: "999", State: behavior.Auxiliary}}
			case "invalid_state":
				d.Behavior.Samples = []behavior.Features{{SampleID: "4", State: "PRIVATE_BODY"}}
			case "duplicate_metric":
				d.Differences = []behavior.Difference{{Metric: behavior.ContractDeviation, State: behavior.PairInsufficient}, {Metric: behavior.ContractDeviation, State: behavior.PairInsufficient}}
			case "usage_denominator":
				d.Tokens.Usage.IncludedSamples = 2
			case "nonfinite_usage":
				d.Tokens.Usage.MedianRelativeError = math.Inf(1)
			}
			if _, _, err := statisticsViews(d); !errors.Is(err, repository.ErrResultDocument) {
				t.Fatal("invalid statistics accepted", err)
			}
		})
	}
}

func TestResultAttemptCodesAndObservedWarningsRemainClosed(t *testing.T) {
	empty := ""
	if attemptErrorCode(nil) != nil || attemptErrorCode(&empty) != nil {
		t.Fatal("successful empty error code displayed as an error")
	}
	for _, code := range strings.Fields(`MI_NETWORK_TEMPORARY MI_SERVICE_UNAVAILABLE MI_CLIENT_SAFETY_LIMIT MI_EVIDENCE_LIMIT MI_SAFETY_REFUSAL MI_EXECUTION_TARGET_STALE MI_EXECUTION_CIRCUIT_OPEN MI_AUTH_FAILED MI_MODEL_NOT_FOUND MI_PROTOCOL_UNSUPPORTED MI_RATE_LIMITED MI_TIMEOUT MI_UNCERTAIN_ATTEMPT MI_CONNECTION_RESET MI_EXECUTION_BUDGET_EXCEEDED MI_EXECUTION_CANCELLED`) {
		if got := attemptErrorCode(&code); got == nil || *got != code {
			t.Fatal("known persisted attempt code lost", code)
		}
	}
	for _, code := range []string{"MI_PRIVATE_BODY", "raw response body", " ", "MI_NETWORK_FAILED"} {
		if got := attemptErrorCode(&code); got == nil || *got != "MI_EXECUTION_ERROR" {
			t.Fatal("unknown stored diagnostic leaked")
		}
	}
	warnings := strings.Fields(`MI_USAGE_UNAVAILABLE MI_USAGE_INVALID MI_PROTOCOL_OBJECT_MISSING MI_PROTOCOL_MODEL_CHANGED_WITHIN_STREAM MI_PROTOCOL_USAGE_CHANGED_WITHIN_STREAM MI_PROTOCOL_USAGE_TOTAL_MISMATCH MI_PROTOCOL_REASONING_EXCEEDS_COMPLETION MI_PROTOCOL_FINISH_REASON_UNKNOWN MI_PROTOCOL_FINISH_REASON_CONFLICT MI_PROTOCOL_MODEL_MISSING MI_PROTOCOL_FINISH_REASON_MISSING MI_PROTOCOL_EMPTY_CONTENT MI_PROTOCOL_USAGE_MISSING MI_PROTOCOL_FIRST_EVENT_TIMEOUT MI_PROTOCOL_STREAM_IDLE_TIMEOUT MI_PROTOCOL_STREAM_EOF_BEFORE_DONE MI_PROTOCOL_UNTERMINATED_EVENT MI_PROTOCOL_STREAM_MALFORMED_EVENT MI_PROTOCOL_CONTENT_AFTER_FINISH MI_PROTOCOL_LOCAL_TOKENIZER_APPROXIMATE`)
	for _, code := range warnings {
		if got := safeCodes([]string{code}); len(got) != 1 || got[0] != code {
			t.Fatal("observed protocol/usage warning lost", code)
		}
	}
	if got := safeCodes([]string{"MI_PROTOCOL_PRIVATE_BODY"}); len(got) != 1 || got[0] != "MI_ANALYSIS_LIMITATION_UNAVAILABLE" {
		t.Fatal("arbitrary protocol-prefix string leaked")
	}
}
