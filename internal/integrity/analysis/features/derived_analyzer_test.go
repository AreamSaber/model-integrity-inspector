package features_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/analyzer"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

type derivedFixtureSigner struct{}

func (derivedFixtureSigner) ActiveVersion() string { return "fixture" }
func (derivedFixtureSigner) ProbeMAC(_ string, data []byte) ([]byte, error) {
	h := hmac.New(sha256.New, []byte("synthetic-derived-test-manifest-key"))
	_, _ = h.Write(data)
	return h.Sum(nil), nil
}

type derivedNoNetwork struct{}

func (derivedNoNetwork) Do(*http.Request) (*http.Response, error) {
	return nil, features.ErrConfiguration
}

func analyzerFixture(t *testing.T, mode string) (*features.Builder, features.Input, generator.Manifest) {
	t.Helper()
	artifact, hash, err := templates.Builtin().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := tokenizer.NewBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	g, err := generator.New(artifact, hash, tokens, derivedFixtureSigner{})
	if err != nil {
		t.Fatal(err)
	}
	builder, err := features.New(features.Config{Verifier: g, Tokenizer: tokens, TemplateArtifact: artifact, TrustedTemplateHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	opts := generator.Options{OrganizationID: 42, Target: domain.ExecutionTarget{ID: 11, Version: 2, SecretID: 12, SecretVersion: 3, Model: "gpt-4o-2024-08-06", Endpoint: "https://example.com/v1", Protocol: "openai_chat", MaxOutputParameter: "max_tokens", AuthType: "bearer", TimeoutSeconds: 180}, Package: "standard", Budget: domain.ExecutionBudget{MaxRequests: 150, MaxTokens: 1000000, TimeoutSeconds: 600}, RuleVersion: "1.0.0-dev.1", ScoringVersion: "1.0.0-dev.1", StandardModel: "gpt-4o-2024-08-06", ContextWindow: 128000, MaxOutputTokens: 4096, SupportsSeed: mode != "no-seed", SupportsStream: true, Concurrency: 3, MaxRetries: 2, ReasoningModel: strings.HasPrefix(mode, "reasoning")}
	opts.AnalysisSourceVersion = domain.AnalysisSourceDerivedV1
	m, err := g.Generate(opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, manifestHash, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := g.ExecutionPlan(raw, manifestHash, opts.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := openaichat.New(openaichat.Config{Endpoint: "https://analysis.invalid/v1", MaxOutputParameter: plan.Target.MaxOutputParameter, Doer: derivedNoNetwork{}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	input := features.Input{Run: features.RunBinding{OrganizationID: 42, ID: 999, Plan: plan, ExecutionClosedAt: now.Add(time.Second)}}
	for i, signed := range m.Samples {
		sampleID, attemptID := int64(i+1000), int64(i+2000)
		frozen := plan.Probes[i].Samples[0]
		_, snapshot, err := adapter.BuildRequest(t.Context(), frozen.Request)
		if err != nil {
			t.Fatal(err)
		}
		body := signed.Variables.Nonce
		switch signed.Family {
		case "sequence":
			body += "|1\n" + signed.Variables.Nonce + "|2"
		case "jsonl":
			body = fmt.Sprintf("{\"%s\":\"%s\",\"n\":1}\n{\"%s\":\"%s\",\"n\":2}", signed.Variables.Label, signed.Variables.Nonce, signed.Variables.Label, signed.Variables.Nonce)
		case "neutral":
			body = strings.ToUpper(body)
		case "format":
			if signed.Variant == 3 {
				body = fmt.Sprintf("{\"%s\":\"%s\"}", signed.Variables.Label, signed.Variables.Nonce)
			}
		case "style":
			body = "Arrange the blank cards by color."
		case "self_report":
			body = "I cannot identify the model."
		}
		if mode == "affix" && (signed.Family == "format" || signed.Family == "neutral" || signed.Family == "differential") {
			body = "This controlled persistent preamble precedes a response. " + body + " A repeated synthetic closing sentence follows the response."
		}
		if mode == "paired-cues" && signed.Arm == "B" {
			body = "I cannot help with this synthetic request."
		}
		local, err := tokens.CountOutput(body, tokenizer.Selection{RequestedModel: opts.Target.Model})
		if err != nil {
			t.Fatal(err)
		}
		prompt, total, first := int64(10), int64(10)+*local.Tokens, int64(2)
		r := domain.NormalizedResponse{ModelReported: opts.Target.Model, Content: body, FinishReason: "stop", PromptTokens: &prompt, CompletionTokens: local.Tokens, TotalTokens: &total, HTTPStatus: 200, ContentType: "application/json", FirstByteMs: 1, DurationMs: 10, RawResponseBytes: int64(len(body) + 256), ParseStatus: "valid", ChoiceCount: 1, EndCause: "complete"}
		if signed.Stream {
			r.StreamTerminated, r.ContentType, r.EndCause, r.FirstTokenMs, r.StreamChunkCount = true, "text/event-stream", "done", &first, 3
		}
		switch mode {
		case "missing-usage":
			r.PromptTokens, r.CompletionTokens, r.TotalTokens, r.ModelReported = nil, nil, nil, ""
		case "reasoning-separated":
			n := int64(5)
			c := *r.CompletionTokens + n
			r.ReasoningTokens, r.CompletionTokens = &n, &c
		case "reported-model":
			r.ModelReported = "gpt-4"
		case "partial-stream":
			if signed.Stream {
				r.ParseStatus, r.EndCause, r.StreamTerminated, r.ParseWarnings = "partial", "eof", false, []string{"STREAM_EOF_BEFORE_DONE"}
			}
		case "protocol":
			if i%3 == 0 {
				r.ContentType = "text/html; private-canary=not-exportable"
			}
		case "refusal":
			if i%3 == 0 {
				r.Refusal = true
			}
		case "refusal-uneven":
			// Keep two fully replicated behavior families and precisely one
			// differential nonce cluster. Real extraction then produces family
			// repeatability terms 1, 1 and 1/3 without hand-filled features.
			keep := signed.Family == "format" || signed.Family == "neutral" || (signed.Family == "differential" && signed.Language == "zh-CN" && signed.Repetition == 0)
			r.Refusal = !keep
		case "structure-limit":
			if i == 0 {
				r.Content = strings.Repeat("x", 65<<10)
			}
		case "behavior-limit":
			if signed.Family == "format" && signed.Variant == 1 {
				r.Content = strings.Repeat(strings.Repeat("x", 198)+".\n", 400)
			}
		}
		evidence, err := features.NewEvidence(features.EvidenceScope{OrganizationID: 42, RunID: 999, SampleID: sampleID, AttemptID: attemptID, RequestHash: snapshot.RequestHash}, r)
		if err != nil {
			t.Fatal(err)
		}
		a := features.AttemptBinding{OrganizationID: 42, RunID: 999, SampleID: sampleID, ID: attemptID, JobID: int64(i + 3000), Number: 1, Status: "COMPLETED", Validity: "VALID", Snapshot: snapshot, RequestHash: snapshot.RequestHash, StartedAt: now, FinishedAt: now.Add(10 * time.Millisecond), Evidence: evidence}
		row := features.SampleBinding{OrganizationID: 42, RunID: 999, ID: sampleID, ProbeInstanceID: int64(i + 4000), Ordinal: i, ExecutionOrdinal: i, RequestPlan: frozen, PairID: signed.PairID, AttemptCount: 1, FinalAttemptID: &attemptID, Validity: "VALID", CompletedAt: now.Add(20 * time.Millisecond), Attempts: []features.AttemptBinding{a}}
		if i == 0 {
			switch mode {
			case "missing-response":
				row.Attempts[0].Evidence = nil
			case "uncertain":
				row.Attempts[0].Status, row.Attempts[0].Validity, row.Validity = "UNCERTAIN", "INVALID_RETRYABLE", "INVALID_RETRYABLE"
				row.Attempts[0].ErrorCode = "MI_NETWORK_TEMPORARY"
			case "invalid":
				row.Attempts[0].Validity, row.Validity = "INVALID_SAFETY_LIMIT", "INVALID_SAFETY_LIMIT"
			case "no-final":
				row.Attempts, row.FinalAttemptID, row.AttemptCount, row.Validity = nil, nil, 0, "NOT_APPLICABLE"
			case "retry":
				old := a
				old.ID += 10000
				old.Evidence = nil
				old.Validity = "INVALID_RETRYABLE"
				old.ErrorCode = "MI_NETWORK_TEMPORARY"
				a.Number = 2
				row.Attempts, row.AttemptCount = []features.AttemptBinding{old, a}, 2
			}
		}
		input.Samples = append(input.Samples, row)
	}
	return builder, input, m
}

func TestDerivedCompleteAnalyzerJSONEqualsRawResponsePath(t *testing.T) {
	for _, mode := range []string{"normal", "no-seed", "affix", "paired-cues", "missing-usage", "reasoning-unseparated", "reasoning-separated", "reported-model", "partial-stream", "protocol", "refusal", "refusal-uneven", "structure-limit", "behavior-limit", "missing-response", "uncertain", "invalid", "no-final", "retry"} {
		t.Run(mode, func(t *testing.T) {
			builder, input, manifest := analyzerFixture(t, mode)
			sealer, verifier, err := features.NewDerivedCapabilities("synthetic.v1", bytes.Repeat([]byte{0x5a}, 32))
			if err != nil {
				t.Fatal(err)
			}
			records := []features.DerivedRecord{}
			for i := range input.Samples {
				for j := range input.Samples[i].Attempts {
					a := input.Samples[i].Attempts[j]
					// Capture must not depend on not-yet-existing commit timestamps.
					run, row := input.Run, input.Samples[i]
					run.ExecutionClosedAt, row.CompletedAt, a.FinishedAt = time.Time{}, time.Time{}, time.Time{}
					prepared, err := builder.DeriveAttempt(t.Context(), run, row, a)
					if err != nil {
						t.Fatal(err)
					}
					record, err := sealer.Seal(t.Context(), prepared)
					if err != nil {
						t.Fatal(err)
					}
					var inner struct {
						Behavior []byte `json:"behavior_observation"`
					}
					if json.Unmarshal(record.Payload, &inner) != nil {
						t.Fatal("fixture payload")
					}
					markers := []string{manifest.RunNonce, manifest.Samples[i].Variables.Nonce, manifest.Samples[i].Variables.Label, "private-canary", "controlled persistent preamble"}
					if seed := manifest.Samples[i].Seed; seed != nil {
						markers = append(markers, strconv.FormatInt(*seed, 10))
					}
					for _, marker := range markers {
						if bytes.Contains(record.Payload, []byte(marker)) || bytes.Contains(inner.Behavior, []byte(marker)) {
							t.Fatal("S2 retained in derived S1")
						}
					}
					for _, field := range []string{`"seed"`, `"nonce"`, `"content"`, `"messages"`, `"model_reported"`, `"content_type"`} {
						if bytes.Contains(record.Payload, []byte(field)) {
							t.Fatalf("forbidden S2 field %s", field)
						}
					}
					records = append(records, record)
				}
			}
			rawBatch, err := builder.BuildResponseReference(t.Context(), input, records, verifier)
			if err != nil {
				t.Fatal(err)
			}
			rawDoc, err := analyzer.Analyze(rawBatch)
			if err != nil {
				t.Fatal(err)
			}
			input = withoutResponses(input)
			derivedBatch, err := builder.BuildDerived(t.Context(), input, records, verifier)
			if err != nil {
				t.Fatal(err)
			}
			derivedDoc, err := analyzer.Analyze(derivedBatch)
			if err != nil {
				t.Fatal(err)
			}
			left, err := json.Marshal(rawDoc)
			if err != nil {
				t.Fatal(err)
			}
			right, err := json.Marshal(derivedDoc)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(left, right) {
				t.Fatal("full analysis JSON differs between raw and authenticated derived paths: " + analysisDifference(left, right))
			}
			if mode == "normal" && (derivedDoc.Features.Included == 0 || derivedDoc.Tokens.ValidSamples == 0 || derivedDoc.Differences[0].CompletePairs == 0) {
				t.Fatal("equivalence achieved by erasing actual observations")
			}
		})
	}
}

func TestDerivedRefusalRawAnalyzerIsByteDeterministic(t *testing.T) {
	builder, input, _ := analyzerFixture(t, "refusal-uneven")
	sealer, verifier, err := features.NewDerivedCapabilities("synthetic.v1", bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	records := sealResponseFixture(t, builder, input, sealer)
	batch, err := builder.BuildResponseReference(t.Context(), input, records, verifier)
	if err != nil {
		t.Fatal(err)
	}
	first, err := analyzer.Analyze(batch)
	if err != nil {
		t.Fatal(err)
	}
	clusters := map[string]map[string]bool{}
	for _, sample := range first.Features.Samples {
		if !sample.Included || sample.AuxiliaryOnly {
			continue
		}
		if sample.Behavior == nil || sample.Behavior.Contract != "matches" {
			t.Fatal("fixture requires actually measured matching contracts")
		}
		if clusters[sample.Family] == nil {
			clusters[sample.Family] = map[string]bool{}
		}
		clusters[sample.Family][sample.ClusterHash] = true
	}
	if len(clusters) != 3 || len(clusters["format"]) < 3 || len(clusters["neutral"]) < 3 || len(clusters["differential"]) != 1 {
		t.Fatalf("fixture cluster counts: families=%d format=%d neutral=%d differential=%d", len(clusters), len(clusters["format"]), len(clusters["neutral"]), len(clusters["differential"]))
	}
	expected, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	for range 128 {
		result, err := analyzer.Analyze(batch)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(expected, actual) {
			t.Fatal("identical raw batch is nondeterministic: " + analysisDifference(expected, actual))
		}
	}
}

func TestDerivedActualSecretPurposeCapabilityAndHistoricalVersions(t *testing.T) {
	builder, input, _ := analyzerFixture(t, "affix")
	oldMaster, newMaster := bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x67}, 32)
	newCapabilities := func(active string, masters map[string][]byte) (*features.DerivedSealer, *features.DerivedVerifier) {
		t.Helper()
		ring, err := secret.NewKeyRing(active, masters)
		if err != nil {
			t.Fatal(err)
		}
		purpose, err := ring.NewDerivedSourceMAC()
		if err != nil {
			t.Fatal(err)
		}
		sealer, verifier, err := features.NewDerivedCapabilitiesWithMAC(active, purpose)
		if err != nil {
			t.Fatal(err)
		}
		return sealer, verifier
	}
	oldSealer, oldVerifier := newCapabilities("OLD.1", map[string][]byte{"OLD.1": oldMaster})
	newSealer, rotatedVerifier := newCapabilities("NEW.2", map[string][]byte{"OLD.1": oldMaster, "NEW.2": newMaster})
	oldRecords, newRecords := []features.DerivedRecord{}, []features.DerivedRecord{}
	for i := range input.Samples {
		for j := range input.Samples[i].Attempts {
			prepared, err := builder.DeriveAttempt(t.Context(), input.Run, input.Samples[i], input.Samples[i].Attempts[j])
			if err != nil {
				t.Fatal(err)
			}
			oldRecord, err := oldSealer.Seal(t.Context(), prepared)
			if err != nil {
				t.Fatal(err)
			}
			newRecord, err := newSealer.Seal(t.Context(), prepared)
			if err != nil {
				t.Fatal(err)
			}
			if oldRecord.KeyVersion != "OLD.1" || newRecord.KeyVersion != "NEW.2" || bytes.Equal(oldRecord.MAC, newRecord.MAC) || !bytes.Equal(oldRecord.Payload, newRecord.Payload) {
				t.Fatal("versioned actual purpose authentication is not detached from measurement bytes")
			}
			oldRecords, newRecords = append(oldRecords, oldRecord), append(newRecords, newRecord)
		}
	}
	rawBatch, err := builder.BuildResponseReference(t.Context(), input, oldRecords, oldVerifier)
	if err != nil {
		t.Fatal(err)
	}
	rawDocument, err := analyzer.Analyze(rawBatch)
	if err != nil {
		t.Fatal(err)
	}
	if rawDocument.Features.Included == 0 || len(rawDocument.Behavior.Patterns) == 0 {
		t.Fatal("fixture has no real measured behavior")
	}
	expected, err := json.Marshal(rawDocument)
	if err != nil {
		t.Fatal(err)
	}
	input = withoutResponses(input)
	for _, tc := range []struct {
		name     string
		records  []features.DerivedRecord
		verifier *features.DerivedVerifier
	}{{"original-ring", oldRecords, oldVerifier}, {"historical-after-rotation", oldRecords, rotatedVerifier}, {"new-active-version", newRecords, rotatedVerifier}} {
		t.Run(tc.name, func(t *testing.T) {
			batch, err := builder.BuildDerived(t.Context(), input, tc.records, tc.verifier)
			if err != nil {
				t.Fatal(err)
			}
			document, err := analyzer.Analyze(batch)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(expected, actual) {
				t.Fatal("actual secret capability changes full analysis JSON: " + analysisDifference(expected, actual))
			}
		})
	}
	_, wrongVerifier := newCapabilities("OLD.1", map[string][]byte{"OLD.1": newMaster})
	_, missingHistory := newCapabilities("NEW.2", map[string][]byte{"NEW.2": newMaster})
	masterAsPurpose, err := features.NewDerivedVerifier(map[string][]byte{"OLD.1": oldMaster})
	if err != nil {
		t.Fatal(err)
	}
	for _, verifier := range []*features.DerivedVerifier{wrongVerifier, missingHistory, masterAsPurpose} {
		if batch, err := builder.BuildDerived(t.Context(), input, oldRecords, verifier); !errors.Is(err, features.ErrBinding) || batch != nil {
			t.Fatal("wrong ring, missing historical purpose or raw master authenticated records", err)
		}
	}
}

func withoutResponses(input features.Input) features.Input {
	input.Samples = slices.Clone(input.Samples)
	for i := range input.Samples {
		input.Samples[i].Attempts = slices.Clone(input.Samples[i].Attempts)
		for j := range input.Samples[i].Attempts {
			input.Samples[i].Attempts[j].Evidence = nil
		}
	}
	return input
}

func sealResponseFixture(t *testing.T, builder *features.Builder, input features.Input, sealer *features.DerivedSealer) []features.DerivedRecord {
	t.Helper()
	records := []features.DerivedRecord{}
	for _, row := range input.Samples {
		for _, attempt := range row.Attempts {
			prepared, err := builder.DeriveAttempt(t.Context(), input.Run, row, attempt)
			if err != nil {
				t.Fatal(err)
			}
			record, err := sealer.Seal(t.Context(), prepared)
			if err != nil {
				t.Fatal(err)
			}
			records = append(records, record)
		}
	}
	return records
}

// Diagnostics are limited to field names from the closed analysis DTO and
// numeric/boolean/null differences. Never print documents, arbitrary strings,
// hashes, responses, manifests, nonce or seed while investigating a mismatch.
func analysisDifference(left, right []byte) string {
	allowed := map[string]bool{}
	var fields func(reflect.Type)
	fields = func(typ reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			allowed[name] = true
			fields(field.Type)
		}
	}
	fields(reflect.TypeFor[analyzer.Document]())
	var a, b any
	ld, rd := json.NewDecoder(bytes.NewReader(left)), json.NewDecoder(bytes.NewReader(right))
	ld.UseNumber()
	rd.UseNumber()
	if ld.Decode(&a) != nil || rd.Decode(&b) != nil {
		return "invalid-analysis-json"
	}
	var difference func(any, any, string) string
	difference = func(a, b any, path string) string {
		if reflect.DeepEqual(a, b) {
			return ""
		}
		switch av := a.(type) {
		case map[string]any:
			bv, ok := b.(map[string]any)
			if !ok {
				return path + " type-difference"
			}
			keys := []string{}
			for key := range av {
				keys = append(keys, key)
			}
			for key := range bv {
				if _, ok := av[key]; !ok {
					keys = append(keys, key)
				}
			}
			slices.Sort(keys)
			for _, key := range keys {
				segment := "unrecognized-field"
				if allowed[key] {
					segment = key
				}
				leftValue, leftOK := av[key]
				rightValue, rightOK := bv[key]
				if leftOK != rightOK {
					return path + "." + segment + " presence-difference"
				}
				if !allowed[key] && !reflect.DeepEqual(leftValue, rightValue) {
					return path + "." + segment + " value-difference"
				}
				if result := difference(leftValue, rightValue, path+"."+segment); result != "" {
					return result
				}
			}
		case []any:
			bv, ok := b.([]any)
			if !ok {
				return path + " type-difference"
			}
			if len(av) != len(bv) {
				return fmt.Sprintf("%s length %d != %d", path, len(av), len(bv))
			}
			for i := range av {
				if result := difference(av[i], bv[i], fmt.Sprintf("%s[%d]", path, i)); result != "" {
					return result
				}
			}
		case json.Number:
			if bv, ok := b.(json.Number); ok && len(av) <= 32 && len(bv) <= 32 {
				return fmt.Sprintf("%s numeric %s != %s", path, av, bv)
			}
		case bool:
			if bv, ok := b.(bool); ok {
				return fmt.Sprintf("%s boolean %t != %t", path, av, bv)
			}
		}
		return path + " value-difference"
	}
	if result := difference(a, b, "$"); result != "" {
		return result
	}
	return "canonical-byte-order-or-encoding-difference"
}

func TestDerivedAnalysisDifferenceDiagnosticsExcludeS2(t *testing.T) {
	for _, tc := range []struct {
		name, left, right, want string
	}{
		{"numeric-factor", `{"scores":{"Confidence":{"RepeatabilityFactor":0.6}}}`, `{"scores":{"Confidence":{"RepeatabilityFactor":0.5999999999999999}}}`, "$.scores.Confidence.RepeatabilityFactor numeric 0.6 != 0.5999999999999999"},
		{"string-value", `{"manifest_hash":"private-canary-left"}`, `{"manifest_hash":"private-canary-right"}`, "$.manifest_hash value-difference"},
		{"arbitrary-field-name", `{"private-canary-field":"private-canary-left"}`, `{"private-canary-field":"private-canary-right"}`, "$.unrecognized-field value-difference"},
		{"unknown-numeric-seed", `{"seed":123456789}`, `{"seed":987654321}`, "$.unrecognized-field value-difference"},
		{"array-length", `{"samples":[]}`, `{"samples":[{"sample_id":"private-canary"}]}`, "$.samples length 0 != 1"},
		{"boolean", `{"samples":[{"included":true}]}`, `{"samples":[{"included":false}]}`, "$.samples[0].included boolean true != false"},
		{"malformed", "private-canary-not-json", "{}", "invalid-analysis-json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := analysisDifference([]byte(tc.left), []byte(tc.right)); got != tc.want {
				t.Fatal("safe diagnostic differs from closed expected result")
			}
		})
	}
}
