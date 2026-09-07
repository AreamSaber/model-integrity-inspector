package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func ptr[T any](v T) *T { return &v }

// Synthetic S1 projections only: no network, repository, private body or key.
func fixture() (Scope, Input) {
	now := time.Date(2026, 9, 7, 10, 0, 0, 123456789, time.UTC)
	versions := Versions{scoring.Version, templates.BuiltinVersion, scoring.Version, tokenizer.BuiltinVersion}
	scope := Scope{ReportID: "9007199254742999", OrganizationID: "9007199254741999", RunID: "42", AnalysisRevision: 1, GeneratedAt: now, Versions: versions}
	in := Input{
		Run:    Run{ID: "42", TargetID: "9007199254743999", Package: "standard", CreatedAt: now.Add(-5 * time.Minute), StartedAt: ptr(now.Add(-4 * time.Minute)), FinishedAt: now.Add(-time.Minute), RequestCount: 14, TokenCount: 1024},
		Result: Result{RunID: "42", AnalysisRevision: 1, Versions: versions, ExpectedSamples: 13, ValidSamples: 12, OverallRisk: ptr(35.0), PromptRisk: ptr(40.0), TokenRisk: ptr(30.0), ResponseRisk: ptr(25.0), EvidenceRisk: ptr(15.0), Confidence: 50, EvidenceGrade: "C", RiskLevel: "watch", Completeness: "full", Limitations: []string{"MI_BASELINE_UNAVAILABLE", "MI_DEVELOPMENT_RULES_UNCALIBRATED"}},
	}
	for i := 0; i < 13; i++ {
		family := "sequence"
		if i >= 6 {
			family = "format"
		}
		if i == 12 {
			family = "self_report"
		}
		attemptID := strconv.Itoa(3000 + i)
		a := Attempt{ID: attemptID, AttemptNo: 1, Validity: "VALID", HTTPStatus: ptr(200), PromptTokens: ptr(int64(10)), CompletionTokens: ptr(int64(20)), TotalTokens: ptr(int64(30)), DurationMS: ptr(int64(500)), StartedAt: ptr(now.Add(-3 * time.Minute)), FinishedAt: ptr(now.Add(-2 * time.Minute))}
		s := Sample{ID: strconv.Itoa(1000 + i), RunID: "42", ProbeInstanceID: strconv.Itoa(2000 + i), Ordinal: i, Family: family, Language: "en-US", Validity: "VALID", Included: i != 12, AuxiliaryOnly: i == 12, RequestedMaxTokens: 256, LocalCompletionTokens: ptr(int64(20)), ReportedCompletionTokens: ptr(int64(20)), TokenizerID: "cl100k_base", TokenizerQuality: "exact", Stream: i%2 == 0, FinishReason: ptr("STOP"), Contract: ptr("not_applicable"), RefusalClass: ptr("not_applicable"), IdentityClass: ptr("not_applicable"), ResponseHash: ptr(strings.Repeat("a", 64)), FinalAttemptID: &attemptID, Attempts: []Attempt{a}}
		if i >= 3 && i < 6 {
			s.RequestedMaxTokens = 512
		}
		if i == 0 {
			s.Attempts[0].AttemptNo = 2
			s.Attempts = append(s.Attempts, Attempt{ID: "4000", AttemptNo: 1, Validity: "INVALID_RETRYABLE", ErrorCode: ptr("MI_TIMEOUT"), StartedAt: ptr(now.Add(-4 * time.Minute)), FinishedAt: ptr(now.Add(-3 * time.Minute))})
		}
		in.Samples = append(in.Samples, s)
	}
	in.Findings = []Finding{
		{ID: "5001", RunID: "42", AnalysisRevision: 1, Category: "prompt", RuleID: "development.aggregate.prompt", RuleVersion: scoring.Version, Severity: "medium", RiskScore: 40, Confidence: 50, EvidenceGrade: "C", Statistics: []Statistic{{Name: "format_contract", Actual: ptr(40.0), Unit: "risk_index"}, {Name: "trusted_baseline_difference", Unit: "risk_index"}}, Alternatives: []string{"ordinary_model_variation", "capability_or_protocol_limits"}, SampleRefs: []string{"1006", "1000"}},
		{ID: "5002", RunID: "42", AnalysisRevision: 1, Category: "evidence", RuleID: "development.aggregate.protocol", RuleVersion: scoring.Version, Severity: "low", RiskScore: 15, Confidence: 50, EvidenceGrade: "C", SampleRefs: []string{"1000"}},
	}
	in.Result.Token = &TokenStatistics{
		Tiers:        []Tier{{SeriesID: strings.Repeat("b", 64), Family: "sequence", Language: "en-US", RequestedMaxTokens: 256, Samples: 3, Median: 20, MAD: 1, RobustCV: .05}, {SeriesID: strings.Repeat("b", 64), Family: "sequence", Language: "en-US", RequestedMaxTokens: 512, Samples: 3, Median: 22, MAD: 1, RobustCV: .045}},
		Plateaus:     []Plateau{{SeriesID: strings.Repeat("b", 64), Family: "sequence", LowRequested: 256, HighRequested: 512, GrowthRatio: 1.1, Strength: 39, Candidate: true, Limited: true, Lower: ptr(0.0), Upper: ptr(5.0), Paired: true, IndependentGroups: 3, Limitations: []string{"MI_HIGH_TIER_SAMPLES_INSUFFICIENT"}, SampleRefs: []string{"1000", "1003"}}},
		UsageSamples: 12, UsageMedianError: ptr(.01), StreamPairs: 6, StreamMedianDifference: ptr(.02), Limitations: []string{"MI_STREAM_VARIATION_ALTERNATIVE"},
	}
	in.Result.Behavior = &BehaviorStatistics{AnalyzedSamples: 12, AuxiliarySamples: 1,
		Patterns:    []Pattern{{Kind: "extra_prefix", Fingerprint: strings.Repeat("c", 64), State: "cross_family_repeat", FamilyCount: 2, TemplateCount: 2, LanguageCount: 1, SampleRefs: []string{"1000", "1006"}}, {Kind: "extra_suffix", Fingerprint: strings.Repeat("d", 64), State: "insufficient_coverage", FamilyCount: 1, TemplateCount: 1, LanguageCount: 1, SampleRefs: []string{"1001"}}},
		Differences: []Difference{{Metric: "contract_deviation", State: "descriptive_available", Pairs: 6, EffectSize: ptr(.5), PValue: ptr(.25), AdjustedP: ptr(.5)}, {Metric: "neutral_refusal_like", State: "insufficient_pairs"}},
		Limitations: []string{"MI_BH_DEPENDENCE_ASSUMPTION", "MI_P_VALUE_NOT_RISK"},
	}
	return scope, in
}

func makeArtifacts(t *testing.T, scope Scope, in Input) *Artifacts {
	t.Helper()
	snapshot, err := NewDevelopmentSnapshot(scope, in)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Generate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestCanonicalArtifactsDeterministicAndBound(t *testing.T) {
	scope, in := fixture()
	a := makeArtifacts(t, scope, in)
	b := makeArtifacts(t, scope, in)
	if !bytes.Equal(a.JSON(), b.JSON()) || !bytes.Equal(a.HTML(), b.HTML()) || a.ContentHash() != b.ContentHash() {
		t.Fatal("same snapshot is not byte stable")
	}
	if a.JSONFileHash() != digest(a.JSON()) || a.HTMLFileHash() != digest(a.HTML()) || a.ContentHash() == a.JSONFileHash() || a.ContentHash() == a.HTMLFileHash() || a.SchemaVersion() != SchemaVersion {
		t.Fatal("content and file hashes must be independent")
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(a.JSON(), &document); err != nil {
		t.Fatal(err)
	}
	var hash string
	if err := json.Unmarshal(document["content_hash"], &hash); err != nil || hash != a.ContentHash() {
		t.Fatal("file must reference canonical content hash")
	}
	delete(document, "content_hash")
	content, err := canonical(document)
	if err != nil || digest(content) != a.ContentHash() {
		t.Fatal("hash must exclude the field, not include null or empty value")
	}
	for key, want := range map[string]string{"development": "true", "calibrated": "false", "review": "null", "review_state": `"not_reviewed"`, "observation_mode": `"blackbox"`, "content_state": `"redacted"`, "organization_id": `"9007199254741999"`} {
		if string(document[key]) != want {
			t.Fatalf("metadata %s not fixed: %s", key, document[key])
		}
	}
	for _, text := range []string{a.ContentHash(), Disclaimer, "未人工复核", "统计与分母", "四维算法风险", "配对差分", "平台比较", "5001", "9007199254743999", "未测", "null"} {
		if !bytes.Contains(a.HTML(), []byte(text)) {
			t.Fatalf("missing rendered section %q", text)
		}
	}
	if len(a.JSON()) > MaxOutputBytes || len(a.HTML()) > MaxOutputBytes || bytes.Contains(a.JSON(), []byte(`"Median"`)) {
		t.Fatal("bounds or JSON schema not honored")
	}
}

func TestCanonicalSetOrderingAndTimezones(t *testing.T) {
	scope, in := fixture()
	a := makeArtifacts(t, scope, in)
	slices.Reverse(in.Findings)
	slices.Reverse(in.Samples)
	slices.Reverse(in.Result.Limitations)
	slices.Reverse(in.Result.Token.Tiers)
	slices.Reverse(in.Result.Behavior.Patterns)
	slices.Reverse(in.Result.Behavior.Differences)
	slices.Reverse(in.Result.Behavior.Limitations)
	for i := range in.Findings {
		slices.Reverse(in.Findings[i].SampleRefs)
		slices.Reverse(in.Findings[i].Alternatives)
		slices.Reverse(in.Findings[i].Statistics)
	}
	for i := range in.Samples {
		slices.Reverse(in.Samples[i].Attempts)
	}
	slices.Reverse(in.Result.Token.Plateaus[0].SampleRefs)
	slices.Reverse(in.Result.Behavior.Patterns[1].SampleRefs)
	zone := time.FixedZone("synthetic", 8*60*60)
	scope.GeneratedAt = scope.GeneratedAt.In(zone)
	in.Run.CreatedAt = in.Run.CreatedAt.In(zone)
	in.Run.FinishedAt = in.Run.FinishedAt.In(zone)
	in.Run.StartedAt = ptr(in.Run.StartedAt.In(zone))
	for i := range in.Samples {
		for j := range in.Samples[i].Attempts {
			a := &in.Samples[i].Attempts[j]
			a.StartedAt = ptr(a.StartedAt.In(zone))
			a.FinishedAt = ptr(a.FinishedAt.In(zone))
		}
	}
	b := makeArtifacts(t, scope, in)
	if !bytes.Equal(a.JSON(), b.JSON()) || !bytes.Equal(a.HTML(), b.HTML()) {
		t.Fatal("set iteration order or equivalent timezone changed the snapshot")
	}
	// Ordinals, unlike a caller's slice order, are semantic execution order.
	in.Samples[0].Ordinal, in.Samples[1].Ordinal = in.Samples[1].Ordinal, in.Samples[0].Ordinal
	if makeArtifacts(t, scope, in).ContentHash() == a.ContentHash() {
		t.Fatal("semantic sample order was discarded")
	}
}

func TestSnapshotOwnsNestedInputsAndArtifactBytes(t *testing.T) {
	scope, in := fixture()
	snapshot, err := NewDevelopmentSnapshot(scope, in)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Generate(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	*in.Result.OverallRisk = 99
	in.Result.Token.Tiers[0].Median = 999
	in.Result.Token.Plateaus[0].SampleRefs[0] = "99999"
	in.Result.Behavior.Patterns[0].Fingerprint = strings.Repeat("0", 64)
	*in.Result.Behavior.Differences[0].PValue = 1
	*in.Samples[0].LocalCompletionTokens = 999
	in.Samples[0].Attempts[0].ID = "8888"
	in.Findings[0].Alternatives[0] = "untrusted"
	*in.Run.StartedAt = time.Time{}
	jb, hb := a.JSON(), a.HTML()
	jb[0], hb[0] = '!', '!'
	b, err := Generate(snapshot)
	if err != nil || !bytes.Equal(a.JSON(), b.JSON()) || !bytes.Equal(a.HTML(), b.HTML()) || a.ContentHash() != b.ContentHash() {
		t.Fatal("caller mutation changed immutable snapshot")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			v, err := Generate(snapshot)
			if err != nil || v.ContentHash() != a.ContentHash() {
				t.Error("concurrent regeneration changed output")
			}
		})
	}
	wg.Wait()
}

func TestInsufficientAndUnknownRemainNull(t *testing.T) {
	scope, in := fixture()
	in.Result.ValidSamples = 0
	in.Result.OverallRisk, in.Result.PromptRisk, in.Result.TokenRisk, in.Result.ResponseRisk, in.Result.EvidenceRisk = nil, nil, nil, nil, nil
	in.Result.Confidence, in.Result.EvidenceGrade, in.Result.Completeness, in.Result.RiskLevel = 0, "D", "insufficient", "insufficient"
	in.Result.Token = &TokenStatistics{}
	in.Result.Behavior = &BehaviorStatistics{}
	in.Findings = nil
	for i := range in.Samples {
		s := &in.Samples[i]
		s.Included, s.Validity, s.TokenizerQuality, s.TokenizerID = false, "INVALID_RETRYABLE", "unavailable", ""
		s.LocalCompletionTokens, s.ReportedCompletionTokens, s.FinalAttemptID, s.ResponseHash = nil, nil, nil, nil
		s.Attempts = nil
	}
	a := makeArtifacts(t, scope, in)
	for _, text := range []string{`"overall_risk":null`, `"usage_median_relative_error":null`, `"stream_median_relative_difference":null`, `"estimated_cost_micros":null`, `"findings":[]`, `"attempts":[]`, `"patterns":[]`} {
		if !bytes.Contains(a.JSON(), []byte(text)) {
			t.Fatalf("null/empty contract missing %s", text)
		}
	}
	if !bytes.Contains(a.HTML(), []byte("信息不足")) || !bytes.Contains(a.HTML(), []byte("没有已发布的发现项")) {
		t.Fatal("empty report must not claim healthy")
	}
	in.Result.Token, in.Result.Behavior = nil, nil
	b := makeArtifacts(t, scope, in)
	if !bytes.Contains(b.HTML(), []byte("Token 聚合统计未提供")) || !bytes.Contains(b.HTML(), []byte("行为聚合统计未提供")) {
		t.Fatal("missing aggregate must remain visible")
	}
}

func TestRejectInvalidScopeAndProjections(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Scope, *Input)
	}{
		{"org", func(s *Scope, _ *Input) { s.OrganizationID = "0" }},
		{"report", func(s *Scope, _ *Input) { s.ReportID = "01" }},
		{"run_id", func(s *Scope, _ *Input) { s.RunID = "43" }},
		{"revision", func(s *Scope, _ *Input) { s.AnalysisRevision = 2 }},
		{"future_version", func(s *Scope, _ *Input) { s.Versions.Rule = "trusted" }},
		{"zero_time", func(s *Scope, _ *Input) { s.GeneratedAt = time.Time{} }},
		{"abnormal_time", func(s *Scope, _ *Input) { s.GeneratedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{"before_run", func(s *Scope, _ *Input) { s.GeneratedAt = s.GeneratedAt.Add(-time.Hour) }},
		{"target_id", func(_ *Scope, in *Input) { in.Run.TargetID = "+1" }},
		{"package", func(_ *Scope, in *Input) { in.Run.Package = "injected" }},
		{"run_time", func(_ *Scope, in *Input) { in.Run.CreatedAt = in.Run.FinishedAt.Add(time.Hour) }},
		{"negative_cost", func(_ *Scope, in *Input) { in.Run.EstimatedCostMicros = ptr(int64(-1)) }},
		{"unsafe_integer", func(_ *Scope, in *Input) { in.Run.TokenCount = 9007199254740992 }},
		{"request_limit", func(_ *Scope, in *Input) { in.Run.RequestCount = 100001 }},
		{"result_run", func(_ *Scope, in *Input) { in.Result.RunID = "43" }},
		{"result_revision", func(_ *Scope, in *Input) { in.Result.AnalysisRevision = 2 }},
		{"result_version", func(_ *Scope, in *Input) { in.Result.Versions.Tokenizer = "x" }},
		{"sample_denominator", func(_ *Scope, in *Input) { in.Result.ExpectedSamples++ }},
		{"valid_denominator", func(_ *Scope, in *Input) { in.Result.ValidSamples++ }},
		{"grade_a", func(_ *Scope, in *Input) { in.Result.EvidenceGrade = "A" }},
		{"grade_b", func(_ *Scope, in *Input) { in.Result.EvidenceGrade = "B" }},
		{"confidence", func(_ *Scope, in *Input) { in.Result.Confidence = 75 }},
		{"partial_confidence", func(_ *Scope, in *Input) { in.Result.Completeness, in.Result.Confidence = "partial", 60 }},
		{"negative_score", func(_ *Scope, in *Input) { in.Result.TokenRisk = ptr(-1.0) }},
		{"nan", func(_ *Scope, in *Input) { in.Result.OverallRisk = ptr(math.NaN()) }},
		{"inf", func(_ *Scope, in *Input) { in.Result.OverallRisk = ptr(math.Inf(1)) }},
		{"false_healthy", func(_ *Scope, in *Input) { in.Result.RiskLevel = "low" }},
		{"nil_full_score", func(_ *Scope, in *Input) { in.Result.OverallRisk = nil }},
		{"insufficient_grade", func(_ *Scope, in *Input) { in.Result.Completeness = "insufficient" }},
		{"zero_valid", func(_ *Scope, in *Input) { in.Result.ValidSamples = 0 }},
		{"unknown_limitation", func(_ *Scope, in *Input) { in.Result.Limitations = []string{"MI_ARBITRARY_BODY"} }},
		{"duplicate_limitation", func(_ *Scope, in *Input) {
			in.Result.Limitations = []string{"MI_NO_VALID_SAMPLES", "MI_NO_VALID_SAMPLES"}
		}},
		{"sample_run", func(_ *Scope, in *Input) { in.Samples[0].RunID = "43" }},
		{"sample_id", func(_ *Scope, in *Input) { in.Samples[0].ID = in.Samples[1].ID }},
		{"ordinal", func(_ *Scope, in *Input) { in.Samples[0].Ordinal = 1 }},
		{"family", func(_ *Scope, in *Input) { in.Samples[0].Family = "untrusted" }},
		{"language", func(_ *Scope, in *Input) { in.Samples[0].Language = "script" }},
		{"tokenizer", func(_ *Scope, in *Input) { in.Samples[0].TokenizerID = "script" }},
		{"tokenizer_missing", func(_ *Scope, in *Input) { in.Samples[0].LocalCompletionTokens = nil }},
		{"tokenizer_unavailable", func(_ *Scope, in *Input) { in.Samples[0].TokenizerQuality = "unavailable" }},
		{"included_invalid", func(_ *Scope, in *Input) { in.Samples[0].Validity = "INVALID_PROTOCOL" }},
		{"aux_included", func(_ *Scope, in *Input) { in.Samples[0].AuxiliaryOnly = true }},
		{"self_report_included", func(_ *Scope, in *Input) { in.Samples[0].Family = "self_report" }},
		{"finish", func(_ *Scope, in *Input) { in.Samples[0].FinishReason = ptr("secret") }},
		{"contract", func(_ *Scope, in *Input) { in.Samples[0].Contract = ptr("secret") }},
		{"response_hash", func(_ *Scope, in *Input) { in.Samples[0].ResponseHash = ptr(strings.Repeat("g", 64)) }},
		{"no_final", func(_ *Scope, in *Input) { in.Samples[0].FinalAttemptID = ptr("7777") }},
		{"attempt_id", func(_ *Scope, in *Input) { in.Samples[0].Attempts[0].ID = "3001" }},
		{"attempt_no", func(_ *Scope, in *Input) { in.Samples[0].Attempts[0].AttemptNo = 1 }},
		{"attempt_limit", func(_ *Scope, in *Input) { in.Samples[0].Attempts = make([]Attempt, 4) }},
		{"attempt_error", func(_ *Scope, in *Input) { in.Samples[0].Attempts[0].ErrorCode = ptr("raw_upstream_error") }},
		{"http_status", func(_ *Scope, in *Input) { in.Samples[0].Attempts[0].HTTPStatus = ptr(999) }},
		{"attempt_time", func(_ *Scope, in *Input) {
			in.Samples[0].Attempts[0].FinishedAt = ptr(in.Run.CreatedAt.Add(-time.Hour))
		}},
		{"finding_id", func(_ *Scope, in *Input) { in.Findings[1].ID = in.Findings[0].ID }},
		{"finding_run", func(_ *Scope, in *Input) { in.Findings[0].RunID = "43" }},
		{"finding_revision", func(_ *Scope, in *Input) { in.Findings[0].AnalysisRevision = 2 }},
		{"finding_rule", func(_ *Scope, in *Input) { in.Findings[0].RuleID = "arbitrary" }},
		{"finding_score", func(_ *Scope, in *Input) { in.Findings[0].RiskScore = 100 }},
		{"finding_missing_ref", func(_ *Scope, in *Input) { in.Findings[0].SampleRefs = []string{"99999"} }},
		{"finding_duplicate_ref", func(_ *Scope, in *Input) { in.Findings[0].SampleRefs = []string{"1000", "1000"} }},
		{"statistic_name", func(_ *Scope, in *Input) { in.Findings[0].Statistics[0].Name = "secret" }},
		{"statistic_duplicate", func(_ *Scope, in *Input) { in.Findings[0].Statistics[1].Name = in.Findings[0].Statistics[0].Name }},
		{"statistic_unit", func(_ *Scope, in *Input) { in.Findings[0].Statistics[0].Unit = "probability" }},
		{"usage_denominator", func(_ *Scope, in *Input) { in.Result.Token.UsageSamples = 0 }},
		{"usage_missing", func(_ *Scope, in *Input) { in.Result.Token.UsageMedianError = nil }},
		{"stream_denominator", func(_ *Scope, in *Input) { in.Result.Token.StreamPairs = 7 }},
		{"tier_duplicate", func(_ *Scope, in *Input) {
			in.Result.Token.Tiers = append(in.Result.Token.Tiers, in.Result.Token.Tiers[0])
		}},
		{"plateau_duplicate", func(_ *Scope, in *Input) {
			in.Result.Token.Plateaus = append(in.Result.Token.Plateaus, in.Result.Token.Plateaus[0])
		}},
		{"plateau_ref", func(_ *Scope, in *Input) { in.Result.Token.Plateaus[0].SampleRefs = []string{"1006"} }},
		{"plateau_interval", func(_ *Scope, in *Input) { in.Result.Token.Plateaus[0].Lower = ptr(6.0) }},
		{"plateau_missing_interval", func(_ *Scope, in *Input) { in.Result.Token.Plateaus[0].Upper = nil }},
		{"behavior_denominator", func(_ *Scope, in *Input) { in.Result.Behavior.AuxiliarySamples = 2 }},
		{"pattern_duplicate", func(_ *Scope, in *Input) {
			in.Result.Behavior.Patterns = append(in.Result.Behavior.Patterns, in.Result.Behavior.Patterns[0])
		}},
		{"pattern_ref", func(_ *Scope, in *Input) { in.Result.Behavior.Patterns[0].SampleRefs = []string{"666"} }},
		{"difference_duplicate", func(_ *Scope, in *Input) {
			in.Result.Behavior.Differences[1].Metric = in.Result.Behavior.Differences[0].Metric
		}},
		{"difference_p", func(_ *Scope, in *Input) { in.Result.Behavior.Differences[0].PValue = ptr(1.01) }},
		{"difference_effect", func(_ *Scope, in *Input) { in.Result.Behavior.Differences[0].EffectSize = ptr(-1.01) }},
		{"oversized_samples", func(_ *Scope, in *Input) { in.Samples = make([]Sample, 2049) }},
		{"oversized_string", func(_ *Scope, in *Input) { in.Samples[0].Family = strings.Repeat("X", 4097) }},
		{"invalid_utf8", func(_ *Scope, in *Input) { in.Samples[0].Family = string([]byte{0xff}) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scope, in := fixture()
			tc.edit(&scope, &in)
			snapshot, err := NewDevelopmentSnapshot(scope, in)
			if snapshot != nil || !errors.Is(err, ErrInput) && !errors.Is(err, ErrLimit) {
				t.Fatalf("invalid snapshot not closed: %v", err)
			}
		})
	}
}

func TestNilAndZeroOpaqueArtifacts(t *testing.T) {
	for _, snapshot := range []*Snapshot{nil, {}} {
		if a, err := Generate(snapshot); a != nil || !errors.Is(err, ErrInput) {
			t.Fatal("unconstructed snapshot accepted")
		}
	}
	var a *Artifacts
	if a.JSON() != nil || a.HTML() != nil || a.ContentHash() != "" || a.JSONFileHash() != "" || a.HTMLFileHash() != "" || a.SchemaVersion() != "" {
		t.Fatal("nil artifact should not imply a generated report")
	}
	for _, kind := range []reflect.Type{reflect.TypeFor[Scope](), reflect.TypeFor[Input](), reflect.TypeFor[Result]()} {
		for _, name := range []string{"Calibrated", "Development", "Approved", "Review", "GatewayEvidence", "Body", "Endpoint", "HTML", "Path", "Secret"} {
			if _, exists := kind.FieldByName(name); exists {
				t.Fatalf("input unexpectedly exposes approval/restricted content field %s", name)
			}
		}
	}
}
