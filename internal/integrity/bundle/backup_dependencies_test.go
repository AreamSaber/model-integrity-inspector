package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func backupDependencyTestSource(category, version string, org, id int64, data []byte) BackupDependencySource {
	return BackupDependencySource{Category: category, OrganizationID: org, RowID: id, Version: version, SHA256: digest(data), Bytes: int64(len(data))}
}
func backupDependencyTestObserve(t *testing.T, source BackupDependencySource, data []byte) *BackupDependencies {
	t.Helper()
	before := bytes.Clone(data)
	got, err := ObserveBackupDependencies(t.Context(), source, BackupDependencyLimits{MaxBytes: source.Bytes, Timeout: time.Second}, func(_ context.Context, consume func(io.Reader) error) error { return consume(bytes.NewReader(data)) })
	if err != nil || got == nil || got.Source() != source || !bytes.Equal(before, data) {
		t.Fatal("original source observation", err)
	}
	return got
}
func backupDependencyTestMarshal(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal("finite source fixture")
	}
	return raw
}

func TestBackupDependenciesActualProducersAndCarriers(t *testing.T) {
	installed, err := Builtin()
	if err != nil {
		t.Fatal("actual installed source", err)
	}
	raw := installed.RuleBytes()
	rule := backupDependencyTestObserve(t, backupDependencyTestSource("rule", BuiltinVersion, 11, 21, raw), raw)
	if rule.Classification() != BackupDependenciesExplained || rule.Codec() != backupRuntimeSchema || len(rule.Dependencies()) != 8 {
		t.Fatal("actual runtime manifest dependencies incomplete")
	}
	templateRaw := installed.TemplateBytes()
	template := backupDependencyTestObserve(t, backupDependencyTestSource("template", templates.BuiltinVersion, 11, 22, templateRaw), templateRaw)
	binding, err := MatchBackupTemplateDependency(t.Context(), rule, template)
	if err != nil || binding.ResourceSource != template.Source() || binding.CarrierSHA256 != templates.BuiltinHash || len(template.Members()) != 20 {
		t.Fatal("actual template content/member linkage", err)
	}
	original, err := templates.Decode(templateRaw, templates.BuiltinHash)
	if err != nil {
		t.Fatal(err)
	}
	member := template.Members()[0]
	if got, err := MatchBackupTemplateMember(t.Context(), template, member); err != nil || got != member {
		t.Fatal("actual template member match", err)
	}
	actual, found := original.Find(member.ID)
	if !found || actual.Version != member.Version {
		t.Fatal("member differs from original compiler")
	}
	if rendered, err := templates.Render(actual, map[string]string{"NONCE": "fixture", "COUNT": "10", "LABEL": "marker", "STYLE": "neutral"}); err != nil || rendered == "" {
		t.Fatal("original template compiler", err)
	}
	tokens, err := tokenizer.NewBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := tokens.InstalledArtifact(t.Context())
	if err != nil {
		t.Fatal("actual tokenizer carrier", err)
	}
	matched, err := MatchBackupTokenizerDependency(t.Context(), rule, carrier)
	if err != nil || matched.Dependency.SHA256 != tokens.Hash() || matched.CarrierSHA256 != carrier.Ref().SHA256 || matched.CarrierSHA256 == matched.Dependency.SHA256 || matched.Dependency.HashRole != BackupDependencyTokenizerConfiguration {
		t.Fatal("configuration/carrier hash roles collapsed", err)
	}
	scoringCarrier, err := installed.InstalledScoringArtifact(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	scoreMatches, err := MatchBackupInstalledScoringReference(t.Context(), rule, scoringCarrier)
	if err != nil || len(scoreMatches) != 2 || scoreMatches[0].Dependency.SHA256 != scoring.RulesHash() || scoreMatches[1].Dependency.SHA256 != tokenrisk.RulesHash() || scoreMatches[0].CarrierSHA256 == scoreMatches[0].Dependency.SHA256 || scoreMatches[0].CarrierSHA256 == rule.Source().SHA256 {
		t.Fatal("original scoring/hash roles collapsed", err)
	}
	// Real candidate producer + finite compiler, not a synthetic current rule.
	candidate, err := DevelopmentArtifact("1.0.0-dev.2")
	if err != nil {
		t.Fatal(err)
	}
	candidate.Manifest.TokenRisk.RobustCV = .04
	tokenEngine, err := tokenrisk.NewDevelopment(candidate.Manifest.TokenRisk)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Manifest.Scoring.TokenRulesHash = tokenEngine.Hash()
	candidate.Manifest.Scoring.NoBaselineFactor = .5
	raw, hash, err := candidate.Canonical()
	if err != nil {
		t.Fatal("actual candidate compiler", err)
	}
	decoded, err := DecodeRuleArtifact(raw, hash)
	if err != nil {
		t.Fatal(err)
	}
	_, scoreEngine, err := decoded.kernels()
	if err != nil {
		t.Fatal(err)
	}
	observed := backupDependencyTestObserve(t, backupDependencyTestSource("rule", candidate.Manifest.Version, 11, 23, raw), raw)
	if observed.Classification() != BackupDependenciesExplained || len(observed.Dependencies()) != 9 {
		t.Fatal("candidate original finite dependencies missing")
	}
	for _, d := range observed.Dependencies() {
		if d.HashRole == BackupDependencyScoringParameters && (d.SHA256 != scoreEngine.Hash() || d.Basis != BackupDependencyDerived) {
			t.Fatal("scoring semantic codec differs from actual compiler")
		}
		if d.HashRole == BackupDependencyTokenRiskParameters && d.SHA256 != tokenEngine.Hash() {
			t.Fatal("token semantic codec differs from actual compiler")
		}
	}
	if got, err := MatchBackupInstalledScoringReference(t.Context(), observed, scoringCarrier); err == nil || got != nil {
		t.Fatal("installed reference replaced independent tenant candidate")
	}
}

func TestBackupDependenciesHistoricalTenantsAndVersionsNeverFlatten(t *testing.T) {
	installed, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var original Manifest
	if err := json.Unmarshal(installed.RuleBytes(), &original); err != nil {
		t.Fatal(err)
	}
	var rules, containers []*BackupDependencies
	for index, org := range []int64{41, 42, 41} {
		// Real template codec accepts same named versions with different bytes.
		// Repository-shaped historical rule data below is NOT runtime admission:
		// current candidate compiler deliberately freezes these template refs.
		b := templates.Builtin()
		b.Templates[0].Prompt += " original tenant variant " + fmt.Sprint(index)
		raw, hash, err := b.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		registry := templates.NewRegistry()
		if registered, err := registry.Add(b); err != nil || registered != hash {
			t.Fatal("tenant-local actual template registry", err)
		}
		containers = append(containers, backupDependencyTestObserve(t, backupDependencyTestSource("template", b.Version, org, int64(60+index), raw), raw))
		m := original
		m.Status = "retired" // Never used by Run; still observe this root's edges.
		m.Template = ArtifactRef{b.Version, hash}
		m.Scoring.NoBaselineFactor = .2 + float64(index)*.1
		raw = backupDependencyTestMarshal(t, m)
		rules = append(rules, backupDependencyTestObserve(t, backupDependencyTestSource("rule", m.Version, org, int64(70+index), raw), raw))
	}
	for i, rule := range rules {
		if rule.Classification() != BackupDependenciesExplained || rule.Source().Version != BuiltinVersion {
			t.Fatal("original history renamed or ignored")
		}
		for j, container := range containers {
			got, err := MatchBackupTemplateDependency(t.Context(), rule, container)
			if i == j {
				if err != nil || got.ResourceSource != container.Source() {
					t.Fatal("same original tenant/hash not mapped", err)
				}
			} else if err == nil || got != (BackupDependencyBinding{}) {
				t.Fatal("same version was flattened across organization or original hash")
			}
		}
	}
	if rules[0].Source().SHA256 == rules[2].Source().SHA256 {
		t.Fatal("fixture did not retain different original same-org/version content observations")
	}
	// Source observation is not the SQL uniqueness validator. Multiple historical
	// observations are retained independently; a snapshot collector enforces its
	// actual row uniqueness without a process-global version-keyed Resolver.
}

func TestBackupDependenciesKnownConflictAndUnknownPreservation(t *testing.T) {
	installed, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var original Manifest
	if json.Unmarshal(installed.RuleBytes(), &original) != nil {
		t.Fatal("manifest fixture")
	}
	for _, mode := range []string{"row_version", "token_hash", "token_version", "behavior_version", "template_hash", "empty_implementation"} {
		t.Run(mode, func(t *testing.T) {
			m := original
			version := m.Version
			switch mode {
			case "row_version":
				version = "0.1.0"
			case "token_hash":
				m.Scoring.TokenRulesHash = strings.Repeat("a", 64)
			case "token_version":
				m.Scoring.TokenVersion = "0.8.0"
			case "behavior_version":
				m.Scoring.BehaviorVersion = "unknown-implementation"
			case "template_hash":
				m.Template.SHA256 = "wrong-role-or-malformed"
			}
			raw := backupDependencyTestMarshal(t, m)
			if mode == "empty_implementation" {
				raw = backupDependencyTestMarshal(t, RuleArtifact{RuleArtifactSchema, "", m})
			}
			source := backupDependencyTestSource("rule", version, 1, 2, raw)
			got, err := ObserveBackupDependencies(t.Context(), source, BackupDependencyLimits{source.Bytes, time.Second}, func(_ context.Context, consume func(io.Reader) error) error { return consume(bytes.NewReader(raw)) })
			if !errors.Is(err, ErrBackupDependencies) || got != nil {
				t.Fatal("complete known-codec conflict downgraded to opaque", err)
			}
		})
	}
	for _, raw := range [][]byte{[]byte(`{"schema_version":"unknown.v9","version":"different","tokenizer":{"version":"x","sha256":"not-a-hash"}}`), []byte("old opaque non-JSON"), nil, []byte(`{"schema_version":"mii.runtime-bundle.v1","version":"only-a-partial-legacy-shape"}`)} {
		got := backupDependencyTestObserve(t, backupDependencyTestSource("rule", "original-row-version", 1, 2, raw), raw)
		if got.Classification() != BackupDependenciesOpaque || len(got.Dependencies()) != 0 || len(got.Members()) != 0 {
			t.Fatal("unknown body recursively guessed as a dependency")
		}
	}
	// An original unavailable version or implementation remains a declaration,
	// not an invitation to defaultManifest or to today's builtin resolver.
	old := original
	old.Tokenizer = ArtifactRef{"0.9.0", strings.Repeat("b", 64)}
	old.Status = "retired"
	old.Version = "old-unused-rule"
	raw := backupDependencyTestMarshal(t, RuleArtifact{RuleArtifactSchema, "mii.historical.analyzer.v0", old})
	got := backupDependencyTestObserve(t, backupDependencyTestSource("rule", old.Version, 9, 10, raw), raw)
	if got.Classification() != BackupDependenciesExplained {
		t.Fatal("known original fields discarded because code is not installed")
	}
	if binding, err := MatchBackupTokenizerDependency(t.Context(), got, nil); err == nil || binding != (BackupDependencyBinding{}) {
		t.Fatal("missing historical tokenizer was satisfied by a string")
	}
}

func TestBackupDependenciesOwnedMetadataAndClosedSerialization(t *testing.T) {
	installed, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	raw := installed.RuleBytes()
	got := backupDependencyTestObserve(t, backupDependencyTestSource("rule", BuiltinVersion, 1, 2, raw), raw)
	before := got.Dependencies()
	mutable := got.Dependencies()
	mutable[0].SHA256 = "changed"
	clear(raw)
	if got.Dependencies()[0] != before[0] {
		t.Fatal("observation aliases caller metadata/body")
	}
	source := BackupDependencySource{Version: "private canary"}
	dependency := BackupDependency{Version: "private canary"}
	member := BackupTemplateMember{ID: "private canary"}
	binding := BackupDependencyBinding{CarrierSHA256: "private canary"}
	for _, v := range []any{source, &source, dependency, &dependency, member, &member, binding, &binding, *got, got} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, v), "canary") || strings.Contains(fmt.Sprintf(format, v), BuiltinHash) {
				t.Fatal("private dependency formatting leaked")
			}
		}
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("implicit dependency JSON enabled")
		}
		if _, err := yaml.Marshal(v); err == nil {
			t.Fatal("implicit dependency YAML enabled")
		}
	}
}

func TestBackupDependenciesUnsupportedRepresentationsRemainExplicitlyOpaque(t *testing.T) {
	installed, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	raw := installed.RuleBytes()
	var m Manifest
	if json.Unmarshal(raw, &m) != nil {
		t.Fatal("source fixture")
	}
	nested := m
	nested.SchemaVersion = "unknown.runtime.v7"
	for _, data := range [][]byte{
		append(bytes.Clone(raw), '\n'),
		bytes.Replace(raw, []byte(`"version":`), []byte(`"version":"discarded-ambiguous","version":`), 1),
		bytes.Replace(raw, []byte(`"generator_version":`), []byte(`"GENERATOR_VERSION":`), 1),
		backupDependencyTestMarshal(t, RuleArtifact{RuleArtifactSchema, "old.analyzer", nested}),
	} {
		observed := backupDependencyTestObserve(t, backupDependencyTestSource("rule", m.Version, 1, 2, data), data)
		if observed.Classification() != BackupDependenciesOpaque || len(observed.Dependencies()) != 0 {
			t.Fatal("unknown/ambiguous representation promoted to known codec")
		}
	}
	template := installed.TemplateBytes()
	source := backupDependencyTestSource("template", "different-original-row-version", 1, 2, template)
	got, err := ObserveBackupDependencies(t.Context(), source, BackupDependencyLimits{source.Bytes, time.Second}, func(_ context.Context, consume func(io.Reader) error) error {
		return consume(bytes.NewReader(template))
	})
	if !errors.Is(err, ErrBackupDependencies) || got != nil {
		t.Fatal("known template container/row conflict downgraded to opaque", err)
	}
}
