package repository_test

import (
	"bytes"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func snapshotReferenceActualCompile(t *testing.T, org int64, target repository.TargetState, source string) domain.ExecutionPlan {
	t.Helper()
	raw, hash, err := templates.Builtin().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := tokenizer.NewBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := secret.NewKeyRing("reference-historical-key", map[string][]byte{"reference-historical-key": bytes.Repeat([]byte{41}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := generator.New(raw, hash, engine, ring)
	if err != nil {
		t.Fatal(err)
	}
	options := generator.Options{OrganizationID: org, AnalysisSourceVersion: source, Target: domain.ExecutionTarget{ID: target.Target.ID, Version: target.Target.Version, SecretID: target.Secret.ID, SecretVersion: target.Secret.Version, Endpoint: target.Target.Endpoint, Model: target.Target.Model, Protocol: target.Target.Protocol, MaxOutputParameter: "max_tokens"}, Package: "quick", Budget: domain.ExecutionBudget{MaxRequests: 150, MaxTokens: 1000000, TimeoutSeconds: 600}, RuleVersion: "1.0.0-dev.1", ScoringVersion: "1.0.0-dev.1", ContextWindow: 128000, MaxOutputTokens: 4096, SupportsSeed: true, SupportsStream: true, Concurrency: 3, MaxRetries: 2}
	manifest, err := compiler.Generate(options)
	if err != nil {
		t.Fatal(err)
	}
	data, hash, err := manifest.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := compiler.ExecutionPlan(data, hash, org)
	if err != nil {
		t.Fatal("actual manifest verification", err)
	}
	return plan
}

func TestSnapshotArtifactReferencesPureActualCompiler(t *testing.T) {
	target := repository.TargetState{Target: repository.TargetRecord{ID: 31, Version: 1, Endpoint: "https://source.example/v1", Model: "fixture-model", Protocol: "openai_chat"}, Secret: repository.SecretMetadata{ID: 37, Version: 1}}
	for _, source := range []string{"", domain.AnalysisSourceDerivedV1} {
		plan := snapshotReferenceActualCompile(t, 17, target, source)
		repository.SnapshotArtifactReferencesPureCompilerBridge(t, plan, 17)
	}
}

func TestSnapshotArtifactReferencesActualGeneratedSources(t *testing.T) {
	repository.SnapshotArtifactReferencesActualSourcesBridge(t, func(org int64, target repository.TargetState) domain.ExecutionPlan {
		return snapshotReferenceActualCompile(t, org, target, domain.AnalysisSourceDerivedV1)
	})
}
