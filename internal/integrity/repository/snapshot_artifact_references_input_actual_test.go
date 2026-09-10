package repository_test

import (
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func TestSnapshotArtifactReferencesInputActualCompiler(t *testing.T) {
	for _, test := range []struct{ model, implementation, encoding string }{
		{"gpt-4", tokenizer.ImplementationVersion, "cl100k_base"},
		{"gpt-4o", tokenizer.ImplementationVersion, "o200k_base"},
		{"合法未知模型", "unicode-byte-v1", "unicode-byte-heuristic"},
	} {
		t.Run(test.encoding, func(t *testing.T) {
			target := repository.TargetState{Target: repository.TargetRecord{ID: 31, Version: 1, Endpoint: "https://source.example/v1", Model: test.model, Protocol: "openai_chat"}, Secret: repository.SecretMetadata{ID: 37, Version: 1}}
			for _, source := range []string{"", domain.AnalysisSourceDerivedV1} {
				plan := snapshotReferenceActualCompile(t, 17, target, source)
				repository.SnapshotArtifactReferencesInputCompilerBridge(t, plan, 17, test.implementation, test.encoding)
			}
		})
	}
}

func TestSnapshotArtifactReferencesInputActualStoredSources(t *testing.T) {
	for _, test := range []struct{ standard, implementation, encoding string }{
		{"gpt-4", tokenizer.ImplementationVersion, "cl100k_base"},
		{"gpt-4o", tokenizer.ImplementationVersion, "o200k_base"},
		{"", "unicode-byte-v1", "unicode-byte-heuristic"},
	} {
		t.Run(test.encoding, func(t *testing.T) {
			repository.SnapshotArtifactReferencesInputSourcesBridge(t, func(org int64, target repository.TargetState) domain.ExecutionPlan {
				return snapshotReferenceActualCompileStandard(t, org, target, domain.AnalysisSourceDerivedV1, test.standard)
			}, test.implementation, test.encoding)
		})
	}
}
