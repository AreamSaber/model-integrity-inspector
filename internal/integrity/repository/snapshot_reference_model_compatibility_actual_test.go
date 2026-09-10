package repository_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func TestSnapshotReferenceModelCompatibilityPureActualCompiler(t *testing.T) {
	for _, tc := range []struct {
		name, model  string
		bytes, runes int
	}{
		{"ascii_129", strings.Repeat("m", 129), 129, 129},
		{"unicode_129", strings.Repeat("模", 43), 129, 43},
		{"ascii_256", strings.Repeat("m", 256), 256, 256},
		{"unicode_256", strings.Repeat("é", 128), 256, 128},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.model) != tc.bytes || utf8.RuneCountInString(tc.model) != tc.runes {
				t.Fatal("model fixture byte/rune identity")
			}
			target := repository.TargetState{Target: repository.TargetRecord{ID: 31, Version: 1, Endpoint: "https://source.example/v1", Model: tc.model, Protocol: "openai_chat"}, Secret: repository.SecretMetadata{ID: 37, Version: 1}}
			for _, source := range []string{"", domain.AnalysisSourceDerivedV1} {
				plan := snapshotReferenceActualCompile(t, 17, target, source)
				repository.SnapshotReferenceModelCompatibilityPureBridge(t, plan, 17)
			}
		})
	}
}

func TestSnapshotReferenceModelCompatibilityActualGeneratedSources(t *testing.T) {
	for _, tc := range []struct{ name, model string }{
		{"unicode_129", strings.Repeat("模", 43)},
		{"unicode_256", strings.Repeat("é", 128)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repository.SnapshotReferenceModelCompatibilityDatabaseBridge(t, tc.model, func(org int64, target repository.TargetState) domain.ExecutionPlan {
				return snapshotReferenceActualCompile(t, org, target, domain.AnalysisSourceDerivedV1)
			})
		})
	}
}
