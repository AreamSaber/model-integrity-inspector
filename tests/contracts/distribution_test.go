package contracts

import (
	"os"
	"strings"
	"testing"
)

func TestTokenizerNoticePresentInDistributionRecipes(t *testing.T) {
	notice, err := os.ReadFile("../../internal/integrity/tokenizer/THIRD_PARTY_NOTICES.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"MIT License", "Permission is hereby granted", "tiktoken-go/tokenizer v0.8.1", "OpenAI tiktoken 0.14.0", "regexp2/v2 v2.5.1"} {
		if !strings.Contains(string(notice), required) {
			t.Fatalf("missing attribution: %s", required)
		}
	}
	docker, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(docker), "COPY --from=backend /src/internal/integrity/tokenizer/THIRD_PARTY_NOTICES.md /licenses/THIRD_PARTY_NOTICES.md") {
		t.Fatal("runtime image omits component notice")
	}
	pack, err := os.ReadFile("../../scripts/package.ps1")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"internal/integrity/tokenizer/THIRD_PARTY_NOTICES.md", "@($binaryPath, $webArchive, $noticePath)", "@($binaryPath, $webArchive, $noticePath, $manifestPath)"} {
		if !strings.Contains(string(pack), required) {
			t.Fatal("package notice not distributed or integrity-covered")
		}
	}
}
