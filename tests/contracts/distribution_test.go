package contracts

import (
	"os"
	"strings"
	"testing"
)

func TestImageBuildStageRetainsFrontendTraceabilityEvidence(t *testing.T) {
	docker, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	_, backend, ok := strings.Cut(string(docker), " AS backend\n")
	if !ok {
		// The repository's checked-out line endings may be CRLF.
		_, backend, ok = strings.Cut(strings.ReplaceAll(string(docker), "\r\n", "\n"), " AS backend\n")
	}
	if !ok {
		t.Fatal("missing backend build stage")
	}
	build, runtime, ok := strings.Cut(backend, "FROM scratch")
	if !ok {
		t.Fatal("missing isolated runtime stage")
	}
	source := strings.Index(build, "COPY web/ ./web/")
	tests := strings.Index(build, "RUN go test ./...")
	if source < 0 || tests < 0 || source > tests {
		t.Fatal("backend must retain frontend sources before running requirement traceability tests")
	}
	if strings.Contains(runtime, "/src/web") || strings.Contains(runtime, "COPY web/") {
		t.Fatal("frontend build/test sources must not be copied into the runtime image")
	}
}

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
