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
	tests := strings.Index(build, dockerFullSuiteInstruction)
	if source < 0 || tests < 0 || source > tests {
		t.Fatal("backend must retain frontend sources before running requirement traceability tests")
	}
	if strings.Contains(runtime, "/src/web") || strings.Contains(runtime, "COPY web/") {
		t.Fatal("frontend build/test sources must not be copied into the runtime image")
	}
}

const dockerFullSuiteInstruction = "RUN go test -p 1 ./..."
const dockerAssetsSuiteInstruction = "RUN go test -tags webassets ./web ./internal/app"

// Docker's overlay fallback shares a small tmpfs across package binaries.
// Serialize binaries, not cases: keep the complete ./... scope and all existing
// intra-package concurrency, failure propagation, and separate webassets run.
func dockerCompleteScratchBoundedTests(recipe string) bool {
	full, assets := 0, 0
	for line := range strings.SplitSeq(strings.ReplaceAll(recipe, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "RUN go test") {
			continue
		}
		switch line {
		case dockerFullSuiteInstruction:
			full++
		case dockerAssetsSuiteInstruction:
			assets++
		default:
			return false
		}
	}
	return full == 1 && assets == 1
}

func TestDockerFullSuiteBoundsSharedScratchWithoutDroppingTests(t *testing.T) {
	docker, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if !dockerCompleteScratchBoundedTests(string(docker)) {
		t.Fatal("Docker must serialize complete package binaries and preserve the separate assets suite")
	}
	valid := dockerFullSuiteInstruction + "\n" + dockerAssetsSuiteInstruction + "\n"
	if !dockerCompleteScratchBoundedTests(valid) || !dockerCompleteScratchBoundedTests(strings.ReplaceAll(valid, "\n", "\r\n")) {
		t.Fatal("valid complete recipe rejected")
	}
	for _, replacement := range []string{
		"", "RUN go test ./...", "RUN go test -p 2 ./...", "RUN go test -p 1 -short ./...",
		"RUN go test -p 1 -run '^TestSubset' ./...", "RUN go test -p 1 ./internal/integrity/privatefile",
		dockerFullSuiteInstruction + " || true", dockerFullSuiteInstruction + "\n" + dockerFullSuiteInstruction,
	} {
		if dockerCompleteScratchBoundedTests(strings.Replace(valid, dockerFullSuiteInstruction, replacement, 1)) {
			t.Error("parallel/partial/skipped/suppressed full suite accepted")
		}
	}
	if dockerCompleteScratchBoundedTests(strings.Replace(valid, dockerAssetsSuiteInstruction, "", 1)) {
		t.Error("assets suite omission accepted")
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
