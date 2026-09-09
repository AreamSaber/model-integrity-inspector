package contracts

import (
	"os"
	"strings"
	"testing"
)

const dockerCSVGeneratorCopy = "COPY scripts/read-contract-schemas.go ./scripts/read-contract-schemas.go"

// Checks the repository's explicit Docker recipe, not arbitrary Docker syntax.
// The generator is a real input to the AST contract test and must exist before
// that test executes. It must not be distributed in the final scratch image.
func dockerCSVGeneratorAvailableForTests(recipe string) bool {
	backend, afterBackend, tested := false, false, false
	copies := 0
	for line := range strings.SplitSeq(strings.ReplaceAll(recipe, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "FROM ") {
			if backend {
				afterBackend = true
			}
			backend = strings.HasSuffix(line, " AS backend")
		}
		if afterBackend && strings.Contains(line, "read-contract-schemas.go") {
			return false
		}
		if !backend {
			continue
		}
		if line == dockerCSVGeneratorCopy {
			if tested {
				return false
			}
			copies++
		}
		if line == dockerFullSuiteInstruction {
			if copies != 1 || tested {
				return false
			}
			tested = true
		}
	}
	return tested && copies == 1 && afterBackend
}

func TestDockerCSVGeneratorAvailableOnlyBeforeBackendTests(t *testing.T) {
	raw, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if !dockerCSVGeneratorAvailableForTests(string(raw)) {
		t.Fatal("CSV schema generator must be copied into the backend before the complete contract suite, never into runtime")
	}
	valid := "FROM fixture AS web\nFROM fixture AS backend\n" + dockerCSVGeneratorCopy + "\n" + dockerFullSuiteInstruction + "\nFROM scratch\n"
	for _, recipe := range []string{valid, strings.ReplaceAll(valid, "\n", "\r\n")} {
		if !dockerCSVGeneratorAvailableForTests(recipe) {
			t.Fatal("valid explicit build-stage fixture rejected")
		}
	}
	for _, changed := range []string{
		strings.Replace(valid, dockerCSVGeneratorCopy, "", 1),
		strings.Replace(valid, dockerCSVGeneratorCopy, "# "+dockerCSVGeneratorCopy, 1),
		strings.Replace(valid, dockerCSVGeneratorCopy, "COPY scripts/package.ps1 ./scripts/package.ps1", 1),
		strings.Replace(valid, dockerCSVGeneratorCopy+"\n"+dockerFullSuiteInstruction, dockerFullSuiteInstruction+"\n"+dockerCSVGeneratorCopy, 1),
		strings.Replace(valid, "FROM fixture AS backend\n"+dockerCSVGeneratorCopy, dockerCSVGeneratorCopy+"\nFROM fixture AS backend", 1),
		strings.Replace(valid, dockerCSVGeneratorCopy, dockerCSVGeneratorCopy+"\n"+dockerCSVGeneratorCopy, 1),
		valid + "COPY --from=backend /src/scripts/read-contract-schemas.go /read-contract-schemas.go\n",
		strings.Replace(valid, dockerFullSuiteInstruction, "", 1),
	} {
		if dockerCSVGeneratorAvailableForTests(changed) {
			t.Fatal("missing/late/wrong-stage/duplicated generator or omitted tests accepted")
		}
	}
}
