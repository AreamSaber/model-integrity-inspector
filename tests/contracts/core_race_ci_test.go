package contracts

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Core may move out of quality without losing any executable step, native
// driver, timeout or failure boundary. Compare the actual decoded whole job;
// comments cannot satisfy checks and hidden fields cannot change execution.
func validCoreRaceWorkflow(workflow string) bool {
	var parsed struct {
		Jobs map[string]map[string]any `yaml:"jobs"`
	}
	if yaml.Unmarshal([]byte(workflow), &parsed) != nil {
		return false
	}
	expected := map[string]any{
		"name": "core-race", "runs-on": "ubuntu-24.04", "timeout-minutes": 25,
		"services": map[string]any{"postgres": map[string]any{
			"image":   pgBackupCIImage,
			"env":     map[string]any{"POSTGRES_DB": "mii_ci", "POSTGRES_USER": "mii_test_owner", "POSTGRES_PASSWORD": pgBackupCIPassword},
			"ports":   []any{"127.0.0.1:15432:5432"},
			"options": `--health-cmd "pg_isready -U mii_test_owner -d mii_ci" --health-interval 5s --health-timeout 5s --health-retries 10`,
		}},
		"steps": []any{
			map[string]any{"name": "Checkout", "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"},
			map[string]any{"name": "Set up Go", "uses": "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e", "with": map[string]any{"go-version": "${{ env.GO_VERSION }}", "cache": false}},
			map[string]any{"name": "Download pinned Go dependencies", "run": "go mod download"},
			map[string]any{"name": "Verify required race coverage policy", "shell": "pwsh", "run": "./scripts/tests/test-m0-04-policy.ps1\n./scripts/tests/test-race-shards.ps1\n"},
			map[string]any{"name": "SQLite and PostgreSQL race regression", "shell": "pwsh", "run": "./scripts/test-race.ps1 -Group Core", "env": map[string]any{"MII_TEST_POSTGRES_DSN": "postgres://mii_test_owner:" + pgBackupCIPassword + "@127.0.0.1:15432/mii_ci?sslmode=disable"}},
		},
	}
	return reflect.DeepEqual(parsed.Jobs["core-race"], expected)
}

func TestCoreRaceIndependentWorkflowIsMandatory(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if !validCoreRaceWorkflow(workflow) || !validNetnsWorkflow(workflow) {
		t.Fatal("Core and offline replay must remain separate complete required jobs")
	}
	match := regexp.MustCompile(`(?ms)^  core-race:\n(.*?)(?:^  [a-zA-Z][a-zA-Z0-9_-]*:|\z)`).FindStringSubmatch(workflow)
	if len(match) != 2 {
		t.Fatal("missing Core mutation target")
	}
	body := match[1]
	for _, mutation := range []struct{ name, old, replacement string }{
		{"missing-job", "    name: core-race", "    name: unrelated"},
		{"skip-job", "    name: core-race", "    name: core-race\n    if: false"},
		{"serialized-build", "    name: core-race", "    name: core-race\n    needs: [quality]"},
		{"raise-limit", "timeout-minutes: 25", "timeout-minutes: 30"},
		{"nonfatal", "    name: core-race", "    name: core-race\n    continue-on-error: true"},
		{"implicit-filter", "    name: core-race", "    name: core-race\n    env:\n      GOFLAGS: -skip=Test"},
		{"wrong-os", "ubuntu-24.04", "windows-2025"},
		{"unpinned-service", pgBackupCIImage, "postgres:latest"},
		{"wrong-port", "127.0.0.1:15432:5432", "15432:5432"},
		{"no-download", "run: go mod download", "run: echo omitted"},
		{"no-policy", "./scripts/tests/test-race-shards.ps1", "echo omitted"},
		{"wrong-group", "-Group Core", "-Group Other"},
		{"wrong-driver", "MII_TEST_POSTGRES_DSN:", "MII_WRONG_POSTGRES_DSN:"},
		{"wrong-endpoint", "@127.0.0.1:15432/mii_ci", "@localhost:5432/mii_ci"},
		{"hidden-step", "    steps:\n", "    steps:\n      - run: echo unwanted\n"},
		{"skipped-step", "        run: ./scripts/test-race.ps1", "        if: false\n        run: ./scripts/test-race.ps1"},
		{"swallowed-exit", "-Group Core", "-Group Core; exit 0"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := strings.Replace(body, mutation.old, mutation.replacement, 1)
			if changed == body || validCoreRaceWorkflow(strings.Replace(workflow, body, changed, 1)) {
				t.Fatal("Core mutation did not fail the exact job guard")
			}
		})
	}
}
