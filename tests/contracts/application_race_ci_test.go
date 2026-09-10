package contracts

import (
	"errors"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Return only fully decoded single-document workflows. Tests below distinguish
// malformed YAML from a valid YAML document whose targeted job is different.
func applicationRaceWorkflowJobs(workflow string) (map[string]map[string]any, bool) {
	var parsed struct {
		Jobs map[string]map[string]any `yaml:"jobs"`
	}
	decoder := yaml.NewDecoder(strings.NewReader(workflow))
	if decoder.Decode(&parsed) != nil {
		return nil, false
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return nil, false
	}
	return parsed.Jobs, true
}

func validApplicationRaceWorkflow(workflow string) bool {
	jobs, ok := applicationRaceWorkflowJobs(workflow)
	if !ok {
		return false
	}
	expected := map[string]any{
		"name": "application-race-${{ matrix.shard }}", "runs-on": "ubuntu-24.04", "timeout-minutes": 25,
		"strategy": map[string]any{"fail-fast": false, "matrix": map[string]any{"shard": []any{0, 1, 2, 3, 4, 5}}},
		"services": map[string]any{"postgres": map[string]any{
			"image":   pgBackupCIImage,
			"env":     map[string]any{"POSTGRES_DB": "mii_ci", "POSTGRES_USER": "mii_test_owner", "POSTGRES_PASSWORD": pgBackupCIPassword},
			"ports":   []any{"127.0.0.1:15432:5432"},
			"options": `--health-cmd "pg_isready -U mii_test_owner -d mii_ci" --health-interval 5s --health-timeout 5s --health-retries 10`,
		}},
		"steps": []any{
			map[string]any{"name": "Checkout", "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"},
			map[string]any{"name": "Set up Go", "uses": "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e", "with": map[string]any{"go-version": "${{ env.GO_VERSION }}", "cache": false}},
			map[string]any{"name": "Download pinned Go dependencies before strict enumeration", "run": "go mod download"},
			map[string]any{"name": "Verify race shard coverage and policy", "shell": "pwsh", "run": "./scripts/tests/test-m0-04-policy.ps1\n./scripts/tests/test-race-shards.ps1 -NativeGo\n"},
			map[string]any{"name": "SQLite and PostgreSQL Application race shard", "shell": "pwsh", "run": "./scripts/test-race.ps1 -Group Application -Shard ${{ matrix.shard }}", "env": map[string]any{"MII_TEST_POSTGRES_DSN": "postgres://mii_test_owner:" + pgBackupCIPassword + "@127.0.0.1:15432/mii_ci?sslmode=disable"}},
		},
	}
	return reflect.DeepEqual(jobs["application-race"], expected)
}

func validApplicationRaceGate(workflow string) bool {
	jobs, ok := applicationRaceWorkflowJobs(workflow)
	if !ok {
		return false
	}
	expected := map[string]any{
		"name": "m0-04-required", "if": "always()", "runs-on": "ubuntu-24.04",
		"needs": []any{"quality", "core-race", "repository-race", "worker-race", "application-race", "identity-postgres-race", "dependency-scan", "package", "image", "pg-backup-native"},
		"steps": []any{map[string]any{
			"name": "Enforce all CI results", "shell": "bash",
			"env": map[string]any{
				"QUALITY": "${{ needs.quality.result }}", "CORE_RACE": "${{ needs.core-race.result }}", "REPOSITORY_RACE": "${{ needs.repository-race.result }}", "WORKER_RACE": "${{ needs.worker-race.result }}", "APPLICATION_RACE": "${{ needs.application-race.result }}", "IDENTITY_POSTGRES_RACE": "${{ needs.identity-postgres-race.result }}", "DEPENDENCY_SCAN": "${{ needs.dependency-scan.result }}", "PACKAGE": "${{ needs.package.result }}", "IMAGE": "${{ needs.image.result }}", "PG_BACKUP_NATIVE": "${{ needs.pg-backup-native.result }}",
			},
			"run": "for result in \"$QUALITY\" \"$CORE_RACE\" \"$REPOSITORY_RACE\" \"$WORKER_RACE\" \"$APPLICATION_RACE\" \"$IDENTITY_POSTGRES_RACE\" \"$DEPENDENCY_SCAN\" \"$PACKAGE\" \"$IMAGE\" \"$PG_BACKUP_NATIVE\"; do\n  test \"$result\" = \"success\" || exit 1\ndone\n",
		}},
	}
	return reflect.DeepEqual(jobs["required"], expected)
}

func TestApplicationRaceIndependentWorkflowIsMandatory(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if !validApplicationRaceWorkflow(workflow) {
		t.Fatal("Application needs its exact unconditional six-shard dual-database race job")
	}
	if !validApplicationRaceGate(workflow) || !validCoreRaceWorkflow(workflow) || !validNetnsWorkflow(workflow) {
		t.Fatal("Application/Core/quality required coverage changed or omitted")
	}
	match := regexp.MustCompile(`(?ms)^  application-race:\n(.*?)(?:^  [a-zA-Z][a-zA-Z0-9_-]*:|\z)`).FindStringSubmatch(workflow)
	if len(match) != 2 {
		t.Fatal("missing Application mutation target")
	}
	body := match[1]
	baseline, ok := applicationRaceWorkflowJobs(workflow)
	if !ok {
		t.Fatal("baseline YAML")
	}
	for _, mutation := range []struct{ name, old, replacement string }{
		{"wrong-name", "    name: application-race-", "    name: unrelated-"},
		{"conditional-job", "    strategy:", "    if: false\n    strategy:"},
		{"serialized-job", "    strategy:", "    needs: [core-race]\n    strategy:"},
		{"nonfatal-job", "    strategy:", "    continue-on-error: true\n    strategy:"},
		{"hidden-flags", "    strategy:", "    env:\n      GOFLAGS: -skip=Test\n    strategy:"},
		{"fail-fast", "fail-fast: false", "fail-fast: true"},
		{"missing-shard", "shard: [0, 1, 2, 3, 4, 5]", "shard: [0, 1, 2, 3, 4]"},
		{"duplicate-shard", "shard: [0, 1, 2, 3, 4, 5]", "shard: [0, 1, 2, 3, 4, 4]"},
		{"excluded-shard", "        shard: [0, 1, 2, 3, 4, 5]", "        shard: [0, 1, 2, 3, 4, 5]\n        exclude: [{shard: 5}]"},
		{"extra-shard", "shard: [0, 1, 2, 3, 4, 5]", "shard: [0, 1, 2, 3, 4, 5, 6]"},
		{"non-linux", "ubuntu-24.04", "windows-2025"},
		{"longer-limit", "timeout-minutes: 25", "timeout-minutes: 35"},
		{"unpinned-service", pgBackupCIImage, "postgres:latest"},
		{"service-port-public", "127.0.0.1:15432:5432", "15432:5432"},
		{"no-service", "    services:", "    disabled-services:"},
		{"no-health-check", "pg_isready -U mii_test_owner -d mii_ci", "true"},
		{"unpinned-checkout", "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "actions/checkout@main"},
		{"unpinned-go", "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e", "actions/setup-go@main"},
		{"wrong-go-version", "${{ env.GO_VERSION }}", "1.25.x"},
		{"cached-go", "cache: false", "cache: true"},
		{"no-download", "run: go mod download", "run: echo omitted"},
		{"missing-policy", "./scripts/tests/test-m0-04-policy.ps1", "echo omitted"},
		{"no-native-enumeration", "test-race-shards.ps1 -NativeGo", "test-race-shards.ps1"},
		{"wrong-suite", "-Group Application", "-Group Worker"},
		{"wrong-shard", "-Shard ${{ matrix.shard }}", "-Shard 0"},
		{"wrong-driver", "MII_TEST_POSTGRES_DSN:", "MII_WRONG_POSTGRES_DSN:"},
		{"wrong-endpoint", "@127.0.0.1:15432/mii_ci", "@localhost:5432/mii_ci"},
		{"skipped-execution", "      - name: SQLite and PostgreSQL Application race shard", "      - name: SQLite and PostgreSQL Application race shard\n        if: false"},
		{"ignored-execution", "      - name: SQLite and PostgreSQL Application race shard", "      - name: SQLite and PostgreSQL Application race shard\n        continue-on-error: true"},
		{"swallowed-exit", "-Shard ${{ matrix.shard }}", "-Shard ${{ matrix.shard }}; exit 0"},
		{"hidden-step", "    steps:", "    steps:\n      - run: echo unwanted"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changedBody := strings.Replace(body, mutation.old, mutation.replacement, 1)
			if changedBody == body {
				t.Fatal("fixture did not mutate Application job")
			}
			changed := strings.Replace(workflow, body, changedBody, 1)
			jobs, ok := applicationRaceWorkflowJobs(changed)
			if !ok {
				t.Fatal("mutation failed YAML parsing, not target contract")
			}
			if reflect.DeepEqual(jobs["application-race"], baseline["application-race"]) {
				t.Fatal("mutation did not change decoded Application job")
			}
			for name, job := range baseline {
				if name != "application-race" && !reflect.DeepEqual(jobs[name], job) {
					t.Fatal("mutation changed unrelated job", name)
				}
			}
			if !validCoreRaceWorkflow(changed) || !validApplicationRaceGate(changed) {
				t.Fatal("mutation failed because unrelated Core/gate changed")
			}
			if validApplicationRaceWorkflow(changed) {
				t.Fatal("target Application contract accepted mutation")
			}
		})
	}
}

func TestApplicationRaceRequiredGateMutationReasons(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if !validApplicationRaceWorkflow(workflow) || !validApplicationRaceGate(workflow) {
		t.Fatal("gate mutation baseline is not valid")
	}
	match := regexp.MustCompile(`(?ms)^  required:\n(.*?)(?:^  [a-zA-Z][a-zA-Z0-9_-]*:|\z)`).FindStringSubmatch(workflow)
	if len(match) != 2 {
		t.Fatal("missing required target")
	}
	body := match[1]
	for _, mutation := range []struct{ name, old, replacement string }{
		{"missing-dependency", "worker-race, application-race, identity-postgres-race", "worker-race, identity-postgres-race"},
		{"wrong-dependency-order", "worker-race, application-race", "application-race, worker-race"},
		{"false-success", "APPLICATION_RACE: ${{ needs.application-race.result }}", "APPLICATION_RACE: success"},
		{"wrong-result", "APPLICATION_RACE: ${{ needs.application-race.result }}", "APPLICATION_RACE: ${{ needs.worker-race.result }}"},
		{"unchecked-result", "\"$WORKER_RACE\" \"$APPLICATION_RACE\"", "\"$WORKER_RACE\""},
		{"gate-conditional", "if: always()", "if: success()"},
		{"gate-nonfatal", "    runs-on:", "    continue-on-error: true\n    runs-on:"},
		{"gate-swallowed-exit", "|| exit 1", "|| exit 0"},
		{"gate-step-skipped", "        shell: bash", "        if: false\n        shell: bash"},
		{"gate-hidden-step", "    steps:", "    steps:\n      - run: echo omitted"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changedBody := strings.Replace(body, mutation.old, mutation.replacement, 1)
			if changedBody == body {
				t.Fatal("fixture did not change gate")
			}
			changed := strings.Replace(workflow, body, changedBody, 1)
			if _, ok := applicationRaceWorkflowJobs(changed); !ok {
				t.Fatal("gate mutation failed YAML, not target contract")
			}
			if !validApplicationRaceWorkflow(changed) || !validCoreRaceWorkflow(changed) {
				t.Fatal("gate mutation changed executable job")
			}
			if validApplicationRaceGate(changed) {
				t.Fatal("target required gate accepted mutation")
			}
		})
	}
}

func TestApplicationRaceMalformedWorkflowDoesNotMasqueradeAsJobMismatch(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if !validApplicationRaceWorkflow(workflow) || !validApplicationRaceGate(workflow) {
		t.Fatal("malformed-document baseline")
	}
	for name, changed := range map[string]string{
		"duplicate-job":      strings.Replace(workflow, "  application-race:\n", "  application-race: {}\n  application-race:\n", 1),
		"duplicate-strategy": strings.Replace(workflow, "    name: application-race-${{ matrix.shard }}\n", "    name: application-race-${{ matrix.shard }}\n    strategy: {}\n", 1),
		"second-document":    workflow + "\n---\njobs: {}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if changed == workflow {
				t.Fatal("malformed mutation did not change input")
			}
			if _, ok := applicationRaceWorkflowJobs(changed); ok {
				t.Fatal("malformed YAML accepted as a complete single document")
			}
			if validApplicationRaceWorkflow(changed) || validApplicationRaceGate(changed) {
				t.Fatal("malformed document accepted")
			}
		})
	}
}
