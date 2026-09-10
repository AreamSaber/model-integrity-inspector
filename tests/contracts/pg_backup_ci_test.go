package contracts

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const pgBackupCIImage = "postgres:18.6-bookworm@sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af"
const pgBackupCIPassword = "mii-ci-${{ github.run_id }}-${{ github.run_attempt }}" // #nosec G101 -- Public synthetic disposable CI fixture template, never a deployment credential.
const pgBackupCIRun = `test "$(go env GOVERSION)" = "go1.26.7"
test "$(go env GOOS)" = "linux"
test -z "$(go env GOFLAGS)"
test -x "$MII_TEST_PG_DUMP" && test -x "$MII_TEST_PG_RESTORE"
case "$("$MII_TEST_PG_DUMP" --version)" in
  'pg_dump (PostgreSQL) 18.6'|'pg_dump (PostgreSQL) 18.6 ('*) ;;
  *) echo "PG_BACKUP_DUMP_VERSION_MISMATCH" >&2; exit 1 ;;
esac
case "$("$MII_TEST_PG_RESTORE" --version)" in
  'pg_restore (PostgreSQL) 18.6'|'pg_restore (PostgreSQL) 18.6 ('*) ;;
  *) echo "PG_BACKUP_RESTORE_VERSION_MISMATCH" >&2; exit 1 ;;
esac
export MII_TEST_PG_BACKUP_DSN="postgres://mii_test_owner:${PGPASSWORD}@postgres:5432/mii_ci?sslmode=disable"
test "$(/usr/lib/postgresql/18/bin/psql -X -w -h postgres -p 5432 -U mii_test_owner -d mii_ci -Atc "SELECT current_setting('server_version_num')='180006' AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolcreatedb)" 2>/dev/null)" = "t"
go test -p 1 -tags pgbackup_integration ./internal/integrity/pgbackup ./internal/integrity/repository -run '^(TestPostgresDump|TestPGBackupTLS|TestNativeProcess)' -count=1 -timeout=10m
`

// Compare the entire decoded job, including unknown fields, so a pinned string
// in a comment or a second ignored step cannot masquerade as native evidence.
func validPGBackupWorkflow(workflow string) bool {
	var parsed struct {
		Jobs map[string]map[string]any `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(workflow), &parsed); err != nil {
		return false
	}
	expected := map[string]any{
		"name":            "pg-backup-native",
		"runs-on":         "ubuntu-24.04",
		"timeout-minutes": 25,
		"container": map[string]any{
			"image": pgBackupCIImage, "options": "--init",
		},
		"services": map[string]any{
			"postgres": map[string]any{
				"image": pgBackupCIImage,
				"env": map[string]any{
					"POSTGRES_DB": "mii_ci", "POSTGRES_USER": "mii_test_owner", "POSTGRES_PASSWORD": pgBackupCIPassword,
				},
				"options": `--health-cmd "pg_isready -U mii_test_owner -d mii_ci" --health-interval 5s --health-timeout 5s --health-retries 10`,
			},
		},
		"steps": []any{
			map[string]any{
				"name": "Install container CI dependencies", "shell": "bash",
				"run": "apt-get update\napt-get install --no-install-recommends -y ca-certificates curl git gzip tar\n",
			},
			map[string]any{
				"name": "Checkout", "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
			},
			map[string]any{
				"name": "Set up Go", "uses": "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
				"with": map[string]any{"go-version": "${{ env.GO_VERSION }}", "cache": false},
			},
			map[string]any{
				"name": "Native PostgreSQL backup and TLS regression", "shell": "bash", "run": pgBackupCIRun,
				"env": map[string]any{
					"MII_TEST_PG_DUMP": "/usr/lib/postgresql/18/bin/pg_dump", "MII_TEST_PG_RESTORE": "/usr/lib/postgresql/18/bin/pg_restore",
					"PGPASSWORD": pgBackupCIPassword, "PGCONNECT_TIMEOUT": 10,
				},
			},
		},
	}
	return reflect.DeepEqual(parsed.Jobs["pg-backup-native"], expected) && validNetnsWorkflow(workflow)
}

func TestPGBackupNativeWorkflowIsMandatory(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if !validPGBackupWorkflow(workflow) {
		t.Fatal("native PostgreSQL evidence must use the exact unconditional pinned job and required gate")
	}
	match := regexp.MustCompile(`(?ms)^  pg-backup-native:\n(.*?)(?:^  [a-zA-Z][a-zA-Z0-9_-]*:|\z)`).FindStringSubmatch(workflow)
	if len(match) != 2 {
		t.Fatal("missing native job mutation target")
	}
	body := match[1]
	for _, mutation := range []struct{ name, old, replacement string }{
		{"wrong-name", "    name: pg-backup-native\n", "    name: unrelated\n"},
		{"skip-job", "    name: pg-backup-native\n", "    name: pg-backup-native\n    if: false\n"},
		{"hidden-env", "    name: pg-backup-native\n", "    name: pg-backup-native\n    env:\n      GOFLAGS: -run=^Nothing$\n"},
		{"ignore-failure", "    name: pg-backup-native\n", "    name: pg-backup-native\n    continue-on-error: true\n"},
		{"non-linux", "ubuntu-24.04", "windows-2025"},
		{"longer-deadline", "timeout-minutes: 25", "timeout-minutes: 35"},
		{"unpinned-tool-image", pgBackupCIImage, "postgres:18.6-bookworm"},
		{"duplicate-container", "    container:\n", "    container: null\n    container:\n"},
		{"missing-init", "      options: --init\n", ""},
		{"privileged-container", "      options: --init", "      options: --init --privileged"},
		{"no-service", "    services:\n", "    disabled-services:\n"},
		{"host-port", "        options: >-\n", "        ports: [5432:5432]\n        options: >-\n"},
		{"health-decoy", "pg_isready -U mii_test_owner -d mii_ci", "true"},
		{"extra-step", "    steps:\n", "    steps:\n      - run: echo unwanted\n"},
		{"skip-step", "      - name: Native PostgreSQL backup and TLS regression\n", "      - name: Native PostgreSQL backup and TLS regression\n        if: false\n"},
		{"unpinned-go-action", "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e", "actions/setup-go@main"},
		{"relative-dump", "/usr/lib/postgresql/18/bin/pg_dump", "pg_dump"},
		{"relative-restore", "/usr/lib/postgresql/18/bin/pg_restore", "pg_restore"},
		{"wrong-tool-version", "'pg_dump (PostgreSQL) 18.6'", "'pg_dump (PostgreSQL) 18.7'"},
		{"bypass-server-version", "current_setting('server_version_num')='180006'", "true"},
		{"bypass-createdb", "AND rolcreatedb", ""},
		{"wrong-service-host", "@postgres:5432/", "@localhost:5432/"},
		{"disclose-dsn", "          go test -p 1", "          echo \"$MII_TEST_PG_BACKUP_DSN\"\n          go test -p 1"},
		{"wrong-suite-dsn", "export MII_TEST_PG_BACKUP_DSN=", "export MII_TEST_POSTGRES_DSN="},
		{"missing-goflags-guard", "          test -z \"$(go env GOFLAGS)\"\n", ""},
		{"wrong-tag", "-tags pgbackup_integration", "-tags missing_integration"},
		{"missing-dump-family", "TestPostgresDump|", ""},
		{"missing-tls-family", "TestPGBackupTLS|", ""},
		{"missing-native-family", "|TestNativeProcess", ""},
		{"missing-repository-package", " ./internal/integrity/repository", ""},
		{"missing-pgbackup-package", " ./internal/integrity/pgbackup", ""},
		{"parallel-packages", "go test -p 1", "go test -p 2"},
		{"cached-evidence", " -count=1", ""},
		{"longer-test-deadline", "-timeout=10m", "-timeout=20m"},
		{"swallowed-failure", "-timeout=10m", "-timeout=10m || true"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changedBody := strings.Replace(body, mutation.old, mutation.replacement, 1)
			if changedBody == body {
				t.Fatal("negative fixture did not mutate native job")
			}
			changed := strings.Replace(workflow, body, changedBody, 1)
			if validPGBackupWorkflow(changed) {
				t.Fatal("invalid native PostgreSQL workflow accepted")
			}
		})
	}
}

func validPGBackupIntegrationSource(raw []byte, prefix, buildTag string) bool {
	if !strings.HasPrefix(strings.ReplaceAll(string(raw), "\r\n", "\n"), "//go:build "+buildTag+"\n\n") {
		return false
	}
	file, err := parser.ParseFile(token.NewFileSet(), "integration_test.go", raw, 0)
	if err != nil {
		return false
	}
	found, skipped := false, false
	ast.Inspect(file, func(node ast.Node) bool {
		if fn, ok := node.(*ast.FuncDecl); ok && strings.HasPrefix(fn.Name.Name, prefix) && fn.Name.Name != "TestNativeProcessHelper" && fn.Recv == nil && fn.Type.Results == nil && fn.Type.Params.NumFields() == 1 {
			if star, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr); ok {
				if sel, ok := star.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "T" {
					if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "testing" {
						found = true
					}
				}
			}
		}
		if call, ok := node.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Skip" || sel.Sel.Name == "Skipf" || sel.Sel.Name == "SkipNow") {
				skipped = true
			}
		}
		return true
	})
	return found && !skipped
}

func TestPGBackupIntegrationFamiliesCannotBeOmittedOrSkipped(t *testing.T) {
	for _, family := range []struct{ path, prefix, buildTag string }{
		{"../../internal/integrity/repository/postgres_dump_integration_test.go", "TestPostgresDump", "pgbackup_integration"},
		{"../../internal/integrity/pgbackup/tls_integration_test.go", "TestPGBackupTLS", "pgbackup_integration"},
		{"../../internal/integrity/pgbackup/process_test.go", "TestNativeProcess", "windows || linux"},
	} {
		t.Run(family.prefix, func(t *testing.T) {
			raw, err := os.ReadFile(family.path)
			if err != nil {
				t.Fatal(err)
			}
			if !validPGBackupIntegrationSource(raw, family.prefix, family.buildTag) {
				t.Fatal("mandatory tagged native integration test family is absent, platform-restricted, or contains a skip")
			}
		})
	}
	valid := "//go:build pgbackup_integration\n\npackage integration\nimport \"testing\"\nfunc TestPostgresDumpProof(t *testing.T) {}\n"
	if !validPGBackupIntegrationSource([]byte(valid), "TestPostgresDump", "pgbackup_integration") {
		t.Fatal("valid source fixture rejected")
	}
	// The subprocess helper deliberately returns without work in the parent
	// process. Its presence alone must not satisfy the native evidence family.
	helperOnly := strings.ReplaceAll(strings.ReplaceAll(valid, "pgbackup_integration", "windows || linux"), "TestPostgresDumpProof", "TestNativeProcessHelper")
	if validPGBackupIntegrationSource([]byte(helperOnly), "TestNativeProcess", "windows || linux") {
		t.Fatal("subprocess helper alone cannot satisfy native regression coverage")
	}
	for name, changed := range map[string]string{
		"absent-tag":      strings.Replace(valid, "//go:build pgbackup_integration\n\n", "", 1),
		"wrong-tag":       strings.Replace(valid, "pgbackup_integration", "not_pgbackup_integration", 1),
		"platform-tag":    strings.Replace(valid, "pgbackup_integration", "windows && pgbackup_integration", 1),
		"wrong-prefix":    strings.Replace(valid, "TestPostgresDumpProof", "TestUnselectedProof", 1),
		"not-a-test":      strings.Replace(valid, "*testing.T", "*testing.B", 1),
		"method-not-test": strings.Replace(valid, "func Test", "type unused struct{}\nfunc (unused) Test", 1),
		"comment-decoy":   strings.Replace(valid, "func Test", "// func Test", 1),
		"skip":            strings.Replace(valid, "{}", "{ t.Skip(\"missing tool\") }", 1),
		"skipf":           strings.Replace(valid, "{}", "{ t.Skipf(\"missing %s\", \"tool\") }", 1),
		"skip-now":        strings.Replace(valid, "{}", "{ t.SkipNow() }", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if changed == valid || validPGBackupIntegrationSource([]byte(changed), "TestPostgresDump", "pgbackup_integration") {
				t.Fatal("invalid native integration source accepted or fixture failed to mutate")
			}
		})
	}
}
