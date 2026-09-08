package contracts

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"
)

const netnsWorkflowStep = "      - name: Offline replay OS network isolation\n        timeout-minutes: 5\n        shell: pwsh\n        run: ./scripts/test-replay-netns.ps1\n"
const netnsRequiredJobs = "needs: [quality, repository-race, worker-race, identity-postgres-race, dependency-scan, package, image]"

func validNetnsWorkflow(workflow string) bool {
	workflow = strings.ReplaceAll(workflow, "\r\n", "\n")
	if len(regexp.MustCompile(`(?m)^  quality:$`).FindAllString(workflow, -1)) != 1 {
		return false
	}
	job := regexp.MustCompile(`(?ms)^  quality:\n(.*?)(?:^  [a-zA-Z][a-zA-Z0-9_-]*:|\z)`).FindAllStringSubmatch(workflow, -1)
	if len(job) != 1 {
		return false
	}
	quality := job[0][1]
	_, tail, found := strings.Cut(quality, "      - name: Offline replay OS network isolation\n")
	if !found || strings.Count(quality, "      - name: Offline replay OS network isolation\n") != 1 {
		return false
	}
	body, _, _ := strings.Cut(tail, "      - name:")
	if "      - name: Offline replay OS network isolation\n"+body != netnsWorkflowStep {
		return false
	}
	if regexp.MustCompile(`(?m)^    if:|^\s*continue-on-error:`).MatchString(quality) {
		return false
	}
	if !strings.Contains(quality, "    runs-on: ubuntu-24.04\n") || !strings.Contains(quality, "        run: ./scripts/build.ps1\n") || strings.Count(quality, "        run: ./scripts/test-race.ps1 -Group Core\n") != 1 {
		return false
	}
	if strings.Index(quality, netnsWorkflowStep) < strings.Index(quality, "        run: ./scripts/build.ps1\n") {
		return false
	}
	gate := regexp.MustCompile(`(?ms)^  required:\n(.*?)(?:^  [a-zA-Z][a-zA-Z0-9_-]*:|\z)`).FindAllStringSubmatch(workflow, -1)
	if len(gate) != 1 || strings.Count(workflow, "        run: ./scripts/test-replay-netns.ps1\n") != 1 {
		return false
	}
	for _, required := range []string{
		"    name: m0-04-required\n", "    if: always()\n", "    " + netnsRequiredJobs + "\n",
		"          QUALITY: ${{ needs.quality.result }}\n", "          REPOSITORY_RACE: ${{ needs.repository-race.result }}\n",
		"          WORKER_RACE: ${{ needs.worker-race.result }}\n", "          IDENTITY_POSTGRES_RACE: ${{ needs.identity-postgres-race.result }}\n",
		"          DEPENDENCY_SCAN: ${{ needs.dependency-scan.result }}\n", "          PACKAGE: ${{ needs.package.result }}\n", "          IMAGE: ${{ needs.image.result }}\n",
		"          for result in \"$QUALITY\" \"$REPOSITORY_RACE\" \"$WORKER_RACE\" \"$IDENTITY_POSTGRES_RACE\" \"$DEPENDENCY_SCAN\" \"$PACKAGE\" \"$IMAGE\"; do\n            test \"$result\" = \"success\" || exit 1\n          done\n",
	} {
		if strings.Count(gate[0][1], required) != 1 {
			return false
		}
	}
	return true
}

func TestReplayNamespaceWorkflowIsMandatory(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if !validNetnsWorkflow(workflow) {
		t.Fatal("network namespace verification must be an unconditional quality step")
	}
	for name, changed := range map[string]string{
		"removed":                  strings.Replace(workflow, netnsWorkflowStep, "", 1),
		"skipped":                  strings.Replace(workflow, "        timeout-minutes: 5\n", "        if: false\n        timeout-minutes: 5\n", 1),
		"ignored-failure":          strings.Replace(workflow, "        timeout-minutes: 5\n", "        continue-on-error: true\n        timeout-minutes: 5\n", 1),
		"policy-only":              strings.Replace(workflow, "run: ./scripts/test-replay-netns.ps1\n", "run: ./scripts/test-replay-netns.ps1 -PolicyOnly\n", 1),
		"wrong-job":                strings.Replace(workflow, "  quality:\n", "  disconnected-quality:\n", 1),
		"non-linux":                strings.Replace(workflow, "    runs-on: ubuntu-24.04\n", "    runs-on: windows-2025\n", 1),
		"gate-omits-quality":       strings.Replace(workflow, netnsRequiredJobs, "needs: [repository-race, worker-race, identity-postgres-race, dependency-scan, package, image]", 1),
		"gate-omits-worker":        strings.Replace(workflow, netnsRequiredJobs, "needs: [quality, repository-race, identity-postgres-race, dependency-scan, package, image]", 1),
		"gate-omits-identity":      strings.Replace(workflow, netnsRequiredJobs, "needs: [quality, repository-race, worker-race, dependency-scan, package, image]", 1),
		"old-sequential-group":     strings.Replace(workflow, "run: ./scripts/test-race.ps1 -Group Core", "run: ./scripts/test-race.ps1 -Group Other", 1),
		"worker-literal-success":   strings.Replace(workflow, "WORKER_RACE: ${{ needs.worker-race.result }}", "WORKER_RACE: success", 1),
		"identity-literal-success": strings.Replace(workflow, "IDENTITY_POSTGRES_RACE: ${{ needs.identity-postgres-race.result }}", "IDENTITY_POSTGRES_RACE: success", 1),
		"ignore-worker-result":     strings.Replace(workflow, "\"$REPOSITORY_RACE\" \"$WORKER_RACE\"", "\"$REPOSITORY_RACE\"", 1),
		"ignore-identity-result":   strings.Replace(workflow, "\"$WORKER_RACE\" \"$IDENTITY_POSTGRES_RACE\"", "\"$WORKER_RACE\"", 1),
		"ignore-gate-failure":      strings.Replace(workflow, "test \"$result\" = \"success\" || exit 1", "test \"$result\" = \"success\" || exit 0", 1),
		"duplicate-quality":        strings.Replace(workflow, "  quality:\n", "  quality:\n  quality:\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if changed == workflow {
				t.Fatal("negative fixture did not mutate current workflow")
			}
			if validNetnsWorkflow(changed) {
				t.Fatal("invalid namespace workflow accepted")
			}
		})
	}
}

func TestReplayNamespaceRunnerAndPolicyRemainFailClosed(t *testing.T) {
	script, err := os.ReadFile("../../scripts/test-replay-netns.ps1")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"Test-MIIReplayNetnsPolicy", "Assert-MIIReplayNetnsResult -ExitCode $code -Lines $lines", "'-tags=replay_netns'", "'^TestOfflineReplayNetworkNamespace$'", "'-count=1'", "'-timeout=4m'", "$event.Action -cnotin @('start','run','output','pass')", "$starts -ne 1 -or $runs -ne 1 -or $passes -ne 1 -or $summaries -ne 1", "MI_REPLAY_NETNS_LINUX_REQUIRED", "MI_REPLAY_NETNS_IMPLICIT_OVERRIDE_REJECTED", "MI_REPLAY_NETNS_PROOF_STAGE_MISSING", "$env:GOPROXY = 'off'", "$env:GOSUMDB = 'off'"} {
		if !strings.Contains(string(script), required) {
			t.Fatalf("namespace script guard missing: %s", required)
		}
	}
	file, err := parser.ParseFile(token.NewFileSet(), "../../tests/replay/cmd/replay/netns_linux_test.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		if fn, ok := node.(*ast.FuncDecl); ok && fn.Name.Name == "TestOfflineReplayNetworkNamespace" {
			found = true
		}
		if call, ok := node.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Skip" || sel.Sel.Name == "Skipf" || sel.Sel.Name == "SkipNow") {
				t.Error("namespace evidence may not skip")
			}
		}
		return true
	})
	if !found || len(file.Comments) == 0 || !strings.Contains(file.Comments[0].Text(), "linux && replay_netns") {
		// Build constraints are retained in Comment.Text, not CommentGroup.Text.
		raw, err := os.ReadFile("../../tests/replay/cmd/replay/netns_linux_test.go")
		if err != nil || !found || !strings.HasPrefix(string(raw), "//go:build linux && replay_netns") {
			t.Fatal("missing explicit Linux-only namespace test")
		}
	}
}

func TestReplayNamespacePolicySourcesPresentOnlyInBuildStage(t *testing.T) {
	raw, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	build, runtime, found := strings.Cut(strings.ReplaceAll(string(raw), "\r\n", "\n"), "FROM scratch")
	if !found {
		t.Fatal("missing runtime boundary")
	}
	for _, copyLine := range []string{"COPY scripts/test-replay-netns.ps1 ./scripts/test-replay-netns.ps1", "COPY .github/workflows/ci.yml ./.github/workflows/ci.yml", "COPY .dockerignore ./.dockerignore"} {
		at := strings.Index(build, copyLine)
		if at < 0 || at > strings.Index(build, "RUN go test ./...") || strings.Contains(runtime, copyLine) {
			t.Fatal("namespace contract sources must exist only before build-stage tests")
		}
	}
	ignore, err := os.ReadFile("../../.dockerignore")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.ReplaceAll(string(ignore), "\r\n", "\n"), "\n")
	var policyPatterns []string
	for _, line := range lines {
		if strings.Contains(line, ".github") {
			policyPatterns = append(policyPatterns, line)
		}
	}
	if strings.Join(policyPatterns, "\n") != ".github/*\n!.github/workflows\n.github/workflows/*\n!.github/workflows/ci.yml" {
		t.Fatal("Docker context must expose only ci.yml, not other GitHub configuration")
	}
}
