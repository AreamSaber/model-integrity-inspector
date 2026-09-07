package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestRequirementsTraceability(t *testing.T) {
	root := filepath.Join("..", "..")
	prd, err := os.ReadFile(filepath.Join(root, "模型真实性检测系统-PRD-V1.0.md"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := os.ReadFile(filepath.Join(root, "模型真实性检测系统-开发计划与审核表-V1.0.md"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "docs", "project", "requirements-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var matrix struct {
		Requirements []struct {
			ID             string   `json:"id"`
			Priority       string   `json:"priority"`
			Owner          string   `json:"owner"`
			Tasks          []string `json:"tasks"`
			Acceptance     []string `json:"acceptance"`
			TestCase       string   `json:"test_case"`
			Implementation string   `json:"implementation"`
			Code           []string `json:"code"`
			Tests          []string `json:"tests"`
		} `json:"requirements"`
	}
	if err := json.Unmarshal(raw, &matrix); err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`(?m)^\| ((?:SYS|TAR|RUN|PINJ|MTOK|RINT|BASE|REP|HIS|CFG)-\d{3}) \|[^\r\n]+\| (P[012]) \|`)
	required := map[string]string{}
	for _, match := range pattern.FindAllStringSubmatch(string(prd), -1) {
		required[match[1]] = match[2]
	}
	if len(required) != 77 {
		t.Fatalf("expected 77 baseline requirements, found %d", len(required))
	}
	seen := map[string]bool{}
	for _, row := range matrix.Requirements {
		if seen[row.ID] || required[row.ID] != row.Priority {
			t.Errorf("duplicate/unknown/changed priority: %s", row.ID)
		}
		seen[row.ID] = true
		if row.Owner == "" || row.TestCase != "REQ-"+row.ID || len(row.Tasks) == 0 {
			t.Errorf("missing ownership/test allocation: %s", row.ID)
		}
		for _, id := range append(row.Tasks, row.Acceptance...) {
			if !strings.Contains(string(plan), "| "+id+" |") {
				t.Errorf("unknown task %s for %s", id, row.ID)
			}
		}
		if row.Priority == "P0" && len(row.Acceptance) == 0 {
			t.Errorf("no acceptance owner: %s", row.ID)
		}
		if row.Implementation == "verified" {
			if len(row.Code) == 0 || len(row.Tests) == 0 {
				t.Errorf("verified without evidence: %s", row.ID)
			}
			for _, file := range append(row.Code, row.Tests...) {
				if !filepath.IsLocal(file) {
					t.Errorf("nonlocal evidence: %s", file)
					continue
				}
				if _, err := os.Stat(filepath.Join(root, file)); err != nil {
					t.Errorf("missing evidence %s: %v", file, err)
				}
			}
		}
	}
	if len(seen) != len(required) {
		t.Fatalf("traceability coverage %d/%d", len(seen), len(required))
	}
}
