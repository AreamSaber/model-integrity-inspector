package baseline

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func scopeFixture() (repository.BaselineRecord, repository.BaselineScope) {
	creator := int64(3)
	seed := int64(7)
	risk := 10.0
	s := repository.BaselineScope{SchemaVersion: ScopeVersion, OrganizationID: 1, RunID: 2, TargetID: 4, AnalysisRevision: 1, Model: "synthetic-model", Protocol: "openai_chat", ManifestHash: strings.Repeat("a", 64), ResultHash: strings.Repeat("b", 64), ParametersHash: strings.Repeat("c", 64), ExpectedSamples: 1, ValidSamples: 1, OverallRisk: &risk, Completeness: "PARTIAL", Samples: []repository.BaselineSampleScope{{TemplateID: "format.en-us.1", TemplateVersion: "1.0.0-dev.1", Family: "format", Language: "en-US", MaxOutputTokens: 64, Seed: &seed, VariablesHash: strings.Repeat("d", 64)}}}
	s.Versions.Scoring = scoring.Version
	raw, _ := json.Marshal(s)
	r := repository.BaselineRecord{ID: 8, OrganizationID: 1, RunID: 2, AnalysisRevision: 1, Name: "reference", Source: "historical", Model: s.Model, Protocol: s.Protocol, Region: "declared-r1", Status: "approved", CreatedBy: &creator, SourceManifestHash: s.ManifestHash, SourceResultHash: s.ResultHash, ParametersHash: s.ParametersHash, SnapshotJSON: string(raw), SnapshotHash: digest(raw), ExpiresAt: time.Now().UTC().Add(time.Hour)}
	return r, s
}
func TestBaselineApplicabilityRequiresScopeExpiryAndExactVariables(t *testing.T) {
	r, reference := scopeFixture()
	candidate := reference
	candidate.RunID = 9
	result := compare(r, reference, candidate, r.Region)
	if !result.MetadataCompatible || !result.PairedVariablesMatch || result.EligibleForScoring {
		t.Fatal("equal synthetic scopes did not remain descriptive only")
	}
	for _, name := range []string{"draft", "retired", "expired", "self", "tenant", "model", "protocol", "version", "parameters", "template_hash", "tokenizer_hash", "historical_target", "missing_region", "different_region", "variables", "seed"} {
		t.Run(name, func(t *testing.T) {
			r, ref := scopeFixture()
			candidate := ref
			candidate.RunID = 9
			candidate.Samples = append([]repository.BaselineSampleScope{}, ref.Samples...)
			region := r.Region
			switch name {
			case "draft", "retired":
				r.Status = name
			case "expired":
				r.ExpiresAt = time.Now().Add(-time.Second)
			case "self":
				candidate.RunID = ref.RunID
			case "tenant":
				candidate.OrganizationID = 99
			case "model":
				candidate.Model = "different"
			case "protocol":
				candidate.Protocol = "different"
			case "version":
				candidate.Versions.Rule = "different"
			case "parameters":
				candidate.ParametersHash = strings.Repeat("e", 64)
			case "template_hash":
				candidate.TemplateHash = strings.Repeat("e", 64)
			case "tokenizer_hash":
				candidate.TokenizerHash = strings.Repeat("e", 64)
			case "historical_target":
				candidate.TargetID++
			case "missing_region":
				region = ""
			case "different_region":
				region = "elsewhere"
			case "variables":
				candidate.Samples[0].VariablesHash = strings.Repeat("e", 64)
			case "seed":
				seed := int64(8)
				candidate.Samples[0].Seed = &seed
			}
			got := compare(r, ref, candidate, region)
			if got.EligibleForScoring || got.PairedVariablesMatch {
				t.Fatal("inapplicable source admitted")
			}
			if got.MetadataCompatible != (name == "variables" || name == "seed") {
				t.Fatal("distribution and paired compatibility conflated")
			}
		})
	}
}
func TestBaselineViewNeverConvertsOrganizationApprovalToCalibration(t *testing.T) {
	r, _ := scopeFixture()
	v, err := view(r)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Development || v.Calibrated || v.EligibleForScoring || v.SourceAssurance != "organization_declared_unverified" || v.RegionAssurance != "organization_declared_unverified" {
		t.Fatal("unsupported trust claim")
	}
	r.ExpiresAt = time.Now().Add(-time.Second)
	v, err = view(r)
	if err != nil || v.Status != "expired" {
		t.Fatal("expiry not visible", err)
	}
	r.Status = "retired"
	v, err = view(r)
	if err != nil || v.Status != "retired" {
		t.Fatal("retirement not preserved", err)
	}
	r.SnapshotJSON = `{"content":"PRIVATE_BODY"}`
	if _, err := view(r); !errors.Is(err, repository.ErrBaselineIntegrity) {
		t.Fatal("arbitrary snapshot accepted")
	}
	if _, err := NewService(Config{}); !errors.Is(err, repository.ErrBaselineInvalid) {
		t.Fatal("missing dependencies")
	}
}
