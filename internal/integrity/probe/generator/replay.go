package generator

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

func (g *Generator) mac(version, purpose string, org int64, runNonce, value string) (string, error) {
	// Typed canonical framing prevents concatenation ambiguity and cross-purpose
	// replay. No raw nonce/key is logged by errors or returned as diagnostic text.
	data, err := json.Marshal(struct {
		Purpose         string
		OrganizationID  int64
		RunNonce, Value string
	}{purpose, org, runNonce, value})
	if err != nil {
		return "", ErrIntegrity
	}
	mac, err := g.signer.ProbeMAC(version, data)
	if err != nil || len(mac) != 32 {
		return "", ErrIntegrity
	}
	return hex.EncodeToString(mac), nil
}

func (g *Generator) nonceMAC(m Manifest, s Sample) (string, error) {
	data, err := json.Marshal(struct {
		Group     string
		Variables Variables
	}{s.GroupID, s.Variables})
	if err != nil {
		return "", ErrIntegrity
	}
	return g.mac(m.KeyVersion, "nonce-v1", m.Options.OrganizationID, m.RunNonce, digest(data))
}

func (g *Generator) sign(m *Manifest) error {
	m.Integrity = ""
	_, hash, err := m.Canonical()
	if err != nil {
		return err
	}
	m.Integrity, err = g.mac(m.KeyVersion, "manifest-v1", m.Options.OrganizationID, m.RunNonce, hash)
	return err
}

// Verify is tenant-bound and needs the frozen artifact/key versions. It never
// generates new randomness, re-estimates tokens or silently upgrades a bundle.
func (g *Generator) Verify(data []byte, expectedHash string, organizationID int64) (Manifest, error) {
	var m Manifest
	if g == nil || organizationID <= 0 || len(data) == 0 || len(data) > maxManifestBytes || digest(data) != expectedHash {
		return m, ErrIntegrity
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil {
		return Manifest{}, ErrIntegrity
	}
	canonical, hash, err := m.Canonical()
	if err != nil || hash != expectedHash || !bytes.Equal(canonical, data) || m.GeneratorVersion != Version || m.Options.OrganizationID != organizationID || !validateOptions(m.Options) || !noncePattern.MatchString(m.RunNonce) || m.TemplateVersion != g.bundle.Version || m.TemplateHash != g.hash || m.TokenizerVersion != g.tokenizer.Version() || m.TokenizerHash != g.tokenizer.Hash() || len(m.Samples) < 1 || len(m.Samples) > 150 {
		return Manifest{}, ErrIntegrity
	}
	provided := m.Integrity
	unsigned := m
	if err := g.sign(&unsigned); err != nil || !hmac.Equal([]byte(provided), []byte(unsigned.Integrity)) {
		return Manifest{}, ErrIntegrity
	}
	for i, s := range m.Samples {
		if s.Ordinal != i || !noncePattern.MatchString(s.GroupID) || (s.PairID != "" && !noncePattern.MatchString(s.PairID)) || (s.Arm != "" && s.Arm != "A" && s.Arm != "B") || s.Repetition < 0 || s.Repetition > 9 || s.InputEstimate.BudgetTokens < 1 || s.InputEstimate.Tokens == nil {
			return Manifest{}, ErrIntegrity
		}
		nonceMAC, err := g.nonceMAC(m, s)
		if err != nil || !hmac.Equal([]byte(nonceMAC), []byte(s.NonceMAC)) {
			return Manifest{}, ErrIntegrity
		}
		request, err := g.request(m.Options, s)
		if err != nil {
			return Manifest{}, err
		}
		raw, err := json.Marshal(request)
		if err != nil || digest(raw) != s.RequestHash {
			return Manifest{}, ErrIntegrity
		}
	}
	projection, err := project(m.Options, m.Samples)
	if err != nil {
		return Manifest{}, err
	}
	a, _ := json.Marshal(projection)
	b, _ := json.Marshal(m.Projection)
	if !bytes.Equal(a, b) {
		return Manifest{}, ErrIntegrity
	}
	return m, nil
}

// ExecutionPlan regenerates each exact request from authenticated frozen data.
// One probe instance per scheduled sample preserves globally shuffled queue
// order; ConditionID/Repetition in Manifest retain statistical grouping. An
// Attempt retry never creates another logical sample or another condition.
func (g *Generator) ExecutionPlan(data []byte, expectedHash string, organizationID int64) (domain.ExecutionPlan, error) {
	m, err := g.Verify(data, expectedHash, organizationID)
	if err != nil {
		return domain.ExecutionPlan{}, err
	}
	o := m.Options
	// Metadata is authenticated alongside requests, never read from current
	// mutable catalog values when replaying an already confirmed Run.
	p := domain.ExecutionPlan{Target: o.Target, Package: o.Package, ManifestHash: expectedHash, Manifest: bytes.Clone(data), Versions: domain.BundleVersions{Rule: o.RuleVersion, Template: m.TemplateVersion, Scoring: o.ScoringVersion, Tokenizer: m.TokenizerVersion}, Budget: o.Budget, Pricing: o.Pricing, Concurrency: o.Concurrency, MaxRetries: o.MaxRetries, BaselineRunID: o.BaselineRunID, Probes: []domain.ProbePlan{}}
	p.PrecheckID, p.ModelProfile = o.PrecheckID, o.ModelProfile
	for _, s := range m.Samples {
		request, err := g.request(o, s)
		if err != nil {
			return domain.ExecutionPlan{}, err
		}
		category := "prompt_behavior"
		if s.Family == "sequence" || s.Family == "jsonl" {
			category = "max_tokens"
		}
		if s.AuxiliaryOnly {
			category = "auxiliary"
		}
		p.Probes = append(p.Probes, domain.ProbePlan{Type: s.Family, TemplateID: s.TemplateID, TemplateVersion: s.TemplateVersion, Category: category, Variant: strconv.Itoa(s.Variant), Samples: []domain.SamplePlan{{Ordinal: s.Ordinal, PairID: s.PairID, Nonce: s.Variables.Nonce, Request: request, EstimatedInputTokens: s.InputEstimate.BudgetTokens}}})
	}
	return p, nil
}
