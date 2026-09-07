package generator

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

type Generator struct {
	bundle    templates.Bundle
	hash      string
	tokenizer *tokenizer.Engine
	signer    Signer
}

// New accepts only a canonically verified artifact and retains a detached copy.
// The expected digest comes from release/operator metadata, not an upload itself.
func New(data []byte, expectedHash string, engine *tokenizer.Engine, signer Signer) (*Generator, error) {
	bundle, err := templates.Decode(data, expectedHash)
	if err != nil || engine == nil || signer == nil {
		return nil, ErrConfiguration
	}
	if _, err := signer.ProbeMAC(signer.ActiveVersion(), []byte("mii/probe/startup-check")); err != nil {
		return nil, ErrConfiguration
	}
	return &Generator{bundle, expectedHash, engine, signer}, nil
}

var label = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var noncePattern = regexp.MustCompile(`^[a-f0-9]{24}$`)

func validateOptions(o Options) bool {
	if o.OrganizationID <= 0 || o.Target.ID <= 0 || o.Target.Version <= 0 || o.Target.SecretID <= 0 || o.Target.SecretVersion <= 0 || o.Target.Protocol != "openai_chat" || (o.Target.MaxOutputParameter != "max_tokens" && o.Target.MaxOutputParameter != "max_completion_tokens") || len(o.Target.Model) == 0 || len(o.Target.Model) > 256 || !utf8.ValidString(o.Target.Model) || strings.ContainsAny(o.Target.Model, "\x00\r\n") {
		return false
	}
	if len(o.Target.Endpoint) == 0 || len(o.Target.Endpoint) > 2048 || !strings.HasPrefix(o.Target.Endpoint, "https://") || !utf8.ValidString(o.Target.Endpoint) || strings.ContainsAny(o.Target.Endpoint, "\x00\r\n") {
		return false
	}
	if !label.MatchString(o.RuleVersion) || !label.MatchString(o.ScoringVersion) || len(o.StandardModel) > 256 || !utf8.ValidString(o.StandardModel) || o.ContextWindow < 1 || o.ContextWindow > 10000000 || o.MaxOutputTokens < 1 || o.MaxOutputTokens > 131072 || o.Concurrency < 1 || o.Concurrency > 100 || o.MaxRetries < 0 || o.MaxRetries > 2 || o.Budget.MaxRequests < 1 || o.Budget.MaxRequests > 100000 || o.Budget.MaxTokens < 1 || o.Budget.MaxTokens > 1000000000000 || o.Budget.TimeoutSeconds < 1 || o.Budget.TimeoutSeconds > 86400 || (o.BaselineRunID != nil && *o.BaselineRunID <= 0) {
		return false
	}
	if o.Temperature != nil && (math.IsNaN(*o.Temperature) || *o.Temperature < 0 || *o.Temperature > 2) {
		return false
	}
	if o.Budget.MaxCostMicros != nil && (*o.Budget.MaxCostMicros < 0 || o.Pricing.InputMicrosPerMillion == nil || o.Pricing.OutputMicrosPerMillion == nil) {
		return false
	}
	for _, price := range []*int64{o.Pricing.InputMicrosPerMillion, o.Pricing.OutputMicrosPerMillion} {
		if price != nil && *price < 0 {
			return false
		}
	}
	switch o.Package {
	case "quick", "standard", "deep":
		return o.Custom == nil
	case "custom":
		c := o.Custom
		if c == nil || len(c.Families) < 1 || len(c.Families) > 7 || c.Repetitions < 1 || c.Repetitions > 10 || len(c.Languages) < 1 || len(c.Languages) > 2 || len(c.Tiers) > 8 {
			return false
		}
		seen := map[string]bool{}
		for _, family := range c.Families {
			if !slices.Contains([]string{"sequence", "jsonl", "format", "neutral", "differential", "style", "self_report"}, family) || seen[family] {
				return false
			}
			seen[family] = true
		}
		seen = map[string]bool{}
		for _, lang := range c.Languages {
			if (lang != "zh-CN" && lang != "en-US") || seen[lang] {
				return false
			}
			seen[lang] = true
		}
		if (slices.Contains(c.Families, "sequence") || slices.Contains(c.Families, "jsonl")) && len(c.Tiers) == 0 {
			return false
		}
		previous := 0
		for _, tier := range c.Tiers {
			if tier < 16 || tier > 131072 || tier <= previous {
				return false
			}
			previous = tier
		}
		return true
	}
	return false
}

type condition struct {
	family, language                string
	variant, repetitions, maxTokens int
	style                           string
}
type conditionGroup struct {
	id         string
	conditions []condition
}

// Reduction happens by complete condition groups, not by dropping individual
// repetitions or one arm of a comparison. Expensive high ladder tiers are last.
func groups(o Options) []conditionGroup {
	reps, formatReps := 3, 3
	tiers := []int{64, 128, 256, 512}
	families := []string{"sequence", "jsonl", "format", "neutral", "differential", "style"}
	languages := []string{"zh-CN", "en-US"}
	if o.Package == "quick" {
		tiers = []int{64, 128}
		formatReps = 1
		families = families[:3]
	}
	if o.Package == "deep" {
		reps = 5
		formatReps = 5
		tiers = append(tiers, 1024)
		families = append(families, "self_report")
	}
	if o.Custom != nil {
		reps = o.Custom.Repetitions
		formatReps = reps
		tiers = o.Custom.Tiers
		families = o.Custom.Families
		languages = o.Custom.Languages
	}
	result := []conditionGroup{}
	for _, family := range families {
		if family == "sequence" || family == "jsonl" {
			continue
		}
		g := conditionGroup{id: family}
		comparisonLanguages := languages[:1]
		if o.Custom != nil {
			comparisonLanguages = languages
		}
		switch family {
		case "format":
			for _, lang := range languages {
				for variant := 1; variant <= 3; variant++ {
					g.conditions = append(g.conditions, condition{family, lang, variant, formatReps, 64, ""})
				}
			}
		case "differential":
			for _, lang := range comparisonLanguages {
				for variant := 1; variant <= 2; variant++ {
					g.conditions = append(g.conditions, condition{family, lang, variant, reps, 64, ""})
				}
			}
		case "style":
			for _, lang := range comparisonLanguages {
				for _, style := range []string{"formal", "friendly"} {
					g.conditions = append(g.conditions, condition{family, lang, 1, reps, 128, style})
				}
			}
		default:
			for _, lang := range languages {
				g.conditions = append(g.conditions, condition{family, lang, 1, reps, 64, ""})
			}
		}
		result = append(result, g)
	}
	for _, tier := range tiers {
		g := conditionGroup{id: "ladder-" + strconv.Itoa(tier)}
		for _, family := range []string{"sequence", "jsonl"} {
			if slices.Contains(families, family) {
				ladderLanguages := languages[:1]
				if o.Custom != nil {
					ladderLanguages = languages
				}
				for _, lang := range ladderLanguages {
					g.conditions = append(g.conditions, condition{family, lang, 1, reps, tier, ""})
				}
			}
		}
		if len(g.conditions) > 0 {
			result = append(result, g)
		}
	}
	return result
}

func newNonce() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", ErrConfiguration
	}
	return hex.EncodeToString(b[:]), nil
}
func randomSeed() (*int64, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 31))
	if err != nil {
		return nil, ErrConfiguration
	}
	v := n.Int64()
	return &v, nil
}

type shared struct {
	groupID, pairID string
	variables       Variables
	seed            *int64
}

func (g *Generator) Generate(options Options) (Manifest, error) {
	if g == nil || !validateOptions(options) {
		return Manifest{}, ErrConfiguration
	}
	// Detach caller-owned pointers/slices before retaining immutable metadata.
	encoded, err := json.Marshal(options)
	var detached Options
	if err != nil || json.Unmarshal(encoded, &detached) != nil {
		return Manifest{}, ErrConfiguration
	}
	options = detached
	if options.Temperature == nil {
		options.Temperature = new(float64)
	}
	runNonce, err := newNonce()
	if err != nil {
		return Manifest{}, err
	}
	m := Manifest{GeneratorVersion: Version, Options: options, RunNonce: runNonce, KeyVersion: g.signer.ActiveVersion(), TemplateVersion: g.bundle.Version, TemplateHash: g.hash, TokenizerVersion: g.tokenizer.Version(), TokenizerHash: g.tokenizer.Hash(), Samples: []Sample{}, Omissions: []Omission{}, Warnings: []string{"MI_PROBE_DEVELOPMENT_UNCALIBRATED", "MI_COST_ESTIMATE_NOT_BILLING_GUARANTEE"}, Completeness: "COMPLETE"}
	if g.hash == templates.BuiltinHash {
		m.Warnings = append(m.Warnings, "MI_TEMPLATE_PUBLIC_DEVELOPMENT_POOL")
	}
	if options.Package == "quick" {
		m.Warnings = append(m.Warnings, "MI_QUICK_NO_HIGH_CONFIDENCE_NEGATIVE")
	}
	if !options.SupportsStream {
		m.Warnings = append(m.Warnings, "MI_STREAM_COMPARISON_NOT_APPLICABLE")
		m.Completeness = "PARTIAL"
	}
	if options.Custom != nil && options.Custom.Repetitions < 3 {
		m.Warnings = append(m.Warnings, "MI_REPETITIONS_INSUFFICIENT")
		m.Completeness = "PARTIAL"
	}
	sharedVariables := map[string]shared{}
	for _, group := range groups(options) {
		candidates, reason, err := g.expand(m, group, sharedVariables)
		if err != nil {
			return Manifest{}, err
		}
		count := 0
		for _, c := range group.conditions {
			count += c.repetitions
		}
		if reason == "" {
			projection, err := project(options, append(slices.Clone(m.Samples), candidates...))
			if err != nil {
				return Manifest{}, err
			}
			switch {
			case projection.Requests > 150 || int64(projection.Requests) > options.Budget.MaxRequests:
				reason = "MI_REQUEST_BUDGET_LIMIT"
			case projection.ReservedTokens > options.Budget.MaxTokens:
				reason = "MI_TOKEN_BUDGET_LIMIT"
			case options.Budget.MaxCostMicros != nil && (projection.EstimatedCostMicros == nil || *projection.EstimatedCostMicros > *options.Budget.MaxCostMicros):
				reason = "MI_COST_BUDGET_LIMIT"
			}
			if reason == "" {
				m.Samples = append(m.Samples, candidates...)
				m.Projection = projection
			}
		}
		if reason != "" {
			m.Omissions = append(m.Omissions, Omission{group.id, reason, count})
			m.Completeness = "PARTIAL"
		}
	}
	if len(m.Samples) == 0 {
		return Manifest{}, ErrBudget
	}
	for i := len(m.Samples) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return Manifest{}, ErrConfiguration
		}
		j := int(n.Int64())
		m.Samples[i], m.Samples[j] = m.Samples[j], m.Samples[i]
	}
	for i := range m.Samples {
		m.Samples[i].Ordinal = i
	}
	if err := g.sign(&m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func (g *Generator) expand(m Manifest, group conditionGroup, sharedVariables map[string]shared) ([]Sample, string, error) {
	result := []Sample{}
	for _, c := range group.conditions {
		var template templates.Template
		found := false
		for _, t := range g.bundle.Templates {
			if t.Family == c.family && t.Language == c.language && t.Variant == c.variant {
				if found {
					return nil, "", ErrConfiguration
				}
				template = t
				found = true
			}
		}
		if !found {
			return nil, "MI_TEMPLATE_NOT_AVAILABLE", nil
		}
		if c.maxTokens > m.Options.MaxOutputTokens {
			return nil, "MI_MODEL_OUTPUT_LIMIT", nil
		}
		for repetition := 0; repetition < c.repetitions; repetition++ {
			key := c.family + "." + strconv.Itoa(repetition)
			if c.family == "differential" {
				key = c.family + "." + c.language + "." + strconv.Itoa(repetition)
			}
			// Both languages/format variants and differential arms share variables.
			// Stream pairs additionally share variables across adjacent repetitions.
			ladder := c.family == "sequence" || c.family == "jsonl"
			if ladder {
				key = c.family + ".stream-pair." + strconv.Itoa(repetition/2)
			}
			v, exists := sharedVariables[key]
			if !exists {
				nonce, err := newNonce()
				if err != nil {
					return nil, "", err
				}
				groupID, err := newNonce()
				if err != nil {
					return nil, "", err
				}
				v = shared{groupID: groupID, pairID: groupID, variables: Variables{Nonce: nonce, Label: "k_" + nonce[:8], Count: 1000000}}
				if m.Options.SupportsSeed {
					v.seed, err = randomSeed()
					if err != nil {
						return nil, "", err
					}
				}
				sharedVariables[key] = v
			}
			s := Sample{ConditionID: group.id + "." + c.family + "." + strings.ToLower(c.language) + "." + strconv.Itoa(c.variant) + "." + c.style, TemplateID: template.ID, TemplateVersion: template.Version, Family: c.family, Language: c.language, Variant: c.variant, Repetition: repetition, GroupID: v.groupID, Variables: v.variables, Seed: v.seed, MaxOutputTokens: c.maxTokens, AuxiliaryOnly: template.AuxiliaryOnly}
			if c.style != "" {
				s.Variables.Style = c.style
				if c.language == "zh-CN" {
					if c.style == "formal" {
						s.Variables.Style = "正式"
					} else {
						s.Variables.Style = "友好"
					}
				}
			}
			if c.family == "differential" {
				s.PairID = v.pairID
				s.Arm = []string{"A", "B"}[c.variant-1]
			}
			if ladder {
				s.Stream = m.Options.SupportsStream && repetition%2 == 1
			}
			request, err := g.request(m.Options, s)
			if err != nil {
				return nil, "", err
			}
			s.InputEstimate, err = g.tokenizer.EstimateInputFor(request, tokenizer.Selection{RequestedModel: request.Model, StandardModel: m.Options.StandardModel})
			if err != nil || s.InputEstimate.Tokens == nil {
				return nil, "", ErrConfiguration
			}
			if s.InputEstimate.BudgetTokens+int64(c.maxTokens) > int64(m.Options.ContextWindow) {
				return nil, "MI_CONTEXT_WINDOW_LIMIT", nil
			}
			requestBytes, err := json.Marshal(request)
			if err != nil {
				return nil, "", ErrConfiguration
			}
			s.RequestHash = digest(requestBytes)
			s.NonceMAC, err = g.nonceMAC(m, s)
			if err != nil {
				return nil, "", err
			}
			result = append(result, s)
		}
	}
	return result, "", nil
}

func (g *Generator) request(o Options, s Sample) (domain.NormalizedRequest, error) {
	t, ok := g.bundle.Find(s.TemplateID)
	if !ok || t.Version != s.TemplateVersion || t.Family != s.Family || t.Language != s.Language || t.Variant != s.Variant || t.AuxiliaryOnly != s.AuxiliaryOnly || !noncePattern.MatchString(s.Variables.Nonce) || s.Variables.Label != "k_"+s.Variables.Nonce[:8] || s.Variables.Count != 1000000 || s.MaxOutputTokens < 1 || s.MaxOutputTokens > o.MaxOutputTokens || (s.Stream && !o.SupportsStream) || (s.Seed != nil && !o.SupportsSeed) {
		return domain.NormalizedRequest{}, ErrIntegrity
	}
	prompt, err := templates.Render(t, map[string]string{"NONCE": s.Variables.Nonce, "LABEL": s.Variables.Label, "COUNT": strconv.Itoa(s.Variables.Count), "STYLE": s.Variables.Style})
	if err != nil {
		return domain.NormalizedRequest{}, ErrIntegrity
	}
	return domain.NormalizedRequest{Model: o.Target.Model, Messages: []domain.NormalizedMessage{{Role: "user", Content: prompt}}, Temperature: o.Temperature, Seed: s.Seed, MaxOutputTokens: s.MaxOutputTokens, Stream: s.Stream}, nil
}

func project(o Options, samples []Sample) (Projection, error) {
	p := Projection{Requests: len(samples), TimeUpperBoundSeconds: o.Budget.TimeoutSeconds}
	for _, s := range samples {
		var err error
		p.InputTokens, err = scheduler.Add(p.InputTokens, s.InputEstimate.BudgetTokens)
		if err != nil {
			return p, ErrBudget
		}
		p.OutputTokens, err = scheduler.Add(p.OutputTokens, int64(s.MaxOutputTokens))
		if err != nil {
			return p, ErrBudget
		}
		cost, err := scheduler.Cost(o.Pricing, s.InputEstimate.BudgetTokens, int64(s.MaxOutputTokens))
		if err != nil {
			return p, ErrBudget
		}
		if cost != nil {
			if p.EstimatedCostMicros == nil {
				p.EstimatedCostMicros = new(int64)
			}
			*p.EstimatedCostMicros, err = scheduler.Add(*p.EstimatedCostMicros, *cost)
			if err != nil {
				return p, ErrBudget
			}
		}
	}
	var err error
	p.ReservedTokens, err = scheduler.Add(p.InputTokens, p.OutputTokens)
	if err != nil {
		return p, ErrBudget
	}
	return p, nil
}
