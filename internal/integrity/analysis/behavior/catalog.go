package behavior

import "model-integrity-inspector.local/mii/internal/integrity/probe/templates"

// VerifiedCatalog holds detached metadata, never prompts. A trusted hash must
// come from release/operator metadata, not from the response under analysis.
// Digest verification establishes provenance, NOT content-safety approval.
type VerifiedCatalog struct{ entries map[TemplateRef]templateSpec }

type templateSpec struct {
	family    Family
	language  string
	variant   int
	auxiliary bool
	builtin   bool
	neutral   bool
}

func VerifyCatalog(data []byte, trustedHash string) (*VerifiedCatalog, error) {
	if len(data) > 1<<20 {
		return nil, ErrLimit
	}
	bundle, err := templates.Decode(data, trustedHash)
	if err != nil {
		return nil, ErrInput
	}
	c := &VerifiedCatalog{entries: make(map[TemplateRef]templateSpec, len(bundle.Templates))}
	builtin := trustedHash == templates.BuiltinHash && bundle.Version == templates.BuiltinVersion
	for _, t := range bundle.Templates {
		ref := TemplateRef{ID: t.ID, Version: t.Version, SHA256: trustedHash}
		if !validRef(ref) {
			return nil, ErrInput
		}
		neutral := builtin && t.Family == "neutral" && (t.ID == "neutral.en-us.1" || t.ID == "neutral.zh-cn.1")
		c.entries[ref] = templateSpec{family: Family(t.Family), language: t.Language, variant: t.Variant, auxiliary: t.AuxiliaryOnly || t.Family == "self_report", builtin: builtin, neutral: neutral}
	}
	return c, nil
}

// New copies a verified catalog; nil permits descriptive format analysis only.
// A zero-value/unknown catalog cannot opt arbitrary tasks into neutral analysis.
func New(catalog *VerifiedCatalog) (*Engine, error) {
	e := &Engine{templates: map[TemplateRef]templateSpec{}}
	if catalog != nil {
		for ref, spec := range catalog.entries {
			e.templates[ref] = spec
		}
	}
	return e, nil
}
