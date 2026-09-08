package behavior

import (
	"bytes"
	"encoding/json"
	"io"
)

const DerivedVersion = "mii.behavior-derived.v1"
const MaxDerivedBytes = 16 << 10

// Derived contains observations only. Its constructor analyzes a real Sample;
// callers cannot populate its private features. This is NOT a signature.
type Derived struct{ observation derivedObservation }

type derivedObservation struct {
	Version  string   `json:"version"`
	Binding  string   `json:"binding"`
	Features Features `json:"features"`
}

// observationBinding deliberately hashes, rather than serializes into durable
// S1, the frozen contract/variables/Pair. Content and timestamps are excluded.
func observationBinding(s Sample) string {
	attempt, _ := validate(s)
	raw, _ := json.Marshal(struct {
		ID, FinalAttemptID                      int64
		Number                                  int
		Validity                                Validity
		Template                                TemplateRef
		Kind                                    ContractKind
		Expected, Key                           string
		Variables                               []string
		Pair                                    Pair
		Sensitive, IdentityRequested, Auxiliary bool
	}{s.ID, s.FinalAttemptID, attempt.Number, attempt.Validity, s.Template, s.Contract.Kind, s.Contract.Expected, s.Contract.Key, s.Variables, s.Pair, s.SensitiveTask, s.IdentityRequested, s.AuxiliaryOnly})
	defer clear(raw)
	return digest("derived_binding", string(raw))
}

func (e *Engine) Derive(s Sample) (*Derived, error) {
	f, err := e.Analyze(s)
	if err != nil {
		return nil, err
	}
	return &Derived{derivedObservation{DerivedVersion, observationBinding(s), f}}, nil
}

func (d *Derived) Canonical() ([]byte, error) {
	if d == nil || d.observation.Version != DerivedVersion {
		return nil, ErrInput
	}
	raw, err := json.Marshal(d.observation)
	if err != nil || len(raw) > MaxDerivedBytes {
		clear(raw)
		return nil, ErrLimit
	}
	return raw, nil
}

// VerifyDerivedBinding checks the transient frozen plan before a containing
// feature batch exposes any observation. expected is only a consistency check;
// it cannot construct or replace the private authenticated observation.
func (e *Engine) VerifyDerivedBinding(sample Sample, observation *Derived, expected Features) error {
	if _, err := e.derivedItems([]Sample{sample}, []*Derived{observation}); err != nil {
		return err
	}
	left, err := json.Marshal(expected)
	if err != nil {
		return ErrInput
	}
	right, err := json.Marshal(observation.observation.Features)
	if err != nil || !bytes.Equal(left, right) {
		return ErrInput
	}
	return nil
}

// DecodeAuthenticatedDerived is only a codec AFTER the containing record's
// authentication has succeeded. It must never be used on HTTP/user JSON.
// The outer features capability performs the independent-purpose HMAC check.
func DecodeAuthenticatedDerived(raw []byte) (*Derived, error) {
	if len(raw) == 0 || len(raw) > MaxDerivedBytes {
		return nil, ErrLimit
	}
	var wire derivedObservation
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&wire) != nil || d.Decode(new(any)) != io.EOF || wire.Version != DerivedVersion || wire.Features.Version != Version || !validHash(wire.Binding) {
		return nil, ErrInput
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrInput
	}
	return &Derived{wire}, nil
}

func (e *Engine) derivedItems(samples []Sample, observations []*Derived) ([]batchItem, error) {
	if len(samples) > MaxSamples {
		return nil, ErrLimit
	}
	if len(samples) != len(observations) {
		return nil, ErrInput
	}
	items := make([]batchItem, 0, len(samples))
	seen := map[int64]bool{}
	resourceBytes := 0
	remaining := observations
	for _, sample := range samples {
		if _, err := validate(sample); err != nil {
			return nil, err
		}
		resourceBytes += len(sample.Contract.Expected) + len(sample.Contract.Key)
		for _, variable := range sample.Variables {
			resourceBytes += len(variable)
		}
		for _, attempt := range sample.Attempts {
			// Restore cannot smuggle a shadow body beside the retained S1.
			if attempt.Content != "" {
				return nil, ErrInput
			}
		}
		if resourceBytes > MaxBatchBytes {
			return nil, ErrLimit
		}
		if len(remaining) == 0 {
			return nil, ErrInput
		}
		observation := remaining[0]
		remaining = remaining[1:]
		if seen[sample.ID] || observation == nil || observation.observation.Version != DerivedVersion || observation.observation.Binding != observationBinding(sample) {
			return nil, ErrInput
		}
		seen[sample.ID] = true
		f := observation.observation.Features
		if f.Version != Version || f.SampleID != freshFeatures(sample.ID).SampleID {
			return nil, ErrInput
		}
		spec, known := templateSpec{}, false
		if e != nil {
			spec, known = e.templates[sample.Template]
		}
		if f.RegistryMatch != known {
			return nil, ErrInput
		}
		eligible := f.State == Analyzed && f.RegistryMatch && (!spec.builtin || builtinContractBound(sample, spec))
		items = append(items, batchItem{sample, f, spec, eligible})
	}
	return items, nil
}

func (e *Engine) AnalyzeDerivedBatch(samples []Sample, observations []*Derived) (Batch, error) {
	items, err := e.derivedItems(samples, observations)
	if err != nil {
		return Batch{}, err
	}
	return analyzeItems(items), nil
}

func (e *Engine) PairedDerivedDifference(samples []Sample, observations []*Derived, metric Metric) (Difference, error) {
	switch metric {
	case ContractDeviation, ExtraAffix, NeutralRefusal, UnsolicitedIdentity:
	default:
		return Difference{}, ErrInput
	}
	items, err := e.derivedItems(samples, observations)
	if err != nil {
		return Difference{}, err
	}
	return pairedItems(items, metric), nil
}
