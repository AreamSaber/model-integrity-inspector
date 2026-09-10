package behavior

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDerivedBehaviorUsesIdenticalPatternAndPairAggregation(t *testing.T) {
	e := testEngine(t)
	for _, samples := range [][]Sample{repeatedSamples("Routing annotation confirms gateway transformation: "), pairedSamples(6, false, true)} {
		rawBatch, err := e.AnalyzeBatch(samples)
		if err != nil {
			t.Fatal(err)
		}
		rawPairs := []Difference{}
		for _, metric := range []Metric{ContractDeviation, ExtraAffix, NeutralRefusal, UnsolicitedIdentity} {
			d, err := e.PairedDifference(samples, metric)
			if err != nil {
				t.Fatal(err)
			}
			rawPairs = append(rawPairs, d)
		}
		observations := []*Derived{}
		for i, s := range samples {
			prepared, err := e.Derive(s)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := prepared.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte(testMarker)) || bytes.Contains(raw, []byte("Routing annotation")) || len(raw) > MaxDerivedBytes {
				t.Fatal("derived observation contains plaintext or exceeds bound")
			}
			// This unit test exercises only the post-auth codec; production's
			// parent features record authenticates these bytes before decoding.
			decoded, err := DecodeAuthenticatedDerived(raw)
			if err != nil {
				t.Fatal(err)
			}
			observations = append(observations, decoded)
			for j := range samples[i].Attempts {
				samples[i].Attempts[j].Content = ""
			}
		}
		derivedBatch, err := e.AnalyzeDerivedBatch(samples, observations)
		if err != nil {
			t.Fatal(err)
		}
		left, err := json.Marshal(rawBatch)
		if err != nil {
			t.Fatal(err)
		}
		right, err := json.Marshal(derivedBatch)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(left, right) {
			t.Fatal("pattern statistics changed")
		}
		for i, metric := range []Metric{ContractDeviation, ExtraAffix, NeutralRefusal, UnsolicitedIdentity} {
			d, err := e.PairedDerivedDifference(samples, observations, metric)
			if err != nil {
				t.Fatal(err)
			}
			left, err := json.Marshal(rawPairs[i])
			if err != nil {
				t.Fatal(err)
			}
			right, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(left, right) {
				t.Fatal("paired statistics changed")
			}
		}
	}
}

func TestDerivedBehaviorRejectsChangedPlanBindingAndShadowContent(t *testing.T) {
	for _, mode := range []string{"body", "contract", "variable", "pair", "template", "sample", "attempt", "missing", "duplicate", "empty", "registry"} {
		t.Run(mode, func(t *testing.T) {
			e := testEngine(t)
			samples := pairedSamples(1, false, true)
			observations := []*Derived{}
			for i, s := range samples {
				p, err := e.Derive(s)
				if err != nil {
					t.Fatal(err)
				}
				observations = append(observations, p)
				samples[i].Attempts[0].Content = ""
			}
			switch mode {
			case "body":
				samples[0].Attempts[0].Content = "shadow-body"
			case "contract":
				samples[0].Contract.Expected = "nonce_changed_123"
			case "variable":
				samples[0].Variables[0] = "nonce_changed_123"
			case "pair":
				samples[0].Pair.Arm = Variant
			case "template":
				samples[0].Template.ID = "format.en-us.1"
			case "sample":
				samples[0].ID++
			case "attempt":
				samples[0].Attempts[0].Number++
			case "missing":
				observations = observations[1:]
			case "duplicate":
				samples[1] = samples[0]
				observations[1] = observations[0]
			case "empty":
				observations[0] = &Derived{}
			case "registry":
				e = nil
			}
			if _, err := e.AnalyzeDerivedBatch(samples, observations); !errors.Is(err, ErrInput) {
				t.Fatal("mismatched observation accepted", err)
			}
		})
	}
	if _, err := (*Engine)(nil).PairedDerivedDifference(nil, nil, "unknown"); !errors.Is(err, ErrInput) {
		t.Fatal("unknown hypothesis")
	}
	if _, err := DecodeAuthenticatedDerived(bytes.Repeat([]byte{'x'}, MaxDerivedBytes+1)); !errors.Is(err, ErrLimit) {
		t.Fatal("oversized codec")
	}
	e := testEngine(t)
	p, err := e.Derive(sampleFor(1, "format.en-us.1", testMarker))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range [][]byte{append([]byte{' '}, raw...), bytes.Replace(raw, []byte(DerivedVersion), []byte("unknown"), 1), append(raw, []byte(`{}`)...), []byte(strings.Replace(string(raw), `"features":`, `"extra":1,"features":`, 1))} {
		if _, err := DecodeAuthenticatedDerived(malformed); !errors.Is(err, ErrInput) {
			t.Fatal("noncanonical/unknown codec accepted")
		}
	}
}
