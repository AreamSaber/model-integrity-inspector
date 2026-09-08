package features

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
)

func derivedFixture(t *testing.T) (fixture, []DerivedRecord, *DerivedVerifier) {
	t.Helper()
	f := newFixture(t, func(o *generator.Options) { o.Package, o.AnalysisSourceVersion = "quick", DerivedVersion })
	sealer, verifier, err := NewDerivedCapabilities("SYNTHETIC.v1", bytes.Repeat([]byte{0x39}, 32))
	if err != nil {
		t.Fatal(err)
	}
	records := []DerivedRecord{}
	for i := range f.input.Samples {
		for j := range f.input.Samples[i].Attempts {
			prepared, err := f.builder.DeriveAttempt(t.Context(), f.input.Run, f.input.Samples[i], f.input.Samples[i].Attempts[j])
			if err != nil {
				t.Fatal(err)
			}
			record, err := sealer.Seal(t.Context(), prepared)
			if err != nil {
				t.Fatal(err)
			}
			records = append(records, record)
			f.input.Samples[i].Attempts[j].Evidence = nil
		}
	}
	return f, records, verifier
}

func TestDerivedAuthenticationScopeAndFinalProjectionReject(t *testing.T) {
	for name, mutate := range map[string]func(*fixture, *[]DerivedRecord){
		"record-version": func(_ *fixture, r *[]DerivedRecord) { (*r)[0].Version = "mii.derived-s1.v99" },
		"key-version":    func(_ *fixture, r *[]DerivedRecord) { (*r)[0].KeyVersion = "missing" },
		"key-case":       func(_ *fixture, r *[]DerivedRecord) { (*r)[0].KeyVersion = "synthetic.v1" },
		"payload-tamper": func(_ *fixture, r *[]DerivedRecord) { (*r)[0].Payload[20] ^= 1 },
		"mac-tamper":     func(_ *fixture, r *[]DerivedRecord) { (*r)[0].MAC[0] ^= 1 },
		"missing":        func(_ *fixture, r *[]DerivedRecord) { *r = (*r)[1:] },
		"duplicate":      func(_ *fixture, r *[]DerivedRecord) { (*r)[1] = (*r)[0] },
		"extra":          func(_ *fixture, r *[]DerivedRecord) { *r = append(*r, (*r)[0]) },
		"scope-org":      func(f *fixture, _ *[]DerivedRecord) { f.input.Run.OrganizationID++ },
		"scope-run": func(f *fixture, _ *[]DerivedRecord) {
			f.input.Run.ID++
			for i := range f.input.Samples {
				f.input.Samples[i].RunID++
				f.input.Samples[i].Attempts[0].RunID++
			}
		},
		"scope-job":   func(f *fixture, _ *[]DerivedRecord) { f.input.Samples[0].Attempts[0].JobID++ },
		"scope-probe": func(f *fixture, _ *[]DerivedRecord) { f.input.Samples[0].ProbeInstanceID += 999 },
		"outcome":     func(f *fixture, _ *[]DerivedRecord) { f.input.Samples[0].Attempts[0].ErrorCode = "MI_TIMEOUT" },
		"sample": func(f *fixture, _ *[]DerivedRecord) {
			f.input.Samples[0].ID += 999
			f.input.Samples[0].Attempts[0].SampleID += 999
		},
		"request":        func(f *fixture, _ *[]DerivedRecord) { f.input.Samples[0].Attempts[0].Snapshot.Payload[20] ^= 1 },
		"final-pointer":  func(f *fixture, _ *[]DerivedRecord) { v := int64(77); f.input.Samples[0].FinalAttemptID = &v },
		"closed-time":    func(f *fixture, _ *[]DerivedRecord) { f.input.Run.ExecutionClosedAt = time.Time{} },
		"unfinished":     func(f *fixture, _ *[]DerivedRecord) { f.input.Samples[0].Attempts[0].Status = "DISPATCHED" },
		"response-mixed": func(f *fixture, _ *[]DerivedRecord) { f.input.Samples[0].Attempts[0].Evidence = &Evidence{} },
	} {
		t.Run(name, func(t *testing.T) {
			f, records, verifier := derivedFixture(t)
			mutate(&f, &records)
			if batch, err := f.builder.BuildDerived(t.Context(), f.input, records, verifier); !errors.Is(err, ErrBinding) || batch != nil {
				t.Fatal("invalid derived source accepted", err)
			}
		})
	}
}

func TestDerivedAuthenticatedCodecStillRejectsUnknownOrNoncanonical(t *testing.T) {
	for _, mode := range []string{"extractor", "payload-version", "unknown-field", "duplicate-field", "trailing", "whitespace", "missing-measurement", "structure-version", "behavior-version", "behavior-binding", "source-hash", "cluster"} {
		t.Run(mode, func(t *testing.T) {
			f, records, verifier := derivedFixture(t)
			var p derivedPayload
			if json.Unmarshal(records[0].Payload, &p) != nil {
				t.Fatal("fixture")
			}
			switch mode {
			case "extractor":
				p.Extractor.Behavior = "unknown"
			case "payload-version":
				p.Version = "unknown"
			case "missing-measurement":
				p.Feature = SampleFeature{}
			case "structure-version":
				p.Feature.Structure.Version = "unknown"
			case "behavior-version":
				p.Behavior = bytes.Replace(p.Behavior, []byte("mii.behavior-derived.v1"), []byte("mii.behavior-derived.v2"), 1)
			case "behavior-binding":
				var inner map[string]any
				if json.Unmarshal(p.Behavior, &inner) != nil {
					t.Fatal("fixture behavior")
				}
				inner["binding"] = strings.Repeat("a", 64)
				p.Behavior, _ = json.Marshal(inner)
			case "source-hash":
				p.SourceHash = strings.Repeat("x", 64)
			case "cluster":
				p.Feature.ClusterHash = strings.Repeat("a", 64)
			}
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "unknown-field":
				raw = append([]byte(`{"unknown":true,`), raw[1:]...)
			case "duplicate-field":
				raw = append([]byte(`{"version":"mii.derived-s1.v1",`), raw[1:]...)
			case "trailing":
				raw = append(raw, []byte(`{}`)...)
			case "whitespace":
				raw = append([]byte{' '}, raw...)
			}
			records[0].Payload = raw
			records[0].MAC, err = derivedMAC(verifier.authenticator, records[0].KeyVersion, raw)
			if err != nil {
				t.Fatal(err)
			}
			if batch, err := f.builder.BuildDerived(t.Context(), f.input, records, verifier); !errors.Is(err, ErrBinding) || batch != nil {
				t.Fatal("authenticated but invalid schema accepted", err)
			}
		})
	}
}

func TestDeriveRequiresFrozenActualBindingAndDetachesMeasurements(t *testing.T) {
	for _, mode := range []string{"nil", "plan", "scope", "wire", "number", "outcome", "evidence-scope", "limit"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, func(o *generator.Options) { o.Package, o.AnalysisSourceVersion = "quick", DerivedVersion })
			run, row, a := f.input.Run, f.input.Samples[0], f.input.Samples[0].Attempts[0]
			switch mode {
			case "nil":
				f.builder = nil
			case "plan":
				run.Plan.ManifestHash = strings.Repeat("a", 64)
			case "scope":
				a.SampleID++
			case "wire":
				a.Snapshot.Payload = []byte("{}")
			case "number":
				a.Number = 99
			case "outcome":
				a.Validity = "unknown"
			case "evidence-scope":
				a.Evidence.scope.AttemptID++
			case "limit":
				a.Evidence.response.Content = strings.Repeat("x", MaxResponseBytes+1)
			}
			if prepared, err := f.builder.DeriveAttempt(t.Context(), run, row, a); err == nil || prepared != nil {
				t.Fatal("unbound derivation accepted")
			}
		})
	}
	f := newFixture(t, func(o *generator.Options) { o.AnalysisSourceVersion = DerivedVersion })
	prepared, err := f.builder.DeriveAttempt(t.Context(), f.input.Run, f.input.Samples[0], f.input.Samples[0].Attempts[0])
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(prepared.canonical)
	*f.input.Samples[0].Attempts[0].Evidence.response.CompletionTokens = 123456
	if !bytes.Equal(before, prepared.canonical) {
		t.Fatal("prepared shares response memory")
	}
	for _, v := range []any{prepared} {
		if strings.Contains(fmt.Sprintf("%#v", v), string(before)) {
			t.Fatal("accidental payload disclosure")
		}
	}
}

type derivedTestMAC struct {
	inner  DerivedAuthenticator
	cancel context.CancelFunc
	fail   bool
	short  bool
}

func (m derivedTestMAC) DerivedMAC(version string, data []byte) ([]byte, error) {
	if m.cancel != nil {
		m.cancel()
	}
	if m.fail {
		return nil, errors.New("synthetic-private-provider-error")
	}
	if m.short {
		return []byte{1}, nil
	}
	return m.inner.DerivedMAC(version, data)
}

func TestDerivedCapabilityBoundedErrorsCancellationAndRotation(t *testing.T) {
	f, records, oldVerifier := derivedFixture(t)
	for _, key := range [][]byte{nil, {1}, make([]byte, 33)} {
		if _, _, err := NewDerivedCapabilities("v1", key); !errors.Is(err, ErrConfiguration) {
			t.Fatal("bad key")
		}
	}
	for _, version := range []string{"", "a b", strings.Repeat("a", 65)} {
		if _, _, err := NewDerivedCapabilities(version, make([]byte, 32)); !errors.Is(err, ErrConfiguration) {
			t.Fatal("bad version")
		}
	}
	rotated, err := NewDerivedVerifier(map[string][]byte{"SYNTHETIC.v1": bytes.Repeat([]byte{0x39}, 32), "v2": bytes.Repeat([]byte{0x41}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.builder.BuildDerived(t.Context(), f.input, records, rotated); err != nil {
		t.Fatal("historical purpose key did not verify", err)
	}
	wrong, err := NewDerivedVerifier(map[string][]byte{"SYNTHETIC.v1": bytes.Repeat([]byte{0x41}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.builder.BuildDerived(t.Context(), f.input, records, wrong); !errors.Is(err, ErrBinding) {
		t.Fatal("wrong purpose key accepted")
	}
	for _, mode := range []string{"cancel", "fail", "short"} {
		ctx, cancel := context.WithCancel(t.Context())
		mac := derivedTestMAC{inner: oldVerifier.authenticator, fail: mode == "fail", short: mode == "short"}
		if mode == "cancel" {
			mac.cancel = cancel
		}
		sealer, verifier, err := NewDerivedCapabilitiesWithMAC("SYNTHETIC.v1", mac)
		if err != nil {
			t.Fatal(err)
		}
		prepared := &PreparedDerived{bytes.Clone(records[0].Payload)}
		_, sealErr := sealer.Seal(ctx, prepared)
		_, openErr := verifier.open(ctx, records[0])
		cancel()
		if sealErr == nil || openErr == nil || strings.Contains(sealErr.Error()+openErr.Error(), "private-provider") {
			t.Fatal("capability failure leaked or succeeded")
		}
	}
	// Cancellation from inside MAC verification must be observed before release,
	// independently of the earlier sealer cancellation path.
	ctx, cancel := context.WithCancel(t.Context())
	_, cancelVerifier, err := NewDerivedCapabilitiesWithMAC("SYNTHETIC.v1", derivedTestMAC{inner: oldVerifier.authenticator, cancel: cancel})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cancelVerifier.open(ctx, records[0]); !errors.Is(err, context.Canceled) {
		t.Fatal("late verifier cancellation ignored")
	}
	cancel()
	records[0].Payload = make([]byte, MaxDerivedBytes+1)
	if _, err := oldVerifier.open(t.Context(), records[0]); !errors.Is(err, ErrBinding) {
		t.Fatal("oversized record accepted")
	}
	if _, err := f.builder.BuildDerived(t.Context(), f.input, make([]DerivedRecord, 451), oldVerifier); !errors.Is(err, ErrLimit) {
		t.Fatal("attempt limit not enforced")
	}
}
