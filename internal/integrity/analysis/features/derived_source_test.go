package features

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
)

func responseReferenceFixture(t *testing.T, missing bool) (fixture, []DerivedRecord, *DerivedVerifier) {
	t.Helper()
	f := newFixture(t, func(o *generator.Options) { o.Package, o.AnalysisSourceVersion = "quick", DerivedVersion })
	if missing {
		f.input.Samples[0].Attempts[0].Evidence = nil
	}
	records, verifier := sealReferenceFixture(t, f)
	return f, records, verifier
}

func sealReferenceFixture(t *testing.T, f fixture) ([]DerivedRecord, *DerivedVerifier) {
	t.Helper()
	sealer, verifier, err := NewDerivedCapabilities("SOURCE.v1", bytes.Repeat([]byte{0x36}, 32))
	if err != nil {
		t.Fatal(err)
	}
	records := []DerivedRecord{}
	for _, row := range f.input.Samples {
		for _, attempt := range row.Attempts {
			prepared, err := f.builder.DeriveAttempt(t.Context(), f.input.Run, row, attempt)
			if err != nil {
				t.Fatal(err)
			}
			record, err := sealer.Seal(t.Context(), prepared)
			if err != nil {
				t.Fatal(err)
			}
			records = append(records, record)
		}
	}
	return records, verifier
}

func copyReferenceRows(input Input, removeResponses bool) Input {
	input.Samples = slices.Clone(input.Samples)
	for i := range input.Samples {
		input.Samples[i].Attempts = slices.Clone(input.Samples[i].Attempts)
		if removeResponses {
			for j := range input.Samples[i].Attempts {
				input.Samples[i].Attempts[j].Evidence = nil
			}
		}
	}
	return input
}

func TestDerivedSignedSourceCannotDowngradeOrUpgradeLegacy(t *testing.T) {
	f, records, verifier := responseReferenceFixture(t, false)
	if _, err := f.builder.Build(f.input); !errors.Is(err, ErrBinding) {
		t.Fatal("signed derived manifest entered legacy raw path")
	}
	bodyless := copyReferenceRows(f.input, true)
	if _, err := f.builder.Build(bodyless); !errors.Is(err, ErrBinding) {
		t.Fatal("missing raw evidence changed signed mode")
	}
	if _, err := f.builder.BuildDerived(t.Context(), bodyless, nil, verifier); !errors.Is(err, ErrBinding) {
		t.Fatal("deleting all S1 records silently changed analysis mode")
	}
	if _, err := f.builder.BuildResponseReference(t.Context(), f.input, nil, verifier); !errors.Is(err, ErrBinding) {
		t.Fatal("reference bypassed complete S1 requirement")
	}
	for _, mode := range []string{"", "mii.derived-s1.v2"} {
		changed := f.input
		changed.Run.Plan.AnalysisSourceVersion = mode
		for _, build := range []func() (*Batch, error){
			func() (*Batch, error) { return f.builder.Build(changed) },
			func() (*Batch, error) {
				return f.builder.BuildDerived(t.Context(), copyReferenceRows(changed, true), records, verifier)
			},
			func() (*Batch, error) {
				return f.builder.BuildResponseReference(t.Context(), changed, records, verifier)
			},
		} {
			if batch, err := build(); !errors.Is(err, ErrBinding) || batch != nil {
				t.Fatal("unsigned Plan source override accepted")
			}
		}
		if _, err := f.builder.DeriveAttempt(t.Context(), changed.Run, changed.Samples[0], changed.Samples[0].Attempts[0]); !errors.Is(err, ErrBinding) {
			t.Fatal("capture accepted Plan source override")
		}
	}
	// A DB edit can change the plain hash and the mirrored mode together, but
	// cannot authenticate deletion of the marker from the signed options.
	m := f.manifest
	m.Options.AnalysisSourceVersion = ""
	data, hash, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	changed := f.input
	changed.Run.Plan.Manifest, changed.Run.Plan.ManifestHash, changed.Run.Plan.AnalysisSourceVersion = data, hash, ""
	if batch, err := f.builder.Build(changed); !errors.Is(err, ErrBinding) || batch != nil {
		t.Fatal("removing signed marker and changing database hash enabled legacy path")
	}
	if batch, err := f.builder.BuildResponseReference(t.Context(), changed, records, verifier); !errors.Is(err, ErrBinding) || batch != nil {
		t.Fatal("reference accepted marker removal")
	}
	legacy := newFixture(t, nil)
	if _, err := legacy.builder.Build(legacy.input); err != nil {
		t.Fatal("legacy raw analysis no longer works", err)
	}
	if _, err := legacy.builder.DeriveAttempt(t.Context(), legacy.input.Run, legacy.input.Samples[0], legacy.input.Samples[0].Attempts[0]); !errors.Is(err, ErrBinding) {
		t.Fatal("unsigned legacy mode was upgraded during capture")
	}
}

func TestResponseReferencePreservesInputAndRealMissingObservation(t *testing.T) {
	for _, missing := range []bool{false, true} {
		f, records, verifier := responseReferenceFixture(t, missing)
		before := copyReferenceRows(f.input, false)
		batch, err := f.builder.BuildResponseReference(t.Context(), f.input, records, verifier)
		if err != nil || batch == nil || batch.Features().Included == 0 {
			t.Fatal("real raw reference unavailable", err)
		}
		if !reflect.DeepEqual(before, f.input) {
			t.Fatal("reference modified input response ownership or frozen rows")
		}
		derived, err := f.builder.BuildDerived(t.Context(), copyReferenceRows(f.input, true), records, verifier)
		if err != nil {
			t.Fatal(err)
		}
		left, err := json.Marshal(batch.Features())
		if err != nil {
			t.Fatal(err)
		}
		right, err := json.Marshal(derived.Features())
		if err != nil || !bytes.Equal(left, right) {
			t.Fatal("reference and derived final features differ")
		}
	}
}

func TestResponseReferenceRejectsDifferentRawSourcesAndAuthenticationFailures(t *testing.T) {
	for _, mode := range []string{"content", "provider-id", "mime", "model", "usage", "missing-raw", "scope", "missing-S1", "duplicate-S1", "tampered-S1", "final-pointer"} {
		t.Run(mode, func(t *testing.T) {
			f, records, verifier := responseReferenceFixture(t, false)
			a := &f.input.Samples[0].Attempts[0]
			switch mode {
			case "content":
				a.Evidence.response.Content = "different synthetic response"
			case "provider-id":
				a.Evidence.response.ProviderRequestID = "different-synthetic-provider-id"
			case "mime":
				a.Evidence.response.ContentType = "application/json; synthetic-marker=different"
			case "model":
				a.Evidence.response.ModelReported = "different-synthetic-model"
			case "usage":
				n := int64(123)
				a.Evidence.response.CompletionTokens = &n
			case "missing-raw":
				a.Evidence = nil
			case "scope":
				a.Evidence.scope.AttemptID++
			case "missing-S1":
				records = nil
			case "duplicate-S1":
				records[1] = records[0]
			case "tampered-S1":
				records[0].MAC[0] ^= 1
			case "final-pointer":
				id := int64(1)
				f.input.Samples[0].FinalAttemptID = &id
			}
			if batch, err := f.builder.BuildResponseReference(t.Context(), f.input, records, verifier); !errors.Is(err, ErrBinding) || batch != nil {
				t.Fatal("unverified/different raw reference released", err)
			}
		})
	}
}

func TestResponseReferenceChecksNonfinalRetrySourceAndAuthenticatedDigest(t *testing.T) {
	f := newFixture(t, func(o *generator.Options) { o.Package, o.AnalysisSourceVersion = "quick", DerivedVersion })
	row := &f.input.Samples[0]
	final := row.Attempts[0]
	old := final
	old.ID += 10000
	old.Validity, old.ErrorCode = "INVALID_RETRYABLE", "MI_NETWORK_TEMPORARY"
	response := old.Evidence.response
	response.Content = "synthetic earlier retry response"
	var err error
	old.Evidence, err = NewEvidence(EvidenceScope{f.input.Run.OrganizationID, f.input.Run.ID, row.ID, old.ID, old.RequestHash}, response)
	if err != nil {
		t.Fatal(err)
	}
	final.Number, row.AttemptCount = 2, 2
	row.Attempts = []AttemptBinding{old, final}
	records, verifier := sealReferenceFixture(t, f)
	if _, err := f.builder.BuildResponseReference(t.Context(), f.input, records, verifier); err != nil {
		t.Fatal("real complete retry chain rejected", err)
	}
	old.Evidence.response.Content = "changed earlier retry response"
	if batch, err := f.builder.BuildResponseReference(t.Context(), f.input, records, verifier); !errors.Is(err, ErrBinding) || batch != nil {
		t.Fatal("non-final retry source was not verified")
	}
	f, records, verifier = responseReferenceFixture(t, false)
	var p derivedPayload
	if json.Unmarshal(records[0].Payload, &p) != nil {
		t.Fatal("fixture decode")
	}
	p.SourceHash = strings.Repeat("a", 64)
	records[0].Payload, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	records[0].MAC, err = derivedMAC(verifier.authenticator, records[0].KeyVersion, records[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	// A valid MAC attests the trusted producer's source hash; only a raw oracle
	// can independently compare that assertion against the actual response.
	if _, err := f.builder.BuildDerived(t.Context(), copyReferenceRows(f.input, true), records, verifier); err != nil {
		t.Fatal("fixture was not an authenticated complete source", err)
	}
	if batch, err := f.builder.BuildResponseReference(t.Context(), f.input, records, verifier); !errors.Is(err, ErrBinding) || batch != nil {
		t.Fatal("authenticated but different source digest accepted by raw reference")
	}
}

type cancelReferenceMAC struct {
	inner    DerivedAuthenticator
	cancel   context.CancelFunc
	calls    int
	cancelAt int
}

func (m *cancelReferenceMAC) DerivedMAC(version string, payload []byte) ([]byte, error) {
	m.calls++
	if m.calls == m.cancelAt {
		m.cancel()
	}
	return m.inner.DerivedMAC(version, payload)
}

func TestResponseReferenceBoundsAndCancellation(t *testing.T) {
	f, records, verifier := responseReferenceFixture(t, false)
	var absentContext context.Context
	if _, err := f.builder.BuildResponseReference(absentContext, f.input, records, verifier); !errors.Is(err, ErrConfiguration) {
		t.Fatal("nil context accepted")
	}
	if _, err := f.builder.BuildResponseReference(t.Context(), f.input, records, nil); !errors.Is(err, ErrConfiguration) {
		t.Fatal("nil authenticator accepted")
	}
	if _, err := (*Builder)(nil).BuildResponseReference(t.Context(), f.input, records, verifier); !errors.Is(err, ErrConfiguration) {
		t.Fatal("nil builder accepted")
	}
	large := f.input
	large.Samples = make([]SampleBinding, 151)
	if _, err := f.builder.BuildResponseReference(t.Context(), large, records, verifier); !errors.Is(err, ErrLimit) {
		t.Fatal("sample budget ignored")
	}
	large.Samples = []SampleBinding{{Attempts: make([]AttemptBinding, 451)}}
	if _, err := f.builder.BuildResponseReference(t.Context(), large, records, verifier); !errors.Is(err, ErrLimit) {
		t.Fatal("attempt budget ignored")
	}
	if _, err := f.builder.BuildResponseReference(t.Context(), f.input, make([]DerivedRecord, 451), verifier); !errors.Is(err, ErrLimit) {
		t.Fatal("record budget ignored")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.builder.BuildResponseReference(ctx, f.input, records, verifier); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	mac := &cancelReferenceMAC{inner: verifier.authenticator, cancel: cancel, cancelAt: len(records) + 1}
	_, lateVerifier, err := NewDerivedCapabilitiesWithMAC("SOURCE.v1", mac)
	if err != nil {
		t.Fatal(err)
	}
	if batch, err := f.builder.BuildResponseReference(ctx, f.input, records, lateVerifier); !errors.Is(err, context.Canceled) || batch != nil || mac.calls != len(records)+1 {
		t.Fatal("late source-authentication cancellation released a reference")
	}
}
