package features

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestVerifyDerivedRecordBindsOpaquePayloadToPhysicalAttempt(t *testing.T) {
	f, records, verifier := derivedFixture(t)
	for i, row := range f.input.Samples {
		if err := f.builder.VerifyDerivedRecord(t.Context(), f.input.Run, row, row.Attempts[0], records[i], verifier); err != nil {
			t.Fatal("actual physical row binding rejected", err)
		}
	}
	records[0], records[1] = records[1], records[0]
	// The whole authenticated set still has every correct Attempt. Only the
	// per-row check can detect swapping payload+MAC while SQL mirrors stay put.
	if _, err := f.builder.BuildDerived(t.Context(), f.input, records, verifier); err != nil {
		t.Fatal("fixture no longer represents the same complete authenticated set", err)
	}
	for i := range 2 {
		row := f.input.Samples[i]
		if err := f.builder.VerifyDerivedRecord(t.Context(), f.input.Run, row, row.Attempts[0], records[i], verifier); !errors.Is(err, ErrBinding) {
			t.Fatal("swapped complete payload and MAC accepted for physical row")
		}
	}
}

func TestVerifyDerivedRecordScopeExtractorAndCancellationReject(t *testing.T) {
	f, records, verifier := derivedFixture(t)
	row := f.input.Samples[0]
	a := row.Attempts[0]
	wrong := a
	wrong.ErrorCode = "MI_TIMEOUT"
	if err := f.builder.VerifyDerivedRecord(t.Context(), f.input.Run, row, wrong, records[0], verifier); !errors.Is(err, ErrBinding) {
		t.Fatal("different physical outcome accepted")
	}
	var payload derivedPayload
	if json.Unmarshal(records[0].Payload, &payload) != nil {
		t.Fatal("fixture payload")
	}
	payload.Extractor.Features = "unknown"
	var err error
	records[0].Payload, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	records[0].MAC, err = derivedMAC(verifier.authenticator, records[0].KeyVersion, records[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.builder.VerifyDerivedRecord(t.Context(), f.input.Run, row, a, records[0], verifier); !errors.Is(err, ErrBinding) {
		t.Fatal("unsupported authenticated extractor accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := f.builder.VerifyDerivedRecord(ctx, f.input.Run, row, a, records[1], verifier); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled verification accepted")
	}
	if err := (*Builder)(nil).VerifyDerivedRecord(t.Context(), f.input.Run, row, a, records[1], verifier); !errors.Is(err, ErrConfiguration) {
		t.Fatal("nil builder accepted")
	}
	if err := f.builder.VerifyDerivedRecord(t.Context(), f.input.Run, row, a, records[1], nil); !errors.Is(err, ErrConfiguration) {
		t.Fatal("nil verifier accepted")
	}
}
