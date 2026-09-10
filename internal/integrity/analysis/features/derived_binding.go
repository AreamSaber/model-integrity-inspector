package features

import "context"

// VerifyDerivedRecord binds one opaque authenticated record to its physical
// persistence row. It does not validate the complete Run graph, final pointers
// or record set, and cannot replace BuildDerived before analysis/publication.
func (b *Builder) VerifyDerivedRecord(ctx context.Context, run RunBinding, row SampleBinding, attempt AttemptBinding, record DerivedRecord, verifier *DerivedVerifier) error {
	if ctx == nil || b == nil || b.tokens == nil || verifier == nil {
		return ErrConfiguration
	}
	payload, err := verifier.open(ctx, record)
	if err != nil {
		return err
	}
	if payload.Scope != scopeFor(run, row, attempt) || payload.Extractor != b.extractor() || !validDerivedHash(payload.SourceHash) {
		return ErrBinding
	}
	return ctx.Err()
}
