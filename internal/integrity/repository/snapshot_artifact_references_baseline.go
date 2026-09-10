package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"

	"gorm.io/gorm"
)

func snapshotReferenceBaselineScope(ctx context.Context, row snapshotReferenceRow, raw []byte) (BaselineScope, bool, error) {
	zero := BaselineScope{}
	if err := snapshotKeyStrictJSON(ctx, raw); err != nil {
		return zero, false, snapshotReferenceJSONError(err)
	}
	object, ok := snapshotKeyObject(raw)
	if !ok {
		return zero, false, errSnapshotReferenceInvalid
	}
	// Migration 12 explicitly retains old unsigned rows with these defaults.
	// A partial default group or a signed empty scope cannot use that exception.
	if len(object) == 0 {
		if row.Unsigned != 1 || row.ManifestHash != "" || row.ResultHash != "" || row.SnapshotHash != "" || row.ParametersHash != "" {
			return zero, false, errSnapshotReferenceInvalid
		}
		return zero, true, nil
	}
	if len(raw) > 200<<10 || !executionHash.MatchString(row.SnapshotHash) || baselineHash(raw) != row.SnapshotHash {
		return zero, false, errSnapshotReferenceInvalid
	}
	version, ok := snapshotKeyJSONString(object["SchemaVersion"])
	if !ok || !snapshotKeyExactNames(object, "SchemaVersion") {
		return zero, false, errSnapshotReferenceInvalid
	}
	if version != "baseline.scope.v1" {
		return zero, false, errSnapshotReferenceUnsupported
	}
	var scope BaselineScope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&scope) != nil {
		return zero, false, errSnapshotReferenceInvalid
	}
	canonical, err := json.Marshal(scope)
	if err != nil || !bytes.Equal(raw, canonical) {
		return zero, false, errSnapshotReferenceInvalid
	}
	if scope.OrganizationID != row.OrganizationID || scope.RunID != row.RunID || scope.AnalysisRevision != row.Revision || scope.TargetID < 1 || scope.Model != row.Model || scope.Protocol != row.Protocol || scope.ManifestHash != row.ManifestHash || scope.ResultHash != row.ResultHash || scope.ParametersHash != row.ParametersHash {
		return zero, false, errSnapshotReferenceInvalid
	}
	for _, hash := range []string{scope.TemplateHash, scope.TokenizerHash, scope.ManifestHash, scope.ResultHash, scope.ParametersHash} {
		if !executionHash.MatchString(hash) {
			return zero, false, errSnapshotReferenceInvalid
		}
	}
	for _, version := range []string{scope.Versions.Rule, scope.Versions.Template, scope.Versions.Scoring, scope.Versions.Tokenizer} {
		if !executionLabel.MatchString(version) {
			return zero, false, errSnapshotReferenceInvalid
		}
	}
	if len(scope.Samples) < 1 || len(scope.Samples) > 150 || scope.ExpectedSamples != len(scope.Samples) || scope.ValidSamples < 0 || scope.ValidSamples > scope.ExpectedSamples {
		return zero, false, errSnapshotReferenceInvalid
	}
	for _, sample := range scope.Samples {
		if !executionLabel.MatchString(sample.TemplateID) || !executionLabel.MatchString(sample.TemplateVersion) || !executionHash.MatchString(sample.VariablesHash) {
			return zero, false, errSnapshotReferenceInvalid
		}
	}
	if ctx.Err() != nil {
		return zero, false, ErrUnavailable
	}
	return scope, row.Unsigned == 1, nil
}

func snapshotReferenceBaseline(ctx context.Context, tx *gorm.DB, row snapshotReferenceRow, raw []byte) (snapshotReferenceObservation, error) {
	zero := snapshotReferenceObservation{}
	scope, legacy, err := snapshotReferenceBaselineScope(ctx, row, raw)
	if err != nil {
		return zero, err
	}
	if scope.SchemaVersion == "" {
		return snapshotReferenceObservation{legacy: true, inputIncomplete: true}, nil
	}
	source := snapshotReferenceSources()[0]
	var runs []snapshotReferenceRow
	if err := tx.Table(source.table+" r").Select(snapshotReferenceColumns(tx, source)).Where("r.organization_id=? AND r.id=?", row.OrganizationID, row.RunID).Limit(2).Find(&runs).Error; err != nil {
		return zero, ErrUnavailable
	}
	if len(runs) != 1 || runs[0].Valid != 1 || runs[0].TargetID != scope.TargetID {
		return zero, errSnapshotReferenceInvalid
	}
	body, err := snapshotReferenceBody(ctx, tx, source, row.OrganizationID, row.RunID)
	if err != nil {
		return zero, err
	}
	observed, err := snapshotReferencePlan(ctx, runs[0], body, false)
	clear(body)
	if err != nil {
		return zero, err
	}
	if observed.legacy || observed.versions != scope.Versions || observed.templateHash != scope.TemplateHash || observed.tokenizerHash != scope.TokenizerHash || runs[0].ManifestHash != scope.ManifestHash || observed.targetModel != scope.Model || observed.targetProtocol != scope.Protocol || observed.targetParameter != scope.MaxOutputParameter {
		return zero, errSnapshotReferenceInvalid
	}
	want := make([]snapshotReferenceMember, len(scope.Samples))
	for i, sample := range scope.Samples {
		want[i] = snapshotReferenceMember{sample.TemplateID, sample.TemplateVersion}
	}
	order := func(a, b snapshotReferenceMember) int {
		return slices.Compare([]string{a.ID, a.Version}, []string{b.ID, b.Version})
	}
	slices.SortFunc(want, order)
	slices.SortFunc(observed.members, order)
	if !slices.Equal(want, observed.members) {
		return zero, errSnapshotReferenceInvalid
	}
	// This compares the retained original result bytes to the frozen baseline
	// digest only. Result schema/scoring dependencies belong to the next unit.
	var results []struct{ Body []byte }
	projection := "CASE WHEN " + snapshotKeyTextOK(tx, "conclusion_json", 1, 4<<20) + " THEN conclusion_json ELSE NULL END AS body"
	if err := tx.Table("integrity_run_results").Select(projection).Where("organization_id=? AND run_id=? AND analysis_revision=?", row.OrganizationID, row.RunID, row.Revision).Limit(2).Find(&results).Error; err != nil {
		for _, result := range results {
			clear(result.Body)
		}
		return zero, ErrUnavailable
	}
	defer func() {
		for _, result := range results {
			clear(result.Body)
		}
	}()
	if len(results) != 1 || len(results[0].Body) == 0 || baselineHash(results[0].Body) != scope.ResultHash {
		return zero, errSnapshotReferenceInvalid
	}
	if ctx.Err() != nil {
		return zero, ErrUnavailable
	}
	observed.legacy = legacy
	return observed, nil
}
