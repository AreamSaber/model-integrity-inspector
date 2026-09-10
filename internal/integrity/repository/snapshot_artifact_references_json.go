package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

// Preserve the actual repository target writer's historical byte bound
// (validTargetRecord), not the service's 128 Unicode characters or the current
// generator's narrower 256 bytes. An observation is not generator approval.
const snapshotReferenceModelMaxBytes = 512

func snapshotReferenceJSONError(err error) error {
	if errors.Is(err, ErrUnavailable) {
		return ErrUnavailable
	}
	if errors.Is(err, errSnapshotKeyUnsupported) {
		return errSnapshotReferenceUnsupported
	}
	return errSnapshotReferenceInvalid
}

func snapshotReferenceVersions(raw []byte) (domain.BundleVersions, error) {
	object, ok := snapshotKeyObject(raw)
	if !ok || len(object) != 4 {
		return domain.BundleVersions{}, errSnapshotReferenceInvalid
	}
	var out domain.BundleVersions
	for key, target := range map[string]*string{"rule": &out.Rule, "template": &out.Template, "scoring": &out.Scoring, "tokenizer": &out.Tokenizer} {
		value, ok := snapshotKeyJSONString(object[key])
		if !ok || !executionLabel.MatchString(value) {
			return domain.BundleVersions{}, errSnapshotReferenceInvalid
		}
		*target = value
	}
	return out, nil
}

func snapshotReferenceID(raw []byte, expected int64) bool {
	var got int64
	return len(raw) > 0 && string(raw) != "null" && json.Unmarshal(raw, &got) == nil && got == expected && got > 0
}

func snapshotReferencePlan(ctx context.Context, row snapshotReferenceRow, raw []byte, estimate bool) (snapshotReferenceObservation, error) {
	zero := snapshotReferenceObservation{}
	_, mode, err := snapshotKeyManifest(ctx, raw, snapshotKeyRow{OrganizationID: row.OrganizationID, ManifestHash: row.ManifestHash, AnalysisSource: row.AnalysisSource}, estimate)
	if err != nil {
		return zero, snapshotReferenceJSONError(err)
	}
	result := snapshotReferenceObservation{legacy: mode == 2, inputIncomplete: mode == 2}
	if !estimate {
		result.versions = domain.BundleVersions{Rule: row.Rule, Template: row.Template, Scoring: row.Scoring, Tokenizer: row.Tokenizer}
		for _, version := range []string{row.Rule, row.Template, row.Scoring, row.Tokenizer} {
			if !executionLabel.MatchString(version) {
				return zero, errSnapshotReferenceUnsupported
			}
		}
	}
	outer, _ := snapshotKeyObject(raw) // already strictly token-scanned
	planRaw, present := outer["plan"]
	if !present {
		return result, nil
	} // legitimate pre-manifest legacy root
	plan, ok := snapshotKeyObject(planRaw)
	if !ok || !snapshotKeyExactNames(plan, "versions", "target", "probes", "analysis_source_version") {
		return zero, errSnapshotReferenceInvalid
	}
	versionsRaw, hasVersions := plan["versions"]
	if hasVersions {
		versions, err := snapshotReferenceVersions(versionsRaw)
		if err != nil || !estimate && versions != result.versions {
			return zero, errSnapshotReferenceInvalid
		}
		result.versions = versions
	} else if !result.legacy {
		return zero, errSnapshotReferenceInvalid
	}
	if targetRaw, present := plan["target"]; present {
		target, ok := snapshotKeyObject(targetRaw)
		if !ok || !snapshotKeyExactNames(target, "id") || !snapshotReferenceID(target["id"], row.TargetID) {
			return zero, errSnapshotReferenceInvalid
		}
	} else if !result.legacy {
		return zero, errSnapshotReferenceInvalid
	}
	planSource := ""
	if sourceRaw, present := plan["analysis_source_version"]; present {
		var ok bool
		planSource, ok = snapshotKeyJSONString(sourceRaw)
		if !ok || planSource != "" && planSource != domain.AnalysisSourceDerivedV1 {
			return zero, errSnapshotReferenceInvalid
		}
	}
	if !estimate {
		expected := AnalysisSourceLegacyV1
		if planSource != "" {
			expected = planSource
		}
		if expected != row.AnalysisSource {
			return zero, errSnapshotReferenceInvalid
		}
	}
	probes, probesPresent := plan["probes"]
	if probesPresent {
		result.members, err = snapshotReferencePlanMembers(probes, result.legacy)
		if err != nil {
			return zero, err
		}
	} else if !result.legacy {
		return zero, errSnapshotReferenceInvalid
	}
	if result.legacy {
		return result, nil
	}
	m, _ := snapshotKeyObject(plan["manifest"])
	options, _ := snapshotKeyObject(m["options"])
	if !snapshotKeyExactNames(options, "rule_version", "scoring_version", "target", "analysis_source_version") {
		return zero, errSnapshotReferenceInvalid
	}
	checks := []struct {
		object        map[string]json.RawMessage
		key, expected string
	}{
		{options, "rule_version", result.versions.Rule}, {options, "scoring_version", result.versions.Scoring},
		{m, "template_version", result.versions.Template}, {m, "tokenizer_version", result.versions.Tokenizer},
	}
	for _, check := range checks {
		value, ok := snapshotKeyJSONString(check.object[check.key])
		if !ok || value != check.expected {
			return zero, errSnapshotReferenceInvalid
		}
	}
	target, ok := snapshotKeyObject(options["target"])
	if !ok || !snapshotKeyExactNames(target, "id") || !snapshotReferenceID(target["id"], row.TargetID) {
		return zero, errSnapshotReferenceInvalid
	}
	planTarget, _ := snapshotKeyObject(plan["target"])
	for key, field := range map[string]*string{"model": &result.targetModel, "protocol": &result.targetProtocol, "max_output_parameter": &result.targetParameter} {
		maxBytes := 128 // Keep the existing finite bounds for other historical fields.
		if key == "model" {
			maxBytes = snapshotReferenceModelMaxBytes
		}
		if !snapshotKeyExactNames(target, key) || !snapshotKeyExactNames(planTarget, key) {
			return zero, errSnapshotReferenceInvalid
		}
		left, leftPresent := planTarget[key]
		right, rightPresent := target[key]
		if !leftPresent && !rightPresent {
			continue
		}
		a, aOK := snapshotKeyJSONString(left)
		b, bOK := snapshotKeyJSONString(right)
		if !leftPresent || !rightPresent || !aOK || !bOK || a != b || len(a) > maxBytes {
			return zero, errSnapshotReferenceInvalid
		}
		*field = a
	}
	manifestSource := ""
	if sourceRaw, present := options["analysis_source_version"]; present {
		manifestSource, ok = snapshotKeyJSONString(sourceRaw)
		if !ok {
			return zero, errSnapshotReferenceInvalid
		}
	}
	if planSource != manifestSource {
		return zero, errSnapshotReferenceInvalid
	}
	for key, target := range map[string]*string{"template_hash": &result.templateHash, "tokenizer_hash": &result.tokenizerHash} {
		value, ok := snapshotKeyJSONString(m[key])
		if !ok || !executionHash.MatchString(value) {
			return zero, errSnapshotReferenceInvalid
		}
		*target = value
	}
	members, inputs, incomplete, err := snapshotReferenceManifestMembers(ctx, m["samples"], result.versions.Tokenizer, result.tokenizerHash)
	if err != nil {
		return zero, err
	}
	if !slices.Equal(result.members, members) {
		return zero, errSnapshotReferenceInvalid
	}
	result.inputTokenizers, result.inputIncomplete = inputs, incomplete
	if ctx.Err() != nil {
		return zero, ErrUnavailable
	}
	return result, nil
}

func snapshotReferenceObjects(raw []byte, limit int) ([]map[string]json.RawMessage, error) {
	var items []json.RawMessage
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &items) != nil || len(items) < 1 || len(items) > limit {
		return nil, errSnapshotReferenceInvalid
	}
	objects := make([]map[string]json.RawMessage, 0, len(items))
	for _, item := range items {
		object, ok := snapshotKeyObject(item)
		if !ok {
			return nil, errSnapshotReferenceInvalid
		}
		objects = append(objects, object)
	}
	return objects, nil
}

func snapshotReferenceMemberOf(object map[string]json.RawMessage, idKey, versionKey string) (snapshotReferenceMember, error) {
	if !snapshotKeyExactNames(object, idKey, versionKey) {
		return snapshotReferenceMember{}, errSnapshotReferenceInvalid
	}
	id, ok := snapshotKeyJSONString(object[idKey])
	version, versionOK := snapshotKeyJSONString(object[versionKey])
	if !ok || !versionOK || !executionLabel.MatchString(id) || !executionLabel.MatchString(version) {
		return snapshotReferenceMember{}, errSnapshotReferenceInvalid
	}
	return snapshotReferenceMember{id, version}, nil
}

// Preserve the ordinal/member relationship, not just a DISTINCT set: changing
// one repeated probe's member must not be hidden by another matching member.
func snapshotReferencePlanMembers(raw []byte, legacy bool) ([]snapshotReferenceMember, error) {
	probes, err := snapshotReferenceObjects(raw, 200)
	if err != nil {
		return nil, err
	}
	byOrdinal := make(map[int]snapshotReferenceMember)
	var legacyMembers []snapshotReferenceMember
	for _, probe := range probes {
		member, err := snapshotReferenceMemberOf(probe, "template_id", "template_version")
		if err != nil || !snapshotKeyExactNames(probe, "samples") {
			return nil, errSnapshotReferenceInvalid
		}
		samples, err := snapshotReferenceObjects(probe["samples"], 1000)
		if err != nil {
			return nil, err
		}
		localOrdinals := make(map[int]bool)
		for _, sample := range samples {
			var ordinal int
			if !snapshotKeyExactNames(sample, "ordinal") || len(sample["ordinal"]) == 0 || string(sample["ordinal"]) == "null" || json.Unmarshal(sample["ordinal"], &ordinal) != nil || ordinal < 0 || localOrdinals[ordinal] {
				return nil, errSnapshotReferenceInvalid
			}
			localOrdinals[ordinal] = true
			// The legacy low-level writer froze per-probe ordinals and assigned
			// execution_ordinal separately. No current compiler global-order
			// invariant may be retroactively imposed on that valid history.
			if legacy {
				legacyMembers = append(legacyMembers, member)
				if len(legacyMembers) > 1000 {
					return nil, errSnapshotReferenceLimit
				}
				continue
			}
			if _, found := byOrdinal[ordinal]; found {
				return nil, errSnapshotReferenceInvalid
			}
			byOrdinal[ordinal] = member
			if len(byOrdinal) > 1000 {
				return nil, errSnapshotReferenceLimit
			}
		}
	}
	if legacy {
		return legacyMembers, nil
	}
	result := make([]snapshotReferenceMember, len(byOrdinal))
	for i := range result {
		member, found := byOrdinal[i]
		if !found {
			return nil, errSnapshotReferenceInvalid
		}
		result[i] = member
	}
	return result, nil
}

func snapshotReferenceManifestMembers(ctx context.Context, raw []byte, configurationVersion, configurationHash string) ([]snapshotReferenceMember, []snapshotReferenceInputTokenizer, bool, error) {
	samples, err := snapshotReferenceObjects(raw, 150)
	if err != nil {
		return nil, nil, false, err
	}
	result := make([]snapshotReferenceMember, len(samples))
	inputs := make([]snapshotReferenceInputTokenizer, 0, len(samples))
	incomplete := false
	for i, sample := range samples {
		if ctx.Err() != nil {
			return nil, nil, false, ErrUnavailable
		}
		var ordinal int
		if !snapshotKeyExactNames(sample, "ordinal") || len(sample["ordinal"]) == 0 || string(sample["ordinal"]) == "null" || json.Unmarshal(sample["ordinal"], &ordinal) != nil || ordinal != i {
			return nil, nil, false, errSnapshotReferenceInvalid
		}
		result[i], err = snapshotReferenceMemberOf(sample, "template_id", "template_version")
		if err != nil {
			return nil, nil, false, err
		}
		input, present, partial, err := snapshotReferenceInputEstimate(sample, configurationVersion, configurationHash)
		if err != nil {
			return nil, nil, false, err
		}
		if present {
			inputs = append(inputs, input)
		}
		incomplete = incomplete || partial
	}
	return result, inputs, incomplete, nil
}
