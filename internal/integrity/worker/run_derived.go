package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

// prepareRunDerived performs no network, credential, database or time lookup.
// The caller supplies its bounded completion context; this function never
// detaches cancellation. The completing transaction alone selects and persists
// the actual final outcome, rechecking all lease and persistence bindings.
func prepareRunDerived(ctx context.Context, config RunConfig, plan domain.ExecutionPlan, sample repository.LogicalSampleRecord, attempt repository.AttemptRecord, response *domain.NormalizedResponse, outcome domain.AttemptOutcome, recovered bool) (repository.AttemptDerivedCandidates, error) {
	empty := repository.AttemptDerivedCandidates{}
	if ctx == nil || config.DerivedBuilder == nil || config.DerivedSealer == nil {
		return empty, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if plan.AnalysisSourceVersion != domain.AnalysisSourceDerivedV1 || sample.OrganizationID <= 0 || sample.RunID <= 0 || sample.ID <= 0 || sample.ProbeInstanceID <= 0 || sample.ExecutionOrdinal < 0 || sample.Ordinal != sample.ExecutionOrdinal || sample.JobID == nil || *sample.JobID <= 0 || sample.CompletedAt != nil || sample.FinalAttemptID != nil || attempt.OrganizationID != sample.OrganizationID || attempt.RunID != sample.RunID || attempt.LogicalSampleID != sample.ID || attempt.JobID != *sample.JobID || attempt.ID <= 0 || attempt.AttemptNo < 1 || attempt.Status != "DISPATCHED" || attempt.Validity != "PENDING" || attempt.DerivedReceipt != repository.DerivedPending || attempt.StartedAt == nil || attempt.StartedAt.IsZero() || attempt.FinishedAt != nil {
		return empty, repository.ErrAnalysisSource
	}
	if len(plan.Manifest) == 0 || len(plan.Manifest) > 2<<20 || len(plan.Probes) > 150 || len(sample.RequestPlan) == 0 || len(sample.RequestPlan) > 2<<20 || len(attempt.RequestSnapshot) == 0 || len(attempt.RequestSnapshot) > 2<<20 {
		return empty, features.ErrLimit
	}
	var frozen domain.SamplePlan
	var wire domain.RequestSnapshot
	if !decodeRunDerivedCanonical(sample.RequestPlan, &frozen) || !decodeRunDerivedCanonical(attempt.RequestSnapshot, &wire) || frozen.Ordinal != sample.ExecutionOrdinal || wire.RequestHash != attempt.RequestHash {
		return empty, repository.ErrAnalysisSource
	}
	defer clear(wire.Payload)
	if recovered {
		if response != nil || outcome.Validity != "INVALID_RETRYABLE" || outcome.ErrorCode != "MI_UNCERTAIN_ATTEMPT" || outcome.HTTPStatus != 0 || outcome.PromptTokens != nil || outcome.CompletionTokens != nil || outcome.LocalCompletionTokens != 0 || outcome.DurationMillis != 0 || outcome.TokenizerID != "" || outcome.TokenizerQuality != "" || outcome.RetryAfterSeconds != 0 {
			return empty, repository.ErrAnalysisSource
		}
	} else if response == nil || !normalRunDerivedOutcome(outcome.Validity, outcome.ErrorCode) {
		return empty, repository.ErrAnalysisSource
	}
	run := features.RunBinding{OrganizationID: sample.OrganizationID, ID: sample.RunID, Plan: plan}
	row := features.SampleBinding{OrganizationID: sample.OrganizationID, RunID: sample.RunID, ID: sample.ID, ProbeInstanceID: sample.ProbeInstanceID, Ordinal: sample.ExecutionOrdinal, ExecutionOrdinal: sample.ExecutionOrdinal, RequestPlan: frozen, AttemptCount: sample.AttemptCount}
	if sample.PairID != nil {
		row.PairID = *sample.PairID
	}
	// sample was normally read before ReserveAttempt incremented its count.
	// Do not fabricate a completed sample, final pointer or FinishedAt here.
	a := features.AttemptBinding{OrganizationID: attempt.OrganizationID, RunID: attempt.RunID, SampleID: attempt.LogicalSampleID, ID: attempt.ID, JobID: attempt.JobID, Number: attempt.AttemptNo, Snapshot: wire, RequestHash: attempt.RequestHash, StartedAt: *attempt.StartedAt}
	if response != nil {
		var err error
		a.Evidence, err = features.NewEvidence(features.EvidenceScope{OrganizationID: sample.OrganizationID, RunID: sample.RunID, SampleID: sample.ID, AttemptID: attempt.ID, RequestHash: attempt.RequestHash}, *response)
		if err != nil {
			return empty, err
		}
	}
	keys := [][3]string{{"COMPLETED", outcome.Validity, outcome.ErrorCode}, {"COMPLETED", "NOT_APPLICABLE", "MI_EXECUTION_CANCELLED"}, {"COMPLETED", "NOT_APPLICABLE", "MI_EXECUTION_TARGET_STALE"}, {"COMPLETED", "NOT_APPLICABLE", "MI_EXECUTION_BUDGET_EXCEEDED"}}
	if recovered {
		keys = [][3]string{{"UNCERTAIN", "INVALID_RETRYABLE", "MI_UNCERTAIN_ATTEMPT"}}
	}
	result := repository.AttemptDerivedCandidates{Scope: repository.AttemptDerivedScope{OrganizationID: sample.OrganizationID, RunID: sample.RunID, LogicalSampleID: sample.ID, ProbeInstanceID: sample.ProbeInstanceID, AttemptID: attempt.ID, JobID: attempt.JobID, AttemptNo: attempt.AttemptNo, Ordinal: sample.ExecutionOrdinal, ManifestHash: plan.ManifestHash, RequestHash: attempt.RequestHash}}
	seen := map[[3]string]bool{}
	for _, key := range keys {
		if seen[key] {
			continue
		}
		seen[key] = true
		a.Status, a.Validity, a.ErrorCode = key[0], key[1], key[2]
		prepared, err := config.DerivedBuilder.DeriveAttempt(ctx, run, row, a)
		if err != nil {
			return empty, err
		}
		record, err := config.DerivedSealer.Seal(ctx, prepared)
		if err != nil {
			return empty, err
		}
		result.Items = append(result.Items, repository.AttemptDerivedCandidate{Status: key[0], Validity: key[1], ErrorCode: key[2], Record: repository.DerivedRecord{Version: record.Version, KeyVersion: record.KeyVersion, Payload: record.Payload, MAC: record.MAC}})
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return result, nil
}

func decodeRunDerivedCanonical(data string, value any) bool {
	d := json.NewDecoder(strings.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		return false
	}
	canonical, err := json.Marshal(value)
	defer clear(canonical)
	return err == nil && bytes.Equal(canonical, []byte(data))
}

// Only source outcome keys are mirrored here; billing/usage validation stays
// in the repository. A minimal retained response can legitimately differ from
// the outcome's original accounting fields, so do not rewrite either source.
func normalRunDerivedOutcome(validity, code string) bool {
	switch validity {
	case "VALID", "VALID_WITH_WARNING":
		return code == ""
	case "INVALID_RETRYABLE", "INVALID_PROTOCOL", "INVALID_SAFETY_LIMIT", "NOT_APPLICABLE":
	default:
		return false
	}
	switch code {
	case "MI_NETWORK_TEMPORARY", "MI_CONNECTION_RESET", "MI_TIMEOUT", "MI_RATE_LIMITED", "MI_SERVICE_UNAVAILABLE", "MI_AUTH_FAILED", "MI_MODEL_NOT_FOUND", "MI_PROTOCOL_UNSUPPORTED", "MI_CLIENT_SAFETY_LIMIT", "MI_EVIDENCE_LIMIT", "MI_SAFETY_REFUSAL", "MI_EXECUTION_CANCELLED", "MI_EXECUTION_TARGET_STALE", "MI_EXECUTION_BUDGET_EXCEEDED", "MI_EXECUTION_CIRCUIT_OPEN":
		return true
	}
	return false
}
