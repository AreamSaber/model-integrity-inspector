package capturefixture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"strconv"

	"model-integrity-inspector.local/mii/internal/integrity/analyzer"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/tests/replay"
)

// draftFromLease is only called in AnalysisSource.Use, after the real queue
// fence and all final-attempt rows are checked. No test INSERT or caller final
// flag substitutes for the actual Worker-persisted source.
func draftFromLease(data repository.AnalysisData, ring *secret.KeyRing, records map[string]exchange, caseID string) (replay.CaptureDraft, error) {
	if data.Run.ExecutionClosedAt == nil || len(data.Samples) == 0 || len(data.Samples) != len(data.Attempts) || len(data.Samples) != len(data.Evidence) || len(data.Samples) != len(records) {
		return replay.CaptureDraft{}, errCapture
	}
	var snapshot struct {
		Plan domain.ExecutionPlan `json:"plan"`
	}
	if json.Unmarshal([]byte(data.Run.ConfigSnapshot), &snapshot) != nil {
		return replay.CaptureDraft{}, errCapture
	}
	draft := replay.CaptureDraft{SchemaVersion: replay.SchemaVersion, Implementation: replay.Implementation, CaseID: caseID, KeyID: "dev-worker-capture", OrganizationID: data.Run.OrganizationID, RunID: data.Run.ID, Manifest: bytes.Clone(snapshot.Plan.Manifest), ManifestHash: data.Run.ManifestHash, ExecutionClosedAt: *data.Run.ExecutionClosedAt}
	attempts := map[int64]repository.AttemptRecord{}
	evidence := map[int64]repository.ResponseEvidenceRecord{}
	for _, a := range data.Attempts {
		attempts[a.ID] = a
	}
	for _, e := range data.Evidence {
		evidence[e.AttemptID] = e
	}
	for _, sample := range data.Samples {
		if sample.CompletedAt == nil || sample.AttemptCount != 1 || sample.FinalAttemptID == nil {
			return replay.CaptureDraft{}, errCapture
		}
		a, exists := attempts[*sample.FinalAttemptID]
		if !exists || a.AttemptNo != 1 || a.LogicalSampleID != sample.ID || a.StartedAt == nil || a.FinishedAt == nil || a.Status != "COMPLETED" {
			return replay.CaptureDraft{}, errCapture
		}
		observed, exists := records[a.RequestHash]
		if !exists {
			return replay.CaptureDraft{}, errCapture
		}
		var wire domain.RequestSnapshot
		if json.Unmarshal([]byte(a.RequestSnapshot), &wire) != nil || !bytes.Equal(wire.Payload, observed.wire) || wire.RequestHash != a.RequestHash {
			return replay.CaptureDraft{}, errCapture
		}
		record, exists := evidence[a.ID]
		if !exists {
			return replay.CaptureDraft{}, errCapture
		}
		response := replay.ResponseCapture{HTTPStatus: observed.status, Headers: observed.headers, Body: bytes.Clone(observed.body), BodyHash: hash(observed.body), End: "eof"}
		scope := secret.EvidenceScope{OrganizationID: data.Run.OrganizationID, RunID: data.Run.ID, LogicalSampleID: sample.ID, AttemptID: a.ID, RequestHash: a.RequestHash}
		sealed := secret.EvidenceRecord{KeyVersion: record.KeyVersion, Nonce: record.Nonce, Ciphertext: record.Ciphertext, PlaintextBytes: record.PlaintextBytes, ContentHash: record.ContentHash}
		err := ring.WithResponseEvidence(scope, sealed, func(value domain.NormalizedResponse) error {
			if value.HTTPStatus != observed.status || value.ResponseHash != response.BodyHash || value.RawResponseBytes != int64(len(response.Body)) {
				return errCapture
			}
			if value.StreamTerminated {
				response.End = "done"
			}
			var err error
			response.ProtocolHash, response.Timing, err = replay.ObserveResponse(value)
			return err
		})
		if err != nil {
			return replay.CaptureDraft{}, errCapture
		}
		attempt := replay.AttemptCapture{ID: a.ID, JobID: a.JobID, Number: a.AttemptNo, Status: a.Status, Validity: a.Validity, StartedAt: *a.StartedAt, FinishedAt: *a.FinishedAt, WirePayload: bytes.Clone(wire.Payload), RequestHash: a.RequestHash, Response: response}
		if a.ErrorCode != nil {
			attempt.ErrorCode = *a.ErrorCode
		}
		s := replay.SampleCapture{ID: sample.ID, ProbeInstanceID: sample.ProbeInstanceID, Ordinal: sample.Ordinal, ExecutionOrdinal: sample.ExecutionOrdinal, AttemptCount: sample.AttemptCount, FinalAttemptID: *sample.FinalAttemptID, Validity: sample.Validity, CompletedAt: *sample.CompletedAt, Attempts: []replay.AttemptCapture{attempt}}
		if sample.PairID != nil {
			s.PairID = *sample.PairID
		}
		draft.Samples = append(draft.Samples, s)
	}
	return draft, nil
}

// Exercise controller rejection on detached copies of genuine lease data;
// never mutate the repository's lent source or turn a forged copy into evidence.
func rejectChangedSource(data repository.AnalysisData, ring *secret.KeyRing, records map[string]exchange, caseID string) error {
	missing := make(map[string]exchange, len(records))
	for key, value := range records {
		missing[key] = value
	}
	for key := range missing {
		delete(missing, key)
		break
	}
	if _, err := draftFromLease(data, ring, missing, caseID); err == nil {
		return errCapture
	}
	extra := make(map[string]exchange, len(records)+1)
	for key, value := range records {
		extra[key] = value
	}
	extra["unmatched-development-record"] = exchange{}
	if _, err := draftFromLease(data, ring, extra, caseID); err == nil {
		return errCapture
	}
	changed := data
	changed.Samples = slices.Clone(data.Samples)
	changed.Samples[0].FinalAttemptID = nil
	if _, err := draftFromLease(changed, ring, records, caseID); err == nil {
		return errCapture
	}
	changed = data
	changed.Evidence = slices.Clone(data.Evidence)
	changed.Evidence[0].Ciphertext = bytes.Clone(data.Evidence[0].Ciphertext)
	changed.Evidence[0].Ciphertext[0] ^= 1
	if _, err := draftFromLease(changed, ring, records, caseID); err == nil {
		return errCapture
	}
	changed = data
	changed.Run.OrganizationID++
	if _, err := draftFromLease(changed, ring, records, caseID); err == nil {
		return errCapture
	}
	return nil
}

// sealSettled is the only controller call site for SealDevelopment. No bytes
// leave this function until actual immutable publication and zero-reservation
// final settlement have been reread successfully AFTER CompleteWith committed.
func sealSettled(ctx context.Context, tenant *repository.Tenant, draft replay.CaptureDraft, key ed25519.PrivateKey) ([]byte, analyzer.Document, error) {
	if ctx.Err() != nil {
		return nil, analyzer.Document{}, errCapture
	}
	run, err := tenant.GetRun(draft.RunID)
	if err != nil || run.OrganizationID != draft.OrganizationID || run.ManifestHash != draft.ManifestHash || run.ExecutionClosedAt == nil || !run.ExecutionClosedAt.Equal(draft.ExecutionClosedAt) || run.FinishedAt == nil || run.ReservedTokens != 0 || run.ReservedCostMicros != 0 || run.RequestCount != int64(len(draft.Samples)) || run.FinalizedSampleCount != int64(len(draft.Samples)) || run.CancelRequestedAt != nil || (run.Status != "COMPLETED" && run.Status != "PARTIAL" && run.Status != "REVIEW_REQUIRED") {
		return nil, analyzer.Document{}, errCapture
	}
	publication, err := tenant.GetPublishedAnalysis(run.ID, 1)
	if err != nil || !publication.IsPublished || publication.OrganizationID != draft.OrganizationID || publication.RunID != draft.RunID || publication.AnalysisRevision != 1 || len(publication.ConclusionJSON) > replay.MaxPredictionBytes {
		return nil, analyzer.Document{}, errCapture
	}
	var document analyzer.Document
	if json.Unmarshal([]byte(publication.ConclusionJSON), &document) != nil || document.SchemaVersion != analyzer.SchemaVersion || document.Features.OrganizationID != strconv.FormatInt(draft.OrganizationID, 10) || document.Features.RunID != strconv.FormatInt(draft.RunID, 10) || document.Features.ManifestHash != draft.ManifestHash || document.Features.Expected != len(draft.Samples) || len(document.Features.Samples) != len(draft.Samples) || document.Scores.Calibrated || !document.Scores.Development {
		return nil, analyzer.Document{}, errCapture
	}
	for i, sample := range draft.Samples {
		feature := document.Features.Samples[i]
		if feature.SampleID != strconv.FormatInt(sample.ID, 10) || feature.AttemptID != strconv.FormatInt(sample.FinalAttemptID, 10) || feature.Ordinal != sample.Ordinal {
			return nil, analyzer.Document{}, errCapture
		}
		// Attempt.Reserved* preserves the original reservation for history. Only
		// the Run's outstanding reservation counters must be zero after settlement.
		attempts, err := tenant.ListAttempts(sample.ID)
		if err != nil || len(attempts) != 1 || attempts[0].ID != sample.FinalAttemptID || attempts[0].Status != "COMPLETED" || attempts[0].RequestHash != sample.Attempts[0].RequestHash {
			return nil, analyzer.Document{}, errCapture
		}
	}
	draft.Commitment = replay.Commitment{RunStatus: run.Status, RunVersion: run.Version, AnalysisRevision: publication.AnalysisRevision, PublicationHash: hash([]byte(publication.ConclusionJSON)), FinishedAt: *run.FinishedAt, SettledRequests: int(run.RequestCount), ReservedTokens: run.ReservedTokens, ReservedCostMicros: run.ReservedCostMicros}
	encoded, err := replay.SealDevelopment(draft, key)
	if err != nil {
		return nil, analyzer.Document{}, err
	}
	return encoded, document, nil
}
