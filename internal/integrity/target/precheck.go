package target

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

type PrecheckView struct {
	ID                 int64                      `json:"id"`
	JobID              int64                      `json:"job_id"`
	TargetID           int64                      `json:"target_id"`
	TargetVersion      int64                      `json:"target_version"`
	Status             string                     `json:"status"`
	Version            int64                      `json:"version"`
	RequestCount       int                        `json:"request_count"`
	MaxOutputParameter string                     `json:"max_output_parameter,omitempty"`
	Checks             []repository.PrecheckCheck `json:"checks"`
	ErrorCode          string                     `json:"error_code,omitempty"`
	CreatedAt          time.Time                  `json:"created_at"`
	StartedAt          *time.Time                 `json:"started_at,omitempty"`
	CheckedAt          *time.Time                 `json:"checked_at,omitempty"`
}

func precheckView(record repository.PrecheckRecord) (PrecheckView, error) {
	if record.JobID == nil || *record.JobID <= 0 || len(record.ResultJSON) > 8192 {
		return PrecheckView{}, repository.ErrUnavailable
	}
	var checks []repository.PrecheckCheck
	if err := json.Unmarshal([]byte(record.ResultJSON), &checks); err != nil {
		return PrecheckView{}, repository.ErrUnavailable
	}
	if checks == nil {
		checks = []repository.PrecheckCheck{}
	}
	return PrecheckView{ID: record.ID, JobID: *record.JobID, TargetID: record.TargetID, TargetVersion: record.TargetVersion, Status: record.Status,
		Version: record.Version, RequestCount: record.RequestCount, MaxOutputParameter: record.MaxOutputParameter, Checks: checks, ErrorCode: record.ErrorCode,
		CreatedAt: record.CreatedAt, StartedAt: record.StartedAt, CheckedAt: record.FinishedAt}, nil
}

func (service *Service) EnqueuePrecheck(ctx context.Context, orgID, targetID, expectedVersion int64, requestKey string) (PrecheckView, error) {
	snapshot, err := service.Snapshot(ctx, orgID, targetID)
	if err != nil {
		return PrecheckView{}, err
	}
	if expectedVersion != snapshot.TargetVersion {
		return PrecheckView{}, repository.ErrConflict
	}
	if requestKey == "" {
		id, err := repository.NewID()
		if err != nil {
			return PrecheckView{}, err
		}
		requestKey = strconv.FormatInt(id, 10)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return PrecheckView{}, ErrInvalid
	}
	tenant, err := service.store.WithOrganization(ctx, orgID)
	if err != nil {
		return PrecheckView{}, err
	}
	record, err := tenant.EnqueuePrecheck(repository.PrecheckRecord{OrganizationID: orgID, TargetID: targetID, TargetVersion: expectedVersion,
		SecretID: snapshot.SecretID, SecretVersion: snapshot.SecretVersion, RequestKey: requestKey, SnapshotJSON: string(encoded)})
	if err != nil {
		return PrecheckView{}, err
	}
	return precheckView(record)
}

// A zero precheck ID selects the latest persisted precheck for this target.
func (service *Service) GetPrecheck(ctx context.Context, orgID, targetID, precheckID int64) (PrecheckView, error) {
	tenant, err := service.store.WithOrganization(ctx, orgID)
	if err != nil {
		return PrecheckView{}, err
	}
	var record repository.PrecheckRecord
	if precheckID == 0 {
		record, err = tenant.GetLatestPrecheck(targetID)
	} else {
		record, err = tenant.GetPrecheck(targetID, precheckID)
	}
	if err != nil {
		return PrecheckView{}, err
	}
	value, err := precheckView(record)
	if err != nil {
		return PrecheckView{}, err
	}
	// Queue reconciliation is authoritative if a handler could not commit a
	// result (crash, cancellation before claim, exhausted recovery). Never leave
	// a terminal Job looking like a perpetually running or successful precheck.
	if value.Status == "queued" || value.Status == "running" {
		job, err := tenant.GetJob(value.JobID)
		if err != nil {
			return PrecheckView{}, err
		}
		if job.Status == "failed" || job.Status == "cancelled" {
			value.Status, value.ErrorCode, value.CheckedAt = "failed", "MI_SERVICE_UNAVAILABLE", job.CompletedAt
			if job.Status == "cancelled" {
				value.ErrorCode = "MI_PRECHECK_CANCELLED"
			} else if record.RequestCount > 0 {
				value.ErrorCode = "MI_UNCERTAIN_ATTEMPT"
			}
		}
	}
	return value, nil
}
