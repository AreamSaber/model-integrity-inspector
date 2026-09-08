package run

import (
	"context"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

const responseRetentionSummaryVersion = "mii.response-retention-summary.v1"

// This live S1 observation is separate from immutable report content. Counts
// describe stored response copies, not authenticated plaintext or request data.
type ResponseRetentionView struct {
	Version              string     `json:"version"`
	RunID                string     `json:"run_id"`
	AnalysisRevision     int        `json:"analysis_revision"`
	ObservedAt           time.Time  `json:"observed_at"`
	PolicyDays           int        `json:"policy_days"`
	PolicyVersion        int        `json:"policy_version"`
	AttemptCount         int        `json:"attempt_count"`
	RawDeletedCount      int        `json:"raw_deleted_count"`
	DisplayDeletedCount  int        `json:"display_deleted_count"`
	DisplayExpiredCount  int        `json:"display_expired_count"`
	DisplayRetainedCount int        `json:"display_retained_count"`
	LastDeletedAt        *time.Time `json:"last_deleted_at"`
}

func responseRetentionView(runID int64, row repository.ResponseRetentionSummary) (ResponseRetentionView, error) {
	if runID <= 0 || row.ObservedAt.IsZero() || row.PolicyDays < 0 || row.PolicyDays > 180 || row.PolicyVersion <= 0 || row.AttemptCount < 0 || row.AttemptCount > 1536 {
		return ResponseRetentionView{}, repository.ErrRetentionSource
	}
	for _, count := range []int{row.RawDeletedCount, row.DisplayDeletedCount, row.DisplayExpiredCount, row.DisplayRetainedCount} {
		if count < 0 || count > row.AttemptCount {
			return ResponseRetentionView{}, repository.ErrRetentionSource
		}
	}
	if row.DisplayDeletedCount+row.DisplayExpiredCount+row.DisplayRetainedCount > row.AttemptCount || (row.RawDeletedCount+row.DisplayDeletedCount == 0) != (row.LastDeletedAt == nil) || row.LastDeletedAt != nil && (row.LastDeletedAt.IsZero() || row.LastDeletedAt.After(row.ObservedAt)) {
		return ResponseRetentionView{}, repository.ErrRetentionSource
	}
	return ResponseRetentionView{Version: responseRetentionSummaryVersion, RunID: decimal(runID), AnalysisRevision: 1, ObservedAt: row.ObservedAt, PolicyDays: row.PolicyDays, PolicyVersion: row.PolicyVersion, AttemptCount: row.AttemptCount, RawDeletedCount: row.RawDeletedCount, DisplayDeletedCount: row.DisplayDeletedCount, DisplayExpiredCount: row.DisplayExpiredCount, DisplayRetainedCount: row.DisplayRetainedCount, LastDeletedAt: row.LastDeletedAt}, nil
}

func (s *Service) ResponseRetention(ctx context.Context, orgID, runID int64) (ResponseRetentionView, error) {
	if s == nil || s.cfg.Store == nil || ctx == nil || runID <= 0 {
		return ResponseRetentionView{}, ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	tenant, err := s.cfg.Store.WithOrganization(bounded, orgID)
	if err != nil {
		return ResponseRetentionView{}, err
	}
	row, err := tenant.ReadResponseRetentionSummary(runID)
	if err != nil {
		return ResponseRetentionView{}, err
	}
	return responseRetentionView(runID, row)
}
