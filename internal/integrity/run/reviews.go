package run

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

// ReviewView is a separate human decision, never an algorithm result override.
type ReviewView struct {
	ID               string    `json:"id"`
	RunID            string    `json:"run_id"`
	AnalysisRevision int       `json:"analysis_revision"`
	Conclusion       string    `json:"conclusion"`
	Explanation      string    `json:"explanation"`
	CreatedBy        string    `json:"created_by"`
	CreatedAt        time.Time `json:"created_at"`
}

// HTTP JSON is intentionally authorized human prose; generic diagnostics are
// not. Preserve the explicit JSON DTO while making accidental fmt/slog safe.
func (ReviewView) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("ReviewView{redacted}"))
}
func (ReviewView) LogValue() slog.Value { return slog.StringValue("ReviewView{redacted}") }

func reviewView(row repository.ReviewRecord) ReviewView {
	return ReviewView{decimal(row.ID), decimal(row.RunID), row.AnalysisRevision, row.Conclusion, row.Explanation, decimal(row.CreatedBy), row.CreatedAt}
}
func (s *Service) AppendReview(ctx context.Context, org int64, input repository.ReviewInput) (ReviewView, error) {
	if !repository.ValidReviewInput(input) {
		return ReviewView{}, ErrInvalid
	}
	// A malformed/unsupported source result cannot silently become reviewable.
	if _, err := s.Result(ctx, org, input.RunID, input.AnalysisRevision, false); err != nil {
		return ReviewView{}, err
	}
	tenant, err := s.tenant(ctx, org)
	if err != nil {
		return ReviewView{}, err
	}
	row, err := tenant.AppendReview(input)
	if err != nil {
		return ReviewView{}, err
	}
	return reviewView(row), nil
}
func (s *Service) Reviews(ctx context.Context, org, run int64, revision int, page repository.ListOptions) ([]ReviewView, error) {
	tenant, err := s.tenant(ctx, org)
	if err != nil {
		return nil, err
	}
	rows, err := tenant.ListReviews(run, revision, page)
	if err != nil {
		return nil, err
	}
	items := make([]ReviewView, 0, len(rows))
	for _, row := range rows {
		items = append(items, reviewView(row))
	}
	return items, nil
}
