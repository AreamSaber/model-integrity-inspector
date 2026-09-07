package run

import (
	"context"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

// AttemptTrendView.SuccessRatePercent is the observed successful dispatch
// fraction, not a prediction: uncertain/in-flight records remain in its
// explicit denominator but are not labelled failures. Latency includes known
// completed successes AND failures, never UNCERTAIN recovery placeholders.
type AttemptTrendView struct {
	Dispatched             int64    `json:"dispatched"`
	LogicalSamples         int64    `json:"logical_samples"`
	RetryAttempts          int64    `json:"retry_attempts"`
	Succeeded              int64    `json:"succeeded"`
	Failed                 int64    `json:"failed"`
	Uncertain              int64    `json:"uncertain"`
	InFlight               int64    `json:"in_flight"`
	SuccessRatePercent     *float64 `json:"success_rate_percent"`
	SuccessRateDenominator int64    `json:"success_rate_denominator"`
	LatencySamples         int64    `json:"latency_samples"`
	LatencyMeanMS          *float64 `json:"latency_mean_ms"`
	LatencyMinMS           *int64   `json:"latency_min_ms"`
	LatencyMaxMS           *int64   `json:"latency_max_ms"`
}

type TrendItem struct {
	Run      HistoryItem      `json:"run"`
	Attempts AttemptTrendView `json:"attempts"`
}

func (s *Service) Trends(ctx context.Context, orgID int64, page repository.ListOptions, filters repository.RunFilters) ([]TrendItem, bool, error) {
	tenant, err := s.tenant(ctx, orgID)
	if err != nil {
		return nil, false, err
	}
	rows, err := tenant.ListRunTrends(page, filters)
	if err != nil {
		return nil, false, err
	}
	items := make([]TrendItem, 0, len(rows.Items))
	for _, row := range rows.Items {
		run, err := historyItem(row.Run)
		if err != nil {
			return nil, false, err
		}
		attempts, err := attemptTrendView(row.Attempts)
		if err != nil {
			return nil, false, err
		}
		items = append(items, TrendItem{Run: run, Attempts: attempts})
	}
	return items, rows.HasMore, nil
}

func attemptTrendView(a repository.AttemptTrendRecord) (AttemptTrendView, error) {
	for _, n := range []int64{a.Dispatched, a.LogicalSamples, a.RetryAttempts, a.Succeeded, a.Failed, a.Uncertain, a.InFlight, a.LatencySamples} {
		if n < 0 || n > 3000 {
			return AttemptTrendView{}, repository.ErrResultDocument
		}
	}
	if a.Dispatched != a.Succeeded+a.Failed+a.Uncertain+a.InFlight || a.Dispatched != a.LogicalSamples+a.RetryAttempts || a.LatencySamples > a.Succeeded+a.Failed || a.LatencyTotalMS < 0 || a.LatencyTotalMS > a.LatencySamples*86400000 {
		return AttemptTrendView{}, repository.ErrResultDocument
	}
	out := AttemptTrendView{Dispatched: a.Dispatched, LogicalSamples: a.LogicalSamples, RetryAttempts: a.RetryAttempts, Succeeded: a.Succeeded, Failed: a.Failed, Uncertain: a.Uncertain, InFlight: a.InFlight, SuccessRateDenominator: a.Dispatched, LatencySamples: a.LatencySamples, LatencyMinMS: a.LatencyMinMS, LatencyMaxMS: a.LatencyMaxMS}
	if a.Dispatched > 0 {
		percent := 100 * float64(a.Succeeded) / float64(a.Dispatched)
		out.SuccessRatePercent = &percent
	}
	if a.LatencySamples == 0 {
		if a.LatencyMinMS != nil || a.LatencyMaxMS != nil || a.LatencyTotalMS != 0 {
			return AttemptTrendView{}, repository.ErrResultDocument
		}
	} else {
		if a.LatencyMinMS == nil || a.LatencyMaxMS == nil || *a.LatencyMinMS < 0 || *a.LatencyMaxMS > 86400000 || *a.LatencyMinMS > *a.LatencyMaxMS || a.LatencyTotalMS < *a.LatencyMinMS*a.LatencySamples || a.LatencyTotalMS > *a.LatencyMaxMS*a.LatencySamples {
			return AttemptTrendView{}, repository.ErrResultDocument
		}
		mean := float64(a.LatencyTotalMS) / float64(a.LatencySamples)
		out.LatencyMeanMS = &mean
	}
	return out, nil
}
