package run

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func TestTrendViewMissingValuesAndExplicitAttemptDenominators(t *testing.T) {
	zero, err := attemptTrendView(repository.AttemptTrendRecord{})
	if err != nil || zero.SuccessRatePercent != nil || zero.LatencyMeanMS != nil || zero.LatencyMinMS != nil || zero.LatencyMaxMS != nil || zero.SuccessRateDenominator != 0 {
		t.Fatal("empty trend is not an observed zero", err)
	}
	minMS, maxMS := int64(0), int64(30)
	view, err := attemptTrendView(repository.AttemptTrendRecord{Dispatched: 6, LogicalSamples: 5, RetryAttempts: 1, Succeeded: 2, Failed: 2, Uncertain: 1, InFlight: 1, LatencySamples: 3, LatencyTotalMS: 50, LatencyMinMS: &minMS, LatencyMaxMS: &maxMS})
	if err != nil || view.SuccessRatePercent == nil || math.Abs(*view.SuccessRatePercent-100.0/3) > 0.000001 || view.SuccessRateDenominator != 6 || view.LatencyMeanMS == nil || math.Abs(*view.LatencyMeanMS-50.0/3) > 0.000001 || *view.LatencyMinMS != 0 {
		t.Fatal("trend changed dispatch fraction or actual observed zero", err)
	}
	body, err := json.Marshal(zero)
	if err != nil || !strings.Contains(string(body), `"success_rate_percent":null`) || !strings.Contains(string(body), `"latency_mean_ms":null`) {
		t.Fatal("missing is not JSON null")
	}
	unknown, err := attemptTrendView(repository.AttemptTrendRecord{Dispatched: 2, LogicalSamples: 2, Uncertain: 1, InFlight: 1})
	if err != nil || unknown.Failed != 0 || unknown.SuccessRatePercent == nil || *unknown.SuccessRatePercent != 0 || unknown.LatencyMeanMS != nil {
		t.Fatal("unknown became failed/latency-zero", err)
	}
}

func TestTrendViewRejectsInconsistentOrUnsafeAggregates(t *testing.T) {
	for name, a := range map[string]repository.AttemptTrendRecord{
		"negative": {Dispatched: -1}, "limit": {Dispatched: 3001, LogicalSamples: 3001, Succeeded: 3001},
		"partition": {Dispatched: 1, LogicalSamples: 1}, "retry": {Dispatched: 1, Succeeded: 1},
		"phantom latency": {LatencySamples: 1}, "negative latency": {LatencyTotalMS: -1},
		"missing range": {Dispatched: 1, LogicalSamples: 1, Succeeded: 1, LatencySamples: 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := attemptTrendView(a); !errors.Is(err, repository.ErrResultDocument) {
				t.Fatal("invalid aggregate accepted", err)
			}
		})
	}
	for _, bounds := range [][3]int64{{-1, 1, 0}, {0, 86400001, 1}, {5, 4, 5}, {5, 8, 4}, {5, 8, 9}} {
		minMS, maxMS := bounds[0], bounds[1]
		a := repository.AttemptTrendRecord{Dispatched: 1, LogicalSamples: 1, Succeeded: 1, LatencySamples: 1, LatencyMinMS: &minMS, LatencyMaxMS: &maxMS, LatencyTotalMS: bounds[2]}
		if _, err := attemptTrendView(a); !errors.Is(err, repository.ErrResultDocument) {
			t.Fatal("invalid latency range accepted", err)
		}
	}
}
