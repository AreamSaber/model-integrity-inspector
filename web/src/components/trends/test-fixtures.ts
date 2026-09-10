// Synthetic contract fixtures are test-only; product pages always call the API.
import type { AttemptTrend, TrendItem, TrendsPage } from '../../trends-api'
import { history, org, otherOrg, runID, userID, ok, fail } from '../results/test-fixtures'
export { org, otherOrg, runID, userID, ok, fail }
export const targetID = '9007199254741005', otherTargetID = '9007199254741007'
export function attempts(): AttemptTrend { return { dispatched: 10, logical_samples: 8, retry_attempts: 2, succeeded: 6, failed: 2, uncertain: 1, in_flight: 1, success_rate_percent: 60, success_rate_denominator: 10, latency_samples: 7, latency_mean_ms: 210.14285714285714, latency_min_ms: 0, latency_max_ms: 410 } }
export function emptyAttempts(): AttemptTrend { return { dispatched: 0, logical_samples: 0, retry_attempts: 0, succeeded: 0, failed: 0, uncertain: 0, in_flight: 0, success_rate_percent: null, success_rate_denominator: 0, latency_samples: 0, latency_mean_ms: null, latency_min_ms: null, latency_max_ms: null } }
export function item(offset = 0): TrendItem {
  return { run: { ...history(), id: String(BigInt(runID) - BigInt(offset)), created_at: new Date(Date.parse('2026-09-07T07:00:00Z') - offset * 60000).toISOString(), status: 'RUNNING', request_count: 10, completed_samples: 6, valid_sample_count: 5, finished_at: null, result: null }, attempts: attempts() }
}
export function page(count = 1, offset = 0): TrendsPage { return { items: Array.from({ length: count }, (_, i) => item(i + offset)), next_cursor: null, scope: 'run_page', analysis_revision: 1, success_rate_basis: 'confirmed_successes_over_all_dispatches_percent', latency_basis: 'completed_attempts_with_observed_duration', development: true, calibrated: false } }
