import type { Overview, OverviewDays, RiskDistribution } from '../../overview-api'
import { riskLevels } from '../../runs-history-api'
import { runStatuses, type RunStatus } from '../../runs-api'

export const org = '9007199254740995', userID = '9007199254740993', otherOrg = '9007199254740997'
export const distribution = (): RiskDistribution => Object.fromEntries(riskLevels.map((level) => [level, 0])) as RiskDistribution
export function overview(days: OverviewDays = 7, organizationID = org, populated = true): Overview {
  const end = '2026-09-07T12:00:00.123456789Z', first = new Date('2026-09-07T00:00:00Z'); first.setUTCDate(first.getUTCDate() - days + 1)
  const statuses = Object.fromEntries(runStatuses.map((s) => [s, 0])) as Record<RunStatus, number>
  if (populated) { statuses.QUEUED = 1; statuses.COMPLETED = 2 }
  const risk = { published_runs: 2, scored_runs: 1, unscored_runs: 1, distribution: { ...distribution(), medium: 1 } }
  return {
    schema_version: 'overview-v1', scope: 'organization_window', organization_id: organizationID, analysis_revision: 1, development: true, calibrated: false,
    window: { days, timezone: 'UTC', as_of: end, start_utc: first.toISOString(), end_utc: end }, targets: { total: populated ? 3 : 0, active: populated ? 2 : 0, disabled: populated ? 1 : 0 },
    runs: { total: populated ? 3 : 0, by_status: statuses, unpublished_runs: populated ? 1 : 0, published_runs: populated ? 2 : 0, scored_runs: populated ? 1 : 0, unscored_runs: populated ? 1 : 0 },
    costs: { currency: 'USD', basis: 'persisted_run_estimate', known_runs: populated ? 1 : 0, unknown_runs: populated ? 2 : 0, known_subtotal_micros: populated ? 1234567 : null, complete_total_micros: null },
    risk_cohorts: populated ? [{ id: 'c1', package: 'quick', versions: { rule_bundle: '1.0.0-dev.1', template_bundle: '1.0.0-dev.1', scoring: '1.0.0-dev.1', tokenizer_bundle: '1.0.0' }, ...structuredClone(risk) }] : [],
    daily: Array.from({ length: days }, (_, i) => { const start = new Date(first); start.setUTCDate(start.getUTCDate() + i); const next = new Date(start); next.setUTCDate(next.getUTCDate() + 1); return { local_date: start.toISOString().slice(0, 10), start_utc: start.toISOString(), end_utc: i === days - 1 ? end : next.toISOString(), partial: i === days - 1, run_count: i === days - 1 && populated ? 3 : 0, risk_cohorts: i === days - 1 && populated ? [{ cohort_id: 'c1', ...structuredClone(risk) }] : [] } }),
  }
}
export const ok = (data: unknown) => Response.json({ data, request_id: 'overview-request' })
export const fail = (code: string, status = 403) => Response.json({ error: { code, message: 'PRIVATE_OVERVIEW_ERROR' }, request_id: 'overview-error' }, { status })
