import { ApiError, request } from './api'
import { closed, decimalID, integer, nullableNumber, readScope, riskLevels, versions, type RiskLevel } from './runs-history-api'
import { packages, runsApi, runStatuses, type RunPackage, type RunStatus, type Versions } from './runs-api'
import { trendInstant } from './trends-api'

export type OverviewDays = 7 | 30
export type RiskDistribution = Record<RiskLevel, number>
export interface RiskCounts { published_runs: number; scored_runs: number; unscored_runs: number; distribution: RiskDistribution }
export interface OverviewCohort extends RiskCounts { id: string; package: RunPackage; versions: Versions }
export interface OverviewDay { local_date: string; start_utc: string; end_utc: string; partial: boolean; run_count: number; risk_cohorts: (RiskCounts & { cohort_id: string })[] }
export interface Overview {
  schema_version: 'overview-v1'; scope: 'organization_window'; organization_id: string; analysis_revision: 1; development: true; calibrated: false
  window: { days: OverviewDays; timezone: string; as_of: string; start_utc: string; end_utc: string }
  targets: { total: number; active: number; disabled: number }
  runs: { total: number; by_status: Record<RunStatus, number>; unpublished_runs: number; published_runs: number; scored_runs: number; unscored_runs: number }
  costs: { currency: 'USD'; basis: 'persisted_run_estimate'; known_runs: number; unknown_runs: number; known_subtotal_micros: number | null; complete_total_micros: number | null }
  risk_cohorts: OverviewCohort[]; daily: OverviewDay[]
}
const count = (v: unknown): v is number => integer(v, 0, 10000)
const utc = (v: unknown): v is string => typeof v === 'string' && v.endsWith('Z') && trendInstant(v) !== null
const riskFields = ['published_runs', 'scored_runs', 'unscored_runs', 'distribution']
function riskCounts(v: unknown, extra: string[] = []): v is RiskCounts {
  return closed(v, [...riskFields, ...extra]) && count(v.published_runs) && v.published_runs > 0 && count(v.scored_runs) && count(v.unscored_runs) && v.published_runs === v.scored_runs + v.unscored_runs &&
    closed(v.distribution, [...riskLevels]) && riskLevels.every((key) => count((v.distribution as Record<string, unknown>)[key])) && riskLevels.reduce((n, key) => n + (v.distribution as RiskDistribution)[key], 0) === v.scored_runs
}
function localParts(instant: string, zone: string) {
  const parts = new Intl.DateTimeFormat('en-CA', { timeZone: zone, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' }).formatToParts(new Date(instant))
  const get = (type: string) => parts.find((p) => p.type === type)?.value
  return { date: `${get('year')}-${get('month')}-${get('day')}`, midnight: get('hour') === '00' && get('minute') === '00' && get('second') === '00' }
}
const tuple = (c: OverviewCohort) => [c.package, c.versions.rule_bundle, c.versions.template_bundle, c.versions.scoring, c.versions.tokenizer_bundle].join('\u0000')
// Counts must agree in both directions (whole window <-> cohorts <-> daily).
// No caller can turn an unknown cost or unpublished result into an observed 0.
export function overviewData(value: unknown, orgID: string, days: OverviewDays): value is Overview {
  if (!closed(value, ['schema_version', 'scope', 'organization_id', 'analysis_revision', 'development', 'calibrated', 'window', 'targets', 'runs', 'costs', 'risk_cohorts', 'daily']) || value.schema_version !== 'overview-v1' || value.scope !== 'organization_window' || value.organization_id !== orgID || value.analysis_revision !== 1 || value.development !== true || value.calibrated !== false || new TextEncoder().encode(JSON.stringify(value)).length > 256 * 1024) return false
  const w = value.window, t = value.targets, r = value.runs, c = value.costs
  if (!closed(w, ['days', 'timezone', 'as_of', 'start_utc', 'end_utc']) || w.days !== days || typeof w.timezone !== 'string' || w.timezone === 'Local' || !/^[A-Za-z0-9_+/-]{1,128}$/.test(w.timezone) || !utc(w.as_of) || !utc(w.start_utc) || !utc(w.end_utc) || trendInstant(w.as_of) !== trendInstant(w.end_utc) || trendInstant(w.start_utc)! >= trendInstant(w.end_utc)!) return false
  if (!closed(t, ['total', 'active', 'disabled']) || !count(t.total) || !count(t.active) || !count(t.disabled) || t.total !== t.active + t.disabled) return false
  if (!closed(r, ['total', 'by_status', 'unpublished_runs', 'published_runs', 'scored_runs', 'unscored_runs']) || !count(r.total) || !count(r.unpublished_runs) || !count(r.published_runs) || !count(r.scored_runs) || !count(r.unscored_runs) || r.total !== r.unpublished_runs + r.published_runs || r.published_runs !== r.scored_runs + r.unscored_runs || !closed(r.by_status, [...runStatuses]) || !runStatuses.every((key) => count((r.by_status as Record<string, unknown>)[key])) || runStatuses.reduce((n, key) => n + (r.by_status as Record<RunStatus, number>)[key], 0) !== r.total) return false
  if (!closed(c, ['currency', 'basis', 'known_runs', 'unknown_runs', 'known_subtotal_micros', 'complete_total_micros']) || c.currency !== 'USD' || c.basis !== 'persisted_run_estimate' || !count(c.known_runs) || !count(c.unknown_runs) || c.known_runs + c.unknown_runs !== r.total || !nullableNumber(c.known_subtotal_micros) || !nullableNumber(c.complete_total_micros) || (c.known_runs === 0) !== (c.known_subtotal_micros === null) || (c.known_runs === 0 || c.unknown_runs > 0 ? c.complete_total_micros !== null : c.complete_total_micros !== c.known_subtotal_micros)) return false
  if (!Array.isArray(value.risk_cohorts) || value.risk_cohorts.length > 16 || !Array.isArray(value.daily) || value.daily.length !== days) return false
  const cohorts = new Map<string, OverviewCohort>(), dailyTotals = new Map<string, RiskCounts>()
  let priorTuple = '', published = 0, scored = 0, unscored = 0
  for (let i = 0; i < value.risk_cohorts.length; i++) {
    const row: unknown = value.risk_cohorts[i]
    if (!riskCounts(row, ['id', 'package', 'versions']) || !('id' in row) || row.id !== `c${i + 1}` || !('package' in row) || !packages.some((p) => p === row.package) || !('versions' in row) || !versions(row.versions)) return false
    const cohort = row as OverviewCohort, key = tuple(cohort)
    if (priorTuple && key <= priorTuple) return false
    priorTuple = key; cohorts.set(cohort.id, cohort); published += cohort.published_runs; scored += cohort.scored_runs; unscored += cohort.unscored_runs
  }
  if (published !== r.published_runs || scored !== r.scored_runs || unscored !== r.unscored_runs) return false
  let runCount = 0, previousEnd = trendInstant(w.start_utc)!, previousDate = ''
  try {
    const lastDate = localParts(w.as_of, w.timezone).date
    for (let i = 0; i < value.daily.length; i++) {
      const d: unknown = value.daily[i]
      if (!closed(d, ['local_date', 'start_utc', 'end_utc', 'partial', 'run_count', 'risk_cohorts']) || typeof d.local_date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(d.local_date) || !utc(d.start_utc) || !utc(d.end_utc) || d.partial !== (i === days - 1) || !count(d.run_count) || !Array.isArray(d.risk_cohorts) || d.risk_cohorts.length > cohorts.size) return false
      const start = trendInstant(d.start_utc)!, end = trendInstant(d.end_utc)!, local = localParts(d.start_utc, w.timezone)
      if (start !== previousEnd || start % 1000000000n !== 0n || end < start || (i < days - 1 && end === start) || local.date !== d.local_date || !local.midnight || (previousDate && new Date(Date.parse(`${previousDate}T00:00:00Z`) + 86400000).toISOString().slice(0, 10) !== d.local_date) || (i === days - 1 && (d.local_date !== lastDate || end !== trendInstant(w.end_utc)))) return false
      previousEnd = end; previousDate = d.local_date; runCount += d.run_count
      const seen = new Set<string>(); let dayPublished = 0, priorIndex = 0
      for (const dc of d.risk_cohorts) {
        if (!riskCounts(dc, ['cohort_id']) || !('cohort_id' in dc) || typeof dc.cohort_id !== 'string' || !cohorts.has(dc.cohort_id) || seen.has(dc.cohort_id)) return false
        const index = Number(dc.cohort_id.slice(1)); if (index <= priorIndex) return false; priorIndex = index; seen.add(dc.cohort_id); dayPublished += dc.published_runs
        const acc = dailyTotals.get(dc.cohort_id) ?? { published_runs: 0, scored_runs: 0, unscored_runs: 0, distribution: Object.fromEntries(riskLevels.map((key) => [key, 0])) as RiskDistribution }
        acc.published_runs += dc.published_runs; acc.scored_runs += dc.scored_runs; acc.unscored_runs += dc.unscored_runs
        for (const key of riskLevels) acc.distribution[key] += dc.distribution[key]
        dailyTotals.set(dc.cohort_id, acc)
      }
      if (dayPublished > d.run_count) return false
    }
  } catch { return false }
  if (runCount !== r.total) return false
  for (const [id, cohort] of cohorts) { const acc = dailyTotals.get(id); if (!acc || acc.published_runs !== cohort.published_runs || acc.scored_runs !== cohort.scored_runs || acc.unscored_runs !== cohort.unscored_runs || riskLevels.some((key) => acc.distribution[key] !== cohort.distribution[key])) return false }
  return true
}
export const overviewApi = {
  async read(orgID: string, userID: string, days: OverviewDays, signal?: AbortSignal): Promise<Overview> {
    if ((days !== 7 && days !== 30) || !decimalID(userID)) throw new ApiError('MI_INVALID_REQUEST')
    const headers = readScope(orgID), grants = await runsApi.permissions(orgID, userID, signal)
    if (signal?.aborted) throw new DOMException('Cancelled', 'AbortError')
    if (!['run.read', 'target.read'].every((permission) => grants.permissions.includes(permission))) throw new ApiError('MI_PERMISSION_DENIED', 403)
    return request(`/overview?days=${days}`, (v): v is Overview => overviewData(v, orgID, days), { headers, signal })
  },
}
