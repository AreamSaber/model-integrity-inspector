import { ApiError, request } from './api'
import { closed, decimalID, historyItem, integer, readScope, safeText, scalar, type RunHistoryItem } from './runs-history-api'
import { packages, runsApi, runStatuses, type RunPackage, type RunStatus } from './runs-api'

export interface AttemptTrend {
  dispatched: number; logical_samples: number; retry_attempts: number
  succeeded: number; failed: number; uncertain: number; in_flight: number
  success_rate_percent: number | null; success_rate_denominator: number
  latency_samples: number; latency_mean_ms: number | null; latency_min_ms: number | null; latency_max_ms: number | null
}
export interface TrendItem { run: RunHistoryItem; attempts: AttemptTrend }
export interface TrendsPage {
  items: TrendItem[]; next_cursor: string | null; scope: 'run_page'; analysis_revision: 1
  success_rate_basis: 'confirmed_successes_over_all_dispatches_percent'
  latency_basis: 'completed_attempts_with_observed_duration'; development: true; calibrated: false
}
export interface TrendsFilters { target_id: string; status?: RunStatus | ''; package?: RunPackage | ''; date_from?: string; date_to?: string }
export type TrendsRoute = { kind: 'form' } | { kind: 'target'; targetID: string } | { kind: 'invalid' }
export function trendsRoute(route: string): TrendsRoute | null {
  if (route === 'trends') return { kind: 'form' }
  if (!route.startsWith('trends/')) return null
  const parts = route.split('/')
  return parts.length === 2 && decimalID(parts[1]) ? { kind: 'target', targetID: parts[1] } : { kind: 'invalid' }
}
export function trendsHref(targetID: string) {
  if (!decimalID(targetID)) throw new ApiError('MI_INVALID_REQUEST')
  return `#/trends/${targetID}`
}
// Preserve RFC3339 nanoseconds for ordering: JavaScript Date alone would treat
// distinct database timestamps within one millisecond as ties and reorder IDs.
export function trendInstant(value: unknown): bigint | null {
  if (typeof value !== 'string') return null
  const parts = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/.exec(value)
  if (!parts) return null
  const wall = Date.parse(`${parts[1]}Z`), instant = Date.parse(`${parts[1]}${parts[3]}`)
  if (!Number.isFinite(wall) || !Number.isFinite(instant) || new Date(wall).toISOString().slice(0, 19) !== parts[1]) return null
  return BigInt(instant) * 1000000n + BigInt((parts[2] ?? '').padEnd(9, '0'))
}
function utcSecond(value: unknown): value is string { return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) && trendInstant(value) !== null }
export function utcFilterInput(value: string): string {
  if (!value) return ''
  // datetime-local may serialize an integral second with a zero millisecond
  // suffix. Accept that exact representation, never round fractional input.
  const integral = value.replace(/\.0{1,3}$/, '')
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(integral)) throw new ApiError('MI_INVALID_REQUEST')
  const utc = `${integral.length === 16 ? `${integral}:00` : integral}Z`
  if (!utcSecond(utc)) throw new ApiError('MI_INVALID_REQUEST')
  return utc
}
export function trendsQuery(filters: TrendsFilters, cursor = '') {
  if (!closed(filters, ['target_id', 'status', 'package', 'date_from', 'date_to']) || !decimalID(filters.target_id)) throw new ApiError('MI_INVALID_REQUEST')
  const query = new URLSearchParams({ target_id: filters.target_id, limit: '25' })
  if (filters.status !== undefined && filters.status !== '') { if (!runStatuses.includes(filters.status)) throw new ApiError('MI_INVALID_REQUEST'); query.set('status', filters.status) }
  if (filters.package !== undefined && filters.package !== '') { if (!packages.includes(filters.package)) throw new ApiError('MI_INVALID_REQUEST'); query.set('package', filters.package) }
  for (const key of ['date_from', 'date_to'] as const) {
    const value = filters[key]
    if (value === undefined || value === '') continue
    if (!utcSecond(value)) throw new ApiError('MI_INVALID_REQUEST')
    query.set(key, value)
  }
  if (filters.date_from && filters.date_to && trendInstant(filters.date_from)! > trendInstant(filters.date_to)!) throw new ApiError('MI_INVALID_REQUEST')
  if (cursor) { if (!safeText(cursor, 1024)) throw new ApiError('MI_INVALID_REQUEST'); query.set('cursor', cursor) }
  return query.toString()
}
export function attemptTrend(value: unknown): value is AttemptTrend {
  const counts = ['dispatched', 'logical_samples', 'retry_attempts', 'succeeded', 'failed', 'uncertain', 'in_flight', 'success_rate_denominator', 'latency_samples'] as const
  if (!closed(value, [...counts, 'success_rate_percent', 'latency_mean_ms', 'latency_min_ms', 'latency_max_ms']) || !counts.every((key) => integer(value[key], 0, 3000))) return false
  const v = value as unknown as AttemptTrend
  if (v.dispatched !== v.succeeded + v.failed + v.uncertain + v.in_flight || v.dispatched !== v.logical_samples + v.retry_attempts || v.success_rate_denominator !== v.dispatched || v.latency_samples > v.succeeded + v.failed) return false
  // Go currently emits the unrounded IEEE754 quotient, not a rounded UI value.
  // A small absolute tolerance only accommodates equivalent float serialization.
  if (v.dispatched === 0 ? v.success_rate_percent !== null : !scalar(v.success_rate_percent) || Math.abs(v.success_rate_percent - 100 * v.succeeded / v.dispatched) > 1e-9) return false
  if (v.latency_samples === 0) return v.latency_mean_ms === null && v.latency_min_ms === null && v.latency_max_ms === null
  return integer(v.latency_min_ms, 0, 86400000) && integer(v.latency_max_ms, v.latency_min_ms, 86400000) && scalar(v.latency_mean_ms, v.latency_min_ms, v.latency_max_ms)
}
export function trendsPage(value: unknown, filters: TrendsFilters, cursor = ''): value is TrendsPage {
  try { trendsQuery(filters, cursor) } catch { return false }
  if (!closed(value, ['items', 'next_cursor', 'scope', 'analysis_revision', 'success_rate_basis', 'latency_basis', 'development', 'calibrated']) || value.scope !== 'run_page' || value.analysis_revision !== 1 || value.success_rate_basis !== 'confirmed_successes_over_all_dispatches_percent' || value.latency_basis !== 'completed_attempts_with_observed_duration' || value.development !== true || value.calibrated !== false || !Array.isArray(value.items) || value.items.length > 25 || !(value.next_cursor === null || safeText(value.next_cursor, 1024)) || (value.next_cursor !== null && (value.items.length !== 25 || value.next_cursor === cursor))) return false
  const ids = new Set<string>()
  let prior: { instant: bigint; id: bigint } | null = null
  for (const item of value.items) {
    if (!closed(item, ['run', 'attempts']) || !historyItem(item.run) || !attemptTrend(item.attempts)) return false
    const run = item.run, attempts = item.attempts, instant = trendInstant(run.created_at)
    if (instant === null || run.target_id !== filters.target_id || run.version > 2147483647 || run.planned_samples > 1000 || attempts.dispatched !== run.request_count || attempts.logical_samples > run.planned_samples || ids.has(run.id) || (filters.status && run.status !== filters.status) || (filters.package && run.package !== filters.package) || (filters.date_from && instant < trendInstant(filters.date_from)!) || (filters.date_to && instant > trendInstant(filters.date_to)!)) return false
    const id = BigInt(run.id)
    if (prior && (instant > prior.instant || (instant === prior.instant && id >= prior.id))) return false
    ids.add(run.id); prior = { instant, id }
  }
  return true
}
export const trendsApi = {
  async list(orgID: string, userID: string, filters: TrendsFilters, cursor = '', signal?: AbortSignal): Promise<TrendsPage> {
    const bound = Object.freeze({ ...filters })
    const query = trendsQuery(bound, cursor), headers = readScope(orgID)
    if (!decimalID(userID)) throw new ApiError('MI_INVALID_REQUEST')
    const grants = await runsApi.permissions(orgID, userID, signal)
    if (signal?.aborted) throw new DOMException('Cancelled', 'AbortError')
    if (!grants.permissions.includes('run.read')) throw new ApiError('MI_PERMISSION_DENIED', 403)
    return request(`/runs/trends?${query}`, (v): v is TrendsPage => trendsPage(v, bound, cursor), { headers, signal })
  },
}
