import { ApiError, request } from './api'
import { closed, decimalID, integer, readScope } from './runs-history-api'

// S1 only: a current policy/deletion observation, never a report rewrite or a
// source for loading ciphertext, raw responses or authenticated display bodies.
export interface ResponseRetentionSummary {
  version: 'mii.response-retention-summary.v1'; run_id: string; analysis_revision: 1
  observed_at: string; policy_days: number; policy_version: number; attempt_count: number
  raw_deleted_count: number; display_deleted_count: number; display_expired_count: number; display_retained_count: number
  last_deleted_at: string | null
}

function timestamp(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 64) return false
  const match = /^(\d{4})-(\d{2})-(\d{2})[Tt](?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.exec(value)
  if (!match || !Number.isFinite(Date.parse(value))) return false
  // Date.parse normalizes e.g. February 30. Reject that alias instead of
  // presenting an invented observation date.
  const day = new Date(`${match[1]}-${match[2]}-${match[3]}T00:00:00Z`)
  return day.getUTCFullYear() === Number(match[1]) && day.getUTCMonth() + 1 === Number(match[2]) && day.getUTCDate() === Number(match[3])
}

// Both inputs have already passed timestamp(). Date.parse applies RFC3339
// offsets but truncates below milliseconds; compare the remaining nanoseconds
// separately so even a one-nanosecond future deletion fails closed.
function timestampAtOrBefore(left: string, right: string): boolean {
  const leftMillis = Date.parse(left), rightMillis = Date.parse(right)
  if (leftMillis !== rightMillis) return leftMillis < rightMillis
  const remainder = (value: string) => Number((/\.(\d{1,9})/.exec(value)?.[1] ?? '').padEnd(9, '0').slice(3))
  return remainder(left) <= remainder(right)
}

export function responseRetentionSummary(value: unknown, runID: string): value is ResponseRetentionSummary {
  if (!closed(value, ['version', 'run_id', 'analysis_revision', 'observed_at', 'policy_days', 'policy_version', 'attempt_count', 'raw_deleted_count', 'display_deleted_count', 'display_expired_count', 'display_retained_count', 'last_deleted_at']) ||
    value.version !== 'mii.response-retention-summary.v1' || !decimalID(value.run_id) || value.run_id !== runID || value.analysis_revision !== 1 || !timestamp(value.observed_at) || !integer(value.policy_days, 0, 180) || !integer(value.policy_version, 1) || !integer(value.attempt_count, 0, 1536) ||
    !integer(value.raw_deleted_count, 0, value.attempt_count) || !integer(value.display_deleted_count, 0, value.attempt_count) || !integer(value.display_expired_count, 0, value.attempt_count) || !integer(value.display_retained_count, 0, value.attempt_count) || !(value.last_deleted_at === null || timestamp(value.last_deleted_at))) return false
  const noDeletions = value.raw_deleted_count === 0 && value.display_deleted_count === 0
  if (noDeletions !== (value.last_deleted_at === null) || (value.last_deleted_at !== null && !timestampAtOrBefore(value.last_deleted_at, value.observed_at))) return false
  // Display categories are mutually exclusive; raw deletion is independent.
  // Check their shared Attempt bound separately from raw deletion.
  return value.display_expired_count <= value.attempt_count - value.display_deleted_count && value.display_retained_count <= value.attempt_count - value.display_deleted_count - value.display_expired_count
}

export const responseRetentionApi = {
  get(org: string, runID: string, analysisRevision: number, signal?: AbortSignal) {
    if (!decimalID(runID) || analysisRevision !== 1) throw new ApiError('MI_INVALID_REQUEST')
    return request(`/runs/${runID}/response-retention?analysis_revision=1`, (value): value is ResponseRetentionSummary => responseRetentionSummary(value, runID), { headers: readScope(org), signal })
  },
}
