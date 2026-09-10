import { ApiError, request } from './api'
import { closed, decimalID, integer, isoDate, readPage, readScope, safeText, type ReadPage } from './runs-history-api'

export const reportFormats = ['json', 'html', 'csv'] as const
export type ReportFormat = typeof reportFormats[number]
export type ReportStatus = 'queued' | 'generating' | 'ready' | 'failed' | 'expired'
export const reportStatusLabels: Record<ReportStatus, string> = { queued: '已排队', generating: '正在生成', ready: '可下载', failed: '生成失败', expired: '已过期' }
export interface Report {
  id: string; run_id: string; analysis_revision: 1; revision: number; format: ReportFormat; schema_version: 'mii.report.v1'; status: ReportStatus
  content_hash?: string; file_hash?: string; file_size?: number; created_at: string; error_code?: 'MI_REPORT_GENERATION_FAILED'; review_state: 'not_included'
}
export interface ReportInput { format: ReportFormat; analysis_revision: 1; include_restricted_content: false }
export const reportMaximumBytes = 16 * 1024 * 1024
export const reportHash = (value: unknown): value is string => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value)
const format = (value: unknown): value is ReportFormat => reportFormats.some((item) => item === value)
export function report(value: unknown): value is Report {
  if (!closed(value, ['id', 'run_id', 'analysis_revision', 'revision', 'format', 'schema_version', 'status', 'content_hash', 'file_hash', 'file_size', 'created_at', 'error_code', 'review_state']) || !decimalID(value.id) || !decimalID(value.run_id) || value.analysis_revision !== 1 || !integer(value.revision, 1, 2147483647) || !format(value.format) || value.schema_version !== 'mii.report.v1' || !['queued', 'generating', 'ready', 'failed', 'expired'].includes(String(value.status)) || !isoDate(value.created_at) || value.review_state !== 'not_included' || (value.error_code !== undefined && value.error_code !== 'MI_REPORT_GENERATION_FAILED')) return false
  if (value.status === 'ready') return reportHash(value.content_hash) && reportHash(value.file_hash) && integer(value.file_size, 1, reportMaximumBytes) && value.error_code === undefined
  return value.content_hash === undefined && value.file_hash === undefined && value.file_size === undefined
}
function endpoint(runID: string, revision: number) {
  if (!decimalID(runID) || revision !== 1) throw new ApiError('MI_INVALID_REQUEST')
  return `/runs/${runID}/reports`
}
// A report revision has immutable identity and terminal bytes. Polling never
// substitutes the latest report or lets a response change its source/format.
export function reportUpdate(before: Report, next: Report): Report {
  const identity = ['id', 'run_id', 'analysis_revision', 'revision', 'format', 'schema_version', 'created_at', 'review_state'] as const
  const transitions: Record<ReportStatus, ReportStatus[]> = { queued: ['queued', 'generating', 'ready', 'failed'], generating: ['generating', 'ready', 'failed'], ready: ['ready'], failed: ['failed'], expired: ['expired'] }
  if (!report(before) || !report(next) || identity.some((key) => before[key] !== next[key]) || !transitions[before.status].includes(next.status) || (before.status === 'ready' && (before.content_hash !== next.content_hash || before.file_hash !== next.file_hash || before.file_size !== next.file_size))) throw new ApiError('MI_INVALID_RESPONSE')
  return next
}
export const reportsApi = {
  list(orgID: string, runID: string, revision: number, cursor = '', signal?: AbortSignal) {
    const path = endpoint(runID, revision), query = new URLSearchParams({ analysis_revision: String(revision), limit: '25' })
    if (cursor) { if (!safeText(cursor, 1024)) throw new ApiError('MI_INVALID_REQUEST'); query.set('cursor', cursor) }
    const page = readPage((value): value is Report => report(value) && value.run_id === runID && value.analysis_revision === revision)
    return request(`${path}?${query}`, (value): value is ReadPage<Report> => page(value) && value.items.length <= 25 && value.items.every((item, index, items) => index === 0 || BigInt(items[index - 1].id) < BigInt(item.id)), { headers: readScope(orgID), signal })
  },
  get(orgID: string, runID: string, revision: number, reportID: string, signal?: AbortSignal) {
    endpoint(runID, revision)
    if (!decimalID(reportID)) throw new ApiError('MI_INVALID_REQUEST')
    return request(`/reports/${reportID}`, (value): value is Report => report(value) && value.id === reportID && value.run_id === runID && value.analysis_revision === revision, { headers: readScope(orgID), signal })
  },
  create(orgID: string, runID: string, csrfToken: string, value: ReportInput, key: string, signal?: AbortSignal) {
    if (!closed(value, ['format', 'analysis_revision', 'include_restricted_content']) || !format(value.format) || value.analysis_revision !== 1 || value.include_restricted_content !== false || !/^[A-Za-z0-9._:-]{16,128}$/.test(key) || !/^[\x21-\x7e]{1,256}$/.test(csrfToken)) throw new ApiError('MI_INVALID_REQUEST')
    const body: ReportInput = { format: value.format, analysis_revision: value.analysis_revision, include_restricted_content: false }
    return request(endpoint(runID, value.analysis_revision), (data): data is Report => report(data) && data.run_id === runID && data.analysis_revision === value.analysis_revision && data.format === value.format, { method: 'POST', body, headers: { ...readScope(orgID), 'X-CSRF-Token': csrfToken, 'Idempotency-Key': key }, signal })
  },
}
