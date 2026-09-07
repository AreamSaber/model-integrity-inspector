import { ApiError, object, request } from './api'
import { packages, runStatuses, type RunPackage, type RunStatus, type Versions } from './runs-api'

export const riskLevels = ['low', 'watch', 'medium', 'high', 'critical', 'insufficient'] as const
export type RiskLevel = typeof riskLevels[number]
export const riskLabels: Record<RiskLevel, string> = { low: '低风险信号', watch: '需关注', medium: '中等风险信号', high: '高风险信号', critical: '严重黑盒统计异常', insufficient: '证据不足' }
export const packageLabels: Record<RunPackage, string> = { quick: '快速', standard: '标准', deep: '深度', custom: '自定义' }
export interface ResultBadge { analysis_revision: 1; overall_risk: number | null; confidence: number; evidence_grade: 'C' | 'D'; risk_level: RiskLevel; completeness: 'full' | 'partial' | 'insufficient' }
export interface RunHistoryItem {
  id: string; target_id: string; created_by: string; package: RunPackage; status: RunStatus; version: number; versions: Versions
  request_count: number; token_count: number; estimated_cost_micros: number | null; valid_sample_count: number; planned_samples: number; completed_samples: number
  created_at: string; started_at: string | null; finished_at: string | null; result: ResultBadge | null
  current_target_name: string | null; current_model: string | null; current_channel_id: string | null
}
export interface ReadPage<T> { items: T[]; next_cursor: string | null }
export interface HistoryFilters { q?: string; target_id?: string; status?: RunStatus | ''; package?: RunPackage | ''; model?: string; channel_id?: string; risk_level?: RiskLevel | ''; date_from?: string; date_to?: string }

// These guards intentionally reject additional fields: S2 must never enter a UI DTO.
export function closed(v: unknown, fields: string[]): v is Record<string, unknown> { return object(v) && Object.keys(v).every((k) => fields.includes(k)) }
export function decimalID(v: unknown): v is string { return typeof v === 'string' && /^[1-9][0-9]{0,18}$/.test(v) && BigInt(v) <= 9223372036854775807n }
export function integer(v: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): v is number { return typeof v === 'number' && Number.isSafeInteger(v) && v >= min && v <= max }
export function scalar(v: unknown, min = 0, max = 100): v is number { return typeof v === 'number' && Number.isFinite(v) && v >= min && v <= max }
export function nullableNumber(v: unknown): v is number | null { return v === null || integer(v) }
export function isoDate(v: unknown): v is string { return typeof v === 'string' && v.length <= 64 && /^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(v) && Number.isFinite(Date.parse(v)) }
export function safeText(v: unknown, max = 128): v is string { return typeof v === 'string' && v.length > 0 && new TextEncoder().encode(v).length <= max && !/\p{Cc}/u.test(v) }
export function identifier(v: unknown): v is string { return typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(v) }
export function versions(v: unknown): v is Versions { const keys = ['rule_bundle', 'template_bundle', 'scoring', 'tokenizer_bundle']; return closed(v, keys) && keys.every((key) => identifier(v[key])) }
export function resultBadge(v: unknown): v is ResultBadge {
  return closed(v, ['analysis_revision', 'overall_risk', 'confidence', 'evidence_grade', 'risk_level', 'completeness']) && v.analysis_revision === 1 &&
    (v.overall_risk === null || scalar(v.overall_risk)) && integer(v.confidence, 0, 74) && (v.evidence_grade === 'C' || v.evidence_grade === 'D') &&
    riskLevels.some((level) => level === v.risk_level) && ['full', 'partial', 'insufficient'].includes(String(v.completeness)) &&
    (v.completeness === 'full' || v.confidence <= 59) && (v.completeness !== 'insufficient' || (v.evidence_grade === 'D' && v.risk_level === 'insufficient'))
}
export function historyItem(v: unknown): v is RunHistoryItem {
  return closed(v, ['id', 'target_id', 'created_by', 'package', 'status', 'version', 'versions', 'request_count', 'token_count', 'estimated_cost_micros', 'valid_sample_count', 'planned_samples', 'completed_samples', 'created_at', 'started_at', 'finished_at', 'result', 'current_target_name', 'current_model', 'current_channel_id']) &&
    decimalID(v.id) && decimalID(v.target_id) && decimalID(v.created_by) && packages.some((p) => p === v.package) && runStatuses.some((s) => s === v.status) && integer(v.version, 1) && versions(v.versions) &&
    integer(v.request_count, 0, 100000) && integer(v.token_count) && nullableNumber(v.estimated_cost_micros) && integer(v.planned_samples, 0, 100000) && integer(v.completed_samples, 0, v.planned_samples) && integer(v.valid_sample_count, 0, v.completed_samples) &&
    isoDate(v.created_at) && (v.started_at === null || isoDate(v.started_at)) && (v.finished_at === null || isoDate(v.finished_at)) && (v.result === null || resultBadge(v.result)) &&
    [v.current_target_name, v.current_model, v.current_channel_id].every((s) => s === null || s === '' || safeText(s, 256))
}
export function readPage<T extends { id: string }>(guard: (v: unknown) => v is T) { return (v: unknown): v is ReadPage<T> => closed(v, ['items', 'next_cursor']) && Array.isArray(v.items) && v.items.length <= 100 && v.items.every(guard) && new Set(v.items.map((item) => item.id)).size === v.items.length && (v.next_cursor === null || safeText(v.next_cursor, 1024)) }
export function readScope(org: string) { if (!decimalID(org)) throw new ApiError('MI_INVALID_REQUEST'); return { 'X-Organization-ID': org } }
export function historyQuery(filters: HistoryFilters, cursor = '') {
  const query = new URLSearchParams({ limit: '25' })
  for (const [key, value] of Object.entries(filters)) {
    if (!['q', 'target_id', 'status', 'package', 'model', 'channel_id', 'risk_level', 'date_from', 'date_to'].includes(key)) throw new ApiError('MI_INVALID_REQUEST')
    if (value === undefined || value === '') continue
    if (!safeText(value, 128) || (key === 'target_id' && !decimalID(value)) || (key === 'status' && !runStatuses.includes(value as RunStatus)) || (key === 'package' && !packages.includes(value as RunPackage)) || (key === 'risk_level' && !riskLevels.includes(value as RiskLevel)) || (key.startsWith('date_') && !isoDate(value))) throw new ApiError('MI_INVALID_REQUEST')
    query.set(key, value)
  }
  if (filters.date_from && filters.date_to && Date.parse(filters.date_from) > Date.parse(filters.date_to)) throw new ApiError('MI_INVALID_REQUEST')
  if (cursor) { if (!safeText(cursor, 1024)) throw new ApiError('MI_INVALID_REQUEST'); query.set('cursor', cursor) }
  return query.toString()
}
export const historyApi = {
  list(org: string, filters: HistoryFilters = {}, cursor = '', signal?: AbortSignal) {
    return request(`/runs?${historyQuery(filters, cursor)}`, readPage(historyItem), { headers: readScope(org), signal })
  },
}
