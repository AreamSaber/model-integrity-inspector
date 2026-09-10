import { ApiError, request } from './api'
import { closed, decimalID, identifier, integer, isoDate, readPage, readScope, scalar, type ReadPage } from './runs-history-api'

export const baselineStatuses = ['draft', 'approved', 'expired', 'retired'] as const
export type BaselineStatus = typeof baselineStatuses[number]
export const baselineLabels: Record<BaselineStatus, string> = { draft: '待审批草稿', approved: '组织已审核参考', expired: '已过期 · 需重新采样', retired: '已退休' }
export const baselineLimitations: Record<string, string> = {
  MI_BASELINE_SOURCE_ORGANIZATION_DECLARED: '来源由组织声明，系统未验证官方身份', MI_BASELINE_REGION_UNVERIFIED: '区域由组织声明，系统未验证',
  MI_DEVELOPMENT_RULES_UNCALIBRATED: '当前开发规则未经独立校准', MI_PUBLIC_DEVELOPMENT_TEMPLATES: '使用公开开发模板',
  MI_BASELINE_SCORING_NOT_ENABLED: '尚不参与可信对照评分或证据等级提升', MI_BASELINE_EXPIRED_RESAMPLE: '基线已过期，请重新采样并创建新草稿',
  MI_BASELINE_NOT_APPROVED: '草稿尚未审批', MI_BASELINE_SOURCE_PARTIAL: '来源分析存在完整性限制',
}
const requiredLimitations = Object.keys(baselineLimitations).slice(0, 5)
export interface Baseline {
  id: string; run_id: string; target_id: string; analysis_revision: 1; version: number; name: string; source: 'official' | 'historical'
  source_assurance: 'organization_declared_unverified'; region: string; region_assurance: 'organization_declared_unverified'; model: string; protocol: 'openai_chat'
  parameters_hash: string; manifest_hash: string; rule_version: string; template_version: string; scoring_version: '1.0.0-dev.1'; tokenizer_version: string
  status: BaselineStatus; expected_samples: number; valid_samples: number; overall_risk: number | null; created_by: string; approved_by: string | null
  created_at: string; updated_at: string; sampled_at: string; approved_at: string | null; expires_at: string; retired_at: string | null
  approval_meaning: 'organization_reviewed_reference_only'; development: true; calibrated: false; eligible_for_scoring: false; limitations: string[]
}
export interface BaselineCreate { name: string; run_id: string; analysis_revision: 1; source: 'official' | 'historical'; region: string; expires_at: string }
export interface BaselinePatch { version: number; name: string; expires_at: string }
export interface BaselineApproval { version: number; reason: string; business_review: string; acknowledge_development_limits: true }
const fields = ['id', 'run_id', 'target_id', 'analysis_revision', 'version', 'name', 'source', 'source_assurance', 'region', 'region_assurance', 'model', 'protocol', 'parameters_hash', 'manifest_hash', 'rule_version', 'template_version', 'scoring_version', 'tokenizer_version', 'status', 'expected_samples', 'valid_samples', 'overall_risk', 'created_by', 'approved_by', 'created_at', 'updated_at', 'sampled_at', 'approved_at', 'expires_at', 'retired_at', 'approval_meaning', 'development', 'calibrated', 'eligible_for_scoring', 'limitations']
export function baselineText(v: unknown, max: number, required = true): v is string { return typeof v === 'string' && new TextEncoder().encode(v).length <= max && !/[\p{Cc}\p{Cs}]/u.test(v) && (!required || v.trim().length > 0) }
const hash = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v)
const version = (v: unknown): v is number => integer(v, 1, 2147483647)
export function baseline(v: unknown): v is Baseline {
  if (!closed(v, fields) || !fields.every((key) => key in v) || !decimalID(v.id) || !decimalID(v.run_id) || !decimalID(v.target_id) || !decimalID(v.created_by) || v.analysis_revision !== 1 || !version(v.version) ||
    !baselineText(v.name, 128) || !['official', 'historical'].includes(String(v.source)) || v.source_assurance !== 'organization_declared_unverified' || v.region_assurance !== 'organization_declared_unverified' || !baselineText(v.region, 64, false) || !baselineText(v.model, 128) || v.protocol !== 'openai_chat' ||
    !hash(v.parameters_hash) || !hash(v.manifest_hash) || ![v.rule_version, v.template_version, v.tokenizer_version].every(identifier) || v.scoring_version !== '1.0.0-dev.1' || !baselineStatuses.some((status) => status === v.status) ||
    !integer(v.expected_samples, 1, 150) || !integer(v.valid_samples, 0, v.expected_samples) || !(v.overall_risk === null || scalar(v.overall_risk)) ||
    ![v.created_at, v.updated_at, v.sampled_at, v.expires_at].every(isoDate) || !(v.approved_at === null || isoDate(v.approved_at)) || !(v.retired_at === null || isoDate(v.retired_at)) || !(v.approved_by === null || decimalID(v.approved_by)) ||
    v.approval_meaning !== 'organization_reviewed_reference_only' || v.development !== true || v.calibrated !== false || v.eligible_for_scoring !== false || !Array.isArray(v.limitations) || v.limitations.length > 8 || !v.limitations.every((item) => typeof item === 'string' && Object.hasOwn(baselineLimitations, item)) || new Set(v.limitations).size !== v.limitations.length || !requiredLimitations.every((code) => (v.limitations as string[]).includes(code))) return false
  if ((v.approved_by === null) !== (v.approved_at === null) || (v.status === 'retired') !== (v.retired_at !== null)) return false
  if (v.status === 'draft' && (v.approved_by !== null || !v.limitations.includes('MI_BASELINE_NOT_APPROVED'))) return false
  if (v.status === 'approved' && (v.approved_by === null || v.version < 2 || v.valid_samples < 6 || v.overall_risk === null)) return false
  if (v.status === 'expired' && !v.limitations.includes('MI_BASELINE_EXPIRED_RESAMPLE')) return false
  return true
}
function path(id: string) { if (!decimalID(id)) throw new ApiError('MI_INVALID_REQUEST'); return `/baselines/${id}` }
function headers(org: string, csrf: string) { if (!/^[\x21-\x7e]{1,256}$/.test(csrf)) throw new ApiError('MI_INVALID_REQUEST'); return { ...readScope(org), 'X-CSRF-Token': csrf } }
export function baselineExpiry(value: unknown): value is string { return isoDate(value) && Date.parse(value) > Date.now() && Date.parse(value) <= Date.now() + 365 * 86400000 }
export function baselineCreate(value: unknown): value is BaselineCreate { return closed(value, ['name', 'run_id', 'analysis_revision', 'source', 'region', 'expires_at']) && baselineText(value.name, 128) && decimalID(value.run_id) && value.analysis_revision === 1 && ['official', 'historical'].includes(String(value.source)) && baselineText(value.region, 64, false) && baselineExpiry(value.expires_at) }
const immutable = ['run_id', 'target_id', 'analysis_revision', 'source', 'region', 'model', 'protocol', 'parameters_hash', 'manifest_hash', 'rule_version', 'template_version', 'scoring_version', 'tokenizer_version', 'expected_samples', 'valid_samples', 'overall_risk', 'created_by', 'created_at', 'sampled_at'] as const
function receipt(value: unknown, current: Baseline): value is Baseline { return baseline(value) && value.id === current.id && value.version === current.version + 1 && immutable.every((key) => value[key] === current[key]) }
export const baselinesApi = {
  list(org: string, query = '', cursor = '', signal?: AbortSignal) {
    if (!baselineText(query, 128, false) || !baselineText(cursor, 1024, false)) throw new ApiError('MI_INVALID_REQUEST')
    const params = new URLSearchParams({ limit: '25' }); if (query) params.set('q', query); if (cursor) params.set('cursor', cursor)
    const page = readPage(baseline)
    return request(`/baselines?${params}`, (value): value is ReadPage<Baseline> => page(value) && value.items.length <= 25, { headers: readScope(org), signal })
  },
  get(org: string, id: string, signal?: AbortSignal) { return request(path(id), (value): value is Baseline => baseline(value) && value.id === id, { headers: readScope(org), signal }) },
  create(org: string, csrf: string, user: string, value: BaselineCreate, signal?: AbortSignal) {
    if (!baselineCreate(value) || !decimalID(user)) throw new ApiError('MI_INVALID_REQUEST')
    const body = { name: value.name.trim(), run_id: value.run_id, analysis_revision: value.analysis_revision, source: value.source, region: value.region, expires_at: value.expires_at }
    return request('/baselines', (data): data is Baseline => baseline(data) && data.status === 'draft' && data.version === 1 && data.created_by === user && data.run_id === body.run_id && data.name === body.name && data.source === body.source && data.region === body.region && Date.parse(data.expires_at) === Date.parse(body.expires_at), { method: 'POST', body, headers: headers(org, csrf), signal })
  },
  patch(org: string, csrf: string, current: Baseline, value: BaselinePatch, signal?: AbortSignal) {
    if (!baseline(current) || current.status !== 'draft' || !closed(value, ['version', 'name', 'expires_at']) || value.version !== current.version || !baselineText(value.name, 128) || !baselineExpiry(value.expires_at)) throw new ApiError('MI_INVALID_REQUEST')
    const body = { version: value.version, name: value.name.trim(), expires_at: value.expires_at }
    return request(path(current.id), (data): data is Baseline => receipt(data, current) && data.status === 'draft' && data.name === body.name && Date.parse(data.expires_at) === Date.parse(body.expires_at), { method: 'PATCH', body, headers: headers(org, csrf), signal })
  },
  approve(org: string, csrf: string, user: string, current: Baseline, value: BaselineApproval, signal?: AbortSignal) {
    if (!baseline(current) || current.status !== 'draft' || current.valid_samples < 6 || current.overall_risk === null || Date.parse(current.expires_at) <= Date.now() || !decimalID(user) || !closed(value, ['version', 'reason', 'business_review', 'acknowledge_development_limits']) || value.version !== current.version || value.acknowledge_development_limits !== true || !baselineText(value.reason, 256) || !baselineText(value.business_review, 512, current.overall_risk >= 40)) throw new ApiError('MI_INVALID_REQUEST')
    const body = { version: value.version, reason: value.reason, business_review: value.business_review, acknowledge_development_limits: true }
    return request(`${path(current.id)}/approve`, (data): data is Baseline => receipt(data, current) && data.status === 'approved' && data.approved_by === user && data.name === current.name && data.expires_at === current.expires_at, { method: 'POST', body, headers: headers(org, csrf), signal })
  },
  retire(org: string, csrf: string, current: Baseline, reason: string, signal?: AbortSignal) {
    if (!baseline(current) || current.status === 'retired' || !baselineText(reason, 256)) throw new ApiError('MI_INVALID_REQUEST')
    return request(`${path(current.id)}/retire`, (data): data is Baseline => receipt(data, current) && data.status === 'retired' && data.name === current.name && data.expires_at === current.expires_at && data.approved_by === current.approved_by && data.approved_at === current.approved_at, { method: 'POST', body: { version: current.version, reason }, headers: headers(org, csrf), signal })
  },
}
