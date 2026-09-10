import { ApiError, id, object, request } from './api'

export const checkNames = ['network', 'authentication', 'model', 'nonstream', 'stream', 'parameters'] as const
export const precheckErrors: Record<string, string> = {
  MI_AUTH_FAILED: '上游认证失败，请检查凭证。',
  MI_MODEL_NOT_FOUND: '上游未提供请求的模型。',
  MI_PROTOCOL_UNSUPPORTED: '上游不支持所需协议或能力。',
  MI_RATE_LIMITED: '上游限流，请稍后再评估是否发起新预检。',
  MI_TARGET_BLOCKED_ADDRESS: '目标地址被网络安全策略阻止。',
  MI_SECRET_UNAVAILABLE: '目标凭证暂不可用，请联系管理员。',
  MI_SERVICE_UNAVAILABLE: '预检服务暂不可用。',
  MI_NETWORK_FAILED: '无法完成上游网络连接。',
  MI_TIMEOUT: '上游请求超时。',
  MI_PRECHECK_STALE: '目标配置或凭证已变化，这次预检不适用于新版本。',
  MI_PRECHECK_EXPIRED: '预检已超过有效执行期限。',
  MI_PRECHECK_CANCELLED: '预检任务已取消。',
  MI_UNCERTAIN_ATTEMPT: '上游请求的完成情况不确定；不会自动重复可能计费的调用。',
  MI_PRECHECK_BUDGET_EXCEEDED: '预检请求预算已耗尽。',
  MI_PRECHECK_ATTEMPTS_EXHAUSTED: '预检执行尝试次数已耗尽。',
}
export interface Precheck {
  id: string; job_id: string; target_id: string; target_version: number; version: number
  status: 'queued' | 'running' | 'passed' | 'failed'; request_count: number
  checks: { name: typeof checkNames[number]; status: 'passed' | 'failed' | 'unsupported'; error_code?: string }[]
  error_code: string; max_output_parameter: '' | 'max_tokens' | 'max_completion_tokens'
  created_at: string; started_at: string | null; checked_at: string | null
}
function counter(value: unknown): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 }
function date(value: unknown): value is string { return typeof value === 'string' && value.length <= 64 && Number.isFinite(Date.parse(value)) }
function errorCode(value: unknown): value is string { return typeof value === 'string' && (value === '' || Object.hasOwn(precheckErrors, value)) }
function check(value: unknown): value is Precheck['checks'][number] {
  return object(value) && Object.keys(value).every((key) => ['name', 'status', 'error_code'].includes(key)) &&
    checkNames.some((name) => name === value.name) && typeof value.status === 'string' && ['passed', 'failed', 'unsupported'].includes(value.status) &&
    (value.error_code === undefined || errorCode(value.error_code)) && (value.status === 'passed' ? !value.error_code : Boolean(value.error_code))
}
export function precheck(value: unknown): value is Precheck {
  if (!object(value) || !Object.keys(value).every((key) => ['id', 'job_id', 'target_id', 'target_version', 'version', 'status', 'request_count', 'checks', 'error_code', 'max_output_parameter', 'created_at', 'started_at', 'checked_at'].includes(key))) return false
  return id(value.id) && id(value.job_id) && id(value.target_id) && counter(value.target_version) && counter(value.version) &&
    typeof value.status === 'string' && ['queued', 'running', 'passed', 'failed'].includes(value.status) && typeof value.request_count === 'number' && Number.isInteger(value.request_count) && value.request_count >= 0 && value.request_count <= 3 &&
    Array.isArray(value.checks) && value.checks.length <= 6 && value.checks.every(check) && new Set(value.checks.map((item) => item.name)).size === value.checks.length &&
    errorCode(value.error_code) && typeof value.max_output_parameter === 'string' && ['', 'max_tokens', 'max_completion_tokens'].includes(value.max_output_parameter) && date(value.created_at) &&
    (value.started_at === null || date(value.started_at)) && (value.checked_at === null || date(value.checked_at)) &&
    (value.status === 'passed' ? value.error_code === '' && value.checks.length === 6 && value.checks.every((item) => item.status === 'passed') && value.max_output_parameter !== '' && value.request_count > 0 && value.checked_at !== null :
      value.status === 'failed' ? value.error_code !== '' : value.error_code === '')
}
function path(targetID: string) { if (!id(targetID)) throw new ApiError('MI_INVALID_REQUEST'); return `/targets/${targetID}` }
function scope(org: string, csrf?: string): Record<string, string> {
  if (!id(org)) throw new ApiError('MI_INVALID_REQUEST')
  return { 'X-Organization-ID': org, ...(csrf ? { 'X-CSRF-Token': csrf } : {}) }
}
export const prechecksApi = {
  enqueue(org: string, csrf: string, targetID: string, version: number, key: string, signal?: AbortSignal) {
    if (!counter(version) || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(key)) throw new ApiError('MI_INVALID_REQUEST')
    return request(`${path(targetID)}/precheck`, (value): value is Precheck => precheck(value) && value.target_id === targetID && value.target_version === version,
      { body: { version }, headers: { ...scope(org, csrf), 'Idempotency-Key': key }, signal })
  },
  latest: (org: string, targetID: string, signal?: AbortSignal) => request(`${path(targetID)}/precheck`, (value): value is Precheck => precheck(value) && value.target_id === targetID, { headers: scope(org), signal }),
  get(org: string, targetID: string, precheckID: string, signal?: AbortSignal) {
    if (!id(precheckID)) throw new ApiError('MI_INVALID_REQUEST')
    return request(`${path(targetID)}/prechecks/${precheckID}`, (value): value is Precheck => precheck(value) && value.id === precheckID && value.target_id === targetID, { headers: scope(org), signal })
  },
}
