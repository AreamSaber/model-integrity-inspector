import { ApiError, id, object, request } from './api'

export const packages = ['quick', 'standard', 'deep', 'custom'] as const
export type RunPackage = typeof packages[number]
export const runStatuses = ['DRAFT', 'PRECHECKING', 'QUEUED', 'RUNNING', 'ANALYZING', 'COMPLETED', 'PARTIAL', 'FAILED', 'REVIEW_REQUIRED', 'CANCELLING', 'CANCELLED'] as const
export type RunStatus = typeof runStatuses[number]
export const probeTypes = ['sequence', 'jsonl', 'format', 'neutral', 'differential', 'style', 'self_report'] as const
export type ProbeType = typeof probeTypes[number]
export interface RunOptions {
  max_requests?: number; max_tokens?: number; max_cost_micros?: number | null; max_minutes?: number; concurrency?: number; max_retries?: number
  repetitions?: number; max_output_levels?: number[]; probe_types?: ProbeType[]; languages?: ('zh-CN' | 'en-US')[]; stream_modes?: boolean[]
}
export interface EstimateInput { target_id: string; target_version: number; package: RunPackage; options: RunOptions }
export interface Versions { rule_bundle: string; template_bundle: string; scoring: string; tokenizer_bundle: string }
export interface RunEstimate {
  requests: number; input_tokens: number; max_output_tokens: number; cost_micros: number | null; duration_seconds: number
  usage_safety_factor: 1.25; warnings: string[]; completeness: 'full' | 'partial'
}
export interface Quote {
  id: string; target_id: string; target_version: number; package: RunPackage; manifest_hash: string; versions: Versions; estimate: RunEstimate; expires_at: string
  budgets: { max_requests: number; max_tokens: number; max_cost_micros: number | null; timeout_seconds: number }
}
export interface Run {
  id: string; target_id: string; created_by: string; package: RunPackage; status: RunStatus; version: number; versions: Versions; estimate: RunEstimate; manifest_hash: string
  request_count: number; token_count: number; estimated_cost_micros: number | null; valid_sample_count: number; planned_samples: number; completed_samples: number
  created_at: string; started_at: string | null; finished_at: string | null; execution_closed_at: string | null; error_summary: { code: string; count: number }[]
}

export const runMessages: Record<string, string> = {
  MI_RUN_ESTIMATE_EXPIRED: '预估草稿已过期，请重新预估后再确认。',
  MI_RUN_ESTIMATE_STALE: '目标、凭证、预算策略或版本已变化，请重新预估。',
  MI_RUN_ESTIMATE_LIMIT: '已达到活跃预估草稿限制，请等待旧草稿过期后再试。',
  MI_EXECUTION_NOT_READY: '检测执行或分析服务尚未就绪，尚不能创建可执行任务。',
  MI_PRECHECK_REQUIRED: '需要先完成该目标版本的预检，请返回目标页。',
  MI_PRECHECK_STALE: '预检对应旧的目标或凭证版本，请返回目标页重新预检。',
  MI_PRICE_UNKNOWN: '模型价格未知，不能使用金额预算；请联系管理员补充价格。',
  MI_EXECUTION_TARGET_STALE: '目标配置或凭证已变化，请重新读取目标并预估。',
  MI_PROBE_BUDGET_INSUFFICIENT: '预算无法容纳完整探针组，请调整预算或检测包。',
  MI_PROBE_CONFIGURATION_INVALID: '检测配置不适用，请检查档位、语言和模型能力。',
  MI_EXECUTION_BUDGET_EXCEEDED: '执行预算已耗尽，剩余样本未执行。',
  MI_EXECUTION_CANCELLED: '检测已请求取消；已经发生的调用和样本仍会保留。',
  MI_EXECUTION_CLOSED: '执行阶段已关闭，不能继续发起上游调用。',
  MI_EXECUTION_CONCURRENCY_LIMIT: '当前执行并发已达到服务端限制。',
  MI_EXECUTION_RATE_LIMIT: '目标请求速率已达到限制。',
  MI_UNCERTAIN_ATTEMPT: '部分上游调用结果不确定，已保留对应记录。',
  MI_AUTH_FAILED: '上游认证失败，请检查目标凭证。',
  MI_MODEL_NOT_FOUND: '上游未提供配置的模型。',
  MI_TIMEOUT: '请求或任务超过执行期限。',
  MI_NETWORK_FAILED: '无法完成上游网络连接。',
  MI_NETWORK_TEMPORARY: '上游出现临时网络故障。',
  MI_CONNECTION_RESET: '上游连接被重置。',
  MI_RATE_LIMITED: '请求被限流，请稍后再试。',
  MI_SERVICE_UNAVAILABLE: '检测服务暂不可用，请稍后重试。',
}
export const warningMessages: Record<string, string> = {
  MI_PROBE_DEVELOPMENT_UNCALIBRATED: '当前探针规则属于未校准开发版本。',
  MI_COST_ESTIMATE_NOT_BILLING_GUARANTEE: '估算不等于上游最终账单；隐藏推理或忽略上限可能增加费用。',
  MI_TEMPLATE_PUBLIC_DEVELOPMENT_POOL: '使用公开开发模板，不是经过独立批准的私有验收集。',
  MI_QUICK_NO_HIGH_CONFIDENCE_NEGATIVE: '快速包不能支持高置信度的阴性结论。',
  MI_STREAM_COMPARISON_NOT_APPLICABLE: '流式比较不适用，覆盖范围有限。',
  MI_STREAM_COMPARISON_DISABLED: '本次配置关闭了流式与非流式对照，不能据此判断流式差异。',
  MI_MODEL_LIMITS_CONSERVATIVE_ASSUMPTION: '模型档案限制不完整：缺失字段按上下文 4096 / 输出 1024 的保守默认值处理；这不是供应商能力声明。',
  MI_REPETITIONS_INSUFFICIENT: '重复次数不足，不能据此给出强结论。',
  MI_REQUEST_BUDGET_LIMIT: '请求预算限制了探针覆盖。',
  MI_TOKEN_BUDGET_LIMIT: 'Token 预算限制了探针覆盖。',
  MI_COST_BUDGET_LIMIT: '金额预算限制了探针覆盖。',
  MI_MODEL_OUTPUT_LIMIT: '模型输出上限限制了可用档位。',
  MI_CONTEXT_WINDOW_LIMIT: '上下文窗口限制了探针覆盖。',
  MI_TEMPLATE_NOT_AVAILABLE: '部分所需模板不可用。',
}

function closed(value: unknown, fields: string[]): value is Record<string, unknown> { return object(value) && Object.keys(value).every((key) => fields.includes(key)) }
function number(value: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum }
function date(value: unknown): value is string { return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(value) && value.length <= 64 && Number.isFinite(Date.parse(value)) }
function hash(value: unknown): value is string { return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value) }
function code(value: unknown): value is string { return typeof value === 'string' && /^MI_[A-Z0-9_]{1,80}$/.test(value) }
function money(value: unknown): value is number | null { return value === null || number(value) }
function version(value: unknown): value is number { return number(value, 1, 2147483647) }
function bundleVersions(value: unknown): value is Versions {
  const keys = ['rule_bundle', 'template_bundle', 'scoring', 'tokenizer_bundle']
  return closed(value, keys) && keys.every((key) => typeof value[key] === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value[key]))
}
function estimate(value: unknown): value is RunEstimate {
  return closed(value, ['requests', 'input_tokens', 'max_output_tokens', 'cost_micros', 'duration_seconds', 'usage_safety_factor', 'warnings', 'completeness']) &&
    number(value.requests, 1, 100000) && number(value.input_tokens) && number(value.max_output_tokens) && money(value.cost_micros) && number(value.duration_seconds, 1, 86400) &&
    value.usage_safety_factor === 1.25 && Array.isArray(value.warnings) && value.warnings.length <= 128 && value.warnings.every(code) &&
    (value.completeness === 'full' || value.completeness === 'partial')
}
export function quote(value: unknown): value is Quote {
  return closed(value, ['id', 'target_id', 'target_version', 'package', 'manifest_hash', 'versions', 'estimate', 'expires_at', 'budgets']) &&
    id(value.id) && id(value.target_id) && version(value.target_version) && packages.some((kind) => kind === value.package) && hash(value.manifest_hash) && bundleVersions(value.versions) && estimate(value.estimate) && date(value.expires_at) &&
    closed(value.budgets, ['max_requests', 'max_tokens', 'max_cost_micros', 'timeout_seconds']) && number(value.budgets.max_requests, 1, 100000) && number(value.budgets.max_tokens, 1, 1e12) && money(value.budgets.max_cost_micros) && number(value.budgets.timeout_seconds, 1, 86400) &&
    value.estimate.requests <= value.budgets.max_requests && value.estimate.input_tokens + value.estimate.max_output_tokens <= value.budgets.max_tokens &&
    (value.budgets.max_cost_micros === null || (value.estimate.cost_micros !== null && value.estimate.cost_micros <= value.budgets.max_cost_micros))
}
export function run(value: unknown): value is Run {
  return closed(value, ['id', 'target_id', 'created_by', 'package', 'status', 'version', 'versions', 'estimate', 'manifest_hash', 'request_count', 'token_count', 'estimated_cost_micros', 'valid_sample_count', 'planned_samples', 'completed_samples', 'created_at', 'started_at', 'finished_at', 'execution_closed_at', 'error_summary']) &&
    id(value.id) && id(value.target_id) && id(value.created_by) && packages.some((kind) => kind === value.package) && runStatuses.some((status) => status === value.status) && version(value.version) && bundleVersions(value.versions) && estimate(value.estimate) && hash(value.manifest_hash) &&
    number(value.request_count, 0, 100000) && number(value.token_count) && money(value.estimated_cost_micros) && number(value.planned_samples, 1, 100000) && number(value.completed_samples, 0, value.planned_samples) && number(value.valid_sample_count, 0, value.planned_samples) &&
    date(value.created_at) && (value.started_at === null || date(value.started_at)) && (value.finished_at === null || date(value.finished_at)) && (value.execution_closed_at === null || date(value.execution_closed_at)) &&
    Array.isArray(value.error_summary) && value.error_summary.length <= 128 && value.error_summary.every((item) => closed(item, ['code', 'count']) && code(item.code) && number(item.count, 1))
}
function scope(org: string, csrf?: string): Record<string, string> { if (!id(org)) throw new ApiError('MI_INVALID_REQUEST'); return { 'X-Organization-ID': org, ...(csrf ? { 'X-CSRF-Token': csrf } : {}) } }
function runPath(runID: string) { if (!id(runID)) throw new ApiError('MI_INVALID_REQUEST'); return `/runs/${runID}` }
export const runsApi = {
  permissions(org: string, userID: string, signal?: AbortSignal) {
    if (!id(userID)) throw new ApiError('MI_INVALID_REQUEST')
    return request('/auth/permissions', (value): value is { organization_id: string; user_id: string; permissions: string[] } => closed(value, ['organization_id', 'user_id', 'permissions']) && value.organization_id === org && value.user_id === userID && Array.isArray(value.permissions) && value.permissions.length <= 1000 && value.permissions.every((permission) => typeof permission === 'string' && /^[a-z][a-z0-9.-]{0,127}$/.test(permission)) && new Set(value.permissions).size === value.permissions.length, { headers: scope(org), signal })
  },
  estimate(org: string, csrf: string, body: EstimateInput, signal?: AbortSignal) {
    if (!id(body.target_id) || !version(body.target_version) || !packages.includes(body.package)) throw new ApiError('MI_INVALID_REQUEST')
    return request('/runs/estimate', (value): value is Quote => quote(value) && value.target_id === body.target_id && value.target_version === body.target_version && value.package === body.package, { body, headers: scope(org, csrf), signal })
  },
  create(org: string, csrf: string, draft: Pick<Quote, 'id' | 'manifest_hash' | 'target_id' | 'package'>, signal?: AbortSignal) {
    if (!id(draft.id) || !id(draft.target_id) || !hash(draft.manifest_hash)) throw new ApiError('MI_INVALID_REQUEST')
    return request('/runs', (value): value is Run => run(value) && value.target_id === draft.target_id && value.manifest_hash === draft.manifest_hash && value.package === draft.package,
      { body: { estimate_id: draft.id, manifest_hash: draft.manifest_hash, confirm_cost: true }, headers: scope(org, csrf), signal })
  },
  get: (org: string, runID: string, signal?: AbortSignal) => request(runPath(runID), (value): value is Run => run(value) && value.id === runID, { headers: scope(org), signal }),
  cancel(org: string, csrf: string, record: Pick<Run, 'id' | 'version' | 'target_id' | 'manifest_hash'>, signal?: AbortSignal) {
    if (!version(record.version)) throw new ApiError('MI_INVALID_REQUEST')
    return request(`${runPath(record.id)}/cancel`, (value): value is Run => run(value) && value.id === record.id && value.target_id === record.target_id && value.manifest_hash === record.manifest_hash && value.version >= record.version,
      { body: { version: record.version }, headers: scope(org, csrf), signal })
  },
}
