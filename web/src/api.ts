// Same-origin only. Cookie authentication is browser-managed; CSRF and setup
// tokens stay in memory and never enter URLs or browser storage.
export interface Organization { id: string; name: string; timezone?: string; status: 'active' | 'disabled' }
export interface Session {
  user: { id: string; username: string; status: 'active' | 'disabled'; system_admin?: boolean; must_change_password: boolean; display_name?: string; version?: number }
  organizations: Organization[]
  csrf_token: string
  expires_at: string
}
export interface Role { name: string; permissions: string[] }

export class ApiError extends Error {
  constructor(readonly code: string, readonly status = 0, readonly requestID = '', readonly retryAfter = 0) {
    // Never retain server messages, response bodies, URLs, or request bodies.
    super(code)
    this.name = 'ApiError'
  }
}
const messages: Record<string, string> = {
  MI_NETWORK_ERROR: '无法连接服务，请检查网络后重试。',
  MI_INVALID_RESPONSE: '服务响应格式异常，请联系管理员。',
  MI_LOGIN_FAILED: '用户名或密码不正确，或账号暂不可用。',
  MI_SESSION_REQUIRED: '会话已失效，请重新登录。',
  MI_CSRF_INVALID: '会话安全校验未通过，请重新登录后再试。',
  MI_PERMISSION_DENIED: '没有执行此操作的权限，请联系管理员。',
  MI_PASSWORD_CHANGE_REQUIRED: '必须先修改临时密码，才能访问工作空间。',
  MI_SETUP_CLOSED: '系统已由其他管理员初始化，请登录。',
  MI_SETUP_REQUIRED: '系统尚未初始化，请刷新页面完成初始化。',
  MI_INVALID_REQUEST: '请检查输入内容是否符合要求。',
  MI_RATE_LIMITED: '请求过于频繁，请稍后再试。',
  MI_SERVICE_UNAVAILABLE: '服务暂不可用，请稍后重试。',
  MI_TARGET_INVALID: '目标配置不符合要求，请检查地址、模型与参数。',
  MI_TARGET_INVALID_ENDPOINT: '目标地址不符合安全要求，请检查 HTTPS 地址。',
  MI_TARGET_BLOCKED_ADDRESS: '目标地址被安全策略阻止，请联系管理员。',
  MI_SECRET_INVALID: '凭证配置不符合要求，请检查认证方式和请求头。',
  MI_CONFLICT: '记录已被其他操作修改，请重新读取后再提交。',
  MI_VERSION_CONFLICT: '记录版本已变化，请重新读取后再提交。',
  MI_NOT_FOUND: '记录不存在、已删除，或不在当前组织范围内。',
}
export function errorMessage(error: unknown): string {
  return error instanceof ApiError ? (messages[error.code] ?? '操作失败，请稍后重试或联系管理员。') : '操作失败，请稍后重试。'
}
export function sessionInvalid(error: unknown): boolean {
  return error instanceof ApiError && (error.code === 'MI_SESSION_REQUIRED' || error.code === 'MI_CSRF_INVALID')
}
export function passwordChangeRequired(error: unknown): boolean {
  return error instanceof ApiError && error.code === 'MI_PASSWORD_CHANGE_REQUIRED'
}
export function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
export function text(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max
}
export function id(value: unknown): value is string { return typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value) }
function organization(value: unknown): value is Organization {
  return object(value) && id(value.id) && text(value.name, 128) && (value.status === 'active' || value.status === 'disabled') &&
    (value.timezone === undefined || text(value.timezone, 64))
}
function session(value: unknown): value is Session {
  return object(value) && object(value.user) && id(value.user.id) && text(value.user.username, 64) &&
    (value.user.status === 'active' || value.user.status === 'disabled') &&
    (value.user.system_admin === undefined || typeof value.user.system_admin === 'boolean') &&
    typeof value.user.must_change_password === 'boolean' &&
    (value.user.display_name === undefined || (typeof value.user.display_name === 'string' && value.user.display_name.length <= 128)) &&
    (value.user.version === undefined || (typeof value.user.version === 'number' && Number.isSafeInteger(value.user.version) && value.user.version > 0)) &&
    Array.isArray(value.organizations) && value.organizations.length <= 1000 && value.organizations.every(organization) &&
    new Set(value.organizations.map((org) => org.id)).size === value.organizations.length &&
    text(value.csrf_token, 128) && /^[A-Za-z0-9_-]+$/.test(value.csrf_token) &&
    text(value.expires_at, 64) && Number.isFinite(Date.parse(value.expires_at))
}
function role(value: unknown): value is Role {
  return object(value) && text(value.name, 64) && Array.isArray(value.permissions) && value.permissions.length <= 1000 && value.permissions.every((permission) => text(permission, 64))
}
export function page<T>(guard: (value: unknown) => value is T) {
  return (value: unknown): value is { items: T[]; next_cursor: string | null } =>
    object(value) && Array.isArray(value.items) && value.items.length <= 1000 && value.items.every(guard) && (value.next_cursor === null || text(value.next_cursor, 512))
}
export function acknowledged(value: unknown): value is { ok: true } { return object(value) && value.ok === true }
interface RequestOptions { method?: 'GET' | 'POST' | 'PATCH' | 'DELETE'; body?: unknown; headers?: Record<string, string>; signal?: AbortSignal }
export async function request<T>(path: string, guard: (value: unknown) => value is T, options: RequestOptions = {}): Promise<T> {
  const timeout = AbortSignal.timeout(45_000)
  const signal = options.signal ? AbortSignal.any([options.signal, timeout]) : timeout
  let response: Response
  try {
    response = await fetch(`/api/v1${path}`, {
      method: options.method ?? (options.body === undefined ? 'GET' : 'POST'), credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      headers: { Accept: 'application/json', ...(options.body === undefined ? {} : { 'Content-Type': 'application/json' }), ...options.headers },
      body: options.body === undefined ? undefined : JSON.stringify(options.body), signal,
    })
  } catch {
    if (options.signal?.aborted) throw new DOMException('Request cancelled', 'AbortError')
    throw new ApiError('MI_NETWORK_ERROR')
  }
  let envelope: unknown
  try { envelope = await response.json() } catch { throw new ApiError('MI_INVALID_RESPONSE', response.status) }
  const requestID = object(envelope) && typeof envelope.request_id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(envelope.request_id) ? envelope.request_id : ''
  if (!response.ok) {
    const code = object(envelope) && object(envelope.error) && typeof envelope.error.code === 'string' && /^MI_[A-Z_]{1,64}$/.test(envelope.error.code) ? envelope.error.code : 'MI_SERVICE_UNAVAILABLE'
    const header = response.headers.get('Retry-After')
    const seconds = header && /^\d+$/.test(header) ? Number(header) : header ? Math.ceil((Date.parse(header) - Date.now()) / 1000) : 0
    throw new ApiError(code, response.status, requestID, Number.isFinite(seconds) ? Math.max(0, Math.min(seconds, 86_400)) : 0)
  }
  if (!object(envelope) || !requestID || 'error' in envelope || !guard(envelope.data)) throw new ApiError('MI_INVALID_RESPONSE', response.status, requestID)
  return envelope.data
}
export const api = {
  setupStatus: (signal?: AbortSignal) => request('/setup/status', (value): value is { initialized: boolean } => object(value) && typeof value.initialized === 'boolean', { signal }),
  initialize: (body: { organization_name: string; username: string; password: string }, setupToken: string, signal?: AbortSignal) => request('/setup/initialize', acknowledged, { body, headers: setupToken ? { 'X-Setup-Token': setupToken } : {}, signal }),
  login: (body: { username: string; password: string }, signal?: AbortSignal) => request('/auth/login', session, { body, signal }),
  me: (signal?: AbortSignal) => request('/auth/me', session, { signal }),
  organizations: (signal?: AbortSignal) => request('/organizations', page(organization), { signal }),
  roles: (organizationID: string, signal?: AbortSignal) => {
    if (!id(organizationID)) return Promise.reject(new ApiError('MI_INVALID_REQUEST'))
    return request('/roles', page(role), { headers: { 'X-Organization-ID': organizationID }, signal })
  },
  logout: (csrfToken: string, signal?: AbortSignal) => request('/auth/logout', acknowledged, { body: {}, headers: { 'X-CSRF-Token': csrfToken }, signal }),
  changePassword: (body: { current_password: string; new_password: string }, csrfToken: string, signal?: AbortSignal) => request('/auth/change-password', acknowledged, { body, headers: { 'X-CSRF-Token': csrfToken }, signal }),
}
