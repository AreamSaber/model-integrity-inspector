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
  MI_LAST_ADMINISTRATOR: '此操作会移除最后一位可用管理员，请先安排其他管理员。',
  MI_SELF_LOCKOUT_FORBIDDEN: '不能通过此操作锁定自己。请使用账号安全页修改自己的密码，并保留自己的管理权限。',
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
    object(value) && Array.isArray(value.items) && value.items.length <= 1000 && value.items.every(guard) && (value.next_cursor === null || text(value.next_cursor, 1024))
}
export function acknowledged(value: unknown): value is { ok: true } { return object(value) && value.ok === true }
async function accessibleOrganizations(signal?: AbortSignal): Promise<{ items: Organization[]; next_cursor: null }> {
  // The management endpoint is paginated. Do not silently replace the workspace
  // selector with only its first page after refresh.
  const items: Organization[] = []
  const cursors = new Set<string>()
  let cursor = ''
  do {
    const result = await request(`/organizations${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`, page(organization), { signal })
    items.push(...result.items)
    if (items.length > 1000 || cursors.size > 100 || (result.next_cursor && cursors.has(result.next_cursor))) throw new ApiError('MI_INVALID_RESPONSE')
    cursor = result.next_cursor ?? ''
    if (cursor) cursors.add(cursor)
  } while (cursor)
  if (new Set(items.map((org) => org.id)).size !== items.length) throw new ApiError('MI_INVALID_RESPONSE')
  return { items, next_cursor: null }
}
interface RequestOptions { method?: 'GET' | 'POST' | 'PATCH' | 'DELETE'; body?: unknown; headers?: Record<string, string>; signal?: AbortSignal }
// Fixed application limits, not caller-controlled overrides. Fetch exposes
// decompressed bytes here; the result/statistics projection fits within 8 MiB.
const maximumJSONBytes = 8 * 1024 * 1024
const maximumErrorBytes = 64 * 1024
const maximumReadOperations = 131072
const requestTimeoutMS = 45000
function cancelled() { return new DOMException('Request cancelled', 'AbortError') }
function checkSignal(signal: AbortSignal) { if (signal.aborted) throw cancelled() }
function abortable<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const abort = () => { signal.removeEventListener('abort', abort); reject(cancelled()) }
    signal.addEventListener('abort', abort, { once: true })
    // Attach both handlers even after cancellation, so a late rejected fetch or
    // read cannot become an unhandled rejection containing transport details.
    operation.then((value) => { signal.removeEventListener('abort', abort); resolve(value) }, () => { signal.removeEventListener('abort', abort); reject(new ApiError('MI_NETWORK_ERROR')) })
    if (signal.aborted) abort()
  })
}
function cancelUnread(body: ReadableStream<Uint8Array> | null) {
  // A remote/adapter cancellation promise is not trusted to settle.
  try { void body?.cancel().catch(() => {}) } catch { /* already locked or closed */ }
}
async function boundedJSON(response: Response, signal: AbortSignal): Promise<unknown> {
  const maximum = response.ok ? maximumJSONBytes : maximumErrorBytes
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined
  let complete = false, received = 0, operations = 0, emptyReads = 0, decoded = ''
  try {
    checkSignal(signal)
    const contentType = response.headers.get('Content-Type') ?? ''
    if (!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?\s*$/i.test(contentType)) throw new ApiError('MI_INVALID_RESPONSE')
    const encoding = response.headers.get('Content-Encoding')?.trim().toLowerCase()
    const identityEncoding = !encoding || encoding === 'identity'
    const length = response.headers.get('Content-Length')
    let declared: number | undefined
    if (length !== null) {
      if (!/^[0-9]{1,16}$/.test(length) || !Number.isSafeInteger(Number(length))) throw new ApiError('MI_INVALID_RESPONSE')
      declared = Number(length)
      // Compressed Content-Length describes the wire representation, not the
      // decompressed stream. It never relaxes the actual-byte limit below.
      if (identityEncoding && declared > maximum) throw new ApiError('MI_INVALID_RESPONSE')
    }
    if (!response.body) throw new ApiError('MI_INVALID_RESPONSE')
    reader = response.body.getReader()
    const decoder = new TextDecoder('utf-8', { fatal: true })
    for (;;) {
      checkSignal(signal)
      // Bound pathological streams of empty/tiny chunks too: a synchronously
      // resolving read loop must not starve the abort timer indefinitely.
      if (++operations > maximumReadOperations) throw new ApiError('MI_INVALID_RESPONSE')
      const part = await abortable(reader.read(), signal)
      checkSignal(signal)
      if (part.done) { complete = true; break }
      // Fetch streams may originate in a different realm (e.g. a test runner or
      // frame). instanceof would reject genuine byte arrays across that boundary.
      if (!ArrayBuffer.isView(part.value) || Object.prototype.toString.call(part.value) !== '[object Uint8Array]') throw new ApiError('MI_INVALID_RESPONSE')
      received += part.value.byteLength
      if (received > maximum || (identityEncoding && declared !== undefined && received > declared)) throw new ApiError('MI_INVALID_RESPONSE')
      if (part.value.byteLength === 0) { if (++emptyReads > 1024) throw new ApiError('MI_INVALID_RESPONSE'); continue }
      emptyReads = 0
      try { decoded += decoder.decode(part.value, { stream: true }) } catch { throw new ApiError('MI_INVALID_RESPONSE') }
    }
    if (received === 0 || (identityEncoding && declared !== undefined && received !== declared)) throw new ApiError('MI_INVALID_RESPONSE')
    try { decoded += decoder.decode() } catch { throw new ApiError('MI_INVALID_RESPONSE') }
    checkSignal(signal)
    try { return JSON.parse(decoded) as unknown } catch { throw new ApiError('MI_INVALID_RESPONSE') }
  } finally {
    decoded = ''
    if (reader) {
      if (!complete) { try { void reader.cancel().catch(() => {}) } catch { /* cancellation is best-effort */ } }
      try { reader.releaseLock() } catch { /* a pending read may be aborting */ }
    } else cancelUnread(response.body)
  }
}
function invalidErrorBody(status: number) {
  // The HTTP status already denies access, but its payload could not be trusted.
  // Safely invalidate the UI session rather than retaining an authorized cached
  // view. This is a client fail-closed downgrade, not a server session diagnosis.
  return new ApiError(status === 401 || status === 403 ? 'MI_SESSION_REQUIRED' : 'MI_INVALID_RESPONSE', status)
}
export async function request<T>(path: string, guard: (value: unknown) => value is T, options: RequestOptions = {}): Promise<T> {
  const timeout = new AbortController()
  const timer = setTimeout(() => timeout.abort(), requestTimeoutMS)
  const signal = options.signal ? AbortSignal.any([options.signal, timeout.signal]) : timeout.signal
  try {
    let response: Response
    try {
      checkSignal(signal)
      response = await abortable(fetch(`/api/v1${path}`, {
        method: options.method ?? (options.body === undefined ? 'GET' : 'POST'), credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers: { Accept: 'application/json', ...(options.body === undefined ? {} : { 'Content-Type': 'application/json' }), ...options.headers },
        body: options.body === undefined ? undefined : JSON.stringify(options.body), signal,
      }).then((value) => { if (signal.aborted) { cancelUnread(value.body); throw cancelled() }; return value }), signal)
    } catch {
      if (options.signal?.aborted) throw cancelled()
      throw new ApiError('MI_NETWORK_ERROR')
    }
    let envelope: unknown
    try { envelope = await boundedJSON(response, signal) } catch (failure) {
      if (options.signal?.aborted) throw cancelled()
      if (response.status === 401 || response.status === 403) throw invalidErrorBody(response.status)
      if (timeout.signal.aborted || (failure instanceof ApiError && failure.code === 'MI_NETWORK_ERROR')) throw new ApiError('MI_NETWORK_ERROR', response.status)
      throw invalidErrorBody(response.status)
    }
    if (options.signal?.aborted) throw cancelled()
    if (timeout.signal.aborted) throw new ApiError('MI_NETWORK_ERROR', response.status)
    const requestID = object(envelope) && typeof envelope.request_id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(envelope.request_id) ? envelope.request_id : ''
    if (!response.ok) {
      const validError = object(envelope) && object(envelope.error) && typeof envelope.error.code === 'string' && /^MI_[A-Z_]{1,64}$/.test(envelope.error.code)
      if ((response.status === 401 || response.status === 403) && (!validError || !requestID || (object(envelope) && 'data' in envelope))) throw invalidErrorBody(response.status)
      const code = validError ? (envelope as { error: { code: string } }).error.code : 'MI_SERVICE_UNAVAILABLE'
      const header = response.headers.get('Retry-After')
      const seconds = header && /^\d+$/.test(header) ? Number(header) : header ? Math.ceil((Date.parse(header) - Date.now()) / 1000) : 0
      throw new ApiError(code, response.status, requestID, Number.isFinite(seconds) ? Math.max(0, Math.min(seconds, 86_400)) : 0)
    }
    let valid = false
    try { valid = object(envelope) && Boolean(requestID) && !('error' in envelope) && guard(envelope.data) } catch { /* guard errors never carry response details */ }
    if (options.signal?.aborted) throw cancelled()
    if (timeout.signal.aborted) throw new ApiError('MI_NETWORK_ERROR', response.status)
    if (!valid || !object(envelope)) throw new ApiError('MI_INVALID_RESPONSE', response.status, requestID)
    return envelope.data as T
  } finally { clearTimeout(timer) }
}
export const api = {
  setupStatus: (signal?: AbortSignal) => request('/setup/status', (value): value is { initialized: boolean } => object(value) && typeof value.initialized === 'boolean', { signal }),
  initialize: (body: { organization_name: string; username: string; password: string }, setupToken: string, signal?: AbortSignal) => request('/setup/initialize', acknowledged, { body, headers: setupToken ? { 'X-Setup-Token': setupToken } : {}, signal }),
  login: (body: { username: string; password: string }, signal?: AbortSignal) => request('/auth/login', session, { body, signal }),
  me: (signal?: AbortSignal) => request('/auth/me', session, { signal }),
  organizations: accessibleOrganizations,
  roles: (organizationID: string, signal?: AbortSignal) => {
    if (!id(organizationID)) return Promise.reject(new ApiError('MI_INVALID_REQUEST'))
    return request('/roles', page(role), { headers: { 'X-Organization-ID': organizationID }, signal })
  },
  logout: (csrfToken: string, signal?: AbortSignal) => request('/auth/logout', acknowledged, { body: {}, headers: { 'X-CSRF-Token': csrfToken }, signal }),
  logoutAll: (csrfToken: string, signal?: AbortSignal) => request('/auth/logout-all', (value): value is { ok: true } => acknowledged(value) && Object.keys(value).length === 1, { method: 'POST', body: {}, headers: { 'X-CSRF-Token': csrfToken }, signal }),
  changePassword: (body: { current_password: string; new_password: string }, csrfToken: string, signal?: AbortSignal) => request('/auth/change-password', acknowledged, { body, headers: { 'X-CSRF-Token': csrfToken }, signal }),
}
