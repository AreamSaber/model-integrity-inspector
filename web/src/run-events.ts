import { ApiError, id, object } from './api'
import { run, runsApi, type Run } from './runs-api'

const maximumFrame = 64 * 1024
const maximumConnectionBytes = 8 * 1024 * 1024
const maximumConnections = 12
const maximumLifetime = 60 * 60 * 1000
const terminal = (value: Run) => ['COMPLETED', 'PARTIAL', 'FAILED', 'REVIEW_REQUIRED', 'CANCELLED'].includes(value.status)
export type RunConnection = 'checking' | 'connecting' | 'live' | 'reconnecting'
export interface WatchRunOptions {
  organizationID: string
  initial: Run
  signal: AbortSignal
  onSnapshot: (value: Run) => void
  onConnection?: (state: RunConnection) => void
}
export interface RunWatchResult { record: Run; reason: 'terminal' | 'limit' }

// An event ID is a transport cursor, never an authorization or execution token.
// No POST, new estimate, credentials in URLs, browser storage, or dynamic URLs.
export function validateRunProgress(initial: Run, current: Run, next: Run): void {
  if (!run(next) || next.id !== initial.id || next.target_id !== initial.target_id || next.created_by !== initial.created_by ||
    next.manifest_hash !== initial.manifest_hash || next.package !== initial.package || next.planned_samples !== initial.planned_samples ||
    (Object.keys(initial.versions) as (keyof Run['versions'])[]).some((key) => next.versions[key] !== initial.versions[key]) ||
    (Object.keys(initial.estimate) as (keyof Run['estimate'])[]).some((key) => key === 'warnings' ?
      JSON.stringify(next.estimate.warnings) !== JSON.stringify(initial.estimate.warnings) : next.estimate[key] !== initial.estimate[key]) || next.version < current.version ||
    next.completed_samples < current.completed_samples || next.request_count < current.request_count || next.token_count < current.token_count ||
    (terminal(current) && next.status !== current.status)) throw new ApiError('MI_INVALID_RESPONSE')
}

function cancelled(): DOMException { return new DOMException('Request cancelled', 'AbortError') }
function checkSignal(signal: AbortSignal) { if (signal.aborted) throw cancelled() }
function decodeUTF8(decoder: TextDecoder, value?: Uint8Array, stream = false): string {
  try { return decoder.decode(value, { stream }) } catch { throw new ApiError('MI_INVALID_RESPONSE') }
}
const errorCodes: Record<string, number> = {
  MI_SESSION_REQUIRED: 401, MI_PASSWORD_CHANGE_REQUIRED: 403, MI_PERMISSION_DENIED: 403,
  MI_NOT_FOUND: 404, MI_SERVICE_UNAVAILABLE: 503, MI_RATE_LIMITED: 429,
}
function closedError(value: unknown, fallbackStatus = 503, retryAfter = 0): ApiError {
  if (object(value) && typeof value.code === 'string' && Object.hasOwn(errorCodes, value.code)) {
    const requestID = typeof value.request_id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value.request_id) ? value.request_id : ''
    return new ApiError(value.code, errorCodes[value.code], requestID, retryAfter)
  }
  const fallback = fallbackStatus === 401 ? 'MI_SESSION_REQUIRED' : fallbackStatus === 403 ? 'MI_PERMISSION_DENIED' : fallbackStatus === 404 ? 'MI_NOT_FOUND' : fallbackStatus === 429 ? 'MI_RATE_LIMITED' : 'MI_SERVICE_UNAVAILABLE'
  return new ApiError(fallback, fallbackStatus, '', retryAfter)
}
function retrySeconds(response: Response): number {
  const value = response.headers.get('Retry-After')
  const seconds = value && /^\d{1,6}$/.test(value) ? Number(value) : value ? Math.ceil((Date.parse(value) - Date.now()) / 1000) : 0
  return Number.isFinite(seconds) ? Math.max(0, Math.min(seconds, 86400)) : 0
}

async function connection(options: WatchRunOptions, current: () => Run, publish: (value: Run) => void, lastEvent: string): Promise<'terminal' | 'eof'> {
  const controller = new AbortController()
  const signal = AbortSignal.any([options.signal, controller.signal])
  const lifetime = setTimeout(() => controller.abort(), 315000)
  let timer: ReturnType<typeof setTimeout> | undefined
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined
  const armTimeout = () => { clearTimeout(timer); timer = setTimeout(() => controller.abort(), 25000) }
  try {
    armTimeout()
    const response = await fetch(`/api/v1/runs/${options.initial.id}/events`, {
      method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal,
      headers: { Accept: 'text/event-stream', 'X-Organization-ID': options.organizationID, ...(lastEvent ? { 'Last-Event-ID': lastEvent } : {}) },
    })
    checkSignal(options.signal)
    if (!response.ok) {
      // Bound handshake error reads independently; never retain server messages.
      if (!response.body) throw new ApiError('MI_SERVICE_UNAVAILABLE', response.status)
      reader = response.body.getReader()
      let encoded = ''
      const decoder = new TextDecoder('utf-8', { fatal: true })
      let bytes = 0
      for (;;) {
        armTimeout()
        const chunk = await reader.read()
        if (chunk.done) break
        bytes += chunk.value.byteLength
        if (bytes > 16384) throw new ApiError('MI_INVALID_RESPONSE', response.status)
        encoded += decodeUTF8(decoder, chunk.value, true)
      }
      encoded += decodeUTF8(decoder)
      let value: unknown
      try { value = JSON.parse(encoded) } catch { throw new ApiError('MI_INVALID_RESPONSE', response.status) }
      const error = object(value) && object(value.error) ? { code: value.error.code, request_id: value.request_id } : undefined
      throw closedError(error, response.status, retrySeconds(response))
    }
    if (response.status !== 200 || !/^text\/event-stream(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('Content-Type') ?? '') || !response.body) throw new ApiError('MI_INVALID_RESPONSE', response.status)
    reader = response.body.getReader()
    const decoder = new TextDecoder('utf-8', { fatal: true })
    let pending = '', event = '', eventID = '', data = '', frameBytes = 0, total = 0
    let sawSnapshot = false
    options.onConnection?.('live')
    function line(value: string): boolean {
      if (value.length > maximumFrame) throw new ApiError('MI_INVALID_RESPONSE')
      frameBytes += new TextEncoder().encode(value).byteLength + 1
      if (frameBytes > maximumFrame || value.includes('\0')) throw new ApiError('MI_INVALID_RESPONSE')
      if (value.endsWith('\r')) value = value.slice(0, -1)
      if (value === '') {
        frameBytes = 0
        if (!event && !eventID && !data) return false
        if (!data || !['progress', 'error'].includes(event)) throw new ApiError('MI_INVALID_RESPONSE')
        let parsed: unknown
        try { parsed = JSON.parse(data) } catch { throw new ApiError('MI_INVALID_RESPONSE') }
        if (event === 'error') {
          if (eventID || !object(parsed) || Object.keys(parsed).some((key) => key !== 'code' && key !== 'request_id')) throw new ApiError('MI_INVALID_RESPONSE')
          throw closedError(parsed)
        }
        if (!run(parsed) || eventID !== `${options.initial.id}:${parsed.version}`) throw new ApiError('MI_INVALID_RESPONSE')
        validateRunProgress(options.initial, current(), parsed)
        publish(parsed)
        sawSnapshot = true
        event = ''; eventID = ''; data = ''
        return terminal(parsed)
      }
      if (value.startsWith(':')) return false
      const colon = value.indexOf(':')
      if (colon < 0) throw new ApiError('MI_INVALID_RESPONSE')
      const field = value.slice(0, colon)
      let text = value.slice(colon + 1)
      if (text.startsWith(' ')) text = text.slice(1)
      if (field === 'event' && !event) event = text
      else if (field === 'id' && !eventID) eventID = text
      else if (field === 'data') data += (data ? '\n' : '') + text
      else throw new ApiError('MI_INVALID_RESPONSE')
      return false
    }
    for (;;) {
      armTimeout()
      const chunk = await reader.read()
      checkSignal(options.signal)
      if (chunk.done) {
        pending += decodeUTF8(decoder)
        if (pending || event || eventID || data) throw new ApiError('MI_NETWORK_ERROR')
        if (!sawSnapshot) throw new ApiError('MI_INVALID_RESPONSE')
        return 'eof'
      }
      total += chunk.value.byteLength
      if (total > maximumConnectionBytes || chunk.value.byteLength > 256 * 1024) throw new ApiError('MI_INVALID_RESPONSE')
      pending += decodeUTF8(decoder, chunk.value, true)
      for (;;) {
        const newline = pending.indexOf('\n')
        if (newline < 0) break
        const complete = pending.slice(0, newline)
        pending = pending.slice(newline + 1)
        if (line(complete)) return 'terminal'
      }
      if (pending.length + frameBytes > maximumFrame) throw new ApiError('MI_INVALID_RESPONSE')
    }
  } catch (error) {
    checkSignal(options.signal)
    if (error instanceof ApiError) throw error
    throw new ApiError('MI_NETWORK_ERROR')
  } finally {
    clearTimeout(timer)
    clearTimeout(lifetime)
    controller.abort()
    if (reader) { void reader.cancel().catch(() => {}); reader.releaseLock() }
  }
}

async function pause(delay: number, signal: AbortSignal): Promise<void> {
  checkSignal(signal)
  await new Promise<void>((resolve, reject) => {
    const abort = () => { clearTimeout(timer); reject(cancelled()) }
    const timer = setTimeout(() => { signal.removeEventListener('abort', abort); resolve() }, delay)
    signal.addEventListener('abort', abort, { once: true })
  })
}

export async function watchRun(options: WatchRunOptions): Promise<RunWatchResult> {
  if (!id(options.organizationID) || !run(options.initial)) throw new ApiError('MI_INVALID_REQUEST')
  checkSignal(options.signal)
  const externalSignal = options.signal
  const lifetime = new AbortController()
  const timer = setTimeout(() => lifetime.abort(), maximumLifetime)
  options = { ...options, signal: AbortSignal.any([externalSignal, lifetime.signal]) }
  let current = options.initial
  let visible = options.initial
  const deadline = Date.now() + maximumLifetime
  const publish = (value: Run) => { checkSignal(options.signal); validateRunProgress(options.initial, current, value); current = value; visible = value; options.onSnapshot(value) }
  const read = async () => { options.onConnection?.('checking'); publish(await runsApi.get(options.organizationID, options.initial.id, options.signal)) }
  try {
  await read()
  if (terminal(current)) return { record: current, reason: 'terminal' }
  let lastEvent = ''
  for (let attempt = 0; attempt < maximumConnections && Date.now() < deadline; attempt++) {
    options.onConnection?.(attempt === 0 ? 'connecting' : 'reconnecting')
    let failure: ApiError | undefined
    try {
      await connection(options, () => current, (value) => {
        validateRunProgress(options.initial, current, value)
        // A terminal event is provisional until exact-ID GET confirms it. It
        // advances internal fencing but cannot expose results through callbacks.
        if (terminal(value)) current = value
        else publish(value)
        lastEvent = `${value.id}:${value.version}`
      }, lastEvent)
    } catch (error) {
      checkSignal(options.signal)
      if (!(error instanceof ApiError) || [401, 403, 404].includes(error.status)) throw error
      failure = error
    }
    // Both disconnects and terminal notifications are reconciled against the
    // exact persisted Run. Read failure is never interpreted as a failed Run.
    await read()
    if (terminal(current)) return { record: current, reason: 'terminal' }
    if (failure?.code === 'MI_INVALID_RESPONSE') throw failure
    const delay = Math.max(Math.min(1000 * 2 ** attempt, 30000), (failure?.retryAfter ?? 0) * 1000)
    if (attempt + 1 >= maximumConnections || Date.now() + delay >= deadline) break
    await pause(delay, options.signal)
  }
  return { record: visible, reason: 'limit' }
  } catch (error) {
    checkSignal(externalSignal)
    if (lifetime.signal.aborted) return { record: visible, reason: 'limit' }
    throw error
  } finally { clearTimeout(timer) }
}
