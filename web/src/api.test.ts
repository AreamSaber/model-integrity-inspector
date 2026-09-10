import { describe, expect, it, vi } from 'vitest'
import { api, ApiError, errorMessage, object, request, sessionInvalid } from './api'

describe('API response validation', () => {
  const user = { id: '9007199254740993', username: 'admin', status: 'active', display_name: '', version: 2, system_admin: false, must_change_password: true }
  const session = { user, organizations: [], csrf_token: 'csrf-token', expires_at: new Date(Date.now() + 3600_000).toISOString() }
  it('preserves actual session flags, empty display names, numeric versions, and string IDs', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockImplementation(async () => Response.json({ data: session, request_id: 'req' }))
    vi.stubGlobal('fetch', fetchMock)
    expect(await api.login({ username: 'admin', password: 'synthetic-password' })).toEqual(session)
    expect(await api.me()).toEqual(session)
  })
  it.each([undefined, 'false', 0, null])('rejects an absent or non-boolean security flag %s', async (flag) => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValue(Response.json({ data: { ...session, user: { ...user, must_change_password: flag } }, request_id: 'req' })))
    await expect(api.me()).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it.each(['2', 0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1])('rejects invalid optimistic-lock versions %s', async (version) => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValue(Response.json({ data: { ...session, user: { ...user, version } }, request_id: 'req' })))
    await expect(api.me()).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it.each([
    { data: { initialized: 'false' }, request_id: 'request-id' },
    { data: { initialized: false } },
    { data: { initialized: false }, error: {}, request_id: 'request-id' },
  ])('rejects a malformed successful setup envelope %#', async (envelope) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json(envelope)))
    await expect(api.setupStatus()).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('rejects a numeric user ID rather than rounding it into another identity', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ data: { user: { id: 42, username: 'admin', status: 'active' }, organizations: [], csrf_token: 'token', expires_at: new Date().toISOString() }, request_id: 'req' })))
    await expect(api.me()).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('does not permit arbitrary organization header contents', async () => {
    const fetchMock = vi.fn<typeof fetch>()
    vi.stubGlobal('fetch', fetchMock)
    await expect(api.roles('1\r\nX-Evil: value')).rejects.toMatchObject({ code: 'MI_INVALID_REQUEST' })
    expect(fetchMock).not.toHaveBeenCalled()
  })
  it('never surfaces arbitrary server messages or unsafe request IDs', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ error: { code: 'UNTRUSTED<script>', message: 'credential-leak' }, request_id: 'credential-leak?secret' }, { status: 503 })))
    const error: unknown = await api.setupStatus().catch((failure: unknown) => failure)
    expect(error).toBeInstanceOf(ApiError)
    expect(String(error)).not.toContain('credential-leak')
    expect(errorMessage(error)).toBe('服务暂不可用，请稍后重试。')
    expect((error as ApiError).requestID).toBe('')
  })
  it('rejects HTML proxy responses', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('<html>private details</html>')))
    await expect(api.setupStatus()).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('uses no mutation retries when the response is lost', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockRejectedValue(new TypeError('failed'))
    vi.stubGlobal('fetch', fetchMock)
    await expect(api.initialize({ organization_name: 'Org', username: 'admin', password: 'synthetic-password' }, '')).rejects.toMatchObject({ code: 'MI_NETWORK_ERROR' })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})

describe('self-service logout-all request', () => {
  it('sends exactly an empty JSON body with CSRF and no query, organization or caller-selected user', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(Response.json({ data: { ok: true }, request_id: 'logout-all' }))
    vi.stubGlobal('fetch', fetcher)
    const controller = new AbortController()
    await expect(api.logoutAll('synthetic-csrf', controller.signal)).resolves.toEqual({ ok: true })
    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(fetcher.mock.calls[0]).toEqual(['/api/v1/auth/logout-all', expect.objectContaining({ method: 'POST', body: '{}', credentials: 'same-origin', cache: 'no-store', redirect: 'error' })])
    const headers = new Headers(fetcher.mock.calls[0][1]?.headers)
    expect(headers.get('X-CSRF-Token')).toBe('synthetic-csrf')
    expect(headers.get('Content-Type')).toBe('application/json')
    for (const name of ['X-Organization-ID', 'Authorization', 'Origin']) expect(headers.has(name)).toBe(false)
    expect(localStorage.length + sessionStorage.length).toBe(0)
  })
  it.each([{}, null, { ok: false }, { ok: 'true' }, { ok: true, body: 'SECRET_BODY_CANARY' }])('rejects an ambiguous acknowledgment %#', async (data) => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValue(Response.json({ data, request_id: 'logout-all' })))
    await expect(api.logoutAll('synthetic-csrf')).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('never retries a lost logout-all response', async () => {
    const fetcher = vi.fn<typeof fetch>().mockRejectedValue(new TypeError('SECRET_BODY_CANARY'))
    vi.stubGlobal('fetch', fetcher)
    await expect(api.logoutAll('synthetic-csrf')).rejects.toMatchObject({ code: 'MI_NETWORK_ERROR' })
    expect(fetcher).toHaveBeenCalledTimes(1)
  })
})

const successLimit = 8 * 1024 * 1024, errorLimit = 64 * 1024
const successJSON = JSON.stringify({ data: { ok: true }, request_id: 'bounded-request' })
const errorJSON = JSON.stringify({ error: { code: 'MI_PERMISSION_DENIED', message: 'SECRET_BODY_CANARY' }, request_id: 'bounded-request' })
const bytes = (text: string) => new TextEncoder().encode(text)
const accepted = (value: unknown): value is { ok: true } => object(value) && value.ok === true
const microtasks = async () => { for (let i = 0; i < 20; i++) await Promise.resolve() }
function byteResponse(data: Uint8Array, options: { status?: number; headers?: HeadersInit; chunkSize?: number; cancel?: () => void | Promise<void> } = {}) {
  let offset = 0
  const pull = vi.fn<(controller: ReadableStreamDefaultController<Uint8Array>) => void>((controller) => {
    if (offset === data.byteLength) { controller.close(); return }
    const next = Math.min(data.byteLength, offset + (options.chunkSize ?? 65536))
    controller.enqueue(data.slice(offset, next)); offset = next
  })
  const cancel = vi.fn<() => void | Promise<void>>(() => options.cancel?.())
  const body = new ReadableStream<Uint8Array>({ pull, cancel }, { highWaterMark: 0 })
  const response = new Response(body, { status: options.status ?? 200, headers: { 'Content-Type': 'application/json', ...Object.fromEntries(new Headers(options.headers)) } })
  return { response, body, pull, cancel }
}
function fetchResponse(response: Response) { const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response); vi.stubGlobal('fetch', fetcher); return fetcher }
function observedGuard() {
  const calls = vi.fn<(value: unknown) => void>()
  return { calls, guard: (value: unknown): value is { ok: true } => { calls(value); return accepted(value) } }
}

describe('bounded shared JSON transport', () => {
  it('preserves headers, method, same-origin credentials, CSRF and no-retry semantics', async () => {
    const fetcher = fetchResponse(Response.json({ data: { ok: true }, request_id: 'request-1' }))
    await request('/control', accepted, { method: 'PATCH', body: { version: 2 }, headers: { 'X-CSRF-Token': 'csrf', 'X-Organization-ID': '9007199254740993' } })
    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(fetcher.mock.calls[0]).toEqual(['/api/v1/control', expect.objectContaining({ method: 'PATCH', credentials: 'same-origin', cache: 'no-store', redirect: 'error', body: '{"version":2}', headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': 'csrf', 'X-Organization-ID': '9007199254740993' } })])
  })
  it('strictly decodes multibyte UTF-8 split at every byte and releases the reader on success', async () => {
    const text = '中文😀é', stream = byteResponse(bytes(JSON.stringify({ data: { text }, request_id: 'req' })), { chunkSize: 1 })
    fetchResponse(stream.response)
    await expect(request('/read', (value): value is { text: string } => object(value) && value.text === text)).resolves.toEqual({ text })
    expect(stream.body.locked).toBe(false); expect(stream.cancel).not.toHaveBeenCalled()
  })
  it.each([
    [0xc0, 0xaf], [0xe0, 0x80, 0xaf], [0xed, 0xa0, 0x80], [0xf4, 0x90, 0x80, 0x80], [0xf0, 0x9f], [0xff],
  ].map((invalid) => ({ invalid })))('rejects malformed UTF-8 %# before JSON parsing or the DTO guard', async ({ invalid }) => {
    const prefix = bytes('{"data":"'), suffix = bytes('","request_id":"req"}')
    const payload = new Uint8Array([...prefix, ...invalid, ...suffix])
    const stream = byteResponse(payload, { chunkSize: 1 }); fetchResponse(stream.response)
    const parse = vi.spyOn(JSON, 'parse'), guard = observedGuard()
    await expect(request('/read', guard.guard)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE', status: 200 })
    expect(parse).not.toHaveBeenCalled(); expect(guard.calls).not.toHaveBeenCalled()
    expect(stream.cancel).toHaveBeenCalledTimes(1); expect(stream.body.locked).toBe(false)
  })
  it('rejects an incomplete trailing code point during the final decoder flush', async () => {
    const stream = byteResponse(new Uint8Array([...bytes(successJSON), 0xf0, 0x9f]), { chunkSize: 1 }); fetchResponse(stream.response)
    const parse = vi.spyOn(JSON, 'parse')
    await expect(request('/read', accepted)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    expect(parse).not.toHaveBeenCalled(); expect(stream.body.locked).toBe(false)
  })
  it('accepts exactly 8 MiB of decoded success data without Content-Length', async () => {
    const stream = byteResponse(bytes(successJSON + ' '.repeat(successLimit - bytes(successJSON).byteLength)))
    fetchResponse(stream.response)
    await expect(request('/read', accepted)).resolves.toEqual({ ok: true })
    expect(stream.body.locked).toBe(false)
  })
  it('rejects a successful chunked response one byte over 8 MiB and does not parse or retain its body', async () => {
    const stream = byteResponse(bytes(successJSON + ' '.repeat(successLimit - bytes(successJSON).byteLength + 1)))
    fetchResponse(stream.response)
    const parse = vi.spyOn(JSON, 'parse'), guard = observedGuard()
    await expect(request('/read', guard.guard)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    expect(parse).not.toHaveBeenCalled(); expect(guard.calls).not.toHaveBeenCalled(); expect(stream.cancel).toHaveBeenCalledTimes(1)
    expect(stream.pull).toHaveBeenCalledTimes(129)
  })
  it.each(['-1', 'invalid', '4, 4', '1.5', '9007199254740992', String(successLimit + 1)])('rejects an invalid/oversized Content-Length %s before reading', async (length) => {
    const stream = byteResponse(bytes(successJSON), { headers: { 'Content-Length': length } }); fetchResponse(stream.response)
    const parse = vi.spyOn(JSON, 'parse')
    await expect(request('/read', accepted)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    expect(stream.pull).not.toHaveBeenCalled(); expect(parse).not.toHaveBeenCalled(); expect(stream.cancel).toHaveBeenCalledTimes(1)
  })
  it.each([0, 1, bytes(successJSON).length - 1, bytes(successJSON).length + 1])('rejects understated or overstated identity length %s without parsing', async (length) => {
    const stream = byteResponse(bytes(successJSON), { headers: { 'Content-Length': String(length) } }); fetchResponse(stream.response)
    const parse = vi.spyOn(JSON, 'parse')
    await expect(request('/read', accepted)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    expect(parse).not.toHaveBeenCalled(); expect(stream.body.locked).toBe(false)
  })
  it('accepts a correct length and does not compare compressed wire length with decoded JSON length', async () => {
    const cases: HeadersInit[] = [{ 'Content-Length': String(bytes(successJSON).length) }, { 'Content-Length': '10', 'Content-Encoding': 'gzip' }]
    for (const headers of cases) {
      const stream = byteResponse(bytes(successJSON), { headers }); fetchResponse(stream.response)
      await expect(request('/read', accepted)).resolves.toEqual({ ok: true })
    }
  })
  it('enforces the decompressed byte cap despite a tiny advertised compressed length', async () => {
    const stream = byteResponse(bytes(successJSON + ' '.repeat(successLimit)), { headers: { 'Content-Length': '10', 'Content-Encoding': 'br' } }); fetchResponse(stream.response)
    const parse = vi.spyOn(JSON, 'parse')
    await expect(request('/read', accepted)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    expect(parse).not.toHaveBeenCalled(); expect(stream.cancel).toHaveBeenCalledTimes(1)
  })
  it('accepts an error exactly at its separate 64 KiB boundary and preserves its closed code', async () => {
    fetchResponse(byteResponse(bytes(errorJSON + ' '.repeat(errorLimit - bytes(errorJSON).length)), { status: 403 }).response)
    const failure = await request('/read', accepted).catch((error: unknown) => error)
    expect(failure).toMatchObject({ code: 'MI_PERMISSION_DENIED', status: 403, requestID: 'bounded-request' })
    expect(String(failure) + JSON.stringify(failure)).not.toContain('SECRET_BODY_CANARY')
  })
  it.each([401, 403])('invalidates the UI session when HTTP %s has an oversized untrusted error body', async (status) => {
    const stream = byteResponse(bytes(errorJSON + ' '.repeat(errorLimit)), { status }); fetchResponse(stream.response)
    const parse = vi.spyOn(JSON, 'parse'), guard = observedGuard()
    const failure = await request('/read', guard.guard).catch((error: unknown) => error)
    expect(failure).toMatchObject({ code: 'MI_SESSION_REQUIRED', status, requestID: '' }); expect(sessionInvalid(failure)).toBe(true)
    expect(guard.calls).not.toHaveBeenCalled(); expect(parse).not.toHaveBeenCalled(); expect(stream.cancel).toHaveBeenCalledTimes(1)
  })
  it.each([401, 403])('invalidates HTTP %s with malformed JSON or an invalid error envelope', async (status) => {
    for (const text of ['{"private":"SECRET_BODY_CANARY"', '{}', '{"error":{"code":"MI_PERMISSION_DENIED"}}', '{"error":{"code":"MI_PERMISSION_DENIED"},"request_id":"invalid?private"}', '{"data":{"ok":true},"error":{"code":"MI_PERMISSION_DENIED"},"request_id":"req"}']) {
      fetchResponse(byteResponse(bytes(text), { status }).response)
      const failure = await request('/read', accepted).catch((error: unknown) => error)
      expect(failure).toMatchObject({ code: 'MI_SESSION_REQUIRED', status })
      expect(sessionInvalid(failure)).toBe(true)
    }
  })
  it.each([['MI_PASSWORD_CHANGE_REQUIRED', 403], ['MI_CSRF_INVALID', 403], ['MI_LOGIN_FAILED', 401], ['MI_RATE_LIMITED', 429]] as const)('preserves valid %s and bounded Retry-After', async (code, status) => {
    fetchResponse(Response.json({ error: { code, message: 'SECRET_BODY_CANARY' }, request_id: 'req' }, { status, headers: { 'Retry-After': '9999999' } }))
    await expect(request('/read', accepted)).rejects.toMatchObject({ code, status, retryAfter: 86400 })
  })
  it.each(['text/html', 'text/plain', 'application/json; charset=iso-8859-1'])('rejects incompatible content type %s before reading', async (type) => {
    const stream = byteResponse(bytes(successJSON), { headers: { 'Content-Type': type } }); fetchResponse(stream.response)
    await expect(request('/read', accepted)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    expect(stream.pull).not.toHaveBeenCalled(); expect(stream.cancel).toHaveBeenCalledTimes(1)
  })
  it('rejects absent or empty bodies, without treating a 204 response as a successful JSON acknowledgment', async () => {
    for (const response of [new Response(null, { status: 204 }), byteResponse(new Uint8Array()).response]) {
      fetchResponse(response)
      await expect(request('/read', accepted)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    }
  })
  it('does not dispatch a pre-aborted request or leak the arbitrary abort reason', async () => {
    const controller = new AbortController(); controller.abort(new Error('SECRET_BODY_CANARY'))
    const fetcher = vi.fn<typeof fetch>(); vi.stubGlobal('fetch', fetcher)
    const failure = await request('/read', accepted, { signal: controller.signal }).catch((error: unknown) => error)
    expect(failure).toMatchObject({ name: 'AbortError', message: 'Request cancelled' }); expect(fetcher).not.toHaveBeenCalled()
    expect(String(failure)).not.toContain('SECRET_BODY_CANARY')
  })
  it('aborts a pending body read promptly even if the stream ignores the fetch signal or its cancel promise never resolves', async () => {
    const controller = new AbortController(), cancel = vi.fn<() => Promise<void>>(() => new Promise(() => {}))
    const body = new ReadableStream<Uint8Array>({ start(stream) { stream.enqueue(bytes('{"data":')) }, cancel }, { highWaterMark: 0 })
    fetchResponse(new Response(body, { headers: { 'Content-Type': 'application/json' } }))
    const parse = vi.spyOn(JSON, 'parse'), result = request('/read', accepted, { signal: controller.signal }).catch((error: unknown) => error)
    await microtasks(); controller.abort(new Error('SECRET_BODY_CANARY'))
    expect(await result).toMatchObject({ name: 'AbortError', message: 'Request cancelled' })
    expect(cancel).toHaveBeenCalledTimes(1); expect(body.locked).toBe(false); expect(parse).not.toHaveBeenCalled()
  })
  it('applies the same 45-second total timeout during stalled body reads and clears its timer afterward', async () => {
    vi.useFakeTimers()
    const cancel = vi.fn<() => void>(), body = new ReadableStream<Uint8Array>({ cancel })
    const fetcher = fetchResponse(new Response(body, { headers: { 'Content-Type': 'application/json' } }))
    const result = request('/read', accepted).catch((error: unknown) => error)
    await microtasks(); await vi.advanceTimersByTimeAsync(44999)
    expect(cancel).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    expect(await result).toMatchObject({ code: 'MI_NETWORK_ERROR', status: 200 })
    expect(fetcher.mock.calls[0][1]?.signal?.aborted).toBe(true); expect(cancel).toHaveBeenCalledTimes(1)
    expect(body.locked).toBe(false); expect(vi.getTimerCount()).toBe(0)
  })
  it('keeps explicit caller cancellation distinct from the security downgrade of a denied stalled response', async () => {
    const controller = new AbortController(), body = new ReadableStream<Uint8Array>()
    fetchResponse(new Response(body, { status: 403, headers: { 'Content-Type': 'application/json' } }))
    const result = request('/read', accepted, { signal: controller.signal }).catch((error: unknown) => error)
    await microtasks(); controller.abort()
    const failure = await result
    expect(failure).toMatchObject({ name: 'AbortError' }); expect(sessionInvalid(failure)).toBe(false)
  })
  it('cannot retain authorized cache when a denied response stalls until the shared read deadline', async () => {
    vi.useFakeTimers()
    fetchResponse(new Response(new ReadableStream<Uint8Array>(), { status: 403, headers: { 'Content-Type': 'application/json' } }))
    const result = request('/read', accepted).catch((error: unknown) => error)
    await microtasks(); await vi.advanceTimersByTimeAsync(45000)
    const failure = await result
    expect(failure).toMatchObject({ code: 'MI_SESSION_REQUIRED', status: 403 }); expect(sessionInvalid(failure)).toBe(true)
  })
  it('will not return an otherwise valid result if the caller cancels during final DTO validation', async () => {
    const controller = new AbortController()
    fetchResponse(Response.json({ data: { ok: true }, request_id: 'req' }))
    await expect(request('/read', (value): value is { ok: true } => { controller.abort(); return accepted(value) }, { signal: controller.signal })).rejects.toMatchObject({ name: 'AbortError' })
  })
  it('aborts pending fetch promises without retrying, including adapters that ignore AbortSignal', async () => {
    vi.useFakeTimers()
    const fetcher = vi.fn<typeof fetch>(() => new Promise(() => {})); vi.stubGlobal('fetch', fetcher)
    const result = request('/read', accepted).catch((error: unknown) => error)
    await vi.advanceTimersByTimeAsync(45000)
    expect(await result).toMatchObject({ code: 'MI_NETWORK_ERROR' }); expect(fetcher).toHaveBeenCalledTimes(1); expect(vi.getTimerCount()).toBe(0)
  })
  it('closes a response that arrives after the caller already cancelled', async () => {
    const controller = new AbortController(), stream = byteResponse(bytes(successJSON))
    let finish!: (value: Response) => void
    vi.stubGlobal('fetch', vi.fn<typeof fetch>(() => new Promise((resolve) => { finish = resolve })))
    const result = request('/read', accepted, { signal: controller.signal }).catch((error: unknown) => error)
    controller.abort(); expect(await result).toMatchObject({ name: 'AbortError' })
    finish(stream.response); await microtasks()
    expect(stream.cancel).toHaveBeenCalledTimes(1); expect(stream.pull).not.toHaveBeenCalled()
  })
  it('bounds an infinite stream of zero-byte chunks without waiting for a starved timer', async () => {
    const cancel = vi.fn<() => void>(), body = new ReadableStream<Uint8Array>({ pull(stream) { stream.enqueue(new Uint8Array()) }, cancel }, { highWaterMark: 0 })
    fetchResponse(new Response(body, { headers: { 'Content-Type': 'application/json' } }))
    const parse = vi.spyOn(JSON, 'parse')
    await expect(request('/read', accepted)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    expect(parse).not.toHaveBeenCalled(); expect(cancel).toHaveBeenCalledTimes(1); expect(body.locked).toBe(false)
  })
  it('bounds total tiny reads independently from the decoded byte cap', async () => {
    let reads = 0
    const cancel = vi.fn<() => void>(), body = new ReadableStream<Uint8Array>({ pull(stream) { reads++; stream.enqueue(new Uint8Array([32])) }, cancel }, { highWaterMark: 0 })
    fetchResponse(new Response(body, { headers: { 'Content-Type': 'application/json' } }))
    const parse = vi.spyOn(JSON, 'parse')
    await expect(request('/read', accepted)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    expect(reads).toBe(131072); expect(parse).not.toHaveBeenCalled(); expect(cancel).toHaveBeenCalledTimes(1)
  })
  it('does not parse partial JSON after a network read failure or retain messages, URLs, errors or logs', async () => {
    const logs = [vi.spyOn(console, 'log'), vi.spyOn(console, 'warn'), vi.spyOn(console, 'error')]
    const body = new ReadableStream<Uint8Array>({ pull(stream) { stream.error(new TypeError('SECRET_BODY_CANARY https://private.example/?key=canary')) } })
    fetchResponse(new Response(body, { headers: { 'Content-Type': 'application/json' } }))
    const parse = vi.spyOn(JSON, 'parse'), failure = await request('/read', accepted).catch((error: unknown) => error)
    expect(failure).toMatchObject({ code: 'MI_NETWORK_ERROR', status: 200 }); expect(parse).not.toHaveBeenCalled()
    expect([String(failure), JSON.stringify(failure), (failure as Error).stack, errorMessage(failure)].join()).not.toContain('SECRET_BODY_CANARY')
    expect(logs.every((spy) => spy.mock.calls.length === 0)).toBe(true)
    expect(localStorage.length + sessionStorage.length).toBe(0)
  })
  it('closes arbitrary exceptions from a DTO guard instead of forwarding embedded data', async () => {
    fetchResponse(Response.json({ data: {}, request_id: 'req' }))
    const failure = await request('/read', (_value): _value is object => { throw new Error('SECRET_BODY_CANARY') }).catch((error: unknown) => error)
    expect(failure).toMatchObject({ code: 'MI_INVALID_RESPONSE' }); expect(String(failure)).not.toContain('SECRET_BODY_CANARY')
  })
})
