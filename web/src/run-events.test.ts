import { describe, expect, it, vi } from 'vitest'
import { watchRun, validateRunProgress } from './run-events'
import type { Run } from './runs-api'

const org = '9007199254740995'
const initial: Run = {
  id: '9007199254741023', target_id: '9007199254741005', created_by: '9007199254740993', package: 'quick', status: 'QUEUED', version: 1,
  versions: { rule_bundle: '1.0.0-dev.1', template_bundle: '1.0.0-dev.1', scoring: '1.0.0-dev.1', tokenizer_bundle: '1.0.0' },
  estimate: { requests: 18, input_tokens: 2000, max_output_tokens: 4000, cost_micros: null, duration_seconds: 900, usage_safety_factor: 1.25, warnings: ['MI_PROBE_DEVELOPMENT_UNCALIBRATED'], completeness: 'full' },
  manifest_hash: 'a'.repeat(64), request_count: 0, token_count: 0, estimated_cost_micros: null, valid_sample_count: 0, planned_samples: 18, completed_samples: 0,
  created_at: '2026-09-07T08:00:00Z', started_at: null, finished_at: null, execution_closed_at: null, error_summary: [],
}
const running: Run = { ...initial, version: 2, status: 'RUNNING', request_count: 1, completed_samples: 1, valid_sample_count: 1, token_count: 20, started_at: '2026-09-07T08:00:01Z' }
const finished: Run = { ...running, version: 3, status: 'PARTIAL', finished_at: '2026-09-07T08:01:00Z', execution_closed_at: '2026-09-07T08:00:59Z' }
const json = (value: Run) => Response.json({ data: value, request_id: 'test-sse-request' })
const frame = (value: Run, eventID = `${value.id}:${value.version}`) => `event: progress\nid: ${eventID}\ndata: ${JSON.stringify(value)}\n\n`
function stream(text: string | Uint8Array, chunks = 1024) {
  const bytes = typeof text === 'string' ? new TextEncoder().encode(text) : text
  return new Response(new ReadableStream<Uint8Array>({ start(controller) {
    for (let offset = 0; offset < bytes.length; offset += chunks) controller.enqueue(bytes.slice(offset, offset + chunks))
    controller.close()
  } }), { headers: { 'Content-Type': 'text/event-stream; charset=utf-8' } })
}
const microtasks = async () => { for (let i = 0; i < 40; i++) await Promise.resolve() }
function options() { return { organizationID: org, initial, signal: new AbortController().signal, onSnapshot: vi.fn<(value: Run) => void>() } }

describe('bounded authenticated Run SSE client', () => {
  it('reads a terminal Run exactly once, without opening events or writing anything', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(finished)); vi.stubGlobal('fetch', fetcher)
    expect(await watchRun(options())).toEqual({ record: finished, reason: 'terminal' })
    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(fetcher.mock.calls[0][0]).toBe(`/api/v1/runs/${initial.id}`)
    expect(fetcher.mock.calls[0][1]?.method).toBe('GET')
  })

  it('decodes fragmented UTF-8/CRLF frames and reconciles a terminal notification using exact GET', async () => {
    const events = (`: 心跳\n\n${frame(running)}${frame(finished)}`).replaceAll('\n', '\r\n')
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(initial)).mockResolvedValueOnce(stream(events, 1)).mockResolvedValueOnce(json(finished))
    vi.stubGlobal('fetch', fetcher)
    const config = options()
    expect(await watchRun(config)).toEqual({ record: finished, reason: 'terminal' })
    expect(config.onSnapshot.mock.calls.map(([value]) => value.version)).toEqual([1, 2, 3, 3])
    const request = fetcher.mock.calls[1][1]!
    expect(request.method).toBe('GET'); expect(request.credentials).toBe('same-origin'); expect(request.redirect).toBe('error')
    const headers = new Headers(request.headers)
    expect(headers.get('Accept')).toBe('text/event-stream'); expect(headers.get('X-Organization-ID')).toBe(org)
    expect(headers.has('Last-Event-ID')).toBe(false); expect(request.body).toBeUndefined()
    expect(window.localStorage.length + window.sessionStorage.length).toBe(0)
  })

  it('recovers EOF by GET and reconnects with the last accepted ID, never a new execution', async () => {
    vi.useFakeTimers()
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(initial)).mockResolvedValueOnce(stream(frame(running))).mockResolvedValueOnce(json(running))
      .mockResolvedValueOnce(stream(frame(finished))).mockResolvedValueOnce(json(finished))
    vi.stubGlobal('fetch', fetcher)
    const result = watchRun(options())
    await microtasks()
    expect(fetcher).toHaveBeenCalledTimes(3)
    await vi.advanceTimersByTimeAsync(1000)
    expect(await result).toEqual({ record: finished, reason: 'terminal' })
    expect(new Headers(fetcher.mock.calls[3][1]?.headers).get('Last-Event-ID')).toBe(`${initial.id}:2`)
    expect(fetcher.mock.calls.every(([path, request]) => String(path).startsWith(`/api/v1/runs/${initial.id}`) && request?.method === 'GET')).toBe(true)
  })

  it.each([
    ['MI_SESSION_REQUIRED', 401], ['MI_PERMISSION_DENIED', 403], ['MI_PASSWORD_CHANGE_REQUIRED', 403], ['MI_NOT_FOUND', 404],
  ])('stops on streamed %s without reconnecting or retaining diagnostic text', async (code, status) => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(initial)).mockResolvedValueOnce(stream(`event: error\ndata: ${JSON.stringify({ code, request_id: 'closed-id' })}\n\n`))
    vi.stubGlobal('fetch', fetcher)
    await expect(watchRun(options())).rejects.toMatchObject({ code, status, requestID: 'closed-id' })
    expect(fetcher).toHaveBeenCalledTimes(2)
  })

  it('stops on denied HTTP handshake and never caches the response message', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(initial)).mockResolvedValueOnce(Response.json({ error: { code: 'MI_PASSWORD_CHANGE_REQUIRED', message: 'PRIVATE-CANARY' }, request_id: 'request-1' }, { status: 403 }))
    vi.stubGlobal('fetch', fetcher)
    const failure = await watchRun(options()).catch((error: unknown) => error)
    expect(failure).toMatchObject({ code: 'MI_PASSWORD_CHANGE_REQUIRED', status: 403 })
    expect(JSON.stringify(failure)).not.toContain('PRIVATE-CANARY'); expect(fetcher).toHaveBeenCalledTimes(2)
  })

  it('honors bounded 429 Retry-After and reconciles persisted state before reconnect', async () => {
    vi.useFakeTimers()
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(initial)).mockResolvedValueOnce(Response.json({ error: { code: 'MI_RATE_LIMITED' }, request_id: 'request-1' }, { status: 429, headers: { 'Retry-After': '5' } }))
      .mockResolvedValueOnce(json(initial)).mockResolvedValueOnce(stream(frame(finished))).mockResolvedValueOnce(json(finished))
    vi.stubGlobal('fetch', fetcher)
    const result = watchRun(options()); await microtasks()
    expect(fetcher).toHaveBeenCalledTimes(3)
    await vi.advanceTimersByTimeAsync(4999); expect(fetcher).toHaveBeenCalledTimes(3)
    await vi.advanceTimersByTimeAsync(1); expect((await result).reason).toBe('terminal')
  })

  it.each([
    ['wrong cursor', () => stream(frame(running, '2:2'))],
    ['wrong target', () => stream(frame({ ...running, target_id: '2' }))],
    ['changed manifest', () => stream(frame({ ...running, manifest_hash: 'b'.repeat(64) }))],
    ['changed version bundle', () => stream(frame({ ...running, versions: { ...running.versions, scoring: 'untrusted' } }))],
    ['changed frozen estimate', () => stream(frame({ ...running, estimate: { ...running.estimate, max_output_tokens: 1 } }))],
    ['extra sensitive field', () => stream(frame({ ...running, prompt: 'PRIVATE-CANARY' } as Run))],
    ['wrong content type', () => Response.json({ private: 'PRIVATE-CANARY' })],
    ['malformed UTF-8', () => stream(new Uint8Array([0xc0, 0xaf, 10, 10]))],
    ['oversized frame', () => stream(`: ${'x'.repeat(65537)}\n\n`)],
    ['oversized UTF-8 frame', () => stream(`: ${'汉'.repeat(22000)}\n\n`)],
    ['unknown event', () => stream('event: private\ndata: {}\n\n')],
  ])('fails closed on %s after one exact-ID recovery read', async (_name, response) => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(initial)).mockResolvedValueOnce(response()).mockResolvedValueOnce(json(initial))
    vi.stubGlobal('fetch', fetcher)
    const config = options()
    await expect(watchRun(config)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    expect(config.onSnapshot.mock.calls.every(([value]) => value === initial || JSON.stringify(value) === JSON.stringify(initial))).toBe(true)
    expect(fetcher).toHaveBeenCalledTimes(3)
  })

  it('does not treat a lost/truncated event as completed, but can recover the persisted terminal Run', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(initial)).mockResolvedValueOnce(stream(frame(finished).slice(0, -2))).mockResolvedValueOnce(json(finished))
    vi.stubGlobal('fetch', fetcher)
    const config = options()
    expect((await watchRun(config)).record).toEqual(finished)
    expect(config.onSnapshot).toHaveBeenCalledTimes(2)
  })

  it('recovers an actual fetch TypeError as a network disconnection', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(initial)).mockRejectedValueOnce(new TypeError('PRIVATE URL')).mockResolvedValueOnce(json(finished))
    vi.stubGlobal('fetch', fetcher)
    expect((await watchRun(options())).reason).toBe('terminal')
  })

  it('limits persistent disconnects to twelve connections and leaves the last real Run unchanged', async () => {
    vi.useFakeTimers()
    let connections = 0
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (path) => {
      if (String(path).endsWith('/events')) { connections++; return stream(frame(initial)) }
      return json(initial)
    })
    vi.stubGlobal('fetch', fetcher)
    const result = watchRun(options())
    await vi.runAllTimersAsync()
    expect(await result).toEqual({ record: initial, reason: 'limit' })
    expect(connections).toBe(12)
    expect(fetcher).toHaveBeenCalledTimes(25)
  })

  it('cancels an in-progress connection when leaving the organization and releases its stream', async () => {
    const controller = new AbortController()
    let streamSignal: AbortSignal | undefined
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(initial)).mockImplementationOnce(async (_path, request) => {
      streamSignal = request?.signal ?? undefined
      return new Response(new ReadableStream<Uint8Array>({ start(streamController) {
        streamController.enqueue(new TextEncoder().encode(frame(running)))
        streamSignal?.addEventListener('abort', () => streamController.error(new DOMException('Aborted', 'AbortError')), { once: true })
      } }), { headers: { 'Content-Type': 'text/event-stream' } })
    })
    vi.stubGlobal('fetch', fetcher)
    const config = { ...options(), signal: controller.signal }
    const result = watchRun(config).catch((error: unknown) => error)
    await microtasks(); controller.abort()
    expect(await result).toMatchObject({ name: 'AbortError' })
    expect(streamSignal?.aborted).toBe(true)
    expect(fetcher).toHaveBeenCalledTimes(2)
  })

  it('checks immutable identity, monotonic counters and terminal state independently of property order', () => {
    const { warnings, ...estimate } = initial.estimate
    expect(() => validateRunProgress(initial, initial, { ...running, estimate: { warnings, ...estimate } })).not.toThrow()
    expect(() => validateRunProgress(initial, running, initial)).toThrow('MI_INVALID_RESPONSE')
    expect(() => validateRunProgress(initial, running, { ...running, request_count: 0 })).toThrow('MI_INVALID_RESPONSE')
    expect(() => validateRunProgress(initial, finished, { ...running, version: 4 })).toThrow('MI_INVALID_RESPONSE')
    expect(() => validateRunProgress(initial, initial, { ...initial, created_by: '2' })).toThrow('MI_INVALID_RESPONSE')
  })
})
