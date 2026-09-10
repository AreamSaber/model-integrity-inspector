import { describe, expect, it, vi } from 'vitest'
import { evidenceDisplayApi, evidenceDisplayStatuses, type EvidenceDisplay, type EvidenceSelection } from './evidence-display-api'
import { ApiError } from './api'

const org = '9007199254740993'
const selection: EvidenceSelection = { runID: '9007199254740995', sampleID: '9007199254740997', attemptID: '9007199254740999', analysisRevision: 1, isFinal: true }
function value(): EvidenceDisplay {
  return { version: 'mii.evidence-display-output.v1', run_id: selection.runID, sample_id: selection.sampleID, attempt_id: selection.attemptID, analysis_revision: 1, is_final: true, status: 'available', payload_hash: 'a'.repeat(64), content: {
    version: 1, policy: 'display-redaction-v1', source_hash: 'b'.repeat(64), request_hash: 'c'.repeat(64), template_hash: 'd'.repeat(64), request_json: '{"messages":[{"role":"user","content":"[REDACTED]"}],"seed":9223372036854775807}', request_changed: true, metadata_omitted: true,
    response: { content: '<script>CANARY_BODY</script>', model_reported: 'synthetic-model', http_status: 200, finish_reason: 'stop', parse_status: 'valid', prompt_tokens: null, completion_tokens: 10, total_tokens: null, reasoning_tokens: null, duration_ms: 100, first_token_ms: null, stream_terminated: false, events: null, event_summary_partial: false },
  } }
}
function ok(data: unknown) { return Response.json({ data, request_id: 'synthetic-evidence-test' }) }
function network(response: Response | (() => Response | Promise<Response>) = ok(value())) {
  const calls = vi.fn<typeof fetch>(async () => typeof response === 'function' ? response() : response)
  vi.stubGlobal('fetch', calls); return calls
}

describe('bounded explicit response-display API', () => {
  it('pins request scope before awaiting fetch, so a caller mutation cannot authorize a different late Attempt', async () => {
    let release: ((response: Response) => void) | undefined
    network(() => new Promise<Response>((resolve) => { release = resolve }))
    const input = { ...selection }, pending = evidenceDisplayApi.get(org, input)
    input.attemptID = '2'; input.isFinal = false
    release!(ok({ ...value(), attempt_id: '2', is_final: false }))
    await expect(pending).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('uses the sole fixed endpoint with exact int64 IDs and same-origin no-store GET, preserving request JSON seed text', async () => {
    const calls = network()
    const result = await evidenceDisplayApi.get(org, selection)
    expect(result.content?.request_json).toContain('9223372036854775807')
    expect(result.content?.response.prompt_tokens).toBeNull()
    expect(calls.mock.calls[0][0]).toBe(`/api/v1/runs/${selection.runID}/samples/${selection.sampleID}/attempts/${selection.attemptID}/evidence?analysis_revision=1`)
    expect(calls.mock.calls[0][1]).toMatchObject({ method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error' })
    expect(new Headers(calls.mock.calls[0][1]?.headers).get('X-Organization-ID')).toBe(org)
    expect(calls.mock.calls[0][1]?.body).toBeUndefined()
    expect(localStorage.length + sessionStorage.length).toBe(0)
  })
  it.each(evidenceDisplayStatuses.filter((status) => status !== 'available'))('accepts only null content for the authenticated unavailable status %s', async (status) => {
    const data = { ...value(), status, content: null }; delete data.payload_hash
    network(ok(data)); expect((await evidenceDisplayApi.get(org, selection)).status).toBe(status)
    network(ok({ ...data, payload_hash: 'a'.repeat(64) })); expect((await evidenceDisplayApi.get(org, selection)).content).toBeNull()
    network(ok({ ...data, content: value().content })); await expect(evidenceDisplayApi.get(org, selection)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it.each(['../2', '1?raw=1', '1#x', '1/2', '01', '0', '-1', '9223372036854775808', '9007199254740993.0', 'https://synthetic.invalid'])('rejects path aliases/injection %s before fetching', async (bad) => {
    const calls = network()
    for (const field of ['runID', 'sampleID', 'attemptID'] as const) expect(() => evidenceDisplayApi.get(org, { ...selection, [field]: bad })).toThrow(ApiError)
    expect(() => evidenceDisplayApi.get(bad, selection)).toThrow(ApiError)
    expect(calls).not.toHaveBeenCalled()
  })
  it('rejects other revision/finality inputs and mismatching output scope or extra S2 transport fields', async () => {
    const calls = network()
    expect(() => evidenceDisplayApi.get(org, { ...selection, analysisRevision: 2 })).toThrow(ApiError)
    expect(() => evidenceDisplayApi.get(org, { ...selection, isFinal: undefined as unknown as boolean })).toThrow(ApiError)
    expect(calls).not.toHaveBeenCalled()
    for (const changed of [{ run_id: '2' }, { sample_id: '2' }, { attempt_id: '2' }, { analysis_revision: 2 }, { is_final: false }, { version: 'unknown' }, { status: 'available_guess' }, { endpoint: 'PRIVATE_ERROR_CANARY' }, { content: null }, { payload_hash: undefined }]) {
      network(ok({ ...value(), ...changed })); await expect(evidenceDisplayApi.get(org, selection)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    }
  })
  it('rejects incompatible content schema, unsafe numbers, invalid events and contradictory request-changed flag', async () => {
    const mutations: ((data: EvidenceDisplay) => unknown)[] = [
      (d) => ({ ...d.content, version: 2 }), (d) => ({ ...d.content, policy: 'request-redaction-v1' }), (d) => ({ ...d.content, metadata_omitted: false }), (d) => ({ ...d.content, request_changed: false }), (d) => ({ ...d.content, request_json: 'not JSON' }), (d) => ({ ...d.content, request_json: '[]' }), (d) => ({ ...d.content, headers: { Authorization: 'PRIVATE_ERROR_CANARY' } }),
      (d) => ({ ...d.content, response: { ...d.content!.response, prompt_tokens: 9007199254740992 } }), (d) => ({ ...d.content, response: { ...d.content!.response, total_tokens: -1 } }), (d) => ({ ...d.content, response: { ...d.content!.response, duration_ms: 86400001 } }), (d) => ({ ...d.content, response: { ...d.content!.response, first_token_ms: 101 } }), (d) => ({ ...d.content, response: { ...d.content!.response, provider_request_id: 'PRIVATE_ERROR_CANARY' } }), (d) => ({ ...d.content, response: { ...d.content!.response, parse_status: 'guess' } }),
      (d) => ({ ...d.content, response: { ...d.content!.response, events: [{ sequence: 1, type: 'content_delta', bytes: 4, arrival_ms: 10, interval_ms: 10 }, { sequence: 1, type: 'done', bytes: 4, arrival_ms: 11, interval_ms: 1 }] } }),
      (d) => ({ ...d.content, response: { ...d.content!.response, events: [{ sequence: 1, type: 'raw', bytes: 4, arrival_ms: 10, interval_ms: 10 }] } }),
      (d) => ({ ...d.content, response: { ...d.content!.response, finish_reason: ['stop'] } }),
      (d) => ({ ...d.content, response: { ...d.content!.response, parse_status: ['valid'] } }),
      (d) => ({ ...d.content, response: { ...d.content!.response, content: '中'.repeat((1 << 20) / 3 + 1) } }),
    ]
    for (const mutate of mutations) { const data = value(); network(ok({ ...data, content: mutate(data) })); await expect(evidenceDisplayApi.get(org, selection)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' }) }
  })
  it('retains backend safe-count maximum exactly, null observations and valid bounded event summaries', async () => {
    const data = value(); data.content!.response.prompt_tokens = Number.MAX_SAFE_INTEGER
    data.content!.response.events = [{ sequence: 1, type: 'content_delta', bytes: 4, arrival_ms: 10, interval_ms: 10 }, { sequence: 3, type: 'done', bytes: 0, arrival_ms: 100, interval_ms: 90 }]
    data.content!.response.event_summary_partial = true
    network(ok(data)); const result = await evidenceDisplayApi.get(org, selection)
    expect(result.content!.response.prompt_tokens).toBe(Number.MAX_SAFE_INTEGER)
    expect(result.content!.response.first_token_ms).toBeNull()
  })
  it('retains ordinary mandatory request_id and rejects malformed/truncated transport before any content result', async () => {
    for (const response of [Response.json({ data: value() }), new Response('{"data":', { headers: { 'Content-Type': 'application/json' } }), new Response('<html>PRIVATE_ERROR_CANARY', { headers: { 'Content-Type': 'text/html' } }), new Response(new Uint8Array([0xff]), { headers: { 'Content-Type': 'application/json' } })]) {
      network(response); await expect(evidenceDisplayApi.get(org, selection)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    }
  })
  it('rejects declared or decompressed bytes above the fixed 8 MiB cap and cancels the stream', async () => {
    const cancel = vi.fn<() => void>()
    const stream = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(new Uint8Array((8 << 20) + 1)) }, cancel })
    network(new Response(stream, { headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip', 'Content-Length': '1' } }))
    await expect(evidenceDisplayApi.get(org, selection)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    expect(cancel).toHaveBeenCalled()
    network(new Response('{}', { headers: { 'Content-Type': 'application/json', 'Content-Length': String((8 << 20) + 1) } }))
    await expect(evidenceDisplayApi.get(org, selection)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it.each([401, 403])('keeps HTTP %s denial fail-closed even when its error envelope is untrusted', async (status) => {
    network(new Response('<html>PRIVATE_ERROR_CANARY', { status }))
    await expect(evidenceDisplayApi.get(org, selection)).rejects.toMatchObject({ code: 'MI_SESSION_REQUIRED', status })
  })
  it('aborts pending permission-independent fetch and rejects an uncooperative late response', async () => {
    let release: ((response: Response) => void) | undefined
    const calls = network(() => new Promise<Response>((resolve) => { release = resolve }))
    const controller = new AbortController(), result = evidenceDisplayApi.get(org, selection, controller.signal)
    const rejected = result.catch((error: unknown) => error)
    controller.abort(); expect(await rejected).toMatchObject({ name: 'AbortError' }); release!(ok(value()))
    expect(calls.mock.calls[0][1]?.signal?.aborted).toBe(true)
  })
})
