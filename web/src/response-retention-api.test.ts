import { describe, expect, it, vi } from 'vitest'
import { ApiError } from './api'
import { responseRetentionApi, type ResponseRetentionSummary } from './response-retention-api'

const org = '9007199254740993', runID = '9007199254740995'
function value(): ResponseRetentionSummary {
  return { version: 'mii.response-retention-summary.v1', run_id: runID, analysis_revision: 1, observed_at: '2026-09-08T12:00:00.123456789Z', policy_days: 30, policy_version: 2, attempt_count: 8, raw_deleted_count: 5, display_deleted_count: 2, display_expired_count: 1, display_retained_count: 3, last_deleted_at: '2026-09-08T11:00:00+08:00' }
}
const ok = (data: unknown) => Response.json({ data, request_id: 'retention-api-test' })
function network(response: Response | (() => Response | Promise<Response>) = ok(value())) {
  const calls = vi.fn<typeof fetch>(async () => typeof response === 'function' ? response() : response)
  vi.stubGlobal('fetch', calls); return calls
}

describe('closed S1 response-retention summary API', () => {
  it('pins exact int64 scope, revision and ordinary no-store transport without requesting body or deletion', async () => {
    const calls = network(), result = await responseRetentionApi.get(org, runID, 1)
    expect(result).toEqual(value())
    expect(calls.mock.calls[0][0]).toBe(`/api/v1/runs/${runID}/response-retention?analysis_revision=1`)
    expect(calls.mock.calls[0][1]).toMatchObject({ method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error' })
    expect(new Headers(calls.mock.calls[0][1]?.headers).get('X-Organization-ID')).toBe(org)
    expect(calls.mock.calls[0][1]?.body).toBeUndefined()
    expect(localStorage.length + sessionStorage.length).toBe(0)
  })
  it.each(['../2', '1?raw=1', '01', '0', '-1', '1/2', '1#x', '9223372036854775808', 'https://private.invalid'])('rejects invalid scope %s before dispatch', (bad) => {
    const calls = network()
    expect(() => responseRetentionApi.get(org, bad, 1)).toThrow(ApiError)
    expect(() => responseRetentionApi.get(bad, runID, 1)).toThrow(ApiError)
    expect(calls).not.toHaveBeenCalled()
  })
  it.each([0, 2, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])('rejects unsupported revision %s before dispatch', (revision) => {
    const calls = network(); expect(() => responseRetentionApi.get(org, runID, revision)).toThrow(ApiError); expect(calls).not.toHaveBeenCalled()
  })
  it('rejects extra fields, wrong scope/version/revision and every missing required field', async () => {
    for (const patch of [{ run_id: '2' }, { analysis_revision: 2 }, { version: 'unknown' }, { raw_body: 'PRIVATE_RETENTION_CANARY' }, { ciphertext: 'PRIVATE_RETENTION_CANARY' }, { observed_at: null }, { last_deleted_at: undefined }]) {
      network(ok({ ...value(), ...patch })); await expect(responseRetentionApi.get(org, runID, 1)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    }
    for (const key of Object.keys(value())) {
      const data = { ...value() } as Record<string, unknown>; delete data[key]
      network(ok(data)); await expect(responseRetentionApi.get(org, runID, 1)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    }
  })
  it.each(['attempt_count', 'raw_deleted_count', 'display_deleted_count', 'display_expired_count', 'display_retained_count', 'policy_version', 'policy_days'])('rejects unsafe/noninteger/negative %s', async (field) => {
    for (const invalid of [-1, 0.5, '1', null, true, Number.MAX_SAFE_INTEGER + 1]) {
      network(ok({ ...value(), [field]: invalid })); await expect(responseRetentionApi.get(org, runID, 1)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    }
  })
  it('requires each count within Attempts and disjoint display counts within their common bound, but keeps raw deletion independent', async () => {
    for (const patch of [{ policy_version: 0 }, { policy_days: 181 }, { attempt_count: 1 }, { raw_deleted_count: 9 }, { display_deleted_count: 9 }, { display_expired_count: 9 }, { display_retained_count: 9 }, { display_deleted_count: 3, display_expired_count: 3, display_retained_count: 3 }]) {
      network(ok({ ...value(), ...patch })); await expect(responseRetentionApi.get(org, runID, 1)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    }
    const data = { ...value(), attempt_count: 2, raw_deleted_count: 2, display_deleted_count: 1, display_expired_count: 0, display_retained_count: 1 }
    network(ok(data)); expect(await responseRetentionApi.get(org, runID, 1)).toEqual(data)
    const maximum = { ...data, attempt_count: 1536, raw_deleted_count: 1536, display_deleted_count: 1535, display_retained_count: 1 }
    network(ok(maximum)); expect((await responseRetentionApi.get(org, runID, 1)).attempt_count).toBe(1536)
    network(ok({ ...maximum, display_expired_count: 1 })); await expect(responseRetentionApi.get(org, runID, 1)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it.each([1537, Number.MAX_SAFE_INTEGER])('rejects attempt count %s above the protocol ceiling', async (attempts) => {
    network(ok({ ...value(), attempt_count: attempts }))
    await expect(responseRetentionApi.get(org, runID, 1)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it.each([{ raw: 0, display: 0 }, { raw: 1, display: 0 }, { raw: 0, display: 1 }, { raw: 1, display: 1 }])('requires deletion time exactly when raw=$raw or display=$display deletion exists', async ({ raw, display }) => {
    const data = { ...value(), raw_deleted_count: raw, display_deleted_count: display, last_deleted_at: raw + display === 0 ? null : value().last_deleted_at }
    network(ok(data)); expect(await responseRetentionApi.get(org, runID, 1)).toEqual(data)
    network(ok({ ...data, last_deleted_at: data.last_deleted_at === null ? value().last_deleted_at : null }))
    await expect(responseRetentionApi.get(org, runID, 1)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it.each([
    { observed: '2026-09-08T12:00:00.123456789Z', deleted: '2026-09-08T20:00:00.123456789+08:00' },
    { observed: '2026-09-08T12:00:00.123456789Z', deleted: '2026-09-08T07:00:00.123456789-05:00' },
    { observed: '2026-09-08T12:00:00.123456789Z', deleted: '2026-09-08T12:00:00.123456788Z' },
    { observed: '2026-09-08T12:00:00.1234Z', deleted: '2026-09-08T12:00:00.123400000Z' },
    { observed: '2026-09-08T12:00:00.123000000Z', deleted: '2026-09-08T12:00:00.122999999Z' },
    { observed: '2026-09-08T00:00:00Z', deleted: '2026-09-07T23:00:00-01:00' },
    { observed: '2026-09-08T00:00:00.000000001Z', deleted: '2026-09-08T00:30:00+00:30' },
  ])('accepts exact or earlier deletion across precision and offsets: $deleted <= $observed', async ({ observed, deleted }) => {
    const data = { ...value(), observed_at: observed, last_deleted_at: deleted }
    network(ok(data)); expect(await responseRetentionApi.get(org, runID, 1)).toEqual(data)
  })
  it.each([
    { observed: '2026-09-08T12:00:00.123456Z', deleted: '2026-09-08T12:00:00.123457Z' },
    { observed: '2026-09-08T12:00:00.123456789Z', deleted: '2026-09-08T12:00:00.123456790Z' },
    { observed: '2026-09-08T12:00:00Z', deleted: '2026-09-08T12:00:00.000000001Z' },
    { observed: '2026-09-08T12:00:00.123456789Z', deleted: '2026-09-08T20:00:00.123456790+08:00' },
    { observed: '2026-09-08T12:00:00.123456789Z', deleted: '2026-09-08T07:00:00.123456790-05:00' },
    { observed: '2026-09-08T00:00:00Z', deleted: '2026-09-07T23:00:00.000000001-01:00' },
    { observed: '2026-09-08T12:00:00.122999999Z', deleted: '2026-09-08T12:00:00.123000000Z' },
  ])('rejects future deletion without rounding sub-millisecond precision: $deleted > $observed', async ({ observed, deleted }) => {
    network(ok({ ...value(), observed_at: observed, last_deleted_at: deleted }))
    await expect(responseRetentionApi.get(org, runID, 1)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it.each([0, 7, 30, 180])('preserves policy %s and observed real zeros/null without inferring deletion', async (days) => {
    const data = { ...value(), policy_days: days, attempt_count: 0, raw_deleted_count: 0, display_deleted_count: 0, display_expired_count: 0, display_retained_count: 0, last_deleted_at: null }
    network(ok(data)); expect(await responseRetentionApi.get(org, runID, 1)).toEqual(data)
  })
  it.each(['2026-02-30T12:00:00Z', '2026-09-08T24:00:00Z', '2026-09-08T12:60:00Z', '2026-09-08', '2026-09-08T12:00:00', '2026-09-08T12:00:00+99:00', 'not-a-date', '<img>PRIVATE_RETENTION_CANARY'])('rejects non-RFC3339 date or calendar alias %s', async (date) => {
    for (const field of ['observed_at', 'last_deleted_at']) {
      network(ok({ ...value(), [field]: date })); await expect(responseRetentionApi.get(org, runID, 1)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    }
  })
  it('does not return a zero summary after a malformed success/error or an oversized transport', async () => {
    for (const response of [Response.json({ data: value() }), new Response('{"data":', { headers: { 'Content-Type': 'application/json' } }), new Response('<html>PRIVATE_RETENTION_CANARY', { status: 503 }), new Response('{}', { headers: { 'Content-Type': 'application/json', 'Content-Length': String((8 << 20) + 1) } })]) {
      network(response); await expect(responseRetentionApi.get(org, runID, 1)).rejects.toBeInstanceOf(ApiError)
    }
  })
  it.each([401, 403])('keeps malformed HTTP %s denied rather than treating it as an empty summary', async (status) => {
    network(new Response('<html>PRIVATE_RETENTION_CANARY', { status }))
    await expect(responseRetentionApi.get(org, runID, 1)).rejects.toMatchObject({ code: 'MI_SESSION_REQUIRED', status })
  })
  it('aborts an uncooperative request and discards its late scoped response', async () => {
    let release: ((response: Response) => void) | undefined
    const calls = network(() => new Promise<Response>((resolve) => { release = resolve }))
    const controller = new AbortController(), pending = responseRetentionApi.get(org, runID, 1, controller.signal).catch((error: unknown) => error)
    controller.abort(); expect(await pending).toMatchObject({ name: 'AbortError' }); release!(ok(value()))
    expect(calls.mock.calls[0][1]?.signal?.aborted).toBe(true)
  })
})
