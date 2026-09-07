import { describe, expect, it, vi } from 'vitest'
import { ApiError } from './api'
import { review, reviewExplanation, reviewsApi, type Review, type ReviewInput } from './reviews-api'

const org = '9007199254740993', run = '9007199254740995', user = '9007199254740997', key = 'review:synthetic-123456789'
const body: ReviewInput = { analysis_revision: 1, conclusion: 'watch', explanation: '人工观察，不是内部配置证明。' }
function record(): Review { return { id: '9007199254740999', run_id: run, analysis_revision: 1, conclusion: body.conclusion, explanation: body.explanation, created_by: user, created_at: '2026-09-07T10:00:00.000001Z' } }
function ok(data: unknown, status = 200) { return Response.json({ data, request_id: 'review-request' }, { status }) }

describe('bounded immutable review API', () => {
  it('reads the exact revision with bounded server paging and opaque cursor, without a mutation', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(ok({ items: [record()], next_cursor: 'opaque:second' })); vi.stubGlobal('fetch', fetcher)
    const value = await reviewsApi.list(org, run, 1, 'opaque first:+')
    expect(value.items[0]).toEqual(record())
    const [url, options] = fetcher.mock.calls[0]
    expect(url).toBe(`/api/v1/runs/${run}/reviews?analysis_revision=1&limit=25&cursor=opaque+first%3A%2B`)
    expect(options?.method).toBe('GET'); expect(options?.body).toBeUndefined()
    expect(new Headers(options?.headers).get('X-Organization-ID')).toBe(org)
    expect(options?.credentials).toBe('same-origin'); expect(options?.cache).toBe('no-store')
  })
  it('sends only the append DTO with session CSRF and unchanged idempotency identity', async () => {
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async () => ok(record(), 201)); vi.stubGlobal('fetch', fetcher)
    await reviewsApi.append(org, run, 'synthetic-csrf', user, body, key)
    await reviewsApi.append(org, run, 'synthetic-csrf', user, body, key)
    const [url, options] = fetcher.mock.calls[0]
    expect(url).toBe(`/api/v1/runs/${run}/reviews`); expect(options?.method).toBe('POST')
    expect(JSON.parse(options!.body as string)).toEqual(body)
    expect(new Headers(options?.headers).get('Idempotency-Key')).toBe(key)
    expect(new Headers(options?.headers).get('X-CSRF-Token')).toBe('synthetic-csrf')
    expect(fetcher.mock.calls[1][1]?.body).toBe(options?.body)
    expect(JSON.parse(options!.body as string)).not.toHaveProperty('previous_review_id')
  })
  it('retains an explicitly read previous review as a string and does not substitute latest data', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(ok(record(), 201)); vi.stubGlobal('fetch', fetcher)
    await reviewsApi.append(org, run, 'csrf', user, { ...body, previous_review_id: '9007199254740998' }, key)
    expect(JSON.parse(fetcher.mock.calls[0][1]!.body as string).previous_review_id).toBe('9007199254740998')
  })
  it.each([
    { ...record(), run_id: '99' }, { ...record(), analysis_revision: 2 }, { ...record(), created_by: '99' },
    { ...record(), explanation: 'different statement' }, { ...record(), conclusion: 'confirmed' }, { ...record(), body: 'SECRET_BODY_CANARY' },
  ])('rejects mismatched append receipts without preserving response text %#', async (value) => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValue(ok(value, 201)))
    const failure = await reviewsApi.append(org, run, 'csrf', user, body, key).catch((error: unknown) => error)
    expect(failure).toMatchObject({ code: 'MI_INVALID_RESPONSE' }); expect(String(failure)).not.toContain('SECRET_BODY_CANARY')
  })
  it.each([
    { items: [record(), record()], next_cursor: null },
    { items: [{ ...record(), run_id: '99' }], next_cursor: null },
    { items: [{ ...record(), analysis_revision: 2 }], next_cursor: null },
    { items: Array.from({ length: 26 }, (_, i) => ({ ...record(), id: String(i + 1) })), next_cursor: null },
    { items: [], next_cursor: 'x'.repeat(1025) }, { items: [], next_cursor: null, raw: 'SECRET_BODY_CANARY' },
  ])('rejects unbounded, duplicate, wrong-scope or non-whitelisted pages %#', async (value) => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValue(ok(value)))
    await expect(reviewsApi.list(org, run, 1)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('enforces UTF-8 bytes, valid Unicode and the server note control policy', () => {
    expect(reviewExplanation('字'.repeat(1365))).toBe(true)
    expect(reviewExplanation('字'.repeat(1366))).toBe(false)
    expect(reviewExplanation('😀'.repeat(1024))).toBe(true)
    expect(reviewExplanation('text\nline\tend')).toBe(true)
    expect(reviewExplanation('<img src=x onerror=alert(1)>')).toBe(true) // Render as text, never HTML.
    for (const note of ['', ' \n\t', '\ud800', 'a\r\nb', 'a\0b', 'a\u202eb', 'a\u200db', 'x'.repeat(4097)]) expect(reviewExplanation(note)).toBe(false)
    expect(review({ ...record(), explanation: undefined })).toBe(false)
    expect(review({ ...record(), id: '9223372036854775808' })).toBe(false)
  })
  it('fails malformed writes and unsupported scope before fetch', () => {
    const fetcher = vi.fn<typeof fetch>(); vi.stubGlobal('fetch', fetcher)
    for (const invalid of [{ ...body, previous_review_id: null }, { ...body, previous_review_id: '0' }, { ...body, conclusion: 'approved' }, { ...body, created_by: user }, { ...body, analysis_revision: 2 }]) {
      expect(() => reviewsApi.append(org, run, 'csrf', user, invalid as ReviewInput, key)).toThrow(ApiError)
    }
    for (const invalid of ['short', 'x'.repeat(129), 'valid-key-but-space ', 'bad-key\r\nvalue']) expect(() => reviewsApi.append(org, run, 'csrf', user, body, invalid)).toThrow(ApiError)
    expect(() => reviewsApi.list('0', run, 1)).toThrow(ApiError)
    expect(() => reviewsApi.list(org, '1/other', 1)).toThrow(ApiError)
    expect(() => reviewsApi.list(org, run, 2)).toThrow(ApiError)
    expect(fetcher).not.toHaveBeenCalled()
  })
  it('returns the closed conflict code and honors cancellation without logging server notes', async () => {
    const log = vi.spyOn(console, 'error'), warn = vi.spyOn(console, 'warn')
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValue(Response.json({ error: { code: 'MI_REVIEW_CONFLICT', message: 'SECRET_BODY_CANARY' }, request_id: 'review-error' }, { status: 409 })))
    await expect(reviewsApi.append(org, run, 'csrf', user, body, key)).rejects.toMatchObject({ code: 'MI_REVIEW_CONFLICT', status: 409 })
    const controller = new AbortController(); controller.abort('SECRET_BODY_CANARY')
    await expect(reviewsApi.list(org, run, 1, '', controller.signal)).rejects.toMatchObject({ name: 'AbortError' })
    expect(log).not.toHaveBeenCalled(); expect(warn).not.toHaveBeenCalled()
  })
})
