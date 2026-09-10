import { describe, expect, it, vi } from 'vitest'
import { attemptTrend, trendInstant, trendsApi, trendsHref, trendsPage, trendsQuery, trendsRoute, utcFilterInput, type TrendsFilters } from './trends-api'
import { attempts, emptyAttempts, fail, item, ok, org, page, targetID, userID } from './components/trends/test-fixtures'

function network(data = page()) {
  const calls = vi.fn<typeof fetch>(async (input) => ok(String(input).includes('/auth/permissions') ? { organization_id: org, user_id: userID, permissions: ['run.read'] } : data))
  vi.stubGlobal('fetch', calls); return calls
}
describe('bounded target trends read contract', () => {
  it('performs only a scoped permission GET and one real trends GET with exact cursor and filters', async () => {
    const data = page(), calls = network(data), cursor = 'signed_opaque.-unchanged'
    const filters: TrendsFilters = { target_id: targetID, status: 'RUNNING', package: 'quick', date_from: '2026-09-07T06:59:00Z', date_to: '2026-09-07T07:00:00Z' }
    await expect(trendsApi.list(org, userID, filters, cursor)).resolves.toEqual(data)
    expect(calls).toHaveBeenCalledTimes(2)
    const url = new URL(String(calls.mock.calls[1][0]), 'https://mii.test')
    expect(url.pathname).toBe('/api/v1/runs/trends'); expect(url.searchParams.get('cursor')).toBe(cursor)
    expect(url.searchParams.get('target_id')).toBe(targetID); expect(url.searchParams.get('limit')).toBe('25')
    expect(url.searchParams.get('date_to')).toBe('2026-09-07T07:00:00Z')
    for (const [, options] of calls.mock.calls) { expect(options?.method).toBe('GET'); expect(options?.credentials).toBe('same-origin'); expect(new Headers(options?.headers).get('X-Organization-ID')).toBe(org) }
  })
  it.each(['', '0', '01', '-1', '+1', '1.0', '1e3', ' 12', '12 ', '1/2', '%31', '9223372036854775808'])('rejects bad target ID %s before any request', async (target) => {
    const calls = network(); await expect(trendsApi.list(org, userID, { target_id: target })).rejects.toMatchObject({ code: 'MI_INVALID_REQUEST' }); expect(calls).not.toHaveBeenCalled()
  })
  it('accepts only exact target routes and validated UTC-second filters', () => {
    expect(trendsRoute('trends')).toEqual({ kind: 'form' }); expect(trendsRoute(`trends/${targetID}`)).toEqual({ kind: 'target', targetID }); expect(trendsHref(targetID)).toBe(`#/trends/${targetID}`)
    for (const route of ['trends/01', 'trends/1/2', 'trends/', 'trends/%31']) expect(trendsRoute(route)).toEqual({ kind: 'invalid' })
    expect(trendsRoute('runs')).toBeNull(); expect(utcFilterInput('2026-09-07T00:00')).toBe('2026-09-07T00:00:00Z')
    expect(utcFilterInput('2026-09-07T00:00:07')).toBe('2026-09-07T00:00:07Z')
    expect(utcFilterInput('2026-09-07T00:00:07.000')).toBe('2026-09-07T00:00:07Z')
    for (const date of ['2026-02-30T12:00', '2026-09-07T12:00:60', '2026-09-07T12:00Z', '2026-09-07T12:00:00.001']) expect(() => utcFilterInput(date)).toThrow('MI_INVALID_REQUEST')
    for (const bad of [{ package: 'unknown' }, { status: 'done' }, { q: 'unexposed' }, { date_from: '2026-09-07T00:00:00+08:00' }, { date_from: '2026-09-07T00:00:00.000Z' }, { date_from: '2026-09-08T00:00:00Z', date_to: '2026-09-07T00:00:00Z' }]) expect(() => trendsQuery({ target_id: targetID, ...bad } as TrendsFilters)).toThrow('MI_INVALID_REQUEST')
  })
  it('requires permission for the exact organization and user and never reads a denied page', async () => {
    for (const grants of [{ organization_id: org, user_id: userID, permissions: [] }, { organization_id: '23', user_id: userID, permissions: ['run.read'] }, { organization_id: org, user_id: '27', permissions: ['run.read'] }]) {
      const calls = vi.fn<typeof fetch>(async () => ok(grants)); vi.stubGlobal('fetch', calls)
      await expect(trendsApi.list(org, userID, { target_id: targetID })).rejects.toBeTruthy(); expect(calls).toHaveBeenCalledTimes(1)
    }
  })
  it('binds the immutable requested filters before the asynchronous permission read', async () => {
    const filters: TrendsFilters = { target_id: targetID }
    const calls = vi.fn<typeof fetch>(async (input) => { if (String(input).includes('/auth/permissions')) { filters.target_id = '29'; return ok({ organization_id: org, user_id: userID, permissions: ['run.read'] }) }; return ok(page()) }); vi.stubGlobal('fetch', calls)
    await expect(trendsApi.list(org, userID, filters)).resolves.toEqual(page()); expect(String(calls.mock.calls[1][0])).toContain(targetID)
  })
  it('keeps zero observations null and validates actual unrounded fractional ratios and latency', () => {
    expect(attemptTrend(emptyAttempts())).toBe(true)
    const fractional = { ...emptyAttempts(), dispatched: 3, logical_samples: 3, succeeded: 1, failed: 2, success_rate_denominator: 3, success_rate_percent: 100 / 3, latency_samples: 3, latency_mean_ms: 10 / 3, latency_min_ms: 1, latency_max_ms: 7 }
    expect(attemptTrend(fractional)).toBe(true); expect(attemptTrend({ ...fractional, success_rate_percent: 33.33 })).toBe(false)
    expect(attemptTrend({ ...emptyAttempts(), success_rate_percent: 0 })).toBe(false)
    expect(attemptTrend({ ...emptyAttempts(), latency_mean_ms: 0 })).toBe(false)
    expect(attemptTrend({ ...attempts(), latency_samples: 0, latency_mean_ms: null, latency_min_ms: null, latency_max_ms: null })).toBe(true)
  })
  it.each(['denominator', 'status-total', 'logical-total', 'dispatched-bound', 'latency-n', 'latency-range', 'nonfinite', 'extra-body', 'missing-latency', 'success-ratio'])('rejects malformed statistics: %s', (which) => {
    const value = { ...attempts() } as Record<string, unknown>
    switch (which) {
      case 'denominator': value.success_rate_denominator = 8; break
      case 'status-total': value.failed = 3; break
      case 'logical-total': value.retry_attempts = 3; break
      case 'dispatched-bound': value.dispatched = 3001; break
      case 'latency-n': value.latency_samples = 9; break
      case 'latency-range': value.latency_mean_ms = 411; break
      case 'nonfinite': value.latency_mean_ms = Infinity; break
      case 'extra-body': value.response_body = 'SECRET_CANARY'; break
      case 'missing-latency': delete value.latency_mean_ms; break
      case 'success-ratio': value.success_rate_percent = 75; break
    }
    expect(attemptTrend(value)).toBe(false)
  })
  it.each(['target', 'duplicate', 'order', 'request-count', 'logical-samples', 'scope', 'basis', 'revision', 'calibrated', 'extra', 'oversized', 'cursor-empty-page', 'cursor-loop', 'status-filter', 'package-filter', 'date-filter'])('rejects invalid page %s through actual API validation', async (which) => {
    const data = page(), filters: TrendsFilters = { target_id: targetID }, cursor = 'loop'
    switch (which) {
      case 'target': data.items[0].run.target_id = '31'; break
      case 'duplicate': data.items.push(data.items[0]); break
      case 'order': data.items.push({ ...item(), run: { ...item().run, id: '9007199254741999' } }); break
      case 'request-count': data.items[0].run.request_count++; break
      case 'logical-samples': data.items[0].run.planned_samples = 7; break
      case 'scope': Object.assign(data, { scope: 'target_total' }); break
      case 'basis': Object.assign(data, { latency_basis: 'successes_only' }); break
      case 'revision': Object.assign(data, { analysis_revision: 2 }); break
      case 'calibrated': Object.assign(data, { calibrated: true }); break
      case 'extra': Object.assign(data, { response_body: 'SECRET_CANARY' }); break
      case 'oversized': data.items = page(26).items; break
      case 'cursor-empty-page': data.items = []; data.next_cursor = 'another'; break
      case 'cursor-loop': data.items = page(25).items; data.next_cursor = cursor; break
      case 'status-filter': filters.status = 'COMPLETED'; break
      case 'package-filter': filters.package = 'deep'; break
      case 'date-filter': filters.date_to = '2026-09-07T06:59:59Z'; break
    }
    network(data); await expect(trendsApi.list(org, userID, filters, cursor)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('preserves nanosecond ordering rather than conflating milliseconds and includes exact UTC boundaries', () => {
    const data = page(2)
    data.items[0].run.created_at = '2026-09-07T07:00:00.000000002Z'; data.items[0].run.id = '21'
    data.items[1].run.created_at = '2026-09-07T07:00:00.000000001Z'; data.items[1].run.id = '22'
    expect(trendsPage(data, { target_id: targetID })).toBe(true)
    expect(trendsPage(data, { target_id: targetID, date_to: '2026-09-07T07:00:00Z' })).toBe(false)
    expect(trendInstant('2026-09-07T15:00:00.000000001+08:00')).toBe(trendInstant(data.items[1].run.created_at))
    expect(trendInstant('2026-02-30T00:00:00Z')).toBeNull()
    expect(trendsPage(page(), { target_id: targetID, date_from: '2026-09-07T07:00:00Z', date_to: '2026-09-07T07:00:00Z' })).toBe(true)
  })
  it('propagates safe session failure and aborts before the page if the scope is cancelled', async () => {
    const calls = vi.fn<typeof fetch>(async () => fail('MI_SESSION_REQUIRED', 401)); vi.stubGlobal('fetch', calls)
    await expect(trendsApi.list(org, userID, { target_id: targetID })).rejects.toMatchObject({ code: 'MI_SESSION_REQUIRED' })
    const controller = new AbortController()
    calls.mockImplementation(async () => { controller.abort(); return ok({ organization_id: org, user_id: userID, permissions: ['run.read'] }) })
    calls.mockClear(); await expect(trendsApi.list(org, userID, { target_id: targetID }, '', controller.signal)).rejects.toBeTruthy(); expect(calls).toHaveBeenCalledTimes(1)
  })
})
