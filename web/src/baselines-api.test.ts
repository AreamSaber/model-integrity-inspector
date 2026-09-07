import { describe, expect, it, vi } from 'vitest'
import { ApiError } from './api'
import { baseline, baselinesApi, baselineText, type BaselineApproval, type BaselineCreate } from './baselines-api'
import { approvedFixture, baselineFixture, baselineID, fail, ok, org, runID, user } from './components/baselines/test-fixtures'

describe('closed baseline transport boundary', () => {
  it('uses authenticated same-origin reads with bound query/cursor and bigint-safe IDs', async () => {
    const value = baselineFixture(), fetcher = vi.fn<typeof fetch>().mockResolvedValue(ok({ items: [baselineFixture()], next_cursor: null })); vi.stubGlobal('fetch', fetcher)
    await baselinesApi.list(org, 'name & scope', 'opaque:+')
    const [url, options] = fetcher.mock.calls[0]
    expect(url).toBe('/api/v1/baselines?limit=25&q=name+%26+scope&cursor=opaque%3A%2B')
    expect(options?.method).toBe('GET'); expect(options?.body).toBeUndefined(); expect(options?.credentials).toBe('same-origin'); expect(options?.cache).toBe('no-store')
    expect(new Headers(options?.headers).get('X-Organization-ID')).toBe(org)
    fetcher.mockResolvedValue(ok(value)); expect(await baselinesApi.get(org, baselineID)).toEqual(value)
  })
  it.each([
    { eligible_for_scoring: true }, { calibrated: true }, { development: false }, { source_assurance: 'officially_verified' }, { region_assurance: 'verified' },
    { approval_meaning: 'project_approved' }, { scoring_version: 'released-1' }, { id: '9223372036854775808' }, { version: 0 }, { overall_risk: -1 },
    { valid_samples: 61 }, { manifest_hash: 'x'.repeat(64) }, { limitations: [] }, { status: 'approved' }, { approved_by: user }, { retired_at: '2026-09-07T11:00:00Z' },
    { snapshot_json: 'PRIVATE_SERVER_BODY' }, { approval_mac: 'PRIVATE_SERVER_BODY' }, { review_explanation: 'PRIVATE_SERVER_BODY' }, { name: '\ud800' },
  ])('rejects forged trust, malformed metadata, unexpected S2 or inconsistent states %#', async (patch) => {
    const value = { ...baselineFixture(), ...patch }
    expect(baseline(value)).toBe(false)
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValue(ok(value)))
    const failure = await baselinesApi.get(org, baselineID).catch((error: unknown) => error)
    expect(failure).toMatchObject({ code: 'MI_INVALID_RESPONSE' }); expect(String(failure)).not.toContain('PRIVATE_SERVER_BODY')
  })
  it.each([
    { items: [baselineFixture(), baselineFixture()], next_cursor: null }, { items: [], next_cursor: 'x'.repeat(1025) },
    { items: Array.from({ length: 26 }, (_, i) => baselineFixture({ id: String(i + 1) })), next_cursor: null }, { items: [], next_cursor: null, body: 'private' },
  ])('rejects invalid pages %#', async (value) => { vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValue(ok(value))); await expect(baselinesApi.list(org)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' }) })
  it('projects creation fields and validates receipt ownership, scope, source and expiry', async () => {
    const value = baselineFixture(), body: BaselineCreate = { name: value.name, run_id: runID, analysis_revision: 1, source: value.source, region: value.region, expires_at: value.expires_at }
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(ok(value, 201)); vi.stubGlobal('fetch', fetcher)
    await baselinesApi.create(org, 'synthetic-csrf', user, body)
    expect(JSON.parse(fetcher.mock.calls[0][1]!.body as string)).toEqual(body)
    expect(new Headers(fetcher.mock.calls[0][1]?.headers).get('X-CSRF-Token')).toBe('synthetic-csrf')
    for (const patch of [{ created_by: '12' }, { run_id: '12' }, { source: 'official' }, { expires_at: '2099-01-01T00:00:00Z' }]) {
      fetcher.mockResolvedValue(ok({ ...value, ...patch }, 201)); await expect(baselinesApi.create(org, 'csrf', user, body)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    }
  })
  it('uses CAS for draft edit, explicit approval and retirement without overwriting approval history', async () => {
    const current = baselineFixture(), input: BaselineApproval = { version: 1, reason: 'Organization review', business_review: 'Elevated-risk business explanation', acknowledge_development_limits: true }
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(ok({ ...current, version: 2, name: 'Renamed' })); vi.stubGlobal('fetch', fetcher)
    await baselinesApi.patch(org, 'csrf', current, { version: 1, name: 'Renamed', expires_at: current.expires_at })
    expect(fetcher.mock.calls[0][1]?.method).toBe('PATCH')
    const approved = approvedFixture(current); fetcher.mockResolvedValue(ok(approved))
    await baselinesApi.approve(org, 'csrf', user, current, input)
    expect(JSON.parse(fetcher.mock.calls[1][1]!.body as string)).toEqual(input)
    fetcher.mockResolvedValue(ok({ ...approved, version: 3, status: 'retired', retired_at: '2026-09-07T12:00:00Z' }))
    await baselinesApi.retire(org, 'csrf', approved, 'Organization withdrawal')
    expect(JSON.parse(fetcher.mock.calls[2][1]!.body as string)).toEqual({ version: 2, reason: 'Organization withdrawal' })
    fetcher.mockResolvedValue(ok({ ...approved, parameters_hash: 'c'.repeat(64) }))
    await expect(baselinesApi.approve(org, 'csrf', user, current, input)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('rejects invalid inputs and missing high-risk explanation before network', () => {
    const fetcher = vi.fn<typeof fetch>(); vi.stubGlobal('fetch', fetcher)
    const current = baselineFixture(), input = { version: 1, reason: 'review', business_review: '', acknowledge_development_limits: true as const }
    expect(() => baselinesApi.approve(org, 'csrf', user, current, input)).toThrow(ApiError)
    expect(() => baselinesApi.approve(org, 'csrf', user, current, { ...input, business_review: 'valid', acknowledge_development_limits: false } as unknown as BaselineApproval)).toThrow(ApiError)
    expect(() => baselinesApi.get(org, '../other')).toThrow(ApiError); expect(() => baselinesApi.list('0')).toThrow(ApiError)
    expect(() => baselinesApi.list(org, '字'.repeat(43))).toThrow(ApiError)
    expect(() => baselinesApi.patch(org, 'csrf', approvedFixture(current), { version: 2, name: 'change', expires_at: current.expires_at })).toThrow(ApiError)
    expect(baselineText('字'.repeat(42), 128)).toBe(true); expect(baselineText('\ud800', 128)).toBe(false)
    expect(fetcher).not.toHaveBeenCalled()
  })
  it('does not retry writes or expose server text and honors cancellation', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(fail('MI_CONFLICT', 409)); vi.stubGlobal('fetch', fetcher)
    const current = baselineFixture()
    await expect(baselinesApi.retire(org, 'csrf', current, 'reason')).rejects.toMatchObject({ code: 'MI_CONFLICT', status: 409 })
    expect(fetcher).toHaveBeenCalledTimes(1)
    const controller = new AbortController(); controller.abort('PRIVATE_SERVER_BODY')
    await expect(baselinesApi.list(org, '', '', controller.signal)).rejects.toMatchObject({ name: 'AbortError' })
    expect(fetcher).toHaveBeenCalledTimes(1)
  })
})
