import { describe, expect, it, vi } from 'vitest'
import { overviewApi, overviewData, type OverviewDays } from './overview-api'
import { fail, ok, org, otherOrg, overview, userID } from './components/overview/test-fixtures'

describe('organization overview S1 boundary', () => {
  it.each([7, 30] as const)('reads one complete %i-day snapshot after both real grants', async (days) => {
    const calls = vi.fn<typeof fetch>(async (input) => String(input).includes('/auth/permissions') ? ok({ organization_id: org, user_id: userID, permissions: ['run.read', 'target.read'] }) : ok(overview(days)))
    vi.stubGlobal('fetch', calls)
    const got = await overviewApi.read(org, userID, days)
    expect(got.window.days).toBe(days); expect(got.organization_id).toBe(org); expect(calls).toHaveBeenCalledTimes(2)
    expect(String(calls.mock.calls[1][0])).toBe(`/api/v1/overview?days=${days}`)
    for (const [, options] of calls.mock.calls) { expect(options?.method).toBe('GET'); expect(options?.credentials).toBe('same-origin'); expect(options?.redirect).toBe('error'); expect(new Headers(options?.headers).get('X-Organization-ID')).toBe(org); expect(options?.body).toBeUndefined() }
  })
  it.each([{ permissions: ['run.read'] }, { permissions: ['target.read'] }, { permissions: [] }])('does not read metrics when required grants are missing: $permissions', async ({ permissions }) => {
    const calls = vi.fn<typeof fetch>(async () => ok({ organization_id: org, user_id: userID, permissions })); vi.stubGlobal('fetch', calls)
    await expect(overviewApi.read(org, userID, 7)).rejects.toMatchObject({ code: 'MI_PERMISSION_DENIED', status: 403 }); expect(calls).toHaveBeenCalledTimes(1)
  })
  it.each(['organization', 'user'])('rejects %s-mismatched permission data before any aggregate call', async (field) => {
    const calls = vi.fn<typeof fetch>(async () => ok({ organization_id: field === 'organization' ? otherOrg : org, user_id: field === 'user' ? otherOrg : userID, permissions: ['run.read', 'target.read'] })); vi.stubGlobal('fetch', calls)
    await expect(overviewApi.read(org, userID, 7)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' }); expect(calls).toHaveBeenCalledTimes(1)
  })
  it.each([0, 6, 31, '7', '07', '+7'])('rejects caller window %j before network', async (days) => {
    const calls = vi.fn<typeof fetch>(); vi.stubGlobal('fetch', calls); await expect(overviewApi.read(org, userID, days as OverviewDays)).rejects.toMatchObject({ code: 'MI_INVALID_REQUEST' }); expect(calls).not.toHaveBeenCalled()
  })
  it.each(['0', '01', '9223372036854775808', '1/other', ' 1'])('rejects noncanonical identity %s before network', async (id) => {
    const calls = vi.fn<typeof fetch>(); vi.stubGlobal('fetch', calls)
    await expect(overviewApi.read(id, userID, 7)).rejects.toMatchObject({ code: 'MI_INVALID_REQUEST' }); await expect(overviewApi.read(org, id, 7)).rejects.toMatchObject({ code: 'MI_INVALID_REQUEST' }); expect(calls).not.toHaveBeenCalled()
  })
  it('keeps missing cost null while preserving a genuinely observed zero', () => {
    const data = overview(); expect(overviewData(data, org, 7)).toBe(true)
    data.costs.known_subtotal_micros = 0; expect(overviewData(data, org, 7)).toBe(true)
    data.costs.complete_total_micros = 0; expect(overviewData(data, org, 7)).toBe(false)
    data.costs.known_runs = 3; data.costs.unknown_runs = 0; expect(overviewData(data, org, 7)).toBe(true)
    const empty = overview(7, org, false); expect(overviewData(empty, org, 7)).toBe(true)
    empty.costs.known_subtotal_micros = 0; expect(overviewData(empty, org, 7)).toBe(false)
  })
  const changes: Record<string, (v: ReturnType<typeof overview>) => void> = {
    'organization identity': (v) => { v.organization_id = otherOrg },
    'window days': (v) => { v.window.days = 30 },
    'Local timezone': (v) => { v.window.timezone = 'Local' },
    'bad timezone': (v) => { v.window.timezone = 'PRIVATE/TIMEZONE' },
    'wrong revision': (v) => { Object.assign(v, { analysis_revision: 2 }) },
    'calibration claim': (v) => { Object.assign(v, { calibrated: true }) },
    'S2 extra key': (v) => { Object.assign(v, { response_content: 'PRIVATE_CANARY' }) },
    'unknown status': (v) => { Object.assign(v.runs.by_status, { HEALTHY: 0 }) },
    'missing status': (v) => { Reflect.deleteProperty(v.runs.by_status, 'QUEUED') },
    'fractional count': (v) => { v.runs.total = 3.5 },
    'target counts': (v) => { v.targets.active++ },
    'total counts': (v) => { v.runs.total++ },
    'status denominator': (v) => { v.runs.by_status.RUNNING++ },
    'unpublished denominator': (v) => { v.runs.unpublished_runs++ },
    'scored denominator': (v) => { v.runs.scored_runs++ },
    'unknown costs denominator': (v) => { v.costs.unknown_runs++ },
    'unsafe micros': (v) => { v.costs.known_subtotal_micros = Number.MAX_SAFE_INTEGER + 1 },
    'nonfinite cost': (v) => { v.costs.known_subtotal_micros = Infinity },
    'fake currency': (v) => { Object.assign(v.costs, { currency: 'CNY' }) },
    'risk denominator': (v) => { v.risk_cohorts[0].distribution.low++ },
    'daily distribution': (v) => { v.daily[6].risk_cohorts[0].distribution = { ...v.daily[6].risk_cohorts[0].distribution, medium: 0, low: 1 } },
    'cohort duplicate': (v) => { v.risk_cohorts.push(v.risk_cohorts[0]) },
    'daily cohort duplicate': (v) => { v.daily[6].risk_cohorts.push(v.daily[6].risk_cohorts[0]) },
    'foreign cohort reference': (v) => { v.daily[6].risk_cohorts[0].cohort_id = 'c2' },
    'unsafe cohort ID': (v) => { v.risk_cohorts[0].id = '<script>' },
    'invalid package': (v) => { Object.assign(v.risk_cohorts[0], { package: 'paid' }) },
    'version extra key': (v) => { Object.assign(v.risk_cohorts[0].versions, { body: 'PRIVATE' }) },
    'XSS version': (v) => { v.risk_cohorts[0].versions.scoring = '<img src=x onerror=alert(1)>' },
    'missing day': (v) => { v.daily.pop() },
    'duplicate day': (v) => { v.daily[1] = v.daily[0] },
    'nonlocal date': (v) => { v.daily[0].local_date = '2026-08-31' },
    'gap': (v) => { v.daily[1].start_utc = '2026-09-02T00:00:01Z' },
    'subsecond start': (v) => { v.daily[1].start_utc = '2026-09-02T00:00:00.000000001Z' },
    'false complete today': (v) => { v.daily[6].partial = false },
    'future end': (v) => { v.daily[6].end_utc = '2026-09-08T00:00:00Z' },
    'asof nanosecond mismatch': (v) => { v.window.as_of = '2026-09-07T12:00:00.123456788Z' },
    'daily run counts': (v) => { v.daily[0].run_count++ },
    'published exceeds daily runs': (v) => { v.daily[6].run_count = 1; v.daily[0].run_count = 2 },
  }
  it.each(Object.entries(changes))('rejects %s without salvaging partial metrics', (_name, change) => { const v = overview(); change(v); expect(overviewData(v, org, 7)).toBe(false) })
  it('accepts a 23-hour DST day and a zero-length current day at exact midnight', () => {
    const v = overview(7, org, false), boundaries = ['2026-03-03T05:00:00Z', '2026-03-04T05:00:00Z', '2026-03-05T05:00:00Z', '2026-03-06T05:00:00Z', '2026-03-07T05:00:00Z', '2026-03-08T05:00:00Z', '2026-03-09T04:00:00Z', '2026-03-09T16:00:00Z']
    v.window = { days: 7, timezone: 'America/New_York', start_utc: boundaries[0], end_utc: boundaries[7], as_of: boundaries[7] }
    v.daily.forEach((d, i) => { d.local_date = boundaries[i].slice(0, 10); d.start_utc = boundaries[i]; d.end_utc = boundaries[i + 1] })
    expect(overviewData(v, org, 7)).toBe(true)
    v.window.as_of = boundaries[6]; v.window.end_utc = boundaries[6]; v.daily[6].end_utc = boundaries[6]
    expect(overviewData(v, org, 7)).toBe(true)
  })
  it('checks caller abort after permissions without starting an aggregate request', async () => {
    const controller = new AbortController(), calls = vi.fn<typeof fetch>(async () => { controller.abort(); return ok({ organization_id: org, user_id: userID, permissions: ['run.read', 'target.read'] }) }); vi.stubGlobal('fetch', calls)
    await expect(overviewApi.read(org, userID, 7, controller.signal)).rejects.toMatchObject({ name: 'AbortError' }); expect(calls).toHaveBeenCalledTimes(1)
  })
  it('returns a bounded error code instead of retaining backend text', async () => {
    const calls = vi.fn<typeof fetch>(async () => fail('MI_OVERVIEW_TIMEOUT', 503)); vi.stubGlobal('fetch', calls)
    await expect(overviewApi.read(org, userID, 7)).rejects.toMatchObject({ code: 'MI_OVERVIEW_TIMEOUT' })
    await expect(overviewApi.read(org, userID, 7)).rejects.not.toHaveProperty('body')
  })
})
