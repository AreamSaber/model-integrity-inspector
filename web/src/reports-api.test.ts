import { describe, expect, it, vi } from 'vitest'
import { report, reportUpdate, reportsApi, type Report, type ReportInput } from './reports-api'

const org = '9007199254740993', runID = '9007199254740995', reportID = '9007199254740997'
const input: ReportInput = { format: 'json', analysis_revision: 1, include_restricted_content: false }
function record(): Report { return { id: reportID, run_id: runID, analysis_revision: 1, revision: 1, format: 'json', schema_version: 'mii.report.v1', status: 'queued', created_at: '2026-09-07T10:00:00.000001Z', review_state: 'not_included' } }
function ready(): Report { return { ...record(), status: 'ready', content_hash: `sha256:${'a'.repeat(64)}`, file_hash: `sha256:${'b'.repeat(64)}`, file_size: 120 } }
function ok(data: unknown) { return Response.json({ data, request_id: 'reports-test' }) }

describe('strict S1 report metadata client', () => {
  it('reads bounded same-origin revision pages with signed opaque cursor and string IDs', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(ok({ items: [record()], next_cursor: null })); vi.stubGlobal('fetch', fetcher)
    expect((await reportsApi.list(org, runID, 1, 'opaque:+')).items).toEqual([record()])
    expect(fetcher.mock.calls[0][0]).toBe(`/api/v1/runs/${runID}/reports?analysis_revision=1&limit=25&cursor=opaque%3A%2B`)
    const options = fetcher.mock.calls[0][1]!
    expect(options.method).toBe('GET'); expect(options.credentials).toBe('same-origin'); expect(options.redirect).toBe('error')
    expect(new Headers(options.headers).get('X-Organization-ID')).toBe(org)
  })
  it('sends only explicit format/revision/restricted=false with fixed body and key on manual recovery', async () => {
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async () => ok(record())); vi.stubGlobal('fetch', fetcher)
    await reportsApi.create(org, runID, 'synthetic-csrf', input, 'report:fixed-key-1234')
    await reportsApi.create(org, runID, 'synthetic-csrf', input, 'report:fixed-key-1234')
    const first = fetcher.mock.calls[0][1]!, next = fetcher.mock.calls[1][1]!
    expect(first.method).toBe('POST'); expect(JSON.parse(first.body as string)).toEqual(input); expect(next.body).toBe(first.body)
    expect(new Headers(first.headers).get('Idempotency-Key')).toBe('report:fixed-key-1234')
    expect(new Headers(next.headers).get('Idempotency-Key')).toBe('report:fixed-key-1234')
    expect(new Headers(first.headers).get('X-CSRF-Token')).toBe('synthetic-csrf')
  })
  it.each([
    { ...record(), id: Number(reportID) }, { ...record(), run_id: '8' }, { ...record(), analysis_revision: 2 }, { ...record(), format: 'pdf' },
    { ...record(), source_json: 'SECRET_CANARY' }, { ...record(), storage_path: 'secret/path' }, { ...record(), review_state: 'not_reviewed' },
    { ...record(), schema_version: 'mii.report.v2' }, { ...record(), status: 'done' }, { ...record(), content_hash: `sha256:${'a'.repeat(64)}` },
    { ...ready(), file_hash: 'SECRET_CANARY' }, { ...ready(), file_size: 16777217 }, { ...ready(), file_size: null },
    { ...ready(), content_hash: null }, { ...ready(), error_code: 'MI_REPORT_GENERATION_FAILED' }, { ...record(), error_code: 'MI_PRIVATE_CANARY' },
  ])('rejects unexpected, restricted, mismatched or incoherent data %#', async (value) => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValue(ok(value)))
    const failure = await reportsApi.get(org, runID, 1, reportID).catch((error: unknown) => error)
    expect(failure).toMatchObject({ code: 'MI_INVALID_RESPONSE' }); expect(String(failure)).not.toContain('SECRET_CANARY')
  })
  it('rejects list duplicate IDs, reversed order and foreign revision', async () => {
    for (const items of [[record(), record()], [{ ...record(), id: '99' }, { ...record(), id: '98' }], [{ ...record(), analysis_revision: 2 }]]) {
      vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValue(ok({ items, next_cursor: null })))
      await expect(reportsApi.list(org, runID, 1)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    }
  })
  it('binds exact GET and terminal metadata, allowing only forward progression', async () => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValue(ok(ready())))
    expect(await reportsApi.get(org, runID, 1, reportID)).toEqual(ready())
    expect(reportUpdate(record(), ready())).toEqual(ready())
    expect(reportUpdate({ ...record(), status: 'generating' }, { ...record(), status: 'failed', error_code: 'MI_REPORT_GENERATION_FAILED' }).status).toBe('failed')
    expect(() => reportUpdate(ready(), record())).toThrow('MI_INVALID_RESPONSE')
    expect(() => reportUpdate(ready(), { ...ready(), file_hash: `sha256:${'c'.repeat(64)}` })).toThrow('MI_INVALID_RESPONSE')
    expect(() => reportUpdate(record(), { ...record(), revision: 2 })).toThrow('MI_INVALID_RESPONSE')
    expect(report(ready())).toBe(true)
  })
  it('rejects local scope/input errors before any fetch and never permits restricted content', () => {
    const fetcher = vi.fn<typeof fetch>(); vi.stubGlobal('fetch', fetcher)
    expect(() => reportsApi.create(org, runID, 'csrf', { ...input, include_restricted_content: true } as unknown as ReportInput, 'report-fixed-key-1234')).toThrow('MI_INVALID_REQUEST')
    expect(() => reportsApi.create(org, runID, 'csrf', input, 'short')).toThrow('MI_INVALID_REQUEST')
    expect(() => reportsApi.get(org, runID, 1, '../path')).toThrow('MI_INVALID_REQUEST')
    expect(() => reportsApi.list(org, runID, 2)).toThrow('MI_INVALID_REQUEST')
    expect(() => reportsApi.list('9223372036854775808', runID, 1)).toThrow('MI_INVALID_REQUEST')
    expect(fetcher).not.toHaveBeenCalled()
  })
})
