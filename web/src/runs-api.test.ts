import { describe, expect, it, vi } from 'vitest'
import { ApiError } from './api'
import { quote, run, runsApi, type Quote, type Run } from './runs-api'

const org = '9007199254740995', user = '9007199254740993'
export const sampleQuote: Quote = {
  id: '9007199254741021', target_id: '9007199254741005', target_version: 4, package: 'quick', manifest_hash: 'a'.repeat(64),
  versions: { rule_bundle: '1.0.0-dev.1', template_bundle: '1.0.0-dev.1', scoring: '1.0.0-dev.1', tokenizer_bundle: '1.0.0' },
  estimate: { requests: 18, input_tokens: 2000, max_output_tokens: 4000, cost_micros: null, duration_seconds: 900, usage_safety_factor: 1.25, warnings: ['MI_PROBE_DEVELOPMENT_UNCALIBRATED', 'MI_TEMPLATE_PUBLIC_DEVELOPMENT_POOL'], completeness: 'full' },
  expires_at: '2099-01-01T00:00:00Z', budgets: { max_requests: 20, max_tokens: 15000, max_cost_micros: null, timeout_seconds: 900 },
}
export const sampleRun: Run = {
  id: '9007199254741023', target_id: sampleQuote.target_id, created_by: user, package: 'quick', status: 'QUEUED', version: 1, versions: sampleQuote.versions, estimate: sampleQuote.estimate,
  manifest_hash: sampleQuote.manifest_hash, request_count: 0, token_count: 0, estimated_cost_micros: null, valid_sample_count: 0, planned_samples: 18, completed_samples: 0,
  created_at: '2026-09-07T08:00:00Z', started_at: null, finished_at: null, execution_closed_at: null, error_summary: [],
}
function ok(data: unknown) { return Response.json({ data, request_id: 'test-run-request' }) }

describe('Run API trust boundary', () => {
  it('validates real Quote and Run shapes with precise string IDs and nullable unknown prices', () => {
    expect(quote(sampleQuote)).toBe(true)
    expect(run(sampleRun)).toBe(true)
    expect(quote({ ...sampleQuote, id: Number(sampleQuote.id) })).toBe(false)
    expect(run({ ...sampleRun, created_by: undefined })).toBe(false)
    expect(run({ ...sampleRun, id: 5 })).toBe(false)
    expect(run({ ...sampleRun, version: '1' })).toBe(false)
    expect(run({ ...sampleRun, status: 'done' })).toBe(false)
    expect(run({ ...sampleRun, completed_samples: 19 })).toBe(false)
    expect(run({ ...sampleRun, valid_sample_count: 19 })).toBe(false)
    expect(run({ ...sampleRun, estimated_cost_micros: NaN })).toBe(false)
  })
  it('rejects extra sensitive fields, malformed frozen versions, impossible budgets and unsafe text', () => {
    expect(quote({ ...sampleQuote, prompt: 'private upstream body' })).toBe(false)
    expect(run({ ...sampleRun, response: 'private upstream body' })).toBe(false)
    expect(run({ ...sampleRun, versions: { ...sampleRun.versions, api_key: 'secret' } })).toBe(false)
    expect(quote({ ...sampleQuote, manifest_hash: 'z'.repeat(64) })).toBe(false)
    expect(quote({ ...sampleQuote, budgets: { ...sampleQuote.budgets, max_tokens: 100 } })).toBe(false)
    expect(quote({ ...sampleQuote, budgets: { ...sampleQuote.budgets, max_cost_micros: 10 } })).toBe(false)
    expect(quote({ ...sampleQuote, estimate: { ...sampleQuote.estimate, usage_safety_factor: 1 } })).toBe(false)
    expect(quote({ ...sampleQuote, estimate: { ...sampleQuote.estimate, warnings: ['private diagnostic text'] } })).toBe(false)
    expect(run({ ...sampleRun, error_summary: [{ code: 'MI_TIMEOUT', count: 1, message: 'private body' }] })).toBe(false)
    expect(run({ ...sampleRun, error_summary: [{ code: '<script>', count: 1 }] })).toBe(false)
  })
  it('binds scoped permissions to the current user and organization rather than role definitions', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(ok({ organization_id: org, user_id: user, permissions: ['run.create', 'run.cancel-own'] })).mockResolvedValueOnce(ok({ organization_id: '2', user_id: user, permissions: ['run.create'] })).mockResolvedValueOnce(ok({ organization_id: org, user_id: '2', permissions: ['run.create'] }))
    vi.stubGlobal('fetch', fetcher)
    await expect(runsApi.permissions(org, user)).resolves.toMatchObject({ permissions: ['run.create', 'run.cancel-own'] })
    expect(new Headers(fetcher.mock.calls[0][1]?.headers).get('X-Organization-ID')).toBe(org)
    await expect(runsApi.permissions(org, user)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    await expect(runsApi.permissions(org, user)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('uses the frozen confirmation body without a generated idempotency header and pins response identities', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(ok(sampleRun)).mockResolvedValueOnce(ok({ ...sampleRun, target_id: '2' })).mockResolvedValueOnce(ok({ ...sampleRun, id: '2' })).mockResolvedValueOnce(ok({ ...sampleRun, status: 'CANCELLING', version: 2 }))
    vi.stubGlobal('fetch', fetcher)
    await runsApi.create(org, 'synthetic-csrf', sampleQuote)
    const request = fetcher.mock.calls[0][1]!
    expect(request.credentials).toBe('same-origin')
    expect(JSON.parse(String(request.body))).toEqual({ estimate_id: sampleQuote.id, manifest_hash: sampleQuote.manifest_hash, confirm_cost: true })
    expect(new Headers(request.headers).get('X-CSRF-Token')).toBe('synthetic-csrf')
    expect(new Headers(request.headers).has('Idempotency-Key')).toBe(false)
    await expect(runsApi.create(org, 'synthetic-csrf', sampleQuote)).rejects.toBeInstanceOf(ApiError)
    await expect(runsApi.get(org, sampleRun.id)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    await runsApi.cancel(org, 'synthetic-csrf', sampleRun)
    expect(JSON.parse(String(fetcher.mock.calls[3][1]?.body))).toEqual({ version: 1 })
  })
  it('never dispatches invalid identifiers, versions or hashes', () => {
    const fetcher = vi.fn<typeof fetch>(); vi.stubGlobal('fetch', fetcher)
    expect(() => runsApi.get(org, '../secret')).toThrow(ApiError)
    expect(() => runsApi.create(org, 'csrf', { ...sampleQuote, manifest_hash: 'bad' })).toThrow(ApiError)
    expect(() => runsApi.cancel(org, 'csrf', { ...sampleRun, version: 0 })).toThrow(ApiError)
    expect(() => runsApi.permissions('not-an-id', user)).toThrow(ApiError)
    expect(fetcher).not.toHaveBeenCalled()
  })
})
