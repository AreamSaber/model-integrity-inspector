import { describe, expect, it, vi } from 'vitest'
import { analysisResult, resultsApi, sample as validSample, sampleDetail as validDetail } from './results-api'
import { detailed, fail, finding, ok, org, runID, sample, sampleDetail, sampleID, summary } from './components/results/test-fixtures'

describe('immutable S1 result API boundary', () => {
  it('reads only pinned revision 1 with cookie and organization scope, not credentials or write headers', async () => {
    const calls = vi.fn<typeof fetch>(async () => ok(summary())); vi.stubGlobal('fetch', calls)
    const controller = new AbortController()
    const result = await resultsApi.get(org, runID, false, controller.signal)
    expect(result).toEqual(summary())
    expect(calls.mock.calls[0][0]).toBe(`/api/v1/runs/${runID}/result?analysis_revision=1`)
    const options = calls.mock.calls[0][1]!
    expect(options).toMatchObject({ method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers: { Accept: 'application/json', 'X-Organization-ID': org } })
    expect(options.body).toBeUndefined(); expect(new Headers(options.headers).has('X-CSRF-Token')).toBe(false)
    controller.abort(); expect(options.signal?.aborted).toBe(true)
  })
  it('requires explicit statistics and refuses statistical data in a summary envelope', async () => {
    expect(analysisResult(detailed())).toBe(false); expect(analysisResult(detailed(), true)).toBe(true)
    expect(analysisResult(summary(), true)).toBe(false)
    const calls = vi.fn<typeof fetch>(async () => ok(detailed())); vi.stubGlobal('fetch', calls)
    await resultsApi.get(org, runID, true)
    expect(String(calls.mock.calls[0][0])).toContain('analysis_revision=1&include=statistics')
  })
  it.each(['body', 'content', 'seed', 'nonce', 'api_key', 'request_headers'])('rejects extra S2 field %s at every exposed object level', (key) => {
    expect(analysisResult({ ...summary(), [key]: 'SECRET_BODY_CANARY' })).toBe(false)
    expect(validSample({ ...sample(), [key]: 'SECRET_BODY_CANARY' })).toBe(false)
    const data = detailed(); data.token_analysis!.tiers[0] = { ...data.token_analysis!.tiers[0], [key]: 'SECRET_BODY_CANARY' }
    expect(analysisResult(data, true)).toBe(false)
    expect(validDetail({ sample: sample(), attempts: [{ ...sampleDetail().attempts[0], [key]: 'SECRET_BODY_CANARY' }] })).toBe(false)
  })
  it.each([
    { analysis_revision: 2 }, { development: false }, { calibrated: true }, { evidence_grade: 'A' }, { evidence_grade: 'B' }, { published: false },
    { confidence: 99 }, { overall_risk: Number.NaN }, { token_risk: -1 }, { completeness: 'partial', confidence: 74 }, { versions: { ...summary().versions, seed: 'private' } },
  ])('rejects unsupported result semantics %#', (change) => { expect(analysisResult({ ...summary(), ...change })).toBe(false) })
  it('bounds nested observations and does not accept duplicate/fabricated final attempts', () => {
    const data = detailed(); data.token_analysis!.tiers = Array(513).fill(data.token_analysis!.tiers[0]); expect(analysisResult(data, true)).toBe(false)
    expect(validSample({ ...sample(), validity: 'UNCERTAIN', included: true })).toBe(false)
    expect(validSample({ ...sample(), local_completion_tokens: undefined })).toBe(false)
    expect(validDetail({ sample: sample(), attempts: [] })).toBe(false)
    expect(validDetail({ sample: sample(), attempts: Array(4).fill(sampleDetail().attempts[0]) })).toBe(false)
    expect(validDetail({ sample: sample(), attempts: [sampleDetail().attempts[0], sampleDetail().attempts[0]] })).toBe(false)
  })
  it('binds list and detail rows to requested Run and Sample without integer precision loss', async () => {
    const calls = vi.fn<typeof fetch>(async (input) => String(input).includes('/findings') ? ok({ items: [finding()], next_cursor: null }) : String(input).includes(`/samples/${sampleID}`) ? ok(sampleDetail()) : ok({ items: [sample()], next_cursor: null }))
    vi.stubGlobal('fetch', calls)
    expect((await resultsApi.samples(org, runID)).items[0].id).toBe(sampleID)
    expect((await resultsApi.findings(org, runID)).items[0].run_id).toBe(runID)
    expect((await resultsApi.sample(org, runID, sampleID)).sample.id).toBe(sampleID)
    calls.mockImplementation(async () => ok({ items: [{ ...sample(), run_id: '1' }], next_cursor: null }))
    await expect(resultsApi.samples(org, runID)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    calls.mockImplementation(async () => ok({ ...sampleDetail(), sample: { ...sample(), id: '1' } }))
    await expect(resultsApi.sample(org, runID, sampleID)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('rejects invalid path IDs before making a request and never stores server error bodies', async () => {
    const calls = vi.fn<typeof fetch>(async () => fail('MI_PERMISSION_DENIED', 403)); vi.stubGlobal('fetch', calls)
    for (const id of ['0', '-1', '1/2', '9223372036854775808', '9007199254740993.0']) expect(() => resultsApi.get(org, id)).toThrow('MI_INVALID_REQUEST')
    expect(calls).not.toHaveBeenCalled()
    await expect(resultsApi.get(org, runID)).rejects.toMatchObject({ code: 'MI_PERMISSION_DENIED', status: 403, message: 'MI_PERMISSION_DENIED' })
  })
})
