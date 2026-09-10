import { describe, expect, it, vi } from 'vitest'
import { comparisonApi, comparisonHref, comparisonLimitations, comparisonRoute, comparisonSelection, descriptiveDifference, type Comparison } from './comparison-api'
import { comparison, failure, ok, org, rightID, runID, userID } from './components/comparison/test-fixtures'

function network(value = comparison(), override?: (url: string, options: RequestInit) => Response | Promise<Response> | undefined) {
  const calls = vi.fn<typeof fetch>(async (input, options = {}) => {
    const url = String(input), replaced = override?.(url, options)
    if (replaced) return replaced
    if (url === '/api/v1/auth/permissions') return ok({ organization_id: org, user_id: userID, permissions: ['run.read'] })
    const side = url.includes(rightID) ? value.right : value.left
    return ok(url.includes('/result?') ? side.result : side.run)
  }); vi.stubGlobal('fetch', calls); return calls
}
const selection = () => comparisonSelection(runID, rightID, 1)

describe('bounded fixed-revision comparison API', () => {
  it('does exactly five scoped read-only requests with no current targets, evidence scan or mutation', async () => {
    const calls = network(), value = await comparisonApi.read(org, userID, selection())
    expect(value.left.result.valid_samples).toBe(16); expect(value.left.run.valid_sample_count).toBe(17)
    expect(calls).toHaveBeenCalledTimes(5)
    expect(calls.mock.calls.map(([url]) => url)).toEqual(['/api/v1/auth/permissions', `/api/v1/runs/${runID}`, `/api/v1/runs/${runID}/result?analysis_revision=1`, `/api/v1/runs/${rightID}`, `/api/v1/runs/${rightID}/result?analysis_revision=1`])
    for (const [, options] of calls.mock.calls) {
      expect(options?.method).toBe('GET'); expect(options?.body).toBeUndefined(); expect(options?.credentials).toBe('same-origin')
      expect(new Headers(options?.headers).get('X-Organization-ID')).toBe(org)
    }
  })
  it.each(['01', '0', '-1', '+12', '1e2', '9.1', ' 12', '12 ', '9223372036854775808', '../1', '%31', '１２'])('rejects noncanonical or overflowing Run IDs %s before network', async (id) => {
    const calls = network()
    await expect(comparisonApi.read(org, userID, { left: id, right: rightID, revision: 1 })).rejects.toMatchObject({ code: 'MI_INVALID_REQUEST' })
    expect(calls).not.toHaveBeenCalled()
    expect(comparisonRoute(`compare/${id}/1/${rightID}/1`)).toEqual({ kind: 'invalid' })
  })
  it('strictly binds two distinct IDs and the only supported route revision', () => {
    expect(comparisonHref(runID, rightID)).toBe(`#/compare/${runID}/1/${rightID}/1`)
    expect(comparisonRoute('compare')).toEqual({ kind: 'form' })
    expect(comparisonRoute(`compare/${runID}/1/${rightID}/1`)).toEqual({ kind: 'pair', selection: selection() })
    for (const route of [`compare/${runID}/1/${runID}/1`, `compare/${runID}/2/${rightID}/1`, `compare/${runID}/1/${rightID}/01`, `compare/${runID}/1/${rightID}/1/extra`]) expect(comparisonRoute(route)).toEqual({ kind: 'invalid' })
    expect(comparisonRoute('unrelated')).toBeNull()
    expect(() => comparisonSelection(runID, runID, 1)).toThrow('MI_INVALID_REQUEST')
  })
  it('stops at the permission GET on denied or incorrect user/org grants', async () => {
    for (const grants of [{ organization_id: org, user_id: userID, permissions: [] }, { organization_id: '7', user_id: userID, permissions: ['run.read'] }, { organization_id: org, user_id: '8', permissions: ['run.read'] }]) {
      const calls = network(comparison(), () => ok(grants))
      await expect(comparisonApi.read(org, userID, selection())).rejects.toBeInstanceOf(Error)
      expect(calls).toHaveBeenCalledTimes(1)
    }
  })
  it.each([
    (value: Comparison) => { value.right.result.run_id = runID },
    (value: Comparison) => { value.left.run.id = rightID },
    (value: Comparison) => { value.right.run.versions.scoring = 'different-version' },
    (value: Comparison) => { value.right.run.target_id = '9223372036854775808' },
    (value: Comparison) => { value.right.run.planned_samples = 19 },
    (value: Comparison) => { value.right.run.completed_samples = 17 },
    (value: Comparison) => { value.right.run.valid_sample_count = 15 },
    (value: Comparison) => { value.right.run.status = 'ANALYZING' },
    (value: Comparison) => { value.right.run.execution_closed_at = null },
    (value: Comparison) => { value.right.run.finished_at = '2026-09-07T08:01:00Z' },
  ])('fails closed for cross-response identity/versions/counters/terminal inconsistencies %#', async (mutate) => {
    const value = comparison(); mutate(value); network(value)
    await expect(comparisonApi.read(org, userID, selection())).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('cancels remaining object requests when one side fails instead of returning half a comparison', async () => {
    const signals: (AbortSignal | null | undefined)[] = []
    network(comparison(), (url, options) => {
      if (url.includes('/runs/')) signals.push(options.signal)
      if (url.includes(rightID) && url.includes('/result?')) return failure('MI_NOT_FOUND', 404)
      if (url === `/api/v1/runs/${runID}`) return new Promise<Response>(() => {})
      return undefined
    })
    const error = await comparisonApi.read(org, userID, selection()).catch((failure: unknown) => failure)
    expect(error).toMatchObject({ code: 'MI_NOT_FOUND', status: 404 }); expect(String(error)).not.toContain('COMPARISON_PRIVATE_CANARY')
    expect(signals).toHaveLength(4); expect(signals.every((signal) => signal?.aborted)).toBe(true)
  })
  it('aborts all scope reads and never accepts late completion after user cancellation', async () => {
    const controller = new AbortController()
    let started = 0
    network(comparison(), (url) => url.includes('/runs/') ? (started++, new Promise<Response>(() => {})) : undefined)
    const pending = comparisonApi.read(org, userID, selection(), controller.signal).catch((failure: unknown) => failure)
    await vi.waitFor(() => expect(started).toBe(4)); controller.abort()
    expect(await pending).toMatchObject({ name: 'AbortError' })
  })
  it('preserves missing metrics and always qualifies version, target, package and denominator differences', () => {
    const value = comparison()
    value.right.run.target_id = '27'; value.right.run.package = 'deep'; value.right.run.manifest_hash = 'b'.repeat(64)
    value.right.result.versions.scoring = 'new-dev'; value.right.result.valid_samples = 8; value.right.result.completeness = 'partial'
    const explanation = comparisonLimitations(value).join('\n')
    expect(explanation).toContain('算法变化与行为变化无法据此拆分')
    expect(explanation).toContain('目标 ID 不同'); expect(explanation).toContain('检测包不同'); expect(explanation).toContain('分母')
    expect(explanation).toContain('不构成成对基线')
    expect(descriptiveDifference(null, 50)).toBeNull(); expect(descriptiveDifference(0, null)).toBeNull()
    expect(descriptiveDifference(20, 10)).toBe(-10); expect(descriptiveDifference(0, 0)).toBe(0)
    expect(descriptiveDifference(Infinity, 1)).toBeNull()
  })
})
