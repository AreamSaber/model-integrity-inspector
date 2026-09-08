import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ResponseRetentionPanel } from './ResponseRetentionPanel'
import type { ResponseRetentionSummary } from '../../response-retention-api'

const org = '9007199254740993', runID = '9007199254740995', userID = '9007199254740997'
const props = { organizationID: org, userID, runID, analysisRevision: 1, csrfToken: 'unused-synthetic-csrf', onDenied: vi.fn<(failure: unknown) => void>(), onSignedOut: vi.fn<(notice: string) => void>(), onPasswordRequired: vi.fn<() => void>() }
function value(): ResponseRetentionSummary { return { version: 'mii.response-retention-summary.v1', run_id: runID, analysis_revision: 1, observed_at: '2026-09-08T12:00:00.123456Z', policy_days: 30, policy_version: 7, attempt_count: 12, raw_deleted_count: 6, display_deleted_count: 2, display_expired_count: 3, display_retained_count: 4, last_deleted_at: '2026-09-08T11:00:00Z' } }
const ok = (data: unknown) => Response.json({ data, request_id: 'retention-panel-test' })
const fail = (status: number) => Response.json({ error: { code: status === 401 ? 'MI_SESSION_REQUIRED' : status === 403 ? 'MI_PERMISSION_DENIED' : 'MI_SERVICE_UNAVAILABLE', message: 'PRIVATE_RETENTION_CANARY' }, request_id: 'retention-panel-error' }, { status })
type Handler = (url: URL, options: RequestInit) => Response | Promise<Response> | undefined
function network(handler?: Handler, permissions = ['run.read', 'evidence.read']) {
  const calls = vi.fn<typeof fetch>(async (input, options = {}) => {
    const url = new URL(String(input), 'http://localhost'), result = handler?.(url, options)
    if (result) return result
    if (url.pathname.endsWith('/auth/permissions')) return ok({ organization_id: new Headers(options.headers).get('X-Organization-ID'), user_id: userID, permissions })
    if (url.pathname.endsWith('/response-retention')) return ok(value())
    throw new Error('Unexpected request PRIVATE_RETENTION_CANARY')
  }); vi.stubGlobal('fetch', calls); return calls
}
async function click(name: string) { await act(async () => { fireEvent.click(screen.getByRole('button', { name })) }) }
const read = () => click('读取当前正文保留状态')
const refresh = () => click('刷新当前正文保留状态')
const loaded = () => screen.findByText(/Run 9007199254740995 · 分析修订 1 · 政策版本 7/)
const metric = (label: string) => screen.getByText(label, { selector: 'dt' }).parentElement?.querySelector('dd')?.textContent
beforeEach(() => { props.onDenied.mockClear(); props.onSignedOut.mockClear(); props.onPasswordRequired.mockClear() })

describe('manual scoped S1 response retention panel', () => {
  it('does not fetch on mount and needs only two read permissions, never body/export permissions', async () => {
    const calls = network(); render(<ResponseRetentionPanel {...props} />)
    expect(calls).not.toHaveBeenCalled(); expect(document.querySelector('dl')).toBeNull()
    await read(); await loaded()
    expect(calls.mock.calls.map(([url]) => String(url))).toEqual(['/api/v1/auth/permissions', `/api/v1/runs/${runID}/response-retention?analysis_revision=1`])
    expect(calls.mock.calls.every(([, options]) => options?.method === 'GET' && options.cache === 'no-store')).toBe(true)
    expect(document.querySelector('pre,iframe,a[download]')).toBeNull(); expect(localStorage.length + sessionStorage.length).toBe(0)
    expect(props.onDenied).not.toHaveBeenCalled()
  })
  it('shows dynamic observations and independent count dimensions, not a rewrite of historical reports', async () => {
    network(); render(<ResponseRetentionPanel {...props} />); await read(); await loaded()
    expect(screen.getByText(/动态观察，不改变旧报告文件\/哈希/)).toBeTruthy()
    expect(metric('本 Run Attempt 总数')).toBe('12')
    expect(metric('原始分析副本已删除')).toBe('6')
    expect(metric('展示副本已删除')).toBe('2')
    expect(metric('展示副本已过期或不再允许保留')).toBe('3')
    expect(metric('展示副本仍在保留窗口')).toBe('4')
    expect(screen.getByText(/原始分析副本是独立维度/)).toBeTruthy()
    expect(document.activeElement?.textContent).toBe('当前响应正文保留状态')
    expect(screen.getByText(value().observed_at).getAttribute('datetime')).toBe(value().observed_at)
  })
  it('does not poll and clears the old snapshot before a manual refresh', async () => {
    let next = false, release: ((response: Response) => void) | undefined
    const calls = network((url) => url.pathname.endsWith('/response-retention') && next ? new Promise<Response>((resolve) => { release = resolve }) : undefined)
    render(<ResponseRetentionPanel {...props} />); await read(); await loaded()
    vi.useFakeTimers()
    try { await act(async () => { await vi.advanceTimersByTimeAsync(60000) }); expect(calls).toHaveBeenCalledTimes(2) } finally { vi.useRealTimers() }
    next = true; await refresh(); expect(document.querySelector('dl')).toBeNull()
    await act(async () => release!(ok({ ...value(), policy_days: 7, policy_version: 8 })))
    expect(metric('当前响应保留策略')).toBe('7 天')
    expect(calls.mock.calls.filter(([url]) => String(url).includes('/response-retention'))).toHaveLength(2)
  })
  it('shows real zero observations and null time without pretending policy zero proves deletion completion', async () => {
    network((url) => url.pathname.endsWith('/response-retention') ? ok({ ...value(), policy_days: 0, raw_deleted_count: 0, display_deleted_count: 0, display_expired_count: 0, display_retained_count: 0, last_deleted_at: null }) : undefined)
    render(<ResponseRetentionPanel {...props} />); await read(); await loaded()
    expect(metric('当前响应保留策略')).toBe('0 天'); expect(metric('展示副本已删除')).toBe('0')
    expect(screen.getByText(/未记录删除时间/)).toBeTruthy()
    expect(screen.getByText(/不能据此推断物理删除已全部完成/)).toBeTruthy()
  })
  it.each([{ permissions: [] }, { permissions: ['run.read'] }, { permissions: ['evidence.read'] }, { permissions: ['report.export', 'evidence.body'] }])('does not infer required read permissions from $permissions', async ({ permissions }) => {
    const calls = network(undefined, permissions); render(<ResponseRetentionPanel {...props} />); await read()
    expect(calls.mock.calls.some(([url]) => String(url).includes('/response-retention'))).toBe(false)
    expect(props.onDenied).toHaveBeenCalledTimes(1); expect(document.querySelector('dl')).toBeNull()
  })
  it('refuses permissions revoked after a successful read without another summary request', async () => {
    let allowed = true
    const calls = network((url) => url.pathname.endsWith('/auth/permissions') && !allowed ? ok({ organization_id: org, user_id: userID, permissions: ['run.read'] }) : undefined)
    render(<ResponseRetentionPanel {...props} />); await read(); await loaded(); allowed = false; await refresh()
    expect(document.querySelector('dl')).toBeNull(); expect(props.onDenied).toHaveBeenCalledTimes(1)
    expect(calls.mock.calls.filter(([url]) => String(url).includes('/response-retention'))).toHaveLength(1)
  })
  it.each([401, 403])('clears old state on HTTP %s denial and never retains server diagnostic text', async (status) => {
    let denied = false, signal: AbortSignal | null | undefined
    network((url, options) => { if (url.pathname.endsWith('/response-retention') && denied) { signal = options.signal; return fail(status) }; return undefined })
    render(<ResponseRetentionPanel {...props} />); await read(); await loaded(); denied = true; await refresh()
    expect(document.querySelector('dl')).toBeNull(); expect(signal?.aborted).toBe(true)
    expect(props.onDenied).toHaveBeenCalledTimes(1); expect(props.onSignedOut).toHaveBeenCalledTimes(status === 401 ? 1 : 0)
    expect(screen.queryByRole('button', { name: '刷新当前正文保留状态' })).toBeNull()
    expect(document.body.textContent).not.toContain('PRIVATE_RETENTION_CANARY')
  })
  it('fails closed on malformed 403 and clears all observations', async () => {
    network((url) => url.pathname.endsWith('/response-retention') ? new Response('<html>PRIVATE_RETENTION_CANARY', { status: 403 }) : undefined)
    render(<ResponseRetentionPanel {...props} />); await read()
    expect(props.onSignedOut).toHaveBeenCalledTimes(1); expect(props.onDenied).toHaveBeenCalledTimes(1)
    expect(document.querySelector('dl')).toBeNull(); expect(document.body.textContent).not.toContain('PRIVATE_RETENTION_CANARY')
  })
  it.each(['failure', 'invalid', 'wrong-scope', 'extra-body'])('discards stale counts on %s without inventing zero or deletion success', async (mode) => {
    let changed = false
    network((url) => {
      if (!url.pathname.endsWith('/response-retention') || !changed) return undefined
      if (mode === 'failure') return fail(503)
      return ok({ ...value(), ...(mode === 'invalid' ? { display_deleted_count: 13 } : mode === 'wrong-scope' ? { run_id: '2' } : { body: 'PRIVATE_RETENTION_CANARY' }) })
    })
    render(<ResponseRetentionPanel {...props} />); await read(); await loaded(); changed = true; await refresh()
    expect(document.querySelector('dl')).toBeNull(); expect(screen.getByText(/当前保留状态未知/)).toBeTruthy()
    expect(document.body.textContent).not.toContain('PRIVATE_RETENTION_CANARY'); expect(props.onDenied).not.toHaveBeenCalled()
  })
  it.each([{ organizationID: '2' }, { userID: '3' }, { runID: '4' }, { analysisRevision: 2 }])('clears visible observations without auto-loading a changed scope %j', async (changed) => {
    const calls = network(), view = render(<ResponseRetentionPanel {...props} />); await read(); await loaded()
    view.rerender(<ResponseRetentionPanel {...props} {...changed} />)
    expect(document.querySelector('dl')).toBeNull(); expect(calls).toHaveBeenCalledTimes(2)
    expect(screen.getByRole('button', { name: '读取当前正文保留状态' })).toBeTruthy()
  })
  it.each(['cancel', 'unmount', 'organization', 'user', 'run', 'revision'])('aborts an uncooperative summary and ignores late completion after %s', async (mode) => {
    let release: ((response: Response) => void) | undefined, signal: AbortSignal | null | undefined
    network((url, options) => url.pathname.endsWith('/response-retention') ? new Promise<Response>((resolve) => { release = resolve; signal = options.signal }) : undefined)
    const view = render(<ResponseRetentionPanel {...props} />); await read(); await waitFor(() => expect(release).toBeTypeOf('function'))
    if (mode === 'cancel') await click('取消并清除保留状态读取')
    else if (mode === 'unmount') view.unmount()
    else view.rerender(<ResponseRetentionPanel {...props} {...(mode === 'organization' ? { organizationID: '2' } : mode === 'user' ? { userID: '3' } : mode === 'run' ? { runID: '4' } : { analysisRevision: 2 })} />)
    expect(signal?.aborted).toBe(true)
    await act(async () => release!(ok(value())))
    expect(document.querySelector('dl')).toBeNull(); expect(props.onDenied).not.toHaveBeenCalled()
  })
  it('cancels a pending permission read, blocks double clicks, and never lets an old completion overwrite a newer result', async () => {
    let first: ((response: Response) => void) | undefined, permissionReads = 0
    const calls = network((url) => url.pathname.endsWith('/auth/permissions') && ++permissionReads === 1 ? new Promise<Response>((resolve) => { first = resolve }) : undefined)
    render(<ResponseRetentionPanel {...props} />)
    const button = screen.getByRole('button', { name: '读取当前正文保留状态' })
    await act(async () => { fireEvent.click(button); fireEvent.click(button) }); expect(calls).toHaveBeenCalledTimes(1)
    await click('取消并清除保留状态读取'); await read(); await loaded()
    await act(async () => first!(ok({ organization_id: org, user_id: userID, permissions: [] })))
    expect(metric('展示副本仍在保留窗口')).toBe('4'); expect(props.onDenied).not.toHaveBeenCalled()
    expect(calls.mock.calls.filter(([url]) => String(url).includes('/response-retention'))).toHaveLength(1)
    await click('清除保留状态'); expect(document.querySelector('dl')).toBeNull()
  })
})
