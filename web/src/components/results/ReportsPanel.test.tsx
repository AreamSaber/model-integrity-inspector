// @ts-expect-error -- Test-only pinned Node runner provides this built-in; no browser Node ambient types are added.
import { createHash, webcrypto } from 'node:crypto'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ReportsPanel } from './ReportsPanel'
import type { Report } from '../../reports-api'

const org = '9007199254740993', runID = '9007199254740995', userID = '9007199254740997', reportID = '9007199254741001'
const props = { organizationID: org, userID, runID, analysisRevision: 1, csrfToken: 'synthetic-csrf', onSignedOut: vi.fn<(notice: string) => void>(), onPasswordRequired: vi.fn<() => void>(), onDenied: vi.fn<(error: unknown) => void>() }
const body = new TextEncoder().encode('{"safe":"S1 statistics only"}')
function record(id = reportID): Report { return { id, run_id: runID, analysis_revision: 1, revision: 1, format: 'json', schema_version: 'mii.report.v1', status: 'queued', created_at: '2026-09-07T10:00:00Z', review_state: 'not_included' } }
function ready(): Report { return { ...record(), status: 'ready', content_hash: `sha256:${'a'.repeat(64)}`, file_hash: `sha256:${createHash('sha256').update(body).digest('hex')}`, file_size: body.length } }
function ok(data: unknown, status = 200) { return Response.json({ data, request_id: 'report-panel' }, { status }) }
function failure(code: string, status: number) { return Response.json({ error: { code, message: 'PRIVATE_REPORT_CANARY' }, request_id: 'report-error' }, { status }) }
type Handler = (url: URL, options: RequestInit) => Response | Promise<Response> | undefined
function network(handler?: Handler, permissions = ['run.read', 'evidence.read', 'report.export']) {
  const fetcher = vi.fn<typeof fetch>(async (input, options = {}) => {
    const url = new URL(String(input), 'http://localhost'), response = handler?.(url, options)
    if (response) return response
    if (url.pathname.endsWith('/auth/permissions')) return ok({ organization_id: new Headers(options.headers).get('X-Organization-ID'), user_id: userID, permissions })
    if (url.pathname.endsWith('/reports') && options.method === 'GET') return ok({ items: [], next_cursor: null })
    if (url.pathname.endsWith('/reports') && options.method === 'POST') return ok({ ...ready(), format: JSON.parse(options.body as string).format }, 202)
    if (url.pathname.endsWith(`/reports/${reportID}`)) return ok(ready())
    if (url.pathname.endsWith('/download')) {
      const value = ready()
      return new Response(body, { headers: { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': String(body.length), 'Content-Disposition': `attachment; filename="report-${reportID}-r1.json"`, 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'", 'X-Report-Content-Hash': value.content_hash!, 'X-Report-File-Hash': value.file_hash! } })
    }
    throw new Error('Unexpected request PRIVATE_REPORT_CANARY')
  }); vi.stubGlobal('fetch', fetcher); return fetcher
}
const posts = (fetcher: ReturnType<typeof network>) => fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')
async function open() { await screen.findByRole('form', { name: '生成脱敏报告' }) }
async function click(name: string) { await act(async () => { fireEvent.click(screen.getByRole('button', { name })) }) }
function confirm() { fireEvent.click(screen.getByRole('checkbox', { name: /我确认仅生成脱敏 S1/ })) }
async function submit() { await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '生成脱敏报告' })) }) }
beforeEach(() => { vi.stubGlobal('crypto', webcrypto); props.onSignedOut.mockClear(); props.onPasswordRequired.mockClear(); props.onDenied.mockClear() })

describe('explicit S1 report panel', () => {
  it('keeps retention as a separate manual S1 observation without mutating report hashes or asking for body', async () => {
    const data = { version: 'mii.response-retention-summary.v1', run_id: runID, analysis_revision: 1, observed_at: '2026-09-08T12:00:00Z', policy_days: 30, policy_version: 2, attempt_count: 6, raw_deleted_count: 2, display_deleted_count: 1, display_expired_count: 2, display_retained_count: 3, last_deleted_at: '2026-09-08T11:00:00Z' }
    const calls = network((url, options) => {
      if (url.pathname.endsWith('/response-retention')) return ok(data)
      if (url.pathname.endsWith('/reports') && options.method === 'GET') return ok({ items: [ready()], next_cursor: null })
      return undefined
    })
    render(<ReportsPanel {...props} />); await open()
    expect(calls.mock.calls.some(([url]) => String(url).includes('/response-retention'))).toBe(false)
    await click(`读取报告 ${reportID}`); await screen.findByRole('heading', { name: `报告 ${reportID} · 可下载` })
    await click('读取当前正文保留状态')
    expect(await screen.findByText(/政策版本 2/)).toBeTruthy()
    expect(screen.getByText(`文件字节哈希：${ready().file_hash}`)).toBeTruthy()
    expect(screen.getByText(/动态观察，不改变旧报告文件\/哈希/)).toBeTruthy()
    expect(posts(calls)).toHaveLength(0)
    expect(calls.mock.calls.some(([url]) => /\/attempts\/|\/download/.test(String(url)))).toBe(false)
  })
  it.each([401, 403])('clears both report and retention state on summary HTTP %s without duplicate sign-out callbacks', async (status) => {
    network((url, options) => {
      if (url.pathname.endsWith('/response-retention')) return failure(status === 401 ? 'MI_SESSION_REQUIRED' : 'MI_PERMISSION_DENIED', status)
      if (url.pathname.endsWith('/reports') && options.method === 'GET') return ok({ items: [ready()], next_cursor: null })
      return undefined
    })
    render(<ReportsPanel {...props} />); await open(); await click('读取当前正文保留状态')
    expect(props.onDenied).toHaveBeenCalledTimes(1); expect(props.onSignedOut).toHaveBeenCalledTimes(status === 401 ? 1 : 0)
    expect(screen.queryByRole('list', { name: '固定修订报告列表' })).toBeNull()
    expect(screen.queryByRole('heading', { name: '当前响应正文保留状态' })).toBeNull()
  })
  it('does not change the existing report.export gate just to reveal a retention summary', async () => {
    const calls = network(undefined, ['run.read', 'evidence.read'])
    render(<ReportsPanel {...props} />); await screen.findByText(/当前没有可用的完整权限/)
    expect(props.onDenied).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('heading', { name: '当前响应正文保留状态' })).toBeNull()
    expect(calls.mock.calls.some(([url]) => String(url).includes('/response-retention'))).toBe(false)
  })
  it('reads only a metadata page and permissions on entry, with no create/download/automatic row poll', async () => {
    const calls = network((url, options) => url.pathname.endsWith('/reports') && options.method === 'GET' ? ok({ items: [record()], next_cursor: null }) : undefined)
    render(<ReportsPanel {...props} />); await open()
    expect(screen.getByText(/当前报告未纳入人工复核快照/)).toBeTruthy()
    expect(posts(calls)).toHaveLength(0)
    expect(calls.mock.calls.some(([url]) => String(url).includes(`/reports/${reportID}`))).toBe(false)
    expect(document.querySelector('iframe')).toBeNull()
    expect(localStorage.length + sessionStorage.length).toBe(0)
  })
  it.each([{ permissions: ['run.read'] }, { permissions: ['run.read', 'report.export'] }, { permissions: ['evidence.read', 'report.export'] }])('requires all three real permissions, not an inferred administrator flag: $permissions', async ({ permissions }) => {
    const calls = network(undefined, permissions)
    render(<ReportsPanel {...props} />)
    await screen.findByText(/当前没有可用的完整权限/)
    expect(calls.mock.calls.some(([url]) => String(url).includes('/reports'))).toBe(false)
    expect(props.onDenied).toHaveBeenCalled()
  })
  it('requires explicit format/confirmation, refreshes permissions and prevents double submission', async () => {
    let resolve: ((value: Response) => void) | undefined
    const calls = network((_url, options) => options.method === 'POST' ? new Promise<Response>((done) => { resolve = done }) : undefined)
    render(<ReportsPanel {...props} />); await open(); await submit(); expect(posts(calls)).toHaveLength(0)
    fireEvent.change(screen.getByLabelText('报告文件格式'), { target: { value: 'html' } }); confirm()
    const form = screen.getByRole('form', { name: '生成脱敏报告' })
    await act(async () => { fireEvent.submit(form); fireEvent.submit(form) })
    expect(posts(calls)).toHaveLength(1)
    expect(JSON.parse(posts(calls)[0][1]!.body as string)).toEqual({ format: 'html', analysis_revision: 1, include_restricted_content: false })
    expect(calls.mock.calls.filter(([url]) => String(url).includes('/auth/permissions')).length).toBeGreaterThanOrEqual(2)
    await act(async () => resolve!(ok({ ...ready(), format: 'html' }, 202)))
    await screen.findByRole('heading', { name: `报告 ${reportID} · 可下载` })
    expect(document.activeElement?.id).toBe('report-selected-title')
  })
  it('retains a single uncertain body/key and only manually restores it, even across a transient permission failure', async () => {
    let permissionReads = 0, writes = 0
    const calls = network((url, options) => {
      if (url.pathname.endsWith('/auth/permissions') && ++permissionReads === 3) return failure('MI_SERVICE_UNAVAILABLE', 503)
      if (options.method === 'POST' && ++writes === 1) throw new TypeError('PRIVATE_REPORT_CANARY')
      return undefined
    })
    render(<ReportsPanel {...props} />); await open(); confirm(); await submit()
    expect(screen.getByRole('heading', { name: '报告创建结果尚未确认' })).toBeTruthy()
    expect(screen.queryByRole('form', { name: '生成脱敏报告' })).toBeNull()
    fireEvent.click(screen.getByRole('checkbox', { name: /我确认仅恢复原报告/ })); await click('手动恢复同一次报告创建')
    expect(posts(calls)).toHaveLength(1)
    expect(screen.getByRole('heading', { name: '报告创建结果尚未确认' })).toBeTruthy()
    fireEvent.click(screen.getByRole('checkbox', { name: /我确认仅恢复原报告/ })); await click('手动恢复同一次报告创建')
    await open(); expect(posts(calls)).toHaveLength(2)
    expect(posts(calls)[1][1]?.body).toBe(posts(calls)[0][1]?.body)
    expect(new Headers(posts(calls)[1][1]?.headers).get('Idempotency-Key')).toBe(new Headers(posts(calls)[0][1]?.headers).get('Idempotency-Key'))
    expect(document.body.textContent).not.toContain('PRIVATE_REPORT_CANARY')
  })
  it('stops a create when permissions were revoked after opening, clearing visible caches', async () => {
    let permissions = 0
    const calls = network((url) => url.pathname.endsWith('/auth/permissions') && ++permissions > 1 ? ok({ organization_id: org, user_id: userID, permissions: ['run.read'] }) : undefined)
    render(<ReportsPanel {...props} />); await open(); confirm(); await submit()
    expect(posts(calls)).toHaveLength(0)
    expect(props.onDenied).toHaveBeenCalled()
    expect(screen.queryByRole('form', { name: '生成脱敏报告' })).toBeNull()
  })
  it('uses exact ID forward-only polling only after an explicit inspection and stops at ready', async () => {
    let reads = 0
    const calls = network((url, options) => {
      if (url.pathname.endsWith('/reports') && options.method === 'GET') return ok({ items: [record()], next_cursor: null })
      if (url.pathname.endsWith(`/reports/${reportID}`)) return ok(++reads === 1 ? { ...record(), status: 'generating' } : ready())
      return undefined
    })
    const rendered = render(<ReportsPanel {...props} />); await open()
    vi.useFakeTimers(); await click(`读取报告 ${reportID}`)
    expect(screen.getByRole('heading', { name: `报告 ${reportID} · 正在生成` })).toBeTruthy()
    await act(async () => { await vi.advanceTimersByTimeAsync(2000) })
    expect(screen.getByRole('heading', { name: `报告 ${reportID} · 可下载` })).toBeTruthy()
    expect((screen.getByRole('button', { name: `下载 JSON 报告 ${reportID}` }) as HTMLButtonElement).disabled).toBe(false)
    await act(async () => { await vi.advanceTimersByTimeAsync(10000) })
    expect(reads).toBe(2); expect(posts(calls)).toHaveLength(0)
    rendered.unmount()
  })
  it('rejects a changed hash/revision in a precise GET and never enables the changed file download', async () => {
    const calls = network((url, options) => {
      if (url.pathname.endsWith('/reports') && options.method === 'GET') return ok({ items: [ready()], next_cursor: null })
      if (url.pathname.endsWith(`/reports/${reportID}`)) return ok({ ...ready(), revision: 2 })
      return undefined
    })
    render(<ReportsPanel {...props} />); await open(); await click(`下载 JSON 报告 ${reportID}`)
    expect(calls.mock.calls.some(([url]) => String(url).endsWith('/download'))).toBe(false)
    expect(screen.getByRole('alert').textContent).not.toContain('PRIVATE_REPORT_CANARY')
  })
  it('stops bounded polling after at most 150 reads and never regenerates a pending report', async () => {
    let reads = 0
    const calls = network((url, options) => {
      if (url.pathname.endsWith('/reports') && options.method === 'GET') return ok({ items: [record()], next_cursor: null })
      if (url.pathname.endsWith(`/reports/${reportID}`)) { reads++; return ok({ ...record(), status: 'generating' }) }
      return undefined
    })
    render(<ReportsPanel {...props} />); await open(); vi.useFakeTimers()
    await click(`读取报告 ${reportID}`)
    await act(async () => { await vi.advanceTimersByTimeAsync(300000) })
    expect(reads).toBeLessThanOrEqual(150)
    expect(screen.queryByRole('button', { name: '停止自动读取报告' })).toBeNull()
    expect(screen.getByText(/自动读取已达/)).toBeTruthy()
    const stopped = reads
    await act(async () => { await vi.advanceTimersByTimeAsync(60000) })
    expect(reads).toBe(stopped); expect(posts(calls)).toHaveLength(0)
  })
  it('shows terminal failure without automatic retry or a fabricated completed download', async () => {
    const failed: Report = { ...record(), status: 'failed', error_code: 'MI_REPORT_GENERATION_FAILED' }
    const calls = network((url, options) => {
      if (url.pathname.endsWith('/reports') && options.method === 'GET') return ok({ items: [failed], next_cursor: null })
      if (url.pathname.endsWith(`/reports/${reportID}`)) return ok(failed)
      return undefined
    })
    render(<ReportsPanel {...props} />); await open(); await click(`读取报告 ${reportID}`)
    expect(screen.getByText(/生成失败，原分析结果仍保留/)).toBeTruthy()
    expect((screen.getByRole('button', { name: '下载当前 JSON 报告' }) as HTMLButtonElement).disabled).toBe(true)
    expect(posts(calls)).toHaveLength(0)
  })
  it('paginates on the server and scopes/aborts in-flight reads on organization changes', async () => {
    let held: AbortSignal | null | undefined
    const calls = network((url, options) => {
      if (!url.pathname.endsWith('/reports') || options.method !== 'GET') return undefined
      if (url.searchParams.has('cursor')) { held = options.signal; return new Promise<Response>(() => {}) }
      return ok({ items: [record()], next_cursor: 'report:page2' })
    })
    const rendered = render(<ReportsPanel {...props} />); await open(); await click('报告下一页')
    expect(calls.mock.calls.some(([url]) => String(url).includes('cursor=report%3Apage2'))).toBe(true)
    rendered.rerender(<ReportsPanel {...props} organizationID="9007199254740994" />)
    await open(); expect(held?.aborted).toBe(true)
    expect(screen.getByText('报告第 1 页')).toBeTruthy()
    expect(new Headers(calls.mock.calls.at(-1)?.[1]?.headers).get('X-Organization-ID')).toBe('9007199254740994')
  })
  it('downloads only on a click, verifies bytes before a Blob URL and revokes it after the save action', async () => {
    const calls = network((url, options) => url.pathname.endsWith('/reports') && options.method === 'GET' ? ok({ items: [ready()], next_cursor: null }) : undefined)
    const create = vi.fn<(blob: Blob) => string>(() => 'blob:verified-file'), revoke = vi.fn<(url: string) => void>()
    vi.stubGlobal('URL', Object.assign(class extends URL {}, { createObjectURL: create, revokeObjectURL: revoke }))
    const anchor = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const rendered = render(<ReportsPanel {...props} />); await open()
    expect(create).not.toHaveBeenCalled(); await click(`下载 JSON 报告 ${reportID}`)
    await screen.findByText(/已请求浏览器保存/)
    expect(create).toHaveBeenCalledTimes(1); expect(create.mock.calls[0][0].size).toBe(body.length)
    expect(anchor).toHaveBeenCalledTimes(1)
    expect(document.querySelector('a[download]')).toBeNull(); expect(document.querySelector('iframe')).toBeNull()
    expect(calls.mock.calls.filter(([url]) => String(url).includes('/auth/permissions'))).toHaveLength(2)
    rendered.unmount(); expect(revoke).toHaveBeenCalledWith('blob:verified-file')
  })
  it('withdraws the session for any HTTP 403 download including a malformed denial body', async () => {
    network((url, options) => {
      if (url.pathname.endsWith('/reports') && options.method === 'GET') return ok({ items: [ready()], next_cursor: null })
      if (url.pathname.endsWith('/download')) return new Response('<html>PRIVATE_REPORT_CANARY', { status: 403 })
      return undefined
    })
    render(<ReportsPanel {...props} />); await open(); await click(`下载 JSON 报告 ${reportID}`)
    expect(props.onSignedOut).toHaveBeenCalled(); expect(props.onDenied).toHaveBeenCalled()
    expect(screen.queryByRole('list', { name: '固定修订报告列表' })).toBeNull()
    expect(document.body.textContent).not.toContain('PRIVATE_REPORT_CANARY')
  })
  it('aborts uncooperative downloads on unmount before any save or object URL', async () => {
    let held: AbortSignal | null | undefined
    network((url, options) => {
      if (url.pathname.endsWith('/reports') && options.method === 'GET') return ok({ items: [ready()], next_cursor: null })
      if (url.pathname.endsWith('/download')) { held = options.signal; return new Promise<Response>(() => {}) }
      return undefined
    })
    const create = vi.fn<() => string>(); vi.stubGlobal('URL', Object.assign(class extends URL {}, { createObjectURL: create, revokeObjectURL: vi.fn<(url: string) => void>() }))
    const rendered = render(<ReportsPanel {...props} />); await open(); await click(`下载 JSON 报告 ${reportID}`)
    await waitFor(() => expect(held).toBeTruthy())
    rendered.unmount(); expect(held?.aborted).toBe(true); expect(create).not.toHaveBeenCalled()
  })
  it('supports an explicit user cancellation without claiming that a file was saved', async () => {
    let held: AbortSignal | null | undefined
    network((url, options) => {
      if (url.pathname.endsWith('/reports') && options.method === 'GET') return ok({ items: [ready()], next_cursor: null })
      if (url.pathname.endsWith('/download')) { held = options.signal; return new Promise<Response>(() => {}) }
      return undefined
    })
    render(<ReportsPanel {...props} />); await open(); await click(`下载 JSON 报告 ${reportID}`)
    await waitFor(() => expect(held).toBeTruthy())
    await click('取消本次报告下载')
    expect(held?.aborted).toBe(true)
    expect(screen.getByText('本次下载已取消，未请求浏览器保存文件。')).toBeTruthy()
    expect(props.onSignedOut).not.toHaveBeenCalled()
    expect(screen.queryByText(/已请求浏览器保存；/)).toBeNull()
  })
})
