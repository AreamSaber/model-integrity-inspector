import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ReviewPanel } from './ReviewPanel'
import type { Review } from '../../reviews-api'

const org = '9007199254740993', runID = '9007199254740995', userID = '9007199254740997'
const context = { organizationID: org, userID, runID, analysisRevision: 1, csrfToken: 'synthetic-csrf', onSignedOut: vi.fn<(message: string) => void>(), onPasswordRequired: vi.fn<() => void>(), onDenied: vi.fn<(error: unknown) => void>() }
function record(id = '9007199254741000'): Review { return { id, run_id: runID, analysis_revision: 1, conclusion: 'watch', explanation: 'Earlier human observation', created_by: userID, created_at: '2026-09-07T10:00:00.000001Z' } }
function ok(data: unknown, status = 200) { return Response.json({ data, request_id: 'review-test' }, { status }) }
function fail(code: string, status: number) { return Response.json({ error: { code, message: 'SECRET_BODY_CANARY' }, request_id: 'review-test-error' }, { status }) }
type Handler = (url: URL, options: RequestInit) => Response | Promise<Response> | undefined
function network(handler?: Handler, permissions = ['run.read', 'review.write']) {
  const fetcher = vi.fn<typeof fetch>(async (input, options = {}) => {
    const url = new URL(String(input), 'http://localhost'), response = handler?.(url, options)
    if (response) return response
    if (url.pathname.endsWith('/auth/permissions')) return ok({ organization_id: new Headers(options.headers).get('X-Organization-ID'), user_id: url.searchParams.get('user_id') ?? userID, permissions })
    if (url.pathname.endsWith('/reviews') && options.method === 'GET') return ok({ items: [], next_cursor: null })
    if (url.pathname.endsWith('/reviews') && options.method === 'POST') {
      const body = JSON.parse(options.body as string) as { conclusion: Review['conclusion']; explanation: string }
      return ok({ ...record(), ...body, previous_review_id: undefined }, 201)
    }
    throw new Error('Unexpected test request')
  }); vi.stubGlobal('fetch', fetcher); return fetcher
}
async function open() { await screen.findByRole('form', { name: '追加人工复核' }) }
function fill(note = '人工核查说明，不含业务正文。') {
  fireEvent.change(screen.getByLabelText('复核说明'), { target: { value: note } })
  fireEvent.click(screen.getByRole('checkbox', { name: /我确认追加人工业务判断/ }))
}
async function submit() { await act(async () => { fireEvent.submit(screen.getByRole('form', { name: '追加人工复核' })) }) }
async function click(name: string) { await act(async () => { fireEvent.click(screen.getByRole('button', { name })) }) }
function posts(fetcher: ReturnType<typeof network>) { return fetcher.mock.calls.filter(([, options]) => options?.method === 'POST') }

describe('append-only human review panel', () => {
  it('reads history with run.read alone and renders reviewer text literally, without a write or HTML execution', async () => {
    const note = '<img src=x onerror=alert(1)>\nObservation only'
    const calls = network(() => undefined, ['run.read'])
    calls.mockImplementation(async (input) => String(input).includes('/reviews') ? ok({ items: [{ ...record(), explanation: note }], next_cursor: null }) : ok({ organization_id: org, user_id: userID, permissions: ['run.read'] }))
    render(<ReviewPanel {...context} />)
    await screen.findByText(/Observation only/)
    expect(document.querySelector('img')).toBeNull()
    expect(screen.getByText(/不代表软件正式审核批准/)).toBeTruthy()
    expect(screen.queryByRole('form', { name: '追加人工复核' })).toBeNull()
    expect(posts(calls)).toHaveLength(0)
    expect(screen.queryByRole('button', { name: /删除|编辑旧/ })).toBeNull()
    expect(localStorage.length + sessionStorage.length).toBe(0)
  })
  it('requires a successful latest read, valid byte-bounded notes and explicit confirmation before the first append', async () => {
    const calls = network(); render(<ReviewPanel {...context} />); await open()
    await submit(); expect(posts(calls)).toHaveLength(0)
    fill('字'.repeat(1366)); await submit(); expect(posts(calls)).toHaveLength(0)
    fireEvent.change(screen.getByLabelText('复核说明'), { target: { value: 'Valid review reason' } })
    await submit()
    await screen.findByText(/本次提交收据/)
    const request = posts(calls)[0][1]!
    expect(JSON.parse(request.body as string)).toEqual({ analysis_revision: 1, conclusion: 'watch', explanation: 'Valid review reason' })
    expect(new Headers(request.headers).get('X-Organization-ID')).toBe(org)
    expect(new Headers(request.headers).get('X-CSRF-Token')).toBe(context.csrfToken)
    expect(new Headers(request.headers).get('Idempotency-Key')).toMatch(/^[A-Za-z0-9._:-]{16,128}$/)
    expect(posts(calls)).toHaveLength(1)
  })
  it('reads the latest version before appending and keeps historical pages read-only until latest is reloaded', async () => {
    const latest = record('9007199254741010'), older = record('9007199254741000')
    const calls = network((url, options) => options.method === 'GET' && url.pathname.endsWith('/reviews') ? ok(url.searchParams.has('cursor') ? { items: [older], next_cursor: null } : { items: [latest], next_cursor: 'history:older' }) : undefined)
    render(<ReviewPanel {...context} />); await open()
    await click('复核下一页'); await screen.findByText(/复核 9007199254741000/)
    expect(screen.queryByRole('form', { name: '追加人工复核' })).toBeNull()
    await click('重新读取最新复核'); await open(); fill(); await submit()
    expect(JSON.parse(posts(calls)[0][1]!.body as string).previous_review_id).toBe(latest.id)
    expect(calls.mock.calls.some(([url]) => String(url).includes('cursor=history%3Aolder'))).toBe(true)
  })
  it('does not enable submission when latest loading fails or permission reading fails', async () => {
    const calls = network((url) => url.pathname.endsWith('/reviews') ? fail('MI_SERVICE_UNAVAILABLE', 503) : undefined)
    const view = render(<ReviewPanel {...context} />)
    await screen.findByRole('button', { name: '重新读取最新复核' })
    await waitFor(() => expect(screen.queryByText('正在读取最新权限与复核历史…')).toBeNull())
    expect(screen.queryByRole('form', { name: '追加人工复核' })).toBeNull(); expect(posts(calls)).toHaveLength(0)
    view.unmount()
    const denied = network((url) => url.pathname.endsWith('/auth/permissions') ? fail('MI_SERVICE_UNAVAILABLE', 503) : undefined)
    render(<ReviewPanel {...context} />)
    await waitFor(() => expect(screen.queryByText('正在读取最新权限与复核历史…')).toBeNull())
    expect(denied.mock.calls.some(([url]) => String(url).includes('/reviews'))).toBe(false)
  })
  it('blocks double submit while the initial permission check or POST is pending', async () => {
    let resolvePost: ((value: Response) => void) | undefined
    const calls = network((_url, options) => options.method === 'POST' ? new Promise<Response>((resolve) => { resolvePost = resolve }) : undefined)
    render(<ReviewPanel {...context} />); await open(); fill()
    const form = screen.getByRole('form', { name: '追加人工复核' })
    await act(async () => { fireEvent.submit(form); fireEvent.submit(form) })
    expect(posts(calls)).toHaveLength(1)
    await click('正在核对原提交…'); expect(posts(calls)).toHaveLength(1)
    await act(async () => resolvePost!(ok({ ...record(), explanation: '人工核查说明，不含业务正文。' }, 201)))
  })
  it('retains exactly one unknown POST and manually restores its original body/key, not a fresh review', async () => {
    let attempts = 0, historyReads = 0
    const later = { ...record('9007199254741020'), explanation: 'Someone appended a newer review' }
    const calls = network((url, options) => {
      if (options.method === 'POST' && attempts++ === 0) throw new TypeError('SECRET_BODY_CANARY')
      if (options.method === 'POST') return ok({ ...record('9007199254741010'), explanation: 'Frozen note' }, 201)
      if (options.method === 'GET' && url.pathname.endsWith('/reviews')) return ok({ items: historyReads++ === 0 ? [record()] : [later], next_cursor: null })
      return undefined
    })
    render(<ReviewPanel {...context} />); await open(); fill('Frozen note'); await submit()
    expect(screen.getByText(/本页保留原提交内容和同一提交标识/)).toBeTruthy()
    expect(screen.queryByLabelText('复核说明')).toBeNull()
    expect((screen.getByRole('button', { name: '重新读取最新复核' }) as HTMLButtonElement).disabled).toBe(true)
    expect(posts(calls)).toHaveLength(1)
    fireEvent.click(screen.getByRole('checkbox', { name: /我确认只恢复原提交/ }))
    await click('手动恢复同一次复核')
    await open()
    expect(screen.getByText(/本次提交收据/)).toBeTruthy()
    expect(posts(calls)).toHaveLength(2)
    expect(posts(calls)[1][1]?.body).toBe(posts(calls)[0][1]?.body)
    expect(new Headers(posts(calls)[1][1]?.headers).get('Idempotency-Key')).toBe(new Headers(posts(calls)[0][1]?.headers).get('Idempotency-Key'))
    expect(document.body.textContent).not.toContain('SECRET_BODY_CANARY')
  })
  it('preserves an uncertain receipt across failed permission reads during manual recovery', async () => {
    let permissionReads = 0, attempts = 0
    const calls = network((url, options) => {
      if (url.pathname.endsWith('/auth/permissions') && ++permissionReads === 3) return fail('MI_SERVICE_UNAVAILABLE', 503)
      if (options.method === 'POST') {
        if (attempts++ === 0) return fail('MI_SERVICE_UNAVAILABLE', 503)
        return ok({ ...record(), explanation: 'Frozen note' }, 201)
      }
      return undefined
    })
    render(<ReviewPanel {...context} />); await open(); fill('Frozen note'); await submit()
    fireEvent.click(screen.getByRole('checkbox', { name: /我确认只恢复原提交/ })); await click('手动恢复同一次复核')
    expect(posts(calls)).toHaveLength(1)
    expect(screen.queryByRole('form', { name: '追加人工复核' })).toBeNull()
    expect(screen.getByRole('button', { name: '手动恢复同一次复核' })).toBeTruthy()
    fireEvent.click(screen.getByRole('checkbox', { name: /我确认只恢复原提交/ })); await click('手动恢复同一次复核')
    await open()
    expect(posts(calls)).toHaveLength(2)
    expect(posts(calls)[1][1]?.body).toBe(posts(calls)[0][1]?.body)
    expect(new Headers(posts(calls)[1][1]?.headers).get('Idempotency-Key')).toBe(new Headers(posts(calls)[0][1]?.headers).get('Idempotency-Key'))
  })
  it('does not confuse an older recovered receipt with the latest previous_review_id', async () => {
    let attempts = 0, reads = 0
    const old = record('9007199254741000'), receiptID = '9007199254741010', latestID = '9007199254741020'
    const calls = network((url, options) => {
      if (options.method === 'GET' && url.pathname.endsWith('/reviews')) return ok({ items: [reads++ === 0 ? old : { ...record(latestID), explanation: 'Newer independent reviewer note' }], next_cursor: null })
      if (options.method === 'POST') {
        if (attempts++ === 0) return fail('MI_SERVICE_UNAVAILABLE', 503)
        const body = JSON.parse(options.body as string) as { conclusion: Review['conclusion']; explanation: string }
        return ok({ ...record(receiptID), conclusion: body.conclusion, explanation: body.explanation }, 201)
      }
      return undefined
    })
    render(<ReviewPanel {...context} />); await open(); fill('Frozen note'); await submit()
    fireEvent.click(screen.getByRole('checkbox', { name: /我确认只恢复原提交/ })); await click('手动恢复同一次复核')
    await open(); expect(screen.getByText(/本次提交收据：复核 9007199254741010/)).toBeTruthy()
    expect(screen.getByText(/基于最新已读复核：9007199254741020/)).toBeTruthy()
    fill('Follow-up note'); await submit()
    expect(JSON.parse(posts(calls)[2][1]!.body as string).previous_review_id).toBe(latestID)
    expect(new Headers(posts(calls)[2][1]?.headers).get('Idempotency-Key')).not.toBe(new Headers(posts(calls)[0][1]?.headers).get('Idempotency-Key'))
  })
  it('requires explicit reload after a latest conflict and never automatically overwrites or retries', async () => {
    let reads = 0
    const calls = network((url, options) => options.method === 'POST' ? fail('MI_REVIEW_CONFLICT', 409) : url.pathname.endsWith('/reviews') ? ok({ items: [record(reads++ === 0 ? '9007199254741000' : '9007199254741020')], next_cursor: null }) : undefined)
    render(<ReviewPanel {...context} />); await open(); fill(); await submit()
    expect(screen.getByText(/最新复核已变化或提交标识发生冲突/)).toBeTruthy()
    expect(screen.queryByRole('form', { name: '追加人工复核' })).toBeNull()
    expect(posts(calls)).toHaveLength(1); expect(reads).toBe(1)
    await click('重新读取最新复核'); await open()
    expect(screen.getByText(/基于最新已读复核：9007199254741020/)).toBeTruthy()
    expect(posts(calls)).toHaveLength(1)
  })
  it('clears the form/history on revoked permission before POST and never uses role names to authorize', async () => {
    let permissionReads = 0
    const onDenied = vi.fn<(failure: unknown) => void>()
    const calls = network((url) => url.pathname.endsWith('/auth/permissions') ? ok({ organization_id: org, user_id: userID, permissions: permissionReads++ === 0 ? ['run.read', 'review.write'] : ['run.read'] }) : url.pathname.endsWith('/reviews') ? ok({ items: [record()], next_cursor: null }) : undefined)
    render(<ReviewPanel {...context} onDenied={onDenied} />); await open(); fill('PRIVATE_FORM_CANARY'); await submit()
    expect(posts(calls)).toHaveLength(0); expect(onDenied).toHaveBeenCalledTimes(1)
    expect(screen.queryByLabelText('复核说明')).toBeNull(); expect(screen.queryByText('Earlier human observation')).toBeNull()
    expect(document.body.textContent).not.toContain('PRIVATE_FORM_CANARY')
  })
  it('clears pending identities and history on POST 403 rather than offering recovery', async () => {
    const onDenied = vi.fn<(failure: unknown) => void>()
    const calls = network((_url, options) => options.method === 'POST' ? fail('MI_PERMISSION_DENIED', 403) : undefined)
    render(<ReviewPanel {...context} onDenied={onDenied} />); await open(); fill(); await submit()
    expect(onDenied).toHaveBeenCalledTimes(1); expect(posts(calls)).toHaveLength(1)
    expect(screen.queryByRole('button', { name: '手动恢复同一次复核' })).toBeNull()
    expect(screen.queryByLabelText('复核说明')).toBeNull()
  })
  it.each(['organization', 'user', 'run', 'revision'] as const)('aborts and forgets pending data when the %s scope changes', async (kind) => {
    let release: ((response: Response) => void) | undefined
    const calls = network((_url, options) => options.method === 'POST' ? new Promise<Response>((resolve) => { release = resolve }) : undefined)
    const view = render(<ReviewPanel {...context} />); await open(); fill('PRIVATE_FORM_CANARY'); await submit()
    expect(release).toBeTypeOf('function')
    const changed = { ...context, ...(kind === 'organization' ? { organizationID: '9007199254740994' } : kind === 'user' ? { userID: '9007199254740998' } : kind === 'run' ? { runID: '9007199254740996' } : { analysisRevision: 2 }) }
    view.rerender(<ReviewPanel {...changed} />)
    await act(async () => release!(ok({ ...record('9007199254741010'), explanation: 'PRIVATE_FORM_CANARY' }, 201)))
    expect(posts(calls)[0][1]?.signal?.aborted).toBe(true)
    expect(screen.queryByRole('button', { name: '手动恢复同一次复核' })).toBeNull()
    expect(document.body.textContent).not.toContain('PRIVATE_FORM_CANARY')
    expect(screen.queryByText(/本次提交收据/)).toBeNull()
  })
  it('stops reads on unmount and ignores late history without any browser persistence', async () => {
    let release: ((response: Response) => void) | undefined
    const calls = network((url) => url.pathname.endsWith('/reviews') ? new Promise<Response>((resolve) => { release = resolve }) : undefined)
    const view = render(<ReviewPanel {...context} />)
    await waitFor(() => expect(release).toBeTypeOf('function')); view.unmount()
    await act(async () => release!(ok({ items: [record()], next_cursor: null })))
    expect(calls.mock.calls.find(([url]) => String(url).includes('/reviews'))?.[1]?.signal?.aborted).toBe(true)
    expect(screen.queryByText('Earlier human observation')).toBeNull()
    expect(localStorage.length + sessionStorage.length).toBe(0)
  })
  it('keeps a timed-out POST as unknown and does not log or replay it', async () => {
    const log = vi.spyOn(console, 'error'), warning = vi.spyOn(console, 'warn')
    const calls = network((_url, options) => options.method === 'POST' ? new Promise<Response>(() => {}) : undefined)
    render(<ReviewPanel {...context} />); await open(); vi.useFakeTimers(); fill(); await submit()
    await act(async () => { await vi.advanceTimersByTimeAsync(45001) })
    expect(screen.getByRole('button', { name: '手动恢复同一次复核' })).toBeTruthy()
    expect(posts(calls)).toHaveLength(1)
    expect(log).not.toHaveBeenCalled(); expect(warning).not.toHaveBeenCalled()
  })
  it('routes authentication failures through the session gate without retaining reviewer text', async () => {
    const onSignedOut = vi.fn<(message: string) => void>(), onDenied = vi.fn<(failure: unknown) => void>()
    network((url) => url.pathname.endsWith('/reviews') ? fail('MI_SESSION_REQUIRED', 401) : undefined)
    render(<ReviewPanel {...context} onSignedOut={onSignedOut} onDenied={onDenied} />)
    await waitFor(() => expect(onSignedOut).toHaveBeenCalledTimes(1))
    expect(onDenied).toHaveBeenCalledTimes(1)
    expect(document.body.textContent).not.toContain('SECRET_BODY_CANARY')
  })
})
