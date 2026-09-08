import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { StrictMode } from 'react'
import { describe, expect, it, vi } from 'vitest'
import type { Session } from '../api'
import { SessionSecurity } from './SessionSecurity'

const session: Session = { user: { id: '9007199254740993', username: 'member', status: 'active', must_change_password: false }, organizations: [], csrf_token: 'synthetic-csrf', expires_at: new Date(Date.now() + 3600000).toISOString() }
const success = () => Response.json({ data: { ok: true }, request_id: 'logout-all-test' })
const failure = (code: string, status: number) => Response.json({ error: { code, message: 'SECRET_BODY_CANARY' }, request_id: 'logout-all-error' }, { status })
function network(response: () => Response | Promise<Response> = success) {
  const fetcher = vi.fn<typeof fetch>(async () => response())
  vi.stubGlobal('fetch', fetcher)
  return fetcher
}
function open() { fireEvent.click(screen.getByRole('button', { name: '退出所有会话' })) }
function confirm() { fireEvent.click(screen.getByRole('checkbox', { name: /我确认退出所有会话/ })) }
async function submit() { await act(async () => { fireEvent.click(screen.getByRole('button', { name: '确认退出所有会话' })) }) }

describe('global self-service session revocation', () => {
  it('requires explicit confirmation, can cancel without a write, and restores keyboard focus', async () => {
    const calls = network(), signedOut = vi.fn<(notice: string) => void>()
    render(<SessionSecurity session={session} onSignedOut={signedOut} />)
    expect(calls).not.toHaveBeenCalled()
    expect(screen.getByText(/不修改密码，也不影响其他账号/)).toBeTruthy()
    open()
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: '确认退出此账号的所有会话？' }))
    await submit()
    expect(calls).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: '暂不退出' }))
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole('button', { name: '退出所有会话' })))
    open()
    expect((screen.getByRole('checkbox') as HTMLInputElement).checked).toBe(false)
    expect(signedOut).not.toHaveBeenCalled()
  })
  it('posts only once despite repeated confirmation clicks and reports success only after acknowledgment', async () => {
    let resolve!: (value: Response) => void
    const calls = network(() => new Promise<Response>((done) => { resolve = done })), signedOut = vi.fn<(notice: string) => void>()
    render(<SessionSecurity session={session} onSignedOut={signedOut} />)
    open(); confirm()
    const button = screen.getByRole('button', { name: '确认退出所有会话' })
    await act(async () => { fireEvent.click(button); fireEvent.click(button) })
    expect(calls).toHaveBeenCalledTimes(1)
    expect(signedOut).not.toHaveBeenCalled()
    expect((screen.getByRole('button', { name: '暂不退出' }) as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getByText(/离开页面只会停止本页等待/)).toBeTruthy()
    await act(async () => resolve(success()))
    expect(signedOut).toHaveBeenCalledTimes(1)
    expect(signedOut).toHaveBeenCalledWith('已退出此账号的所有会话（包括当前会话）。密码未修改，请重新登录。')
    expect(calls.mock.calls[0]).toEqual(['/api/v1/auth/logout-all', expect.objectContaining({ method: 'POST', body: '{}', credentials: 'same-origin' })])
    expect(new Headers(calls.mock.calls[0][1]?.headers).get('X-CSRF-Token')).toBe(session.csrf_token)
  })
  it.each(['unavailable', 'network', 'invalid-ack', 'invalid-request'] as const)('keeps %s outcomes unknown without retry, raw errors or a success claim', async (kind) => {
    const calls = network(() => {
      if (kind === 'network') throw new TypeError('SECRET_BODY_CANARY')
      if (kind === 'invalid-ack') return Response.json({ data: { ok: false }, request_id: 'logout-all' })
      return failure(kind === 'invalid-request' ? 'MI_INVALID_REQUEST' : 'MI_SERVICE_UNAVAILABLE', kind === 'invalid-request' ? 400 : 503)
    }), signedOut = vi.fn<(notice: string) => void>(), storage = vi.spyOn(Storage.prototype, 'setItem')
    render(<SessionSecurity session={session} onSignedOut={signedOut} />)
    open(); confirm(); await submit()
    const notice = await screen.findByRole('alert')
    expect(notice.textContent).toContain('请求可能已经生效，也可能未生效')
    expect(notice).toBe(document.activeElement)
    expect(signedOut).not.toHaveBeenCalled()
    expect(screen.queryByRole('button', { name: '退出所有会话' })).toBeNull()
    expect(document.body.textContent).not.toContain('SECRET_BODY_CANARY')
    expect(calls).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: '返回登录（结果未确认）' }))
    expect(signedOut).toHaveBeenCalledWith(expect.stringContaining('结果未确认'))
    expect(calls).toHaveBeenCalledTimes(1)
    expect(storage).not.toHaveBeenCalled()
  })
  it.each([['MI_SESSION_REQUIRED', 401], ['MI_CSRF_INVALID', 403], ['MI_PERMISSION_DENIED', 403]] as const)('drops session UI on %s without pretending all devices were revoked', async (code, status) => {
    const calls = network(() => failure(code, status)), signedOut = vi.fn<(notice: string) => void>()
    render(<SessionSecurity session={session} onSignedOut={signedOut} />)
    open(); confirm(); await submit()
    expect(signedOut).toHaveBeenCalledTimes(1)
    expect(signedOut).toHaveBeenCalledWith(expect.stringContaining('结果未确认'))
    expect(signedOut.mock.calls[0][0]).not.toContain('已退出此账号的所有会话')
    expect(calls).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('checkbox')).toBeNull()
  })
  it.each(['unmount', 'user', 'csrf'] as const)('aborts pending work and ignores late results after %s changes', async (kind) => {
    let resolve!: (value: Response) => void
    const calls = network(() => new Promise<Response>((done) => { resolve = done })), signedOut = vi.fn<(notice: string) => void>()
    const view = render(<SessionSecurity session={session} onSignedOut={signedOut} />)
    open(); confirm(); await submit()
    if (kind === 'unmount') view.unmount()
    else view.rerender(<SessionSecurity session={{ ...session, ...(kind === 'user' ? { user: { ...session.user, id: '9007199254740994' } } : { csrf_token: 'new-synthetic-csrf' }) }} onSignedOut={signedOut} />)
    expect(calls.mock.calls[0][1]?.signal?.aborted).toBe(true)
    await act(async () => resolve(success()))
    expect(signedOut).not.toHaveBeenCalled()
    expect(calls).toHaveBeenCalledTimes(1)
    expect(screen.queryAllByRole('button', { name: '退出所有会话' })).toHaveLength(kind === 'unmount' ? 0 : 1)
  })
  it('treats timeout as unknown even if fetch ignores cancellation, without retrying or logging', async () => {
    const calls = network(() => new Promise<Response>(() => {})), signedOut = vi.fn<(notice: string) => void>()
    const logs = [vi.spyOn(console, 'error'), vi.spyOn(console, 'warn')]
    render(<SessionSecurity session={session} onSignedOut={signedOut} />)
    vi.useFakeTimers(); open(); confirm(); await submit()
    await act(async () => { await vi.advanceTimersByTimeAsync(45001) })
    expect(screen.getByRole('alert').textContent).toContain('结果未确认')
    expect(signedOut).not.toHaveBeenCalled()
    expect(calls).toHaveBeenCalledTimes(1)
    expect(calls.mock.calls[0][1]?.signal?.aborted).toBe(true)
    expect(logs.every((log) => log.mock.calls.length === 0)).toBe(true)
  })
  it('does not issue a mutation on mount or StrictMode re-render and honors the parent gate', () => {
    const calls = network(), signedOut = vi.fn<(notice: string) => void>()
    const view = render(<StrictMode><SessionSecurity session={session} onSignedOut={signedOut} disabled /></StrictMode>)
    open(); expect(screen.queryByRole('checkbox')).toBeNull()
    view.rerender(<StrictMode><SessionSecurity session={session} onSignedOut={signedOut} /></StrictMode>)
    open(); confirm()
    view.rerender(<StrictMode><SessionSecurity session={session} onSignedOut={signedOut} disabled /></StrictMode>)
    fireEvent.click(screen.getByRole('button', { name: '确认退出所有会话' }))
    expect(calls).not.toHaveBeenCalled()
  })
})
