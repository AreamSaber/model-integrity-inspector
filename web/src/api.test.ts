import { describe, expect, it, vi } from 'vitest'
import { api, ApiError, errorMessage } from './api'

describe('API response validation', () => {
  const user = { id: '9007199254740993', username: 'admin', status: 'active', display_name: '', version: 2, system_admin: false, must_change_password: true }
  const session = { user, organizations: [], csrf_token: 'csrf-token', expires_at: new Date(Date.now() + 3600_000).toISOString() }
  it('preserves actual session flags, empty display names, numeric versions, and string IDs', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockImplementation(async () => Response.json({ data: session, request_id: 'req' }))
    vi.stubGlobal('fetch', fetchMock)
    expect(await api.login({ username: 'admin', password: 'synthetic-password' })).toEqual(session)
    expect(await api.me()).toEqual(session)
  })
  it.each([undefined, 'false', 0, null])('rejects an absent or non-boolean security flag %s', async (flag) => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValue(Response.json({ data: { ...session, user: { ...user, must_change_password: flag } }, request_id: 'req' })))
    await expect(api.me()).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it.each(['2', 0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1])('rejects invalid optimistic-lock versions %s', async (version) => {
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValue(Response.json({ data: { ...session, user: { ...user, version } }, request_id: 'req' })))
    await expect(api.me()).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it.each([
    { data: { initialized: 'false' }, request_id: 'request-id' },
    { data: { initialized: false } },
    { data: { initialized: false }, error: {}, request_id: 'request-id' },
  ])('rejects a malformed successful setup envelope %#', async (envelope) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json(envelope)))
    await expect(api.setupStatus()).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('rejects a numeric user ID rather than rounding it into another identity', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ data: { user: { id: 42, username: 'admin', status: 'active' }, organizations: [], csrf_token: 'token', expires_at: new Date().toISOString() }, request_id: 'req' })))
    await expect(api.me()).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('does not permit arbitrary organization header contents', async () => {
    const fetchMock = vi.fn<typeof fetch>()
    vi.stubGlobal('fetch', fetchMock)
    await expect(api.roles('1\r\nX-Evil: value')).rejects.toMatchObject({ code: 'MI_INVALID_REQUEST' })
    expect(fetchMock).not.toHaveBeenCalled()
  })
  it('never surfaces arbitrary server messages or unsafe request IDs', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ error: { code: 'UNTRUSTED<script>', message: 'credential-leak' }, request_id: 'credential-leak?secret' }, { status: 503 })))
    const error: unknown = await api.setupStatus().catch((failure: unknown) => failure)
    expect(error).toBeInstanceOf(ApiError)
    expect(String(error)).not.toContain('credential-leak')
    expect(errorMessage(error)).toBe('服务暂不可用，请稍后重试。')
    expect((error as ApiError).requestID).toBe('')
  })
  it('rejects HTML proxy responses', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('<html>private details</html>')))
    await expect(api.setupStatus()).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('uses no mutation retries when the response is lost', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockRejectedValue(new TypeError('failed'))
    vi.stubGlobal('fetch', fetchMock)
    await expect(api.initialize({ organization_name: 'Org', username: 'admin', password: 'synthetic-password' }, '')).rejects.toMatchObject({ code: 'MI_NETWORK_ERROR' })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})
