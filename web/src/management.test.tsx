import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { App } from './App'
import { api, type Session } from './api'
import { managedOrganization, managedUser, managementApi, member, type ManagedOrganization, type ManagedUser, type Member } from './management-api'

const orgID = '9007199254740995'
const orgTwo = '9007199254740997'
const userID = '9007199254741001'
const memberID = '9007199254741003'
const csrf = 'synthetic-management-csrf'
const adminID = '9007199254740993'
const userRecord: ManagedUser = { id: userID, username: 'reader', display_name: '', status: 'active', system_admin: false, must_change_password: true, version: 7 }
const organizationRecord: ManagedOrganization = { id: orgID, name: 'Alpha', timezone: 'UTC', status: 'active', full_response_retention_days: 30, version: 4 }
const memberRecord: Member = { id: memberID, user_id: userID, org_id: orgID, username: 'reader', status: 'active', roles: ['viewer'], permissions: ['member.read'], version: 9 }
const roles = [{ name: 'viewer', permissions: ['organization.read', 'target.read'] }, { name: 'admin', permissions: ['organization.read', 'member.read', 'member.write', 'target.read'] }]
const session: Session = { user: { id: adminID, username: 'admin', status: 'active', system_admin: true, must_change_password: false, display_name: '', version: 1 }, organizations: [organizationRecord, { ...organizationRecord, id: orgTwo, name: 'Beta' }], csrf_token: csrf, expires_at: new Date(Date.now() + 3600_000).toISOString() }
function ok(data: unknown, status = 200) { return Response.json({ data, request_id: 'management-request' }, { status }) }
function fail(code: string, status = 409) { return Response.json({ error: { code, message: 'sensitive-server-password-content' }, request_id: 'management-error' }, { status }) }
function page(items: unknown[], cursor: string | null = null) { return ok({ items, next_cursor: cursor }) }
type Handler = (path: string, options: RequestInit, url: URL) => Response | Promise<Response> | undefined
function network(handler?: Handler) {
  let users = [structuredClone(userRecord)]
  let organizations = [structuredClone(organizationRecord), { ...organizationRecord, id: orgTwo, name: 'Beta' }]
  let members = [structuredClone(memberRecord)]
  const calls = vi.fn<typeof fetch>(async (input, options = {}) => {
    const url = new URL(String(input), 'http://localhost')
    const path = url.pathname
    const override = handler?.(path, options, url)
    if (override) return override
    if (path.endsWith('/setup/status')) return ok({ initialized: true })
    if (path.endsWith('/auth/me')) return ok(session)
    if (path.endsWith('/auth/logout')) return ok({ ok: true })
    if (path.endsWith('/roles')) return page(roles)
    if (path === '/api/v1/users') {
      if (options.method === 'POST') {
        const body = JSON.parse(options.body as string)
        const created = { ...userRecord, id: '9007199254741009', username: body.username, display_name: body.display_name, version: 1 }
        users.push(created)
        return ok(created, 201)
      }
      return page(users)
    }
    if (path.startsWith(`/api/v1/users/${userID}`)) {
      const body = JSON.parse(options.body as string)
      const current = users.find((item) => item.id === userID)!
      const updated = { ...current, ...(options.method === 'PATCH' ? body : {}), version: current.version + 1 }
      users = users.map((item) => item.id === userID ? updated : item)
      return ok(updated)
    }
    if (path === '/api/v1/organizations') {
      if (options.method === 'POST') {
        const body = JSON.parse(options.body as string)
        const created = { ...organizationRecord, ...body, id: '9007199254741011', version: 1 }
        organizations.push(created)
        return ok(created, 201)
      }
      return page(organizations)
    }
    const matchOrg = path.match(/^\/api\/v1\/organizations\/([0-9]+)$/)
    if (matchOrg) {
      const current = organizations.find((item) => item.id === matchOrg[1])!
      if (options.method === 'PATCH') {
        const updated = { ...current, ...JSON.parse(options.body as string), version: current.version + 1 }
        organizations = organizations.map((item) => item.id === current.id ? updated : item)
        return ok(updated)
      }
      return ok(current)
    }
    if (path.endsWith('/members')) {
      if (options.method === 'POST') {
        const created = { ...memberRecord, ...JSON.parse(options.body as string), id: '9007199254741013', username: 'added-member', version: 1 }
        members.push(created)
        return ok(created, 201)
      }
      return page(path.includes(orgTwo) ? [] : members)
    }
    if (path.endsWith(`/members/${memberID}`) && options.method === 'PATCH') {
      const updated = { ...memberRecord, ...JSON.parse(options.body as string), version: memberRecord.version + 1 }
      members = [updated]
      return ok(updated)
    }
    throw new Error('Unexpected management test route')
  })
  vi.stubGlobal('fetch', calls)
  return calls
}
function renderRoute(route: string) { window.history.replaceState(null, '', `/#/${route}`); return render(<App />) }
function writes(calls: ReturnType<typeof network>, method: string) { return calls.mock.calls.filter(([, options]) => options?.method === method) }
function setField(label: string, value: string) { fireEvent.change(screen.getByLabelText(label), { target: { value } }) }
function setPasswords(password = 'synthetic-password-only') { setField('临时密码', password); setField('确认临时密码', password) }

describe('user management real request interactions', () => {
  it('creates ordinary users with a temporary password, same-origin CSRF, and no browser persistence', async () => {
    const calls = network()
    const storage = vi.spyOn(Storage.prototype, 'setItem')
    renderRoute('users')
    await screen.findByText('reader')
    await userEvent.setup().click(screen.getByRole('button', { name: '创建用户' }))
    setField('新用户名', 'new-reader'); setField('显示名称（可选）', 'New reader'); setPasswords()
    const passwordField = screen.getByLabelText('临时密码') as HTMLInputElement
    fireEvent.submit(screen.getByRole('form', { name: '创建用户账号' }))
    await screen.findByText('new-reader')
    const request = writes(calls, 'POST')[0][1]!
    expect(JSON.parse(request.body as string)).toEqual({ username: 'new-reader', display_name: 'New reader', password: 'synthetic-password-only' })
    expect(request.credentials).toBe('same-origin')
    expect(new Headers(request.headers).get('X-CSRF-Token')).toBe(csrf)
    expect(new Headers(request.headers).get('X-Organization-ID')).toBeNull()
    expect(passwordField.value).toBe('')
    expect(storage).not.toHaveBeenCalled()
    expect(document.body.textContent).not.toContain('synthetic-password-only')
  })
  it('clears both password inputs after local mismatch without creating a user', async () => {
    const calls = network(); renderRoute('users')
    await screen.findByText('reader'); await userEvent.setup().click(screen.getByRole('button', { name: '创建用户' }))
    setField('新用户名', 'new-reader'); setPasswords(); setField('确认临时密码', 'different-password')
    fireEvent.submit(screen.getByRole('form', { name: '创建用户账号' }))
    await screen.findByText('两次临时密码输入不一致。')
    expect((screen.getByLabelText('临时密码') as HTMLInputElement).value).toBe('')
    expect((screen.getByLabelText('确认临时密码') as HTMLInputElement).value).toBe('')
    expect(writes(calls, 'POST')).toHaveLength(0)
  })
  it('updates only display name and status with the read integer version', async () => {
    const calls = network(); renderRoute('users')
    await screen.findByText('reader'); await userEvent.setup().click(screen.getByRole('button', { name: '编辑用户 reader' }))
    setField('显示名称（可选）', 'Renamed reader')
    await userEvent.setup().selectOptions(screen.getByLabelText('状态'), 'disabled')
    fireEvent.submit(screen.getByRole('form', { name: '编辑用户账号' }))
    await screen.findByText('用户已更新。')
    expect(JSON.parse(writes(calls, 'PATCH')[0][1]!.body as string)).toEqual({ version: 7, display_name: 'Renamed reader', status: 'disabled' })
  })
  it('requires explicit confirmation for unlock and does not claim a lock state', async () => {
    const calls = network(); renderRoute('users')
    await screen.findByText('reader'); await userEvent.setup().click(screen.getByRole('button', { name: '清除登录锁定 reader' }))
    expect(writes(calls, 'POST')).toHaveLength(0)
    fireEvent.submit(screen.getByRole('form', { name: '清除用户登录锁定' }))
    await screen.findByText('已提交清除登录锁定与失败计数。')
    const request = writes(calls, 'POST')[0]
    expect(String(request[0])).toBe(`/api/v1/users/${userID}/unlock`)
    expect(JSON.parse(request[1]!.body as string)).toEqual({ version: 7 })
  })
  it('resets temporary passwords with version and clears secrets on denied writes without raw errors', async () => {
    const calls = network((path) => path.endsWith('/reset-password') ? fail('MI_PERMISSION_DENIED', 403) : undefined)
    renderRoute('users'); await screen.findByText('reader')
    await userEvent.setup().click(screen.getByRole('button', { name: '重置临时密码 reader' })); setPasswords()
    fireEvent.submit(screen.getByRole('form', { name: '重置用户临时密码' }))
    await screen.findByText('没有执行此操作的权限，请联系管理员。')
    expect((screen.getByLabelText('临时密码') as HTMLInputElement).value).toBe('')
    expect(document.body.textContent).not.toContain('sensitive-server-password-content')
    expect(JSON.parse(writes(calls, 'POST')[0][1]!.body as string)).toEqual({ version: 7, password: 'synthetic-password-only' })
  })
  it('shows last-administrator errors and refreshes only after an explicit choice, without automatic write retries', async () => {
    const calls = network((path, options) => path.includes('/users/') && options.method === 'PATCH' ? fail('MI_LAST_ADMINISTRATOR') : undefined)
    renderRoute('users'); await screen.findByText('reader')
    await userEvent.setup().click(screen.getByRole('button', { name: '编辑用户 reader' }))
    fireEvent.submit(screen.getByRole('form', { name: '编辑用户账号' }))
    await screen.findByText('此操作会移除最后一位可用管理员，请先安排其他管理员。')
    expect(writes(calls, 'PATCH')).toHaveLength(1)
    await userEvent.setup().click(screen.getByRole('button', { name: '返回并刷新列表' }))
    await screen.findByText('reader')
    expect(writes(calls, 'PATCH')).toHaveLength(1)
  })
  it('does not request global users for an ordinary organization administrator, even on a direct hash route', async () => {
    const calls = network((path) => path.endsWith('/auth/me') ? ok({ ...session, user: { ...session.user, system_admin: false } }) : undefined)
    renderRoute('users')
    await screen.findByText('用户管理仅对系统管理员开放。组织管理员可在成员管理中使用已有用户 ID 添加成员。')
    expect(screen.queryByRole('link', { name: /用户管理/ })).toBeNull()
    expect(calls.mock.calls.some(([url]) => String(url).includes('/users'))).toBe(false)
  })
  it('disables self password-reset and self-disable controls', async () => {
    network((path) => path === '/api/v1/users' ? page([{ ...userRecord, id: adminID }]) : undefined)
    renderRoute('users'); await screen.findByText('reader')
    expect((screen.getByRole('button', { name: '重置临时密码 reader' }) as HTMLButtonElement).disabled).toBe(true)
    await userEvent.setup().click(screen.getByRole('button', { name: '编辑用户 reader' }))
    expect((screen.getByRole('option', { name: '停用' }) as HTMLOptionElement).disabled).toBe(true)
  })
  it('sends server-side query and opaque cursors without filtering a single local page', async () => {
    const calls = network((path, _, url) => {
      if (path !== '/api/v1/users') return undefined
      if (url.searchParams.get('cursor')) return page([{ ...userRecord, username: 'reader-page-two' }])
      return page([userRecord], 'opaque-cursor')
    })
    renderRoute('users'); await screen.findByText('reader')
    setField('服务端搜索用户', 'reader & colleague')
    fireEvent.submit(screen.getByRole('form', { name: '搜索用户' }))
    await waitFor(() => expect(calls.mock.calls.some(([url]) => String(url).includes('q=reader+%26+colleague'))).toBe(true))
    await waitFor(() => expect((screen.getByRole('button', { name: '下一页' }) as HTMLButtonElement).disabled).toBe(false))
    await userEvent.setup().click(screen.getByRole('button', { name: '下一页' }))
    await screen.findByText('reader-page-two')
    expect(calls.mock.calls.some(([url]) => String(url) === '/api/v1/users?limit=25&cursor=opaque-cursor&q=reader+%26+colleague')).toBe(true)
    expect(screen.getByText('第 2 页')).toBeTruthy()
  })
})

describe('organization and member management real request interactions', () => {
  it('creates an organization and makes the returned string ID selectable without silently switching', async () => {
    const calls = network(); renderRoute('organization-management')
    await screen.findByRole('button', { name: '编辑组织 Alpha' })
    await userEvent.setup().click(screen.getByRole('button', { name: '创建组织' }))
    setField('组织名称', 'Gamma'); setField('组织时区', 'Asia/Shanghai')
    fireEvent.submit(screen.getByRole('form', { name: '创建新组织' }))
    await screen.findByRole('option', { name: 'Gamma' })
    expect(JSON.parse(writes(calls, 'POST')[0][1]!.body as string)).toEqual({ name: 'Gamma', timezone: 'Asia/Shanghai' })
    expect((screen.getByLabelText('当前组织') as HTMLSelectElement).value).toBe(orgID)
  })
  it('reads a fresh organization before edit and binds path plus X-Organization-ID to that row, not the selected workspace', async () => {
    const calls = network((path, options) => path === `/api/v1/organizations/${orgTwo}` && options.method === 'GET' ? ok({ ...organizationRecord, id: orgTwo, name: 'Beta', version: 12 }) : undefined)
    renderRoute('organization-management'); await screen.findByRole('button', { name: '编辑组织 Beta' })
    await userEvent.setup().click(screen.getByRole('button', { name: '编辑组织 Beta' }))
    await screen.findByRole('form', { name: '编辑组织设置' }); setField('完整响应留存天数', '0')
    fireEvent.submit(screen.getByRole('form', { name: '编辑组织设置' }))
    await screen.findByText('组织已更新。已停用的组织不能被选作当前工作空间。')
    const call = writes(calls, 'PATCH')[0]
    expect(String(call[0])).toBe(`/api/v1/organizations/${orgTwo}`)
    expect(new Headers(call[1]!.headers).get('X-Organization-ID')).toBe(orgTwo)
    expect(JSON.parse(call[1]!.body as string)).toEqual({ version: 12, name: 'Beta', timezone: 'UTC', full_response_retention_days: 0, status: 'active' })
    expect((screen.getByLabelText('当前组织') as HTMLSelectElement).value).toBe(orgID)
  })
  it('rejects invalid retention locally and clears selection after disabling the active organization', async () => {
    const calls = network(); renderRoute('organization-management')
    await screen.findByRole('button', { name: '编辑组织 Alpha' }); await userEvent.setup().click(screen.getByRole('button', { name: '编辑组织 Alpha' }))
    await screen.findByRole('form', { name: '编辑组织设置' }); setField('完整响应留存天数', '181')
    fireEvent.submit(screen.getByRole('form', { name: '编辑组织设置' })); await screen.findByText('完整响应留存天数必须是 0–180 的整数。')
    expect(writes(calls, 'PATCH')).toHaveLength(0)
    setField('完整响应留存天数', '30'); await userEvent.setup().selectOptions(screen.getByLabelText('状态'), 'disabled')
    fireEvent.submit(screen.getByRole('form', { name: '编辑组织设置' }))
    await screen.findByRole('option', { name: 'Alpha（已停用）' })
    expect((screen.getByLabelText('当前组织') as HTMLSelectElement).value).toBe('')
  })
  it('adds a real user ID using complete role pages and explicit extra grants, with no global user listing', async () => {
    const calls = network((path, _, url) => path.endsWith('/roles') ? page(url.searchParams.get('cursor') ? [roles[1]] : [roles[0]], url.searchParams.get('cursor') ? null : 'roles-next') : undefined)
    renderRoute('members'); await screen.findByText('reader')
    await userEvent.setup().click(screen.getByRole('button', { name: '添加成员' }))
    await screen.findByRole('form', { name: '添加组织成员' })
    setField('已有用户 ID', '9007199254741015')
    await userEvent.setup().click(screen.getByRole('checkbox', { name: /^viewer/ }))
    await userEvent.setup().click(screen.getByRole('checkbox', { name: 'member.read' }))
    fireEvent.submit(screen.getByRole('form', { name: '添加组织成员' }))
    await screen.findByText('added-member')
    const call = writes(calls, 'POST')[0]
    expect(String(call[0])).toBe(`/api/v1/organizations/${orgID}/members`)
    expect(JSON.parse(call[1]!.body as string)).toEqual({ user_id: '9007199254741015', roles: ['viewer'], permissions: ['member.read'] })
    expect(new Headers(call[1]!.headers).get('X-Organization-ID')).toBe(orgID)
    expect(new Headers(call[1]!.headers).get('X-CSRF-Token')).toBe(csrf)
    expect(calls.mock.calls.some(([url]) => String(url).includes('cursor=roles-next'))).toBe(true)
    expect(calls.mock.calls.some(([url]) => String(url).includes('/users'))).toBe(false)
  })
  it('edits member roles and sends an explicit empty extra-grant array plus integer version', async () => {
    const calls = network(); renderRoute('members'); await screen.findByText('reader')
    await userEvent.setup().click(screen.getByRole('button', { name: '编辑成员 reader' })); await screen.findByRole('form', { name: '编辑组织成员资格' })
    await userEvent.setup().click(screen.getByRole('checkbox', { name: 'member.read' }))
    await userEvent.setup().selectOptions(screen.getByLabelText('状态'), 'disabled')
    fireEvent.submit(screen.getByRole('form', { name: '编辑组织成员资格' }))
    await screen.findByText('成员资格已更新，权限变更由服务端即时校验。')
    const call = writes(calls, 'PATCH')[0]
    expect(String(call[0])).toBe(`/api/v1/organizations/${orgID}/members/${memberID}`)
    expect(JSON.parse(call[1]!.body as string)).toEqual({ version: 9, roles: ['viewer'], permissions: [], status: 'disabled' })
    expect(writes(calls, 'DELETE')).toHaveLength(0)
  })
  it('blocks granting without a real role directory and exposes a retry, not fake roles', async () => {
    const calls = network((path) => path.endsWith('/roles') ? fail('MI_PERMISSION_DENIED', 403) : undefined)
    renderRoute('members'); await screen.findByText('reader'); await userEvent.setup().click(screen.getByRole('button', { name: '添加成员' }))
    await screen.findByText('没有执行此操作的权限，请联系管理员。')
    expect(screen.queryByRole('checkbox')).toBeNull()
    expect(screen.getByRole('button', { name: '重试读取目录' })).toBeTruthy()
    expect(writes(calls, 'POST')).toHaveLength(0)
  })
  it('aborts old member work and clears forms when switching organization', async () => {
    let resolve: ((response: Response) => void) | undefined
    const calls = network((path) => path.endsWith('/roles') ? new Promise<Response>((done) => { resolve = done }) : undefined)
    renderRoute('members'); await screen.findByText('reader'); await userEvent.setup().click(screen.getByRole('button', { name: '添加成员' }))
    await screen.findByText('正在读取完整角色目录…')
    await userEvent.setup().selectOptions(screen.getByLabelText('当前组织'), orgTwo)
    await screen.findByRole('heading', { name: 'Beta · 组织成员' })
    await screen.findByText('没有符合条件的成员。')
    const old = calls.mock.calls.find(([url]) => String(url).includes('/roles'))!
    expect(old[1]!.signal?.aborted).toBe(true)
    await act(async () => { resolve?.(page(roles)) })
    expect(screen.queryByRole('form', { name: '添加组织成员' })).toBeNull()
    expect(screen.queryByText('reader')).toBeNull()
  })
  it('logs out on management CSRF failures and does not replay the write', async () => {
    const calls = network((path, options) => path.includes('/members/') && options.method === 'PATCH' ? fail('MI_CSRF_INVALID', 403) : undefined)
    renderRoute('members'); await screen.findByText('reader'); await userEvent.setup().click(screen.getByRole('button', { name: '编辑成员 reader' }))
    await screen.findByRole('form', { name: '编辑组织成员资格' }); fireEvent.submit(screen.getByRole('form', { name: '编辑组织成员资格' }))
    await screen.findByRole('heading', { name: '登录工作空间' })
    expect(writes(calls, 'PATCH')).toHaveLength(1)
  })
  it('shows truthful loading, empty and stale-error states while disabling stale row actions', async () => {
    let count = 0
    network((path) => path.endsWith('/members') ? (++count === 1 ? page([memberRecord]) : fail('MI_SERVICE_UNAVAILABLE', 503)) : undefined)
    renderRoute('members'); await screen.findByText('reader'); await userEvent.setup().click(screen.getByRole('button', { name: '刷新列表' }))
    await screen.findByText('服务暂不可用，请稍后重试。')
    expect(screen.getByText('reader')).toBeTruthy()
    expect((screen.getByRole('button', { name: '编辑成员 reader' }) as HTMLButtonElement).disabled).toBe(true)
    expect(screen.queryByText('没有符合条件的成员。')).toBeNull()
  })
  it('keeps checkboxes keyboard-operable and the form heading focused after role loading', async () => {
    network(); renderRoute('members'); await screen.findByText('reader'); await userEvent.setup().click(screen.getByRole('button', { name: '添加成员' }))
    await screen.findByRole('form', { name: '添加组织成员' })
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: '添加组织成员' }))
    const checkbox = within(screen.getByRole('group', { name: '成员角色' })).getByRole('checkbox', { name: /^viewer/ }) as HTMLInputElement
    checkbox.focus(); await userEvent.setup().keyboard(' ')
    expect(checkbox.checked).toBe(true)
  })
})

describe('management response boundaries', () => {
  it('requires boolean session flags, numeric versions, bounded retention and string IDs', () => {
    expect(managedUser(userRecord)).toBe(true)
    for (const patch of [{ id: Number(userID) }, { version: '7' }, { version: 0 }, { must_change_password: 'true' }, { system_admin: null }, { password_hash: 'secret' }, { created_at: {} }]) expect(managedUser({ ...userRecord, ...patch })).toBe(false)
    expect(managedOrganization(organizationRecord)).toBe(true)
    expect(managedOrganization({ ...organizationRecord, full_response_retention_days: 181 })).toBe(false)
    expect(member(memberRecord)).toBe(true)
    expect(member({ ...memberRecord, roles: ['viewer', 'viewer'] })).toBe(false)
  })
  it('rejects returned organization or member data from another scope', async () => {
    network((path) => path.endsWith('/members') ? page([{ ...memberRecord, org_id: orgTwo }]) : path === `/api/v1/organizations/${orgID}` ? ok({ ...organizationRecord, id: orgTwo }) : undefined)
    await expect(managementApi.members(orgID)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
    await expect(managementApi.organization(orgID)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('rejects successful user mutations that name a different user', async () => {
    network((path) => path.endsWith('/unlock') ? ok({ ...userRecord, id: adminID }) : undefined)
    await expect(managementApi.unlockUser(csrf, userID, 7)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
  it('refreshes the legacy organization selector using all pages, including signed cursors longer than 512 characters', async () => {
    const cursor = 'x'.repeat(700)
    const calls = network((path, _, url) => path === '/api/v1/organizations' ? page([url.searchParams.has('cursor') ? { ...organizationRecord, id: orgTwo } : organizationRecord], url.searchParams.has('cursor') ? null : cursor) : undefined)
    const result = await api.organizations()
    expect(result.items.map((item) => item.id)).toEqual([orgID, orgTwo])
    expect(result.next_cursor).toBeNull()
    expect(calls).toHaveBeenCalledTimes(2)
  })
  it('rejects cyclic organization pagination instead of hanging or presenting partial results', async () => {
    network((path) => path === '/api/v1/organizations' ? page([organizationRecord], 'cycle') : undefined)
    await expect(api.organizations()).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
})
