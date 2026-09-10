import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { App } from './App'
import type { Session } from './api'
import { target, targetsApi, type Target, type TargetInput } from './targets-api'

const org = '9007199254740995'
const secondOrg = '9007199254740997'
const providerID = '9007199254741001'
const profileID = '9007199254741003'
const csrf = 'synthetic-csrf'
const initial: Target = {
  id: '9007199254741005', name: 'Primary target', provider_id: providerID, model_profile_id: profileID,
  endpoint: 'https://upstream.example/v1', protocol: 'openai_chat', model: 'example-model', environment: 'staging', channel_id: 'channel-a', tags: ['baseline'],
  options: { max_output_parameter: 'auto', tls_verify: true, timeout_seconds: 180, concurrency: 1, rpm: 60 },
  secret: { id: '9007199254741007', version: 3, mask: '********test' }, status: 'active', version: 4,
}
const session: Session = { user: { id: '9007199254740993', username: 'admin', status: 'active', system_admin: true, must_change_password: false, display_name: '', version: 1 }, organizations: [{ id: org, name: 'Alpha', status: 'active' }, { id: secondOrg, name: 'Beta', status: 'active' }], csrf_token: csrf, expires_at: new Date(Date.now() + 3600_000).toISOString() }
function ok(data: unknown, status = 200) { return Response.json({ data, request_id: 'request-targets' }, { status }) }
function fail(code: string, status: number) { return Response.json({ error: { code, message: 'sensitive-upstream-details' }, request_id: 'request-error' }, { status }) }
type Handler = (path: string, options: RequestInit, url: URL) => Response | Promise<Response> | undefined
function network(handler?: Handler) {
  let record = structuredClone(initial)
  let records = [record]
  const fetchMock = vi.fn<typeof fetch>(async (input, options = {}) => {
    const url = new URL(String(input), 'http://localhost')
    const path = url.pathname
    const override = handler?.(path, options, url)
    if (override) return override
    if (path.endsWith('/setup/status')) return ok({ initialized: true })
    if (path.endsWith('/auth/me')) return ok(session)
    if (path.endsWith('/providers')) return ok({ items: [{ id: providerID, name: 'Example provider', status: 'active', version: 1 }], next_cursor: null })
    if (path.endsWith('/model-profiles')) return ok({ items: [{ id: profileID, provider_id: providerID, name: 'catalog-model', display_name: 'Catalog model', protocol: 'openai_chat', version: 1 }], next_cursor: null })
    if (path === '/api/v1/targets' && options.method === 'GET') return ok({ items: records, next_cursor: null })
    if (path === '/api/v1/targets' && options.method === 'POST') {
      const { auth: _auth, ...body } = JSON.parse(options.body as string) as TargetInput & { auth: unknown }
      record = { ...body, id: initial.id, status: 'active', version: 1, secret: { ...initial.secret, version: 1 } }
      records = [record]
      return ok(record, 201)
    }
    if (path.endsWith('/rotate-secret')) { record = { ...record, version: record.version + 1, secret: { ...record.secret, version: record.secret.version + 1 } }; records = [record]; return ok(record) }
    if (path === `/api/v1/targets/${initial.id}`) {
      if (options.method === 'DELETE') { records = []; return ok({ ok: true }) }
      if (options.method === 'PATCH') { record = { ...record, ...JSON.parse(options.body as string), version: record.version + 1 }; records = [record] }
      return ok(record)
    }
    throw new Error('Unexpected test API route')
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}
function renderTargets() {
  window.history.replaceState(null, '', '/#/targets')
  return render(<App />)
}
async function createForm() {
  await screen.findByRole('heading', { name: '组织检测目标' })
  await userEvent.setup().click(screen.getByRole('button', { name: '新建目标' }))
  await screen.findByRole('option', { name: 'Example provider' })
  fireEvent.change(screen.getByLabelText('目标名称'), { target: { value: 'New target' } })
  fireEvent.change(screen.getByLabelText('Endpoint'), { target: { value: 'https://upstream.example/v1' } })
  fireEvent.change(screen.getByLabelText('上游模型名称'), { target: { value: 'manual-model' } })
  fireEvent.change(screen.getByLabelText('新 API Key'), { target: { value: 'synthetic-secret-key' } })
}
function writes(calls: ReturnType<typeof network>, method: string) { return calls.mock.calls.filter(([, options]) => options?.method === method) }

describe('target management API boundary', () => {
  it('loads string-ID targets with real metadata and explicit precheck/run configuration entries without automatic writes', async () => {
    const calls = network()
    renderTargets()
    await screen.findByText('Primary target')
    expect(screen.getByText('********test · v3')).toBeTruthy()
    expect((screen.getByRole('button', { name: '预检 Primary target' }) as HTMLButtonElement).disabled).toBe(false)
    expect((screen.getByRole('button', { name: '配置检测 Primary target' }) as HTMLButtonElement).disabled).toBe(false)
    expect(screen.getByText(/检测历史与已有分析结果已接入；报告生成与导出尚未接入/)).toBeTruthy()
    expect(screen.queryByText(/分析结果和报告尚未接入/)).toBeNull()
    const call = calls.mock.calls.find(([url]) => String(url).includes('/targets?'))!
    expect(String(call[0])).toBe('/api/v1/targets?limit=25')
    expect(new Headers(call[1]?.headers).get('X-Organization-ID')).toBe(org)
    expect(screen.getByRole('searchbox', { name: '搜索名称、模型或渠道' })).toBeTruthy()
    expect(writes(calls, 'POST')).toHaveLength(0)
  })

  it('creates a target using real provider/model selection, CSRF, verified TLS and write-only credentials', async () => {
    const calls = network()
    const storage = vi.spyOn(Storage.prototype, 'setItem')
    renderTargets()
    await createForm()
    const user = userEvent.setup()
    await user.selectOptions(screen.getByLabelText('模型档案（可选）'), profileID)
    expect((screen.getByLabelText('上游模型名称') as HTMLInputElement).value).toBe('catalog-model')
    expect((screen.getByLabelText('供应商档案（可选）') as HTMLSelectElement).value).toBe(providerID)
    await user.click(screen.getByRole('button', { name: '创建目标' }))
    await screen.findByText('New target')
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: '组织检测目标' }))
    const options = writes(calls, 'POST')[0][1]!
    expect(new Headers(options.headers).get('X-CSRF-Token')).toBe(csrf)
    expect(new Headers(options.headers).get('X-Organization-ID')).toBe(org)
    const body = JSON.parse(options.body as string)
    expect(body).toMatchObject({ provider_id: providerID, model_profile_id: profileID, model: 'catalog-model', protocol: 'openai_chat', options: { tls_verify: true }, auth: { type: 'bearer', api_key: 'synthetic-secret-key', headers: {} } })
    expect(storage).not.toHaveBeenCalled()
    expect(document.body.textContent).not.toContain('synthetic-secret-key')
    expect(screen.queryByLabelText('新 API Key')).toBeNull()
  })

  it('edits non-secret fields with the fresh target version and never includes auth in PATCH', async () => {
    const calls = network()
    renderTargets()
    await screen.findByText('Primary target')
    await userEvent.setup().click(screen.getByRole('button', { name: '编辑 Primary target' }))
    await screen.findByRole('form', { name: '编辑目标配置' })
    expect(screen.queryByLabelText('新 API Key')).toBeNull()
    expect(screen.queryByLabelText('认证方式')).toBeNull()
    fireEvent.change(screen.getByLabelText('目标名称'), { target: { value: 'Updated target' } })
    fireEvent.submit(screen.getByRole('form', { name: '编辑目标配置' }))
    await screen.findByText('Updated target')
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: '组织检测目标' }))
    const body = JSON.parse(writes(calls, 'PATCH')[0][1]!.body as string)
    expect(body.version).toBe(4)
    expect(body.status).toBe('active')
    expect(body.auth).toBeUndefined()
    expect(body.secret).toBeUndefined()
    expect(body.headers).toBeUndefined()
  })

  it('rotates complete credentials with both versions and no old credential prefill', async () => {
    const calls = network()
    renderTargets()
    await screen.findByText('Primary target')
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: '轮换凭证 Primary target' }))
    await screen.findByRole('form', { name: '轮换目标凭证' })
    expect((screen.getByLabelText('新 API Key') as HTMLInputElement).value).toBe('')
    await user.selectOptions(screen.getByLabelText('认证方式'), 'custom_header')
    fireEvent.change(screen.getByLabelText('认证请求头名称'), { target: { value: 'X-Api-Key' } })
    fireEvent.change(screen.getByLabelText('新 API Key'), { target: { value: 'replacement-synthetic-key' } })
    await user.click(screen.getByRole('button', { name: '添加请求头' }))
    fireEvent.change(screen.getByLabelText('请求头名称 1'), { target: { value: 'OpenAI-Project' } })
    fireEvent.change(screen.getByLabelText('请求头值 1'), { target: { value: 'synthetic-project' } })
    fireEvent.submit(screen.getByRole('form', { name: '轮换目标凭证' }))
    await screen.findByText('Primary target')
    const call = calls.mock.calls.find(([url]) => String(url).endsWith('/rotate-secret'))!
    expect(JSON.parse(call[1]!.body as string)).toEqual({ version: 4, secret_version: 3, auth: { type: 'custom_header', api_key: 'replacement-synthetic-key', header_name: 'X-Api-Key', headers: { 'OpenAI-Project': 'synthetic-project' } } })
    expect(await screen.findByText('********test · v4')).toBeTruthy()
    expect(document.body.textContent).not.toContain('replacement-synthetic-key')
  })

  it('clears all credential inputs after a failed create without fabricating success', async () => {
    const calls = network((path, options) => path === '/api/v1/targets' && options.method === 'POST' ? fail('MI_SERVICE_UNAVAILABLE', 503) : undefined)
    renderTargets()
    await createForm()
    await userEvent.setup().click(screen.getByRole('button', { name: '添加请求头' }))
    fireEvent.change(screen.getByLabelText('请求头名称 1'), { target: { value: 'X-Test' } })
    fireEvent.change(screen.getByLabelText('请求头值 1'), { target: { value: 'synthetic-sensitive-header' } })
    fireEvent.submit(screen.getByRole('form', { name: '新建检测目标' }))
    await screen.findByRole('alert')
    for (const label of ['新 API Key', '请求头名称 1', '请求头值 1']) expect((screen.getByLabelText(label) as HTMLInputElement).value).toBe('')
    expect((screen.getByLabelText('目标名称') as HTMLInputElement).value).toBe('New target')
    expect(document.body.textContent).not.toContain('sensitive-upstream-details')
    expect(writes(calls, 'POST')).toHaveLength(1)
  })

  it('keeps local edits on a conflict and only reloads after explicit user action', async () => {
    let gets = 0
    const calls = network((path, options) => {
      if (path === `/api/v1/targets/${initial.id}` && options.method === 'GET') return ok(gets++ === 0 ? initial : { ...initial, name: 'Concurrent edit', version: 5 })
      if (options.method === 'PATCH') return fail('MI_VERSION_CONFLICT', 409)
    })
    renderTargets()
    await screen.findByText('Primary target')
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: '编辑 Primary target' }))
    await screen.findByRole('form', { name: '编辑目标配置' })
    fireEvent.change(screen.getByLabelText('目标名称'), { target: { value: 'Local edit' } })
    fireEvent.submit(screen.getByRole('form', { name: '编辑目标配置' }))
    await screen.findByRole('alert')
    expect((screen.getByLabelText('目标名称') as HTMLInputElement).value).toBe('Local edit')
    expect(gets).toBe(1)
    await user.click(screen.getByRole('button', { name: '重新读取目标' }))
    await waitFor(() => expect((screen.getByLabelText('目标名称') as HTMLInputElement).value).toBe('Concurrent edit'))
    expect(writes(calls, 'PATCH')).toHaveLength(1)
  })

  it('requires deletion confirmation and sends DELETE with the current version', async () => {
    const calls = network()
    renderTargets()
    await screen.findByText('Primary target')
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: '删除 Primary target' }))
    await screen.findByRole('form', { name: '确认删除目标' })
    fireEvent.submit(screen.getByRole('form', { name: '确认删除目标' }))
    expect(writes(calls, 'DELETE')).toHaveLength(0)
    fireEvent.change(screen.getByLabelText('输入目标名称确认删除'), { target: { value: 'Primary target' } })
    fireEvent.submit(screen.getByRole('form', { name: '确认删除目标' }))
    await screen.findByText('当前页没有检测目标。可新建目标，或返回上一页。')
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: '组织检测目标' }))
    const options = writes(calls, 'DELETE')[0][1]!
    expect(JSON.parse(options.body as string)).toEqual({ version: 4 })
    expect(new Headers(options.headers).get('X-CSRF-Token')).toBe(csrf)
  })

  it('uses server cursors verbatim and supports going back without client-side search', async () => {
    const calls = network((path, _options, url) => path === '/api/v1/targets' ? ok({ items: url.searchParams.has('cursor') ? [{ ...initial, name: 'Second page' }] : [initial], next_cursor: url.searchParams.has('cursor') ? null : 'signed-cursor+/=' }) : undefined)
    renderTargets()
    await screen.findByText('Primary target')
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: '下一页' }))
    await screen.findByText('Second page')
    expect(screen.queryByText('Primary target')).toBeNull()
    expect(calls.mock.calls.some(([url]) => String(url).includes('cursor=signed-cursor%2B%2F%3D'))).toBe(true)
    await user.click(screen.getByRole('button', { name: '上一页' }))
    await screen.findByText('Primary target')
  })

  it('unmounts secret inputs and ignores prior-organization responses after switching organizations', async () => {
    let resolveMutation!: (response: Response) => void
    const calls = network((path, options) => {
      if (path === '/api/v1/targets' && options.method === 'POST') return new Promise<Response>((resolve) => { resolveMutation = resolve })
      if (path === '/api/v1/targets' && new Headers(options.headers).get('X-Organization-ID') === secondOrg) return ok({ items: [{ ...initial, name: 'Beta target' }], next_cursor: null })
    })
    renderTargets()
    await createForm()
    fireEvent.submit(screen.getByRole('form', { name: '新建检测目标' }))
    await waitFor(() => expect(resolveMutation).toBeTypeOf('function'))
    await userEvent.setup().selectOptions(screen.getByLabelText('当前组织'), secondOrg)
    await screen.findByText('Beta target')
    expect(screen.queryByLabelText('新 API Key')).toBeNull()
    await act(async () => resolveMutation(ok({ ...initial, name: 'Stale Alpha saved' })))
    expect(screen.queryByText('Stale Alpha saved')).toBeNull()
    expect(writes(calls, 'POST')[0][1]?.signal?.aborted).toBe(true)
  })

  it('shows permission denial without pretending the target list is empty', async () => {
    network((path) => path === '/api/v1/targets' ? fail('MI_PERMISSION_DENIED', 403) : undefined)
    renderTargets()
    expect((await screen.findByRole('alert')).textContent).toContain('没有执行此操作的权限')
    expect(screen.queryByText('当前页没有检测目标。可新建目标，或返回上一页。')).toBeNull()
  })

  it('rejects insecure or credential-bearing endpoint input before writing', async () => {
    const calls = network()
    renderTargets()
    await createForm()
    for (const endpoint of ['http://upstream.example/v1', 'https://user:secret@upstream.example/v1', 'https://upstream.example/v1?key=secret']) {
      fireEvent.change(screen.getByLabelText('Endpoint'), { target: { value: endpoint } })
      fireEvent.submit(screen.getByRole('form', { name: '新建检测目标' }))
      expect(screen.getByLabelText('Endpoint').getAttribute('aria-invalid')).toBe('true')
    }
    expect(writes(calls, 'POST')).toHaveLength(0)
  })

  it('rejects reserved, duplicate and malformed custom headers before sending', async () => {
    const calls = network()
    renderTargets()
    await createForm()
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: '添加请求头' }))
    fireEvent.change(screen.getByLabelText('请求头名称 1'), { target: { value: 'hOsT' } })
    fireEvent.change(screen.getByLabelText('请求头值 1'), { target: { value: 'evil.example' } })
    fireEvent.submit(screen.getByRole('form', { name: '新建检测目标' }))
    expect(await screen.findByText(/额外请求头名称或值无效/)).toBeTruthy()
    expect(writes(calls, 'POST')).toHaveLength(0)
  })

  it('preserves the previous target list as stale on refresh failure and disables stale mutations', async () => {
    let count = 0
    network((path) => path === '/api/v1/targets' && count++ > 0 ? fail('MI_SERVICE_UNAVAILABLE', 503) : undefined)
    renderTargets()
    await screen.findByText('Primary target')
    await userEvent.setup().click(screen.getByRole('button', { name: '刷新目标' }))
    await screen.findByRole('alert')
    expect(screen.getByText('Primary target')).toBeTruthy()
    expect(screen.getByText(/下方保留上次成功的列表/)).toBeTruthy()
    expect((screen.getByRole('button', { name: '编辑 Primary target' }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('clears a failed rotation key and keeps the original secret version without automatic retry', async () => {
    const calls = network((path) => path.endsWith('/rotate-secret') ? fail('MI_VERSION_CONFLICT', 409) : undefined)
    renderTargets()
    await screen.findByText('Primary target')
    await userEvent.setup().click(screen.getByRole('button', { name: '轮换凭证 Primary target' }))
    await screen.findByRole('form', { name: '轮换目标凭证' })
    fireEvent.change(screen.getByLabelText('新 API Key'), { target: { value: 'synthetic-rotation-key' } })
    fireEvent.submit(screen.getByRole('form', { name: '轮换目标凭证' }))
    await screen.findByRole('alert')
    expect((screen.getByLabelText('新 API Key') as HTMLInputElement).value).toBe('')
    expect(screen.getByText(/版本 3。请输入完整的新认证配置/)).toBeTruthy()
    expect(writes(calls, 'POST')).toHaveLength(1)
  })

  it('honors the password-change gate on a denied target list without replaying the business request', async () => {
    let count = 0
    const calls = network((path) => {
      if (path.endsWith('/auth/me')) return ok(count++ === 0 ? session : { ...session, user: { ...session.user, must_change_password: true } })
      if (path === '/api/v1/targets') return fail('MI_PASSWORD_CHANGE_REQUIRED', 403)
    })
    renderTargets()
    await screen.findByRole('form', { name: '修改密码' })
    expect(screen.queryByRole('navigation')).toBeNull()
    expect(calls.mock.calls.filter(([url]) => String(url).includes('/targets?'))).toHaveLength(1)
  })
})

describe('target API response confidentiality', () => {
  it('projects a read DTO down to allowed edit fields rather than resubmitting secret metadata', async () => {
    const calls = vi.fn<typeof fetch>().mockResolvedValue(ok(initial))
    vi.stubGlobal('fetch', calls)
    await targetsApi.update(org, csrf, initial.id, initial, 'active', initial.version)
    const body = JSON.parse(calls.mock.calls[0][1]!.body as string)
    expect(body.secret).toBeUndefined()
    expect(body.id).toBeUndefined()
    expect(body.created_at).toBeUndefined()
    expect(body.auth).toBeUndefined()
  })
  it.each([
    { ...initial, auth: { api_key: 'plaintext' } },
    { ...initial, headers: { 'X-Key': 'plaintext' } },
    { ...initial, secret: { ...initial.secret, ciphertext: 'encrypted' } },
    { ...initial, secret: { ...initial.secret, fingerprint: 'digest' } },
    { ...initial, secret: { ...initial.secret, mask: 'unmasked-key' } },
    { ...initial, id: Number(initial.id) },
    { ...initial, options: { ...initial.options, tls_verify: false } },
    { ...initial, secret: { ...initial.secret, rotated_at: { api_key: 'plaintext' } } },
  ])('rejects credential-bearing or invalid target DTO %#', async (response) => {
    expect(target(response)).toBe(false)
    vi.stubGlobal('fetch', vi.fn<typeof fetch>().mockResolvedValue(ok(response)))
    await expect(targetsApi.get(org, initial.id)).rejects.toMatchObject({ code: 'MI_INVALID_RESPONSE' })
  })
})
