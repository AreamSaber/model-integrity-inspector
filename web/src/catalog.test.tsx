import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { App } from './App'
import type { Session } from './api'
import type { ModelProfile, Provider } from './catalog-api'
const org = '9007199254740993', otherOrg = '9007199254740994', userID = '9007199254740995', providerID = '9007199254740997', modelID = '9007199254740999'
const provider: Provider = { id: providerID, name: 'Example vendor', description: 'Directory metadata', contact: 'Operations', status: 'active', version: 1, created_at: '2026-09-07T08:00:00Z', updated_at: '2026-09-07T08:00:00Z' }
const model: ModelProfile = { id: modelID, provider_id: providerID, name: 'example-model', display_name: 'Example model', protocol: 'openai_chat', status: 'active', version: 1, created_at: '2026-09-07T08:00:00Z', updated_at: '2026-09-07T08:00:00Z', supports_stream: true, supports_seed: false, reasoning_model: false, tokenizer_id: 'declared-example', tokenizer_quality: 'compatible', max_output_tokens: 2048, context_window: 8192, input_price_micros_per_million: null, output_price_micros_per_million: 0 }
const session: Session = { user: { id: userID, username: 'admin', status: 'active', system_admin: true, must_change_password: false }, organizations: [{ id: org, name: 'Alpha', status: 'active' }, { id: otherOrg, name: 'Beta', status: 'active' }], csrf_token: 'synthetic-csrf', expires_at: '2099-01-01T00:00:00Z' }
function ok(data: unknown, status = 200) { return Response.json({ data, request_id: 'catalog-test' }, { status }) }
function fail(code: string, status = 409) { return Response.json({ error: { code, message: 'private-server-diagnostics' }, request_id: 'catalog-test-error' }, { status }) }
function summary(record: ModelProfile) { const { supports_stream: _stream, supports_seed: _seed, reasoning_model: _reasoning, tokenizer_id: _id, tokenizer_quality: _quality, max_output_tokens: _output, context_window: _context, ...value } = record; return value }
type Handler = (path: string, options: RequestInit, url: URL) => Response | Promise<Response> | undefined
function network(handler?: Handler) {
  let providers = [provider], models = [model]
  const calls = vi.fn<typeof fetch>(async (input, options = {}) => {
    const url = new URL(String(input), 'http://localhost'), path = url.pathname
    const override = handler?.(path, options, url); if (override) return override
    if (path.endsWith('/setup/status')) return ok({ initialized: true })
    if (path.endsWith('/auth/me')) return ok(session)
    if (path.endsWith('/auth/logout')) return ok({ ok: true })
    if (path.endsWith('/auth/permissions')) return ok({ organization_id: new Headers(options.headers).get('X-Organization-ID'), user_id: userID, permissions: ['read', 'catalog.write'] })
    if (path === '/api/v1/providers') {
      if (options.method === 'POST') { const result = { ...provider, ...JSON.parse(String(options.body)), id: '9007199254741011', version: 1 }; providers = [...providers, result]; return ok(result, 201) }
      return ok({ items: providers, next_cursor: null })
    }
    if (path === '/api/v1/model-profiles') {
      if (options.method === 'POST') {
        const result = { ...model, ...JSON.parse(String(options.body)), id: '9007199254741013', version: 1 }
        if (result.max_output_tokens === null) delete result.max_output_tokens
        if (result.context_window === null) delete result.context_window
        models = [...models, result]; return ok(result, 201)
      }
      return ok({ items: models.map(summary), next_cursor: null })
    }
    if (path.startsWith('/api/v1/providers/')) {
      const recordID = path.split('/').at(-1), record = providers.find((item) => item.id === recordID)
      if (!record) return fail('MI_NOT_FOUND', 404)
      if (options.method === 'DELETE') { providers = providers.filter((item) => item.id !== recordID); return ok({ ok: true }) }
      if (options.method === 'PATCH') { const result = { ...record, ...JSON.parse(String(options.body)), version: record.version + 1 }; providers = providers.map((item) => item.id === recordID ? result : item); return ok(result) }
      return ok(record)
    }
    if (path.startsWith('/api/v1/model-profiles/')) {
      const recordID = path.split('/').at(-1), record = models.find((item) => item.id === recordID)
      if (!record) return fail('MI_NOT_FOUND', 404)
      if (options.method === 'DELETE') { models = models.filter((item) => item.id !== recordID); return ok({ ok: true }) }
      if (options.method === 'PATCH') {
        const result = { ...record, ...JSON.parse(String(options.body)), version: record.version + 1 }
        if (result.max_output_tokens === null) delete result.max_output_tokens
        if (result.context_window === null) delete result.context_window
        models = models.map((item) => item.id === recordID ? result : item); return ok(result)
      }
      return ok(record)
    }
    throw new Error('Unexpected controlled catalog route')
  })
  vi.stubGlobal('fetch', calls); return calls
}
function show(kind = 'providers') { window.history.replaceState(null, '', `/#/${kind}`); return render(<App />) }
async function click(name: string) { await screen.findByRole('button', { name }); await waitFor(() => expect((screen.getByRole('button', { name }) as HTMLButtonElement).disabled).toBe(false)); await act(async () => { fireEvent.click(screen.getByRole('button', { name })) }) }
function change(label: string, value: string) { fireEvent.change(screen.getByLabelText(label), { target: { value } }) }
async function submit(name: string) { await act(async () => { fireEvent.submit(screen.getByRole('form', { name })) }) }
function writes(calls: ReturnType<typeof network>, method = 'POST') { return calls.mock.calls.filter(([, options]) => options?.method === method) }
function read(calls: ReturnType<typeof network>, path: string) { return calls.mock.calls.filter(([url, options]) => new URL(String(url), 'http://localhost').pathname === path && options?.method === 'GET') }

describe('real provider catalog management', () => {
  it('reads the actual directory and effective permissions without discovery, roles or paid calls', async () => {
    const calls = network(); show(); await screen.findByText('Example vendor')
    expect(screen.getByText(/Directory metadata/)).toBeTruthy()
    expect(read(calls, '/api/v1/auth/permissions')).toHaveLength(1)
    expect(writes(calls)).toHaveLength(0)
    expect(calls.mock.calls.some(([url]) => /roles|precheck|runs|tokenizer|templates/.test(String(url)))).toBe(false)
  })
  it('creates a provider with exact fields and restores focus to the list heading', async () => {
    const calls = network(); show(); await click('创建供应商')
    change('供应商名称', 'New vendor'); change('描述（可选）', 'Non-sensitive directory'); change('联系人（可选）', 'Maintainer')
    await submit('创建供应商档案')
    expect(screen.getByText('New vendor')).toBeTruthy()
    expect(JSON.parse(String(writes(calls)[0][1]?.body))).toEqual({ name: 'New vendor', description: 'Non-sensitive directory', contact: 'Maintainer', status: 'active' })
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: '组织供应商目录' }))
    expect(new Headers(writes(calls)[0][1]?.headers).get('X-CSRF-Token')).toBe('synthetic-csrf')
    expect(read(calls, '/api/v1/auth/permissions')).toHaveLength(2)
  })
  it('gets the latest provider version before editing and submits CAS without read-only metadata', async () => {
    const calls = network((path, options) => path.endsWith(`providers/${providerID}`) && options.method === 'GET' ? ok({ ...provider, version: 7 }) : undefined)
    show(); await click('编辑供应商 Example vendor'); change('供应商名称', 'Renamed')
    await submit('编辑供应商档案')
    expect(JSON.parse(String(writes(calls, 'PATCH')[0][1]?.body))).toEqual({ name: 'Renamed', description: provider.description, contact: provider.contact, status: 'active', version: 7 })
    // The controlled server intentionally returned v2 instead of the expected v8.
    expect(screen.getByText('服务响应格式异常，请联系管理员。')).toBeTruthy()
    expect(screen.getByText(/提交结果不确定/)).toBeTruthy()
  })
  it('saves provider status and text changes with the expected incremented version', async () => {
    const calls = network(); show(); await click('编辑供应商 Example vendor'); change('供应商名称', 'Updated vendor'); change('档案状态', 'disabled'); await submit('编辑供应商档案')
    expect(screen.getByText('Updated vendor')).toBeTruthy()
    expect(screen.getByText(/ID 9007199254740997 · v2/)).toBeTruthy()
    expect(JSON.parse(String(writes(calls, 'PATCH')[0][1]?.body))).toMatchObject({ version: 1, status: 'disabled' })
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: '组织供应商目录' }))
  })
  it('requires exact deletion confirmation and explains both association and version protection without cascading', async () => {
    const calls = network((path, options) => path.endsWith(`providers/${providerID}`) && options.method === 'DELETE' ? fail('MI_VERSION_CONFLICT') : undefined)
    show(); await click('删除供应商 Example vendor'); await submit('删除供应商档案')
    expect(writes(calls, 'DELETE')).toHaveLength(0)
    change('输入档案名称确认删除', provider.name); await submit('删除供应商档案')
    expect(JSON.parse(String(writes(calls, 'DELETE')[0][1]?.body))).toEqual({ version: 1 })
    expect(screen.getByText(/记录版本或关联约束冲突/)).toBeTruthy()
    expect(document.body.textContent).not.toContain('private-server-diagnostics')
    expect(writes(calls, 'DELETE')).toHaveLength(1)
    await click('返回列表并重新读取'); expect(screen.getByText('Example vendor')).toBeTruthy()
  })
  it('deletes an unreferenced provider and displays an honest empty state', async () => {
    const calls = network(); show(); await click('删除供应商 Example vendor'); change('输入档案名称确认删除', provider.name); await submit('删除供应商档案')
    expect(screen.getByText('没有符合条件的供应商。')).toBeTruthy()
    expect(writes(calls, 'DELETE')).toHaveLength(1)
  })
  it('keeps catalog writes disabled without actual permission but permits read-only full details', async () => {
    const calls = network((path) => path.endsWith('/auth/permissions') ? ok({ organization_id: org, user_id: userID, permissions: ['read'] }) : undefined)
    show(); await screen.findByText('Example vendor')
    expect((screen.getByRole('button', { name: '创建供应商' }) as HTMLButtonElement).disabled).toBe(true)
    expect((screen.getByRole('button', { name: '编辑供应商 Example vendor' }) as HTMLButtonElement).disabled).toBe(true)
    await click('查看供应商 Example vendor')
    expect(screen.getByRole('heading', { name: '档案详情：Example vendor' })).toBeTruthy()
    expect(read(calls, `/api/v1/providers/${providerID}`)).toHaveLength(1)
    expect(writes(calls)).toHaveLength(0)
  })
  it('revalidates write permission just before saving and stops when it was revoked', async () => {
    let permissions = 0
    const calls = network((path) => path.endsWith('/auth/permissions') ? ok({ organization_id: org, user_id: userID, permissions: ++permissions === 1 ? ['read', 'catalog.write'] : ['read'] }) : undefined)
    show(); await click('创建供应商'); change('供应商名称', 'Unauthorized'); await submit('创建供应商档案')
    expect(screen.getByText(/当前有效权限不足或未知/)).toBeTruthy()
    expect((screen.getByRole('button', { name: '保存档案' }) as HTMLButtonElement).disabled).toBe(true)
    expect(writes(calls)).toHaveLength(0)
  })
  it('does not replay an uncertain create and requires read-back before another edit', async () => {
    const calls = network((path, options) => path === '/api/v1/providers' && options.method === 'POST' ? Promise.reject(new Error('private-network-detail')) : undefined)
    show(); await click('创建供应商'); change('供应商名称', 'Maybe-created'); await submit('创建供应商档案'); await submit('创建供应商档案')
    expect(screen.getByText(/提交结果不确定/)).toBeTruthy()
    expect((screen.getByRole('button', { name: '保存档案' }) as HTMLButtonElement).disabled).toBe(true)
    expect(writes(calls)).toHaveLength(1)
    expect(document.body.textContent).not.toContain('private-network-detail')
  })
  it('uses server-side search and carries q through signed-cursor pagination', async () => {
    const calls = network((path, options, url) => path === '/api/v1/providers' && options.method === 'GET' && url.searchParams.get('q') === 'Vendor%_' ? ok({ items: [provider], next_cursor: url.searchParams.has('cursor') ? null : 'signed-catalog-cursor' }) : undefined)
    show(); await screen.findByText('Example vendor'); change('服务端搜索供应商', 'Vendor%_'); await submit('搜索供应商'); await click('下一页')
    const last = read(calls, '/api/v1/providers').at(-1)!
    const query = new URL(String(last[0]), 'http://localhost').searchParams
    expect(query.get('q')).toBe('Vendor%_'); expect(query.get('cursor')).toBe('signed-catalog-cursor')
    expect(screen.getByText('第 2 页')).toBeTruthy()
  })
  it('marks stale list data and disables mutations when refreshing fails', async () => {
    let reads = 0
    network((path) => path === '/api/v1/providers' && ++reads > 1 ? fail('MI_SERVICE_UNAVAILABLE', 503) : undefined)
    show(); await screen.findByText('Example vendor'); await click('刷新列表')
    expect(screen.getByText(/上次成功加载的数据/)).toBeTruthy()
    expect((screen.getByRole('button', { name: '编辑供应商 Example vendor' }) as HTMLButtonElement).disabled).toBe(true)
  })
})

describe('real model profiles and lifecycle boundaries', () => {
  it('loads model summary then complete details without inventing capabilities', async () => {
    const calls = network(); show('model-profiles'); await screen.findByText('example-model')
    expect(screen.getByText(/输入：价格未知/)).toBeTruthy()
    expect(read(calls, `/api/v1/model-profiles/${modelID}`)).toHaveLength(0)
    await click('查看模型档案 example-model')
    expect(screen.getByText('compatible · declared-example')).toBeTruthy()
    expect(screen.getByText(/不是已验证的运行时能力/)).toBeTruthy()
    expect(read(calls, `/api/v1/model-profiles/${modelID}`)).toHaveLength(1)
  })
  it('creates exact numeric prices and explicit capability declarations through real provider options', async () => {
    const calls = network(); show('model-profiles'); await click('创建模型档案')
    change('所属供应商', providerID); change('供应商模型标识', 'new-model'); change('模型显示名称（可选）', 'New model')
    fireEvent.click(screen.getByLabelText('支持流式')); fireEvent.click(screen.getByLabelText('支持 seed')); fireEvent.click(screen.getByLabelText('推理模型'))
    change('Tokenizer 质量声明', 'exact'); change('Tokenizer 标识声明', 'declared-not-trusted')
    change('公开输出 Token 上限（可选）', '1024'); change('公开上下文窗口（可选）', '4096')
    change('输入价格（USD / 百万 Token）', '9007199254.740991'); change('输出价格（USD / 百万 Token）', '0')
    await submit('创建模型档案')
    const body = JSON.parse(String(writes(calls)[0][1]?.body))
    expect(body).toEqual({ provider_id: providerID, name: 'new-model', display_name: 'New model', protocol: 'openai_chat', status: 'active', supports_stream: true, supports_seed: true, reasoning_model: true, tokenizer_id: 'declared-not-trusted', tokenizer_quality: 'exact', max_output_tokens: 1024, context_window: 4096, input_price_micros_per_million: Number.MAX_SAFE_INTEGER, output_price_micros_per_million: 0 })
    expect(screen.getByText('new-model')).toBeTruthy()
    expect(calls.mock.calls.some(([url]) => /tokenizer|templates|runs|precheck/.test(String(url)))).toBe(false)
  })
  it('reads the existing provider by ID, clears optional limits/prices and does not treat an unavailable tokenizer as exact', async () => {
    const calls = network((path, options) => path === '/api/v1/providers' && options.method === 'GET' ? ok({ items: [], next_cursor: null }) : undefined)
    show('model-profiles'); await click('编辑模型档案 example-model')
    expect((screen.getByLabelText('所属供应商') as HTMLSelectElement).value).toBe(providerID)
    expect(read(calls, `/api/v1/providers/${providerID}`)).toHaveLength(1)
    change('Tokenizer 质量声明', 'unavailable'); change('公开输出 Token 上限（可选）', ''); change('公开上下文窗口（可选）', ''); change('输出价格（USD / 百万 Token）', '')
    await submit('编辑模型档案')
    expect(JSON.parse(String(writes(calls, 'PATCH')[0][1]?.body))).toMatchObject({ version: 1, tokenizer_id: '', tokenizer_quality: 'unavailable', max_output_tokens: null, context_window: null, input_price_micros_per_million: null, output_price_micros_per_million: null })
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: '组织模型档案目录' }))
  })
  it('rejects contradictory limits, excessive precision and missing tokenizer IDs locally', async () => {
    const calls = network(); show('model-profiles'); await click('创建模型档案'); change('所属供应商', providerID); change('供应商模型标识', 'invalid-model')
    change('公开输出 Token 上限（可选）', '1025'); change('公开上下文窗口（可选）', '1024'); await submit('创建模型档案')
    expect(screen.getByRole('alert').textContent).toContain('不能大于')
    change('公开输出 Token 上限（可选）', '1024'); change('输入价格（USD / 百万 Token）', '0.0000001'); await submit('创建模型档案')
    expect(screen.getByRole('alert').textContent).toContain('最多 6 位小数')
    change('输入价格（USD / 百万 Token）', ''); change('Tokenizer 质量声明', 'exact'); await submit('创建模型档案')
    expect(writes(calls)).toHaveLength(0)
  })
  it('does not create an active model under a disabled provider', async () => {
    const calls = network((path) => path === '/api/v1/providers' ? ok({ items: [{ ...provider, status: 'disabled' }], next_cursor: null }) : undefined)
    show('model-profiles'); await click('创建模型档案'); change('所属供应商', providerID); change('供应商模型标识', 'new-model'); await submit('创建模型档案')
    expect(screen.getByRole('alert').textContent).toContain('启用的供应商')
    expect(writes(calls)).toHaveLength(0)
  })
  it('does not fabricate provider choices or save when provider loading fails', async () => {
    const calls = network((path) => path === '/api/v1/providers' ? fail('MI_PERMISSION_DENIED', 403) : undefined)
    show('model-profiles'); await click('创建模型档案'); change('供应商模型标识', 'new-model'); await submit('创建模型档案')
    expect(screen.queryByRole('option', { name: /Example vendor/ })).toBeNull()
    expect(writes(calls)).toHaveLength(0)
  })
  it('loads more actual provider options and validates multibyte search before requesting', async () => {
    const second = { ...provider, id: '9007199254741017', name: 'Second vendor' }
    const calls = network((path, options, url) => path === '/api/v1/providers' && options.method === 'GET' ? ok({ items: url.searchParams.has('cursor') ? [second] : [provider], next_cursor: url.searchParams.has('cursor') ? null : 'provider-page-2' }) : undefined)
    show('model-profiles'); await click('创建模型档案'); await click('加载更多供应商')
    expect(screen.getByRole('option', { name: /Second vendor/ })).toBeTruthy()
    expect(new URL(String(read(calls, '/api/v1/providers').at(-1)?.[0]), 'http://localhost').searchParams.get('cursor')).toBe('provider-page-2')
    change('查找供应商（服务端）', '界'.repeat(50)); await click('搜索供应商选项')
    expect(screen.getByText('供应商搜索不得超过 128 字节或包含控制字符。')).toBeTruthy()
    expect(read(calls, '/api/v1/providers')).toHaveLength(2)
    expect(writes(calls)).toHaveLength(0)
  })
  it('deletes a model using the full-detail version and never deletes its provider', async () => {
    const calls = network(); show('model-profiles'); await click('删除模型档案 example-model'); change('输入档案名称确认删除', model.name); await submit('删除模型档案')
    expect(screen.getByText('没有符合条件的模型档案。')).toBeTruthy()
    expect(writes(calls, 'DELETE')).toHaveLength(1)
    expect(String(writes(calls, 'DELETE')[0][0])).toBe(`/api/v1/model-profiles/${modelID}`)
    expect(JSON.parse(String(writes(calls, 'DELETE')[0][1]?.body))).toEqual({ version: 1 })
  })
  it('aborts a pending mutation when the organization changes and ignores its late success', async () => {
    let resolve: ((response: Response) => void) | undefined
    const calls = network((path, options) => path === '/api/v1/providers' && options.method === 'POST' ? new Promise<Response>((done) => { resolve = done }) : undefined)
    show(); await click('创建供应商'); change('供应商名称', 'Pending vendor'); await submit('创建供应商档案')
    await submit('创建供应商档案'); expect(writes(calls)).toHaveLength(1)
    await userEvent.setup().selectOptions(screen.getByLabelText('当前组织'), otherOrg)
    expect(writes(calls)[0][1]?.signal?.aborted).toBe(true)
    await act(async () => { resolve?.(ok({ ...provider, name: 'Pending vendor', id: '9007199254741019' })) })
    expect(screen.queryByText('Pending vendor')).toBeNull()
    expect(read(calls, '/api/v1/auth/permissions').at(-1)?.[1]?.headers).toMatchObject({ 'X-Organization-ID': otherOrg })
  })
  it('enforces mandatory-password gates without replaying mutations', async () => {
    let recovery = false
    const calls = network((path, options) => {
      if (path === '/api/v1/providers' && options.method === 'POST') { recovery = true; return fail('MI_PASSWORD_CHANGE_REQUIRED', 403) }
      if (path.endsWith('/auth/me') && recovery) return ok({ ...session, user: { ...session.user, must_change_password: true } })
      return undefined
    })
    show(); await click('创建供应商'); change('供应商名称', 'Blocked'); await submit('创建供应商档案')
    expect(screen.getByRole('heading', { name: '修改密码' })).toBeTruthy()
    expect(writes(calls)).toHaveLength(1)
    expect(screen.queryByRole('link', { name: '供应商管理' })).toBeNull()
  })
  it.each(['MI_SESSION_REQUIRED', 'MI_CSRF_INVALID'])('signs out on %s without replaying the rejected mutation', async (code) => {
    const calls = network((path, options) => path === '/api/v1/providers' && options.method === 'POST' ? fail(code, code === 'MI_SESSION_REQUIRED' ? 401 : 403) : undefined)
    show(); await click('创建供应商'); change('供应商名称', 'Rejected'); await submit('创建供应商档案')
    expect(screen.getByRole('heading', { name: '登录工作空间' })).toBeTruthy()
    expect(writes(calls)).toHaveLength(1)
    expect(writes(calls)[0][1]?.signal?.aborted).toBe(true)
  })
  it('cleans up a pending detail read on logout and restores keyboard focus when returning normally', async () => {
    let pending = false
    const calls = network((path) => path.endsWith(`providers/${providerID}`) && pending ? new Promise<Response>(() => {}) : undefined)
    show(); await click('查看供应商 Example vendor')
    const back = screen.getByRole('button', { name: '返回档案列表' }); back.focus(); await userEvent.setup().keyboard('{Enter}')
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: '组织供应商目录' }))
    pending = true; await click('查看供应商 Example vendor'); await click('退出登录')
    expect(screen.getByRole('heading', { name: '登录工作空间' })).toBeTruthy()
    expect(read(calls, `/api/v1/providers/${providerID}`).at(-1)?.[1]?.signal?.aborted).toBe(true)
  })
})
