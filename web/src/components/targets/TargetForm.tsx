import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, passwordChangeRequired, sessionInvalid } from '../../api'
import { targetsApi, type ModelProfile, type Page, type Provider, type Target, type TargetInput } from '../../targets-api'
import { ErrorNotice, Loading } from '../Feedback'
import { CredentialFields } from './CredentialFields'
import { clearCredentials, readCredentials, validateTarget, type FieldErrors } from './validation'

export interface TargetCallbacks {
  organizationID: string; csrfToken: string; onSignedOut: (message: string) => void; onPasswordRequired: () => void
}
export function TargetForm({ organizationID, csrfToken, current, onSaved, onCancel, onSignedOut, onPasswordRequired, onReload }: TargetCallbacks & {
  current?: Target; onSaved: (target: Target) => void; onCancel: () => void; onReload: () => void
}) {
  const [providers, setProviders] = useState<Page<Provider> | null>(null)
  const [profiles, setProfiles] = useState<Page<ModelProfile> | null>(null)
  const [catalogLoading, setCatalogLoading] = useState(true)
  const [catalogError, setCatalogError] = useState<unknown>(null)
  const [providerID, setProviderID] = useState(current?.provider_id ?? '')
  const [profileID, setProfileID] = useState(current?.model_profile_id ?? '')
  const [model, setModel] = useState(current?.model ?? '')
  const [error, setError] = useState<unknown>(null)
  const [fields, setFields] = useState<FieldErrors>({})
  const [saving, setSaving] = useState(false)
  const [catalogAttempt, setCatalogAttempt] = useState(0)
  const activeRequest = useRef<AbortController | null>(null)
  const catalogRequest = useRef<AbortController | null>(null)
  const submitting = useRef(false)
  const heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => { heading.current?.focus() }, [])
  useEffect(() => () => { activeRequest.current?.abort(); catalogRequest.current?.abort() }, [])
  useEffect(() => {
    const controller = new AbortController()
    catalogRequest.current = controller
    void Promise.all([targetsApi.providers(organizationID, '', controller.signal), targetsApi.profiles(organizationID, '', controller.signal)]).then(([providerResult, profileResult]) => {
      if (!controller.signal.aborted) { setProviders(providerResult); setProfiles(profileResult) }
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      if (sessionInvalid(failure)) onSignedOut('会话已失效，请重新登录。')
      else if (passwordChangeRequired(failure)) onPasswordRequired()
      else setCatalogError(failure)
    }).finally(() => { if (!controller.signal.aborted) setCatalogLoading(false) })
    return () => controller.abort()
  }, [organizationID, catalogAttempt, onSignedOut, onPasswordRequired])

  async function loadMore(kind: 'providers' | 'profiles') {
    if (catalogLoading) return
    const cursor = kind === 'providers' ? providers?.next_cursor : profiles?.next_cursor
    if (!cursor) return
    const controller = new AbortController()
    catalogRequest.current = controller
    setCatalogLoading(true)
    setCatalogError(null)
    try {
      if (kind === 'providers') {
        const next = await targetsApi.providers(organizationID, cursor, controller.signal)
        if (!controller.signal.aborted) setProviders((previous) => ({ items: [...(previous?.items ?? []), ...next.items.filter((item) => !previous?.items.some((old) => old.id === item.id))], next_cursor: next.next_cursor }))
      } else {
        const next = await targetsApi.profiles(organizationID, cursor, controller.signal)
        if (!controller.signal.aborted) setProfiles((previous) => ({ items: [...(previous?.items ?? []), ...next.items.filter((item) => !previous?.items.some((old) => old.id === item.id))], next_cursor: next.next_cursor }))
      }
    } catch (failure) {
      if (controller.signal.aborted) return
      if (sessionInvalid(failure)) onSignedOut('会话已失效，请重新登录。')
      else if (passwordChangeRequired(failure)) onPasswordRequired()
      else setCatalogError(failure)
    } finally { if (!controller.signal.aborted) setCatalogLoading(false) }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (submitting.current) return
    const form = event.currentTarget
    const data = new FormData(form)
    const value = (name: string) => String(data.get(name) ?? '')
    const input: TargetInput = {
      name: value('name').trim(), endpoint: value('endpoint').trim(), protocol: 'openai_chat', model: model.trim(),
      provider_id: providerID || null, model_profile_id: profileID || null, environment: value('environment').trim(), channel_id: value('channel_id').trim(),
      tags: value('tags').split(',').map((tag) => tag.trim()).filter(Boolean),
      options: { max_output_parameter: value('max_output_parameter') as TargetInput['options']['max_output_parameter'], tls_verify: true, timeout_seconds: Number(value('timeout_seconds')), concurrency: Number(value('concurrency')), rpm: Number(value('rpm')) },
    }
    const credentials = current ? undefined : readCredentials(form)
    const errors = { ...validateTarget(input), ...credentials?.errors }
    setFields(errors)
    setError(null)
    if (Object.keys(errors).length) {
      const control = form.elements.namedItem(Object.keys(errors)[0])
      if (control instanceof HTMLElement) control.focus()
      return
    }
    const controller = new AbortController()
    activeRequest.current = controller
    submitting.current = true
    setSaving(true)
    try {
      const result = current
        ? await targetsApi.update(organizationID, csrfToken, current.id, input, value('status') as 'active' | 'disabled', current.version, controller.signal)
        : await targetsApi.create(organizationID, csrfToken, input, credentials!.auth!, controller.signal)
      if (!controller.signal.aborted) onSaved(result)
    } catch (failure) {
      if (controller.signal.aborted) return
      if (sessionInvalid(failure)) onSignedOut('会话已失效，请重新登录。')
      else if (passwordChangeRequired(failure)) onPasswordRequired()
      else setError(failure)
    } finally {
      clearCredentials(form)
      submitting.current = false
      if (!controller.signal.aborted) setSaving(false)
    }
  }
  function field(name: string, label: string, initial = '', maxLength = 128, help?: string) {
    return <div className="field"><label htmlFor={name}>{label}</label><input id={name} name={name} defaultValue={initial} maxLength={maxLength} aria-invalid={Boolean(fields[name])} aria-describedby={[fields[name] ? `${name}-error` : '', help ? `${name}-help` : ''].filter(Boolean).join(' ') || undefined} />{help && <p id={`${name}-help`} className="field-help">{help}</p>}{fields[name] && <p className="field-error" id={`${name}-error`}>{fields[name]}</p>}</div>
  }
  const title = current ? '编辑目标配置' : '新建检测目标'
  return <section className="panel target-editor" aria-labelledby="target-form-title">
    <div className="section-heading"><h2 id="target-form-title" ref={heading} tabIndex={-1}>{title}</h2><button disabled={saving} onClick={onCancel}>返回列表</button></div>
    <p className="muted">{current ? '这里只修改非凭证配置。空字段不会清除原密钥；如需更新凭证，请使用轮换操作。' : '只保存配置，不会自动发起上游请求或产生调用费用。'}</p>
    <ErrorNotice error={error} id="target-form-error" />
    {error instanceof ApiError && (error.status === 409 || error.status === 404) && <div><p className="field-help">重新读取会丢弃当前未保存的配置编辑，载入服务端最新版本；不会自动重试保存。</p><button disabled={saving} onClick={onReload}>重新读取目标</button></div>}
    {catalogLoading && <Loading>正在读取供应商和模型档案…</Loading>}
    <ErrorNotice error={catalogError} id="catalog-error" />
    {Boolean(catalogError) && <div className="catalog-retry"><p className="field-help">目录读取失败；已加载的目录可能过期。可以不关联档案，手动填写模型名称；不会用示例选项替代真实目录。</p><button type="button" disabled={catalogLoading} onClick={() => { setCatalogError(null); setCatalogLoading(true); setCatalogAttempt((value) => value + 1) }}>重新读取目录</button></div>}
    <form onSubmit={submit} noValidate aria-label={title}><fieldset disabled={saving}><legend className="sr-only">{title}</legend>
      <div className="form-grid">{field('name', '目标名称', current?.name)}{field('environment', '环境（可选）', current?.environment, 64)}{field('channel_id', '渠道（可选）', current?.channel_id)}{field('tags', '标签（逗号分隔，可选）', current?.tags.join(', '), 1300)}</div>
      {field('endpoint', 'Endpoint', current?.endpoint, 1024, '仅支持 HTTPS，不接受 URL 中的凭证或查询参数。前端格式检查不替代服务端 SSRF、DNS 与网络策略校验。')}
      <div className="form-grid">
        <div className="field"><label htmlFor="provider_id">供应商档案（可选）</label><select id="provider_id" value={providerID} disabled={catalogLoading} onChange={(event) => { setProviderID(event.target.value); setProfileID('') }}><option value="">不关联供应商</option>{providerID && !providers?.items.some((item) => item.id === providerID) && <option value={providerID}>当前关联 ID {providerID}（目录未加载）</option>}{providers?.items.map((item) => <option key={item.id} value={item.id} disabled={item.status !== 'active'}>{item.name}{item.status !== 'active' ? '（停用）' : ''}</option>)}</select>{providers?.items.length === 0 && <p className="field-help">当前组织尚无供应商档案。</p>}</div>
        <div className="field"><label htmlFor="model_profile_id">模型档案（可选）</label><select id="model_profile_id" value={profileID} disabled={catalogLoading} onChange={(event) => {
          const selected = profiles?.items.find((item) => item.id === event.target.value)
          setProfileID(event.target.value)
          if (selected) { setProviderID(selected.provider_id); setModel(selected.name) }
        }}><option value="">不关联模型档案</option>{profileID && !profiles?.items.some((item) => item.id === profileID) && <option value={profileID}>当前关联 ID {profileID}（目录未加载）</option>}{profiles?.items.filter((item) => !providerID || item.provider_id === providerID).map((item) => <option key={item.id} value={item.id}>{item.display_name || item.name}</option>)}</select>{profiles?.items.length === 0 && <p className="field-help">当前组织尚无模型档案，可手动填写模型名称。</p>}</div>
      </div>
      {(providers?.next_cursor || profiles?.next_cursor) && <div className="form-actions">{providers?.next_cursor && <button type="button" disabled={catalogLoading} onClick={() => void loadMore('providers')}>加载更多供应商</button>}{profiles?.next_cursor && <button type="button" disabled={catalogLoading} onClick={() => void loadMore('profiles')}>加载更多模型档案</button>}</div>}
      <div className="field"><label htmlFor="model">上游模型名称</label><input id="model" name="model" value={model} onChange={(event) => setModel(event.target.value)} maxLength={128} aria-invalid={Boolean(fields.model)} aria-describedby={fields.model ? 'model-error' : undefined} />{fields.model && <p id="model-error" className="field-error">{fields.model}</p>}</div>
      <p className="field-help">协议：OpenAI Chat Completions · TLS 证书校验：始终开启</p>
      <div className="form-grid">
        <div className="field"><label htmlFor="max_output_parameter">输出上限参数</label><select id="max_output_parameter" name="max_output_parameter" defaultValue={current?.options.max_output_parameter ?? 'auto'}><option value="auto">自动选择</option><option value="max_tokens">max_tokens</option><option value="max_completion_tokens">max_completion_tokens</option></select></div>
        {field('timeout_seconds', '请求超时（秒）', String(current?.options.timeout_seconds ?? 180), 3)}
        {field('concurrency', '并发上限', String(current?.options.concurrency ?? 1), 3)}
        {field('rpm', '每分钟请求上限', String(current?.options.rpm ?? 60), 5)}
      </div>
      {current ? <div className="field"><label htmlFor="status">目标状态</label><select id="status" name="status" defaultValue={current.status}><option value="active">启用</option><option value="disabled">停用</option></select><p className="field-help">配置版本 {current.version}；现有凭证只显示掩码 {current.secret.mask}，凭证版本 {current.secret.version}。</p></div> : <CredentialFields errors={fields} />}
      <div className="form-actions"><button type="submit" className="primary-button" disabled={saving}>{saving ? '正在保存…' : current ? '保存配置' : '创建目标'}</button><button type="button" disabled={saving} onClick={onCancel}>取消</button></div>
      {saving && <Loading>正在保存目标配置…</Loading>}
    </fieldset></form>
  </section>
}
