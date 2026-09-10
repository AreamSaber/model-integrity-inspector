import { useCallback, useEffect, useRef, useState } from 'react'
import { managementApi, type ManagedOrganization } from '../../management-api'
import { ErrorNotice, Loading } from '../Feedback'
import { Field, formStatus, formValue, ListControls, ListFeedback, ManagedForm, Pagination, requireText, StatusField, useFailure, useManagementList, type ManagementContext } from './shared'

export function OrganizationsPage(props: ManagementContext & { onChanged: (organization: ManagedOrganization) => void }) {
  const onFailure = useFailure(props)
  const load = useCallback((cursor: string, q: string, signal: AbortSignal) => managementApi.organizations(cursor, q, signal), [])
  const list = useManagementList(load, onFailure)
  const [editor, setEditor] = useState<{ organization: ManagedOrganization | null } | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [notice, setNotice] = useState('')
  const request = useRef<AbortController | null>(null)
  useEffect(() => () => request.current?.abort(), [])
  const refresh = () => { setEditor(null); list.refresh() }
  async function edit(org: ManagedOrganization) {
    if (request.current) return
    const controller = new AbortController()
    request.current = controller
    setBusy(true); setError(null); setNotice('')
    try { const organization = await managementApi.organization(org.id, controller.signal); if (!controller.signal.aborted) setEditor({ organization }) }
    catch (failure) { if (!controller.signal.aborted && !onFailure(failure)) setError(failure) }
    finally { request.current = null; if (!controller.signal.aborted) setBusy(false) }
  }
  if (editor) return <OrganizationForm organization={editor.organization} csrfToken={props.csrfToken} onFailure={onFailure} onCancel={() => setEditor(null)} onConflict={refresh} onSaved={(org) => {
    props.onChanged(org); setNotice(editor.organization ? '组织已更新。已停用的组织不能被选作当前工作空间。' : '组织已创建，可在当前组织选择器中切换。'); refresh()
  }} />
  return <section className="panel" aria-labelledby="organizations-admin-title"><div className="section-heading"><h2 id="organizations-admin-title">组织管理目录</h2>{props.systemAdmin && <button disabled={busy} onClick={() => { setNotice(''); setEditor({ organization: null }) }}>创建组织</button>}</div>
    <p className="muted">目录由服务端按账号授权范围返回。创建和修改组织设置需要系统管理员权限。编辑请求的路径与组织头均绑定所选记录，不使用另一个工作空间的 ID。</p>
    {notice && <output className="notice success">{notice}</output>}<ErrorNotice error={error} />{busy && <Loading>正在读取组织最新版本…</Loading>}
    <ListControls list={list} label="组织" /><ListFeedback list={list} label="组织" />
    {list.result && list.result.items.length > 0 && <div className="table-scroll"><table><caption className="sr-only">可管理组织列表</caption><thead><tr><th scope="col">组织</th><th scope="col">设置</th><th scope="col">操作</th></tr></thead><tbody>{list.result.items.map((org) => <tr key={org.id}><th scope="row">{org.name}<span className="cell-detail">ID {org.id} · v{org.version}</span></th><td>{org.status === 'active' ? '启用' : '停用'} · {org.timezone}<span className="cell-detail">完整响应留存：{org.full_response_retention_days} 天</span></td><td>{props.systemAdmin ? <button disabled={busy || list.loading || Boolean(list.error)} onClick={() => void edit(org)} aria-label={`编辑组织 ${org.name}`}>编辑设置</button> : '仅查看'}</td></tr>)}</tbody></table></div>}
    <Pagination list={list} />
  </section>
}
function OrganizationForm({ organization, csrfToken, onFailure, onSaved, onCancel, onConflict }: { organization: ManagedOrganization | null; csrfToken: string; onFailure: (error: unknown) => boolean; onSaved: (org: ManagedOrganization) => void; onCancel: () => void; onConflict: () => void }) {
  async function submit(form: HTMLFormElement, signal: AbortSignal) {
    const body = { name: requireText(formValue(form, 'name').trim(), 128), timezone: requireText(formValue(form, 'timezone').trim(), 64) }
    if (!organization) return managementApi.createOrganization(csrfToken, body, signal)
    const raw = formValue(form, 'retention')
    const retention = Number(raw)
    if (!/^\d+$/.test(raw) || !Number.isInteger(retention) || retention < 0 || retention > 180) throw '完整响应留存天数必须是 0–180 的整数。'
    return managementApi.updateOrganization(csrfToken, organization.id, { ...body, version: organization.version, status: formStatus(form), full_response_retention_days: retention }, signal)
  }
  return <ManagedForm title={organization ? '编辑组织设置' : '创建新组织'} description={organization ? `操作组织：${organization.name} · ID ${organization.id} · 最新读取版本 ${organization.version}。停用将使组织业务不可用；留存配置不代表历史数据已被立即清除。` : '创建组织与创建者管理员成员资格。时区使用 IANA 名称，最终由服务端验证。'} submit={submit} onSaved={onSaved} onFailure={onFailure} onCancel={onCancel} onConflict={onConflict}>
    <Field name="name" label="组织名称" value={organization?.name} help="UTF-8 编码最多 128 字节。" /><Field name="timezone" label="组织时区" value={organization?.timezone ?? 'UTC'} maxLength={64} help="例如 UTC 或 Asia/Shanghai。" />
    {organization && <><StatusField value={organization.status} /><Field name="retention" label="完整响应留存天数" type="number" value={String(organization.full_response_retention_days)} help="0–180 天。" /></>}
  </ManagedForm>
}
