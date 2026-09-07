import { useCallback, useEffect, useState } from 'react'
import { ApiError, id, type Role } from '../../api'
import { managementApi, type Member } from '../../management-api'
import { ErrorNotice, Loading } from '../Feedback'
import { Field, formStatus, formValue, ListControls, ListFeedback, ManagedForm, Pagination, StatusField, useFailure, useManagementList, type ManagementContext } from './shared'

export function MembersPage(props: ManagementContext & { organizationID: string; organizationName: string }) {
  const onFailure = useFailure(props)
  const load = useCallback((cursor: string, q: string, signal: AbortSignal) => managementApi.members(props.organizationID, cursor, q, signal), [props.organizationID])
  const list = useManagementList(load, onFailure)
  const [editor, setEditor] = useState<{ member: Member | null } | null>(null)
  const [notice, setNotice] = useState('')
  const refresh = () => { setEditor(null); list.refresh() }
  if (editor) return <MemberForm {...props} member={editor.member} onFailure={onFailure} onCancel={() => setEditor(null)} onConflict={refresh} onSaved={() => { setNotice(editor.member ? '成员资格已更新，权限变更由服务端即时校验。' : '成员已添加到当前组织。'); refresh() }} />
  return <section className="panel" aria-labelledby="members-title"><div className="section-heading"><h2 id="members-title">{props.organizationName} · 组织成员</h2><button onClick={() => { setNotice(''); setEditor({ member: null }) }}>添加成员</button></div>
    <p className="muted">成员来自当前组织的真实接口。修改需要成员管理权限；可用角色目录不代表当前账号拥有这些权限。移除访问使用停用成员资格，不删除用户账号。</p>
    {notice && <output className="notice success">{notice}</output>}
    <ListControls list={list} label="成员" /><ListFeedback list={list} label="成员" />
    {list.result && list.result.items.length > 0 && <div className="table-scroll"><table><caption className="sr-only">当前组织成员列表</caption><thead><tr><th scope="col">用户与成员记录</th><th scope="col">角色与额外授权</th><th scope="col">操作</th></tr></thead><tbody>{list.result.items.map((member) => <tr key={member.id}><th scope="row">{member.username}<span className="cell-detail">用户 ID {member.user_id}<br />成员 ID {member.id} · v{member.version}</span></th><td>{member.status === 'active' ? '启用' : '停用'} · 角色：{member.roles.join('、') || '无'}<span className="cell-detail">额外授权：{member.permissions.join('、') || '无'}（不含角色内置权限）</span></td><td><button disabled={list.loading || Boolean(list.error)} onClick={() => setEditor({ member })} aria-label={`编辑成员 ${member.username}`}>编辑成员资格</button></td></tr>)}</tbody></table></div>}
    <Pagination list={list} />
  </section>
}
function MemberForm({ member, organizationID, organizationName, csrfToken, userID, onFailure, onSaved, onCancel, onConflict }: ManagementContext & {
  organizationID: string; organizationName: string; member: Member | null; onFailure: (failure: unknown) => boolean; onSaved: () => void; onCancel: () => void; onConflict: () => void
}) {
  const [roles, setRoles] = useState<Role[] | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [loading, setLoading] = useState(true)
  const [attempt, setAttempt] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    async function load() {
      const records: Role[] = []
      const cursors = new Set<string>()
      let cursor = ''
      do {
        const page = await managementApi.roles(organizationID, cursor, controller.signal)
        records.push(...page.items)
        if (records.length > 100 || cursors.size > 20 || (page.next_cursor && cursors.has(page.next_cursor))) throw new ApiError('MI_INVALID_RESPONSE')
        cursor = page.next_cursor ?? ''
        if (cursor) cursors.add(cursor)
      } while (cursor && !controller.signal.aborted)
      if (new Set(records.map((role) => role.name)).size !== records.length || records.length === 0) throw new ApiError('MI_INVALID_RESPONSE')
      if (!controller.signal.aborted) setRoles(records)
    }
    void load().catch((failure: unknown) => { if (!controller.signal.aborted && !onFailure(failure)) setError(failure) }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [organizationID, onFailure, attempt])
  if (loading || error || !roles) return <section className="panel"><h2>读取成员角色目录</h2><p className="muted">正在为 {organizationName} 读取真实角色与权限定义，不提供假设的默认权限。</p>{loading && <Loading>正在读取完整角色目录…</Loading>}<ErrorNotice error={error} />{!loading && <button onClick={() => { setLoading(true); setError(null); setAttempt((value) => value + 1) }}>重试读取目录</button>}<button onClick={onCancel}>取消</button></section>
  const roleNames = [...new Set([...roles.map((role) => role.name), ...(member?.roles ?? [])])]
  const permissions = [...new Set([...roles.flatMap((role) => role.permissions).filter((name) => !name.startsWith('system.')), ...(member?.permissions ?? [])])].sort()
  async function submit(form: HTMLFormElement, signal: AbortSignal) {
    const data = new FormData(form)
    const selectedRoles = data.getAll('roles').map(String)
    const selectedPermissions = data.getAll('permissions').map(String)
    const status = member ? formStatus(form) : 'active'
    if ((status === 'active' && selectedRoles.length === 0) || selectedRoles.length > 5 || selectedPermissions.length > 100 || selectedRoles.some((name) => !roleNames.includes(name)) || selectedPermissions.some((name) => !permissions.includes(name))) throw '启用的成员至少需要一个角色，最多 5 个角色及 100 个额外授权。'
    if (!member) {
      const user = formValue(form, 'user_id').trim()
      if (!id(user) || BigInt(user) > 9223372036854775807n) throw '请输入系统管理员提供的有效用户 ID（正整数文本）。'
      return managementApi.addMember(csrfToken, organizationID, { user_id: user, roles: selectedRoles, permissions: selectedPermissions }, signal)
    }
    if (member.user_id === userID && status !== 'active') throw new ApiError('MI_SELF_LOCKOUT_FORBIDDEN')
    return managementApi.updateMember(csrfToken, organizationID, member.id, { version: member.version, roles: selectedRoles, permissions: selectedPermissions, status }, signal)
  }
  return <ManagedForm title={member ? '编辑组织成员资格' : '添加组织成员'} description={`操作组织：${organizationName} · ID ${organizationID}。${member ? `用户 ${member.username} · 成员 ID ${member.id} · 读取版本 ${member.version}。` : '只能添加已存在且启用的用户，不会同时创建用户。'}`} submit={submit} onSaved={onSaved} onFailure={onFailure} onCancel={onCancel} onConflict={onConflict}>
    {!member && <Field name="user_id" label="已有用户 ID" maxLength={19} help="请向系统管理员获取。普通组织管理员不能浏览全局用户目录；此处始终按文本传输 ID。" />}
    {member && <StatusField value={member.status} selfProtected={member.user_id === userID} />}
    <fieldset className="grant-fields"><legend>成员角色</legend><p className="field-help">角色包含下列内置权限。服务端会阻止超出操作者权限的授权，以及移除最后管理员或锁定自己的操作。</p>
      {roleNames.map((name, index) => <label className="grant-option" key={name} htmlFor={`role-${index}`}><input type="checkbox" id={`role-${index}`} name="roles" value={name} defaultChecked={member?.roles.includes(name) ?? false} /><span>{name}<small>{roles.find((role) => role.name === name)?.permissions.join(' · ') || '记录现有角色，目录未提供定义；请与管理员确认。'}</small></span></label>)}
    </fieldset>
    <fieldset className="grant-fields"><legend>额外授权（可选）</legend><p className="field-help">仅表示角色之外单独添加的权限。清空勾选会清除额外授权，但不移除角色自带权限。</p>
      {permissions.map((name, index) => <label className="grant-option" key={name} htmlFor={`permission-${index}`}><input type="checkbox" id={`permission-${index}`} name="permissions" value={name} defaultChecked={member?.permissions.includes(name) ?? false} /><span>{name}</span></label>)}
    </fieldset>
  </ManagedForm>
}
