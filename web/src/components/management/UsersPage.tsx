import { useCallback, useState } from 'react'
import { ApiError } from '../../api'
import { managementApi, type ManagedUser } from '../../management-api'
import { Field, formStatus, formValue, ListControls, ListFeedback, ManagedForm, Pagination, requireText, StatusField, temporaryPassword, useFailure, useManagementList, type ManagementContext } from './shared'

type Editor = { kind: 'create' } | { kind: 'edit' | 'unlock' | 'reset'; user: ManagedUser }
export function UsersPage(props: ManagementContext) {
  // Navigation is a convenience, not authorization. The API enforces system.users.
  return props.systemAdmin ? <Users {...props} /> : <section className="panel"><p className="empty-note">用户管理仅对系统管理员开放。组织管理员可在成员管理中使用已有用户 ID 添加成员。</p></section>
}
function Users(props: ManagementContext) {
  const onFailure = useFailure(props)
  const load = useCallback((cursor: string, q: string, signal: AbortSignal) => managementApi.users(cursor, q, signal), [])
  const list = useManagementList(load, onFailure)
  const [editor, setEditor] = useState<Editor | null>(null)
  const [notice, setNotice] = useState('')
  const close = () => setEditor(null)
  const refresh = () => { close(); list.refresh() }
  if (editor) return <UserForm key={editor.kind} editor={editor} {...props} onFailure={onFailure} onCancel={close} onConflict={refresh} onSaved={() => {
    setNotice(editor.kind === 'create' ? '用户已创建；首次登录必须修改临时密码。' : editor.kind === 'reset' ? '临时密码已重置，该用户现有会话已撤销；请通过安全渠道告知用户。' : editor.kind === 'unlock' ? '已提交清除登录锁定与失败计数。' : '用户已更新。')
    refresh()
  }} />
  return <section className="panel" aria-labelledby="users-title"><div className="section-heading"><h2 id="users-title">系统用户</h2><button onClick={() => { setNotice(''); setEditor({ kind: 'create' }) }}>创建用户</button></div>
    <p className="muted">管理已有账号与临时密码，不提供创建系统管理员或删除用户的入口。锁定详情未由接口公开，不能据此列表判断登录锁定状态。</p>
    {notice && <output className="notice success">{notice}</output>}
    <ListControls list={list} label="用户" /><ListFeedback list={list} label="用户" />
    {list.result && list.result.items.length > 0 && <div className="table-scroll"><table><caption className="sr-only">系统用户列表</caption><thead><tr><th scope="col">账号</th><th scope="col">状态与权限</th><th scope="col">操作</th></tr></thead><tbody>{list.result.items.map((user) => <tr key={user.id}><th scope="row">{user.username}<span className="cell-detail">{user.display_name || '未设置显示名称'} · ID {user.id} · v{user.version}</span></th><td>{user.status === 'active' ? '启用' : '停用'} · {user.system_admin ? '系统管理员' : '普通用户'}<span className="cell-detail">{user.must_change_password ? '下次登录必须改密' : '无强制改密标记'}</span></td><td><div className="row-actions">
      <button disabled={list.loading || Boolean(list.error)} onClick={() => setEditor({ kind: 'edit', user })} aria-label={`编辑用户 ${user.username}`}>编辑</button>
      <button disabled={list.loading || Boolean(list.error)} onClick={() => setEditor({ kind: 'unlock', user })} aria-label={`清除登录锁定 ${user.username}`}>清除登录锁定</button>
      <button disabled={list.loading || Boolean(list.error) || user.id === props.userID} onClick={() => setEditor({ kind: 'reset', user })} aria-label={`重置临时密码 ${user.username}`}>重置临时密码</button>
    </div>{user.id === props.userID && <span className="cell-detail">自己的密码请在账号安全页修改。</span>}</td></tr>)}</tbody></table></div>}
    <Pagination list={list} />
  </section>
}
function UserForm({ editor, csrfToken, userID, onFailure, onSaved, onCancel, onConflict }: ManagementContext & {
  editor: Editor; onFailure: (error: unknown) => boolean; onSaved: () => void; onCancel: () => void; onConflict: () => void
}) {
  const user = editor.kind === 'create' ? null : editor.user
  const title = editor.kind === 'create' ? '创建用户账号' : editor.kind === 'edit' ? '编辑用户账号' : editor.kind === 'reset' ? '重置用户临时密码' : '清除用户登录锁定'
  async function submit(form: HTMLFormElement, signal: AbortSignal) {
    if (editor.kind === 'create') {
      const username = formValue(form, 'username')
      if (!/^[A-Za-z0-9_.-]{3,64}$/.test(username)) throw '用户名须为 3–64 位字母、数字、下划线、点或短横线。'
      return managementApi.createUser(csrfToken, { username, display_name: requireText(formValue(form, 'display_name'), 128, false), password: temporaryPassword(form) }, signal)
    }
    if (editor.kind === 'edit') {
      const status = formStatus(form)
      if (editor.user.id === userID && status !== 'active') throw new ApiError('MI_SELF_LOCKOUT_FORBIDDEN')
      return managementApi.updateUser(csrfToken, editor.user.id, { version: editor.user.version, display_name: requireText(formValue(form, 'display_name'), 128, false), status }, signal)
    }
    if (editor.kind === 'reset') {
      if (editor.user.id === userID) throw new ApiError('MI_SELF_LOCKOUT_FORBIDDEN')
      return managementApi.resetPassword(csrfToken, editor.user.id, editor.user.version, temporaryPassword(form), signal)
    }
    return managementApi.unlockUser(csrfToken, editor.user.id, editor.user.version, signal)
  }
  return <ManagedForm title={title} description={user ? `操作账号：${user.username} · ID ${user.id} · 读取版本 ${user.version}。并发修改会由服务端拒绝，不会自动覆盖。` : '新账号获得普通用户身份。创建后还需单独分配组织成员资格；临时密码只用于本次请求。'} submit={submit} onSaved={onSaved} onCancel={onCancel} onFailure={onFailure} onConflict={onConflict}>
    {editor.kind === 'create' && <Field name="username" label="新用户名" maxLength={64} />}
    {(editor.kind === 'create' || editor.kind === 'edit') && <Field name="display_name" label="显示名称（可选）" value={user?.display_name} help="UTF-8 编码最多 128 字节。" />}
    {editor.kind === 'edit' && user && <StatusField value={user.status} selfProtected={user.id === userID} />}
    {(editor.kind === 'create' || editor.kind === 'reset') && <><p className="security-note">用户下次登录必须修改临时密码。提交后密码字段会清空；不要将密码放入备注、URL 或共享截图。</p><Field name="password" label="临时密码" type="password" maxLength={256} help="至少 12 个字符，UTF-8 编码不超过 256 字节。" /><Field name="confirm_password" label="确认临时密码" type="password" maxLength={256} /></>}
    {editor.kind === 'reset' && <p className="notice warning">确认后将撤销该用户的全部现有会话。</p>}
    {editor.kind === 'unlock' && <p className="notice warning">确认清除该账号的登录失败计数与锁定时间？不会启用已停用账号，也不会修改密码。</p>}
  </ManagedForm>
}
