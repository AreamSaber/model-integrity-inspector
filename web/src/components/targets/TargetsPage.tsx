import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { passwordChangeRequired, sessionInvalid } from '../../api'
import { targetsApi, type Page, type Target } from '../../targets-api'
import { ErrorNotice, Loading } from '../Feedback'
import { TargetForm, type TargetCallbacks } from './TargetForm'
import { SecretForm } from './SecretForm'

type Editor = { mode: 'create' } | { mode: 'edit' | 'rotate' | 'delete'; target: Target } | null
export function TargetsPage({ organizationID, csrfToken, onSignedOut, onPasswordRequired }: TargetCallbacks) {
  const [page, setPage] = useState<Page<Target> | null>(null)
  const [cursor, setCursor] = useState('')
  const [history, setHistory] = useState<string[]>([])
  const [attempt, setAttempt] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<unknown>(null)
  const [notice, setNotice] = useState('')
  const [editor, setEditor] = useState<Editor>(null)
  const [busy, setBusy] = useState(false)
  const operation = useRef<AbortController | null>(null)
  const pending = useRef(false)
  const handleError = useCallback((failure: unknown) => {
    if (sessionInvalid(failure)) onSignedOut('会话已失效，请重新登录。')
    else if (passwordChangeRequired(failure)) onPasswordRequired()
    else setError(failure)
  }, [onSignedOut, onPasswordRequired])
  useEffect(() => () => operation.current?.abort(), [])
  useEffect(() => {
    const controller = new AbortController()
    void targetsApi.list(organizationID, cursor, controller.signal).then((result) => {
      if (!controller.signal.aborted) setPage(result)
    }).catch((failure: unknown) => { if (!controller.signal.aborted) handleError(failure) }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [organizationID, cursor, attempt, handleError])
  function refresh() { setLoading(true); setError(null); setAttempt((value) => value + 1) }
  const cancel = () => { setEditor(null); setError(null) }
  async function open(mode: 'edit' | 'rotate' | 'delete', targetID: string) {
    if (pending.current) return
    pending.current = true
    const controller = new AbortController()
    operation.current = controller
    setBusy(true)
    setError(null)
    setNotice('')
    try {
      const result = await targetsApi.get(organizationID, targetID, controller.signal)
      if (!controller.signal.aborted) setEditor({ mode, target: result })
    } catch (failure) { if (!controller.signal.aborted) handleError(failure) }
    finally { pending.current = false; if (!controller.signal.aborted) setBusy(false) }
  }
  function saved(result: Target) {
    setEditor(null)
    setNotice(`目标「${result.name}」已保存，配置版本 ${result.version}，凭证版本 ${result.secret.version}。未发起上游调用。`)
    refresh()
  }
  async function remove(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (pending.current || editor?.mode !== 'delete') return
    if (String(new FormData(event.currentTarget).get('confirm_name') ?? '') !== editor.target.name) { setError('请输入完整目标名称以确认删除。'); return }
    pending.current = true
    const controller = new AbortController()
    operation.current = controller
    setBusy(true)
    setError(null)
    try {
      await targetsApi.delete(organizationID, csrfToken, editor.target.id, editor.target.version, controller.signal)
      if (!controller.signal.aborted) { setEditor(null); setNotice('目标及其当前加密凭证已删除；既有检测历史按服务端保留规则保留。'); refresh() }
    } catch (failure) { if (!controller.signal.aborted) handleError(failure) }
    finally { pending.current = false; if (!controller.signal.aborted) setBusy(false) }
  }
  const callbacks = { organizationID, csrfToken, onSignedOut, onPasswordRequired }
  return <>
    {notice && <output className="notice success">{notice}</output>}
    <ErrorNotice error={error} id="targets-error" />
    {busy && <Loading>正在处理目标请求…</Loading>}
    {editor?.mode === 'create' || editor?.mode === 'edit'
      ? <TargetForm key={editor.mode === 'edit' ? `${editor.target.id}-${editor.target.version}` : 'create'} {...callbacks} current={editor.mode === 'edit' ? editor.target : undefined} onSaved={saved} onCancel={cancel} onReload={() => { if (editor.mode === 'edit') void open('edit', editor.target.id); else cancel() }} />
      : editor?.mode === 'rotate'
        ? <SecretForm key={`${editor.target.id}-${editor.target.version}`} {...callbacks} current={editor.target} onSaved={saved} onCancel={cancel} onReload={() => void open('rotate', editor.target.id)} />
        : editor?.mode === 'delete'
          ? <section className="panel delete-panel" aria-labelledby="delete-title"><h2 id="delete-title">删除目标：{editor.target.name}</h2><p>此操作删除目标及当前加密凭证，无法从此页面恢复。历史样本和结果按保留策略保留，不会因删除目标而伪造或清空历史。</p><form aria-label="确认删除目标" onSubmit={remove}><fieldset disabled={busy}><legend className="sr-only">删除确认</legend><div className="field"><label htmlFor="confirm_name">输入目标名称确认删除</label><input id="confirm_name" name="confirm_name" autoComplete="off" /></div><div className="form-actions"><button className="danger-button" type="submit">确认删除目标</button><button type="button" onClick={cancel}>取消</button><button type="button" onClick={() => void open('delete', editor.target.id)}>重新读取目标</button></div></fieldset></form></section>
          : <section className="panel" aria-labelledby="target-list-title">
            <div className="section-heading"><h2 id="target-list-title">组织检测目标</h2><div className="form-actions"><button disabled={loading || busy} onClick={refresh}>刷新目标</button><button disabled={busy} onClick={() => { setEditor({ mode: 'create' }); setError(null); setNotice('') }}>新建目标</button></div></div>
            <p className="muted">列表来自当前组织。仅展示配置和凭证掩码，不返回 API Key、自定义请求头或密文。搜索将在服务端过滤能力接入后提供。</p>
            {loading && <Loading>正在读取目标列表…</Loading>}
            {Boolean(error) && page && <p className="empty-note">读取失败，下方保留上次成功的列表，可能已过期；请刷新后操作。</p>}
            {!loading && !error && page?.items.length === 0 && <p className="empty-note">当前页没有检测目标。可新建目标，或返回上一页。</p>}
            {page && page.items.length > 0 && <div className="table-scroll"><table><caption className="sr-only">当前组织目标列表</caption><thead><tr><th scope="col">目标 / 模型</th><th scope="col">Endpoint / 环境</th><th scope="col">状态 / 凭证</th><th scope="col">操作</th></tr></thead><tbody>{page.items.map((item) => <tr key={item.id}><th scope="row"><strong>{item.name}</strong><small className="cell-detail">{item.model}<br />ID {item.id} · v{item.version}</small></th><td>{item.endpoint}<small className="cell-detail">{item.environment || '未标注环境'} · {item.channel_id || '未标注渠道'}</small></td><td>{item.status === 'active' ? '启用' : item.status === 'disabled' ? '停用' : '已删除'}<small className="cell-detail">{item.secret.mask} · v{item.secret.version}</small></td><td><div className="row-actions"><button disabled={busy || loading || Boolean(error) || item.status === 'deleted'} onClick={() => void open('edit', item.id)} aria-label={`编辑 ${item.name}`}>编辑</button><button disabled={busy || loading || Boolean(error) || item.status === 'deleted'} onClick={() => void open('rotate', item.id)} aria-label={`轮换凭证 ${item.name}`}>轮换凭证</button><button disabled={busy || loading || Boolean(error) || item.status === 'deleted'} onClick={() => void open('delete', item.id)} aria-label={`删除 ${item.name}`}>删除</button></div></td></tr>)}</tbody></table></div>}
            <div className="pagination"><button disabled={loading || busy || history.length === 0} onClick={() => { setCursor(history[history.length - 1]); setHistory((previous) => previous.slice(0, -1)); setPage(null); setLoading(true); setError(null) }}>上一页</button><span>第 {history.length + 1} 页</span><button disabled={loading || busy || !page?.next_cursor || Boolean(error)} onClick={() => { if (page?.next_cursor) { setHistory((previous) => [...previous, cursor]); setCursor(page.next_cursor); setPage(null); setLoading(true); setError(null) } }}>下一页</button></div>
          </section>}
    <section className="panel"><div className="section-heading"><h2>检测操作</h2><span className="status-label">尚未接入</span></div><p className="muted">预检和发起检测尚未连接后端，当前页面不会执行上游调用或返回模拟成功。</p><div className="form-actions"><button disabled>预检（尚未接入）</button><button disabled>发起检测（尚未接入）</button></div></section>
  </>
}
