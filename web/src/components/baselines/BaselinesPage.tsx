import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError } from '../../api'
import { baselinesApi, baselineLabels, baselineText, type Baseline } from '../../baselines-api'
import type { ReadPage } from '../../runs-history-api'
import { runsApi } from '../../runs-api'
import { ErrorNotice, Loading } from '../Feedback'
import type { ReadContext } from '../history/RunHistory'
import { useFailure } from '../management/shared'
import { BaselineDetails } from './BaselineDetails'
import { BaselineForm, type BaselineCommand, type BaselineEditor } from './BaselineForms'

const errors: Record<string, string> = { MI_BASELINE_SOURCE_INVALID: '来源必须是当前组织已结束且已发布的有效修订；来源被修改、证据不足或样本过少时不能审批。', MI_BASELINE_INTEGRITY: '参考签名或绑定数据校验失败，已停止操作，请联系管理员。', MI_BASELINE_STATE_CONFLICT: '参考状态已经变化，已批准或退休记录不能静默修改。请重新读取。', MI_BASELINE_EXPIRED: '参考已过期，请重新采样并创建新草稿。' }
const needsSource = ['baseline.read', 'run.read', 'evidence.read']
const unknownOutcome = (failure: unknown) => !(failure instanceof ApiError) || failure.code === 'MI_NETWORK_ERROR' || failure.code === 'MI_INVALID_RESPONSE' || failure.status >= 500
const staleRecord = (failure: unknown) => failure instanceof ApiError && ['MI_CONFLICT', 'MI_VERSION_CONFLICT', 'MI_BASELINE_STATE_CONFLICT'].includes(failure.code)
export function BaselinesPage(context: ReadContext) { return <BaselineScope key={`${context.organizationID}:${context.userID}`} {...context} /> }
function BaselineScope(context: ReadContext) {
  const onFailure = useFailure(context)
  const [permissions, setPermissions] = useState<string[] | null>(null), [page, setPage] = useState<ReadPage<Baseline> | null>(null), [record, setRecord] = useState<Baseline | null>(null)
  const [editor, setEditor] = useState<BaselineEditor | null>(null), [query, setQuery] = useState(''), [draftQuery, setDraftQuery] = useState(''), [cursors, setCursors] = useState(['']), [reload, setReload] = useState(0)
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(null), [notice, setNotice] = useState(''), [uncertain, setUncertain] = useState(false)
  const active = useRef(false), operation = useRef<AbortController | null>(null)
  const cursor = cursors[cursors.length - 1]
  useEffect(() => () => operation.current?.abort(), [])
  useEffect(() => {
    const controller = new AbortController()
    void (async () => {
      const granted = await runsApi.permissions(context.organizationID, context.userID, controller.signal)
      if (controller.signal.aborted) return
      if (!granted.permissions.includes('baseline.read')) throw new ApiError('MI_PERMISSION_DENIED', 403)
      setPermissions(granted.permissions)
      const result = await baselinesApi.list(context.organizationID, query, cursor, controller.signal)
      if (!controller.signal.aborted) setPage(result)
    })().catch((failure: unknown) => {
      if (controller.signal.aborted) return
      setPage(null); setRecord(null); setEditor(null); setPermissions(null); setNotice('')
      onFailure(failure); setError(failure)
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [context.organizationID, context.userID, query, cursor, reload, onFailure])
  function fail(failure: unknown) {
    if (onFailure(failure) || (failure instanceof ApiError && failure.status === 403)) { setPermissions(null); setPage(null); setRecord(null); setEditor(null); setNotice('') }
    setError(failure)
  }
  function refresh(next = [''], search = query) { setPage(null); setRecord(null); setEditor(null); setPermissions(null); setError(null); setLoading(true); setCursors(next); setQuery(search); setReload((value) => value + 1) }
  function search(event: FormEvent) { event.preventDefault(); if (!baselineText(draftQuery, 128, false)) { setError('搜索名称不能超过 128 字节或包含控制字符。'); return }; refresh([''], draftQuery.trim()) }
  async function open(id: string) {
    if (active.current || loading) return
    const controller = new AbortController(); operation.current = controller; active.current = true; setBusy(true); setError(null); setRecord(null); setEditor(null)
    try { const value = await baselinesApi.get(context.organizationID, id, controller.signal); if (!controller.signal.aborted) setRecord(value) }
    catch (failure) { if (!controller.signal.aborted) fail(failure) }
    finally { active.current = false; if (!controller.signal.aborted) setBusy(false) }
  }
  async function submit(command: BaselineCommand) {
    if (active.current || loading || uncertain) return
    const controller = new AbortController(); operation.current = controller; active.current = true; setBusy(true); setError(null); setNotice('')
    let dispatched = false
    try {
      const granted = await runsApi.permissions(context.organizationID, context.userID, controller.signal)
      if (controller.signal.aborted) return
      setPermissions(granted.permissions)
      const required = command.kind === 'create' ? [...needsSource, 'baseline.write'] : command.kind === 'approve' ? [...needsSource, 'baseline.approve'] : ['baseline.read', command.kind === 'edit' ? 'baseline.write' : 'baseline.approve']
      if (!required.every((code) => granted.permissions.includes(code))) throw new ApiError('MI_PERMISSION_DENIED', 403)
      if (command.kind !== 'create' && !record) throw new ApiError('MI_INVALID_REQUEST')
      dispatched = true
      const result = command.kind === 'create' ? await baselinesApi.create(context.organizationID, context.csrfToken, context.userID, command.body, controller.signal) :
        command.kind === 'edit' ? await baselinesApi.patch(context.organizationID, context.csrfToken, record!, { version: record!.version, name: command.name, expires_at: command.expiry }, controller.signal) :
          command.kind === 'approve' ? await baselinesApi.approve(context.organizationID, context.csrfToken, context.userID, record!, { version: record!.version, reason: command.reason, business_review: command.business, acknowledge_development_limits: true }, controller.signal) : await baselinesApi.retire(context.organizationID, context.csrfToken, record!, command.reason, controller.signal)
      if (controller.signal.aborted) return
      setRecord(result); setPage(null); setEditor(null); setNotice(`已保存组织参考 ${result.id} · v${result.version}。此操作不改变机器结果或可信评分资格。`)
    } catch (failure) {
      if (controller.signal.aborted) return
      if (dispatched && unknownOutcome(failure)) { setUncertain(true); setEditor(null); setRecord(null); setPage(null) }
      if (staleRecord(failure) || (failure instanceof ApiError && failure.code === 'MI_BASELINE_EXPIRED')) { setEditor(null); setRecord(null); setPage(null) }
      fail(failure)
    } finally { active.current = false; if (!controller.signal.aborted) setBusy(false) }
  }
  const hasSource = needsSource.every((code) => permissions?.includes(code)), canWrite = permissions?.includes('baseline.write'), canApprove = permissions?.includes('baseline.approve')
  const blocked = loading || busy || uncertain || Boolean(error), draft = record?.status === 'draft', canAdmit = record && draft && record.valid_samples >= 6 && record.overall_risk !== null
  return <section className="panel baseline-page" aria-labelledby="baseline-list-title"><div className="section-heading"><h2 id="baseline-list-title">组织参考基线</h2><button disabled={blocked || !hasSource || !canWrite} onClick={() => { setRecord(null); setEditor('create'); setNotice('') }}>创建基线草稿</button></div>
    <p className="notice warning">当前只管理组织审核参考：来源与区域未经系统验证，开发规则未经独立校准且模板公开。即使已审批，也不参与可信对照评分，不提升证据等级，不代表供应商真实性证明或项目正式批准。</p>
    <p className="field-help">查询和管理均不触发付费检测。名称搜索由服务端完成，签名游标绑定当前用户、组织和搜索条件；不把当前页状态过滤冒充全量筛选。</p>
    <ErrorNotice error={error instanceof ApiError && errors[error.code] ? errors[error.code] : error} id="baseline-error" />
    {Boolean(error) && <p className="field-help">本次操作未确认成功；权限失败会清除本页缓存。请核对输入或重新读取，不会自动重试写操作。</p>}
    {staleRecord(error) && <p className="notice warning">版本或状态冲突：未自动覆盖。点击“刷新基线与权限”读取最新版本后，再明确选择操作。</p>}
    {notice && <output className="notice success">{notice}</output>}
    {uncertain && <div className="notice warning"><p>提交结果未确认，服务端可能已保存。不要直接重试创建或审批；请先刷新列表、按名称查询并打开最新记录核对。取消请求不能撤销已保存变更。</p><button disabled={loading || busy || !page} onClick={() => { setUncertain(false); setError(null) }}>已核对最新记录，允许新的手动操作</button></div>}
    <form className="management-search" aria-label="搜索参考基线" onSubmit={search}><label htmlFor="baseline-query">服务端搜索基线名称</label><input id="baseline-query" type="search" value={draftQuery} onChange={(event) => setDraftQuery(event.target.value)} maxLength={128} /><button disabled={loading || busy}>搜索基线</button><button type="button" disabled={loading || busy} onClick={() => refresh()}>刷新基线与权限</button></form>
    {loading && <Loading>正在读取基线与当前权限…</Loading>}{busy && <Loading>正在处理基线操作…</Loading>}
    {!loading && permissions && (!canWrite || !hasSource) && <p className="field-help">创建草稿需要 baseline.write、run.read 和 evidence.read；审批另需 baseline.approve，不从系统管理员标记推断权限。</p>}
    {page && <>{page.items.length ? <div className="table-scroll"><table><caption className="sr-only">当前组织参考基线列表</caption><thead><tr><th scope="col">参考 / 来源 Run</th><th scope="col">审核状态 / 有效样本</th><th scope="col">到期时间</th><th scope="col">操作</th></tr></thead><tbody>{page.items.map((item) => <tr key={item.id}><th scope="row">{item.name}<span className="cell-detail">基线 {item.id} · Run {item.run_id}</span></th><td><span className={`baseline-status baseline-status-${item.status}`}>{baselineLabels[item.status]}</span><span className="cell-detail">{item.valid_samples} / {item.expected_samples} · v{item.version}</span></td><td><time dateTime={item.expires_at}>{new Date(item.expires_at).toLocaleString()}</time></td><td><button disabled={loading || busy} onClick={() => void open(item.id)} aria-label={`查看基线 ${item.name}`}>查看详情</button></td></tr>)}</tbody></table></div> : <p className="empty-note">没有符合名称条件的组织基线；空列表不表示已有可信或健康基线。</p>}</>}
    <div className="pagination"><button disabled={loading || busy || cursors.length === 1} onClick={() => refresh(cursors.slice(0, -1))}>基线上一页</button><span>基线第 {cursors.length} 页</span><button disabled={loading || busy || !page?.next_cursor || cursors.length >= 1000 || (page?.next_cursor ? cursors.includes(page.next_cursor) : false)} onClick={() => { if (page?.next_cursor) refresh([...cursors, page.next_cursor]) }}>基线下一页</button></div>
    {record && <><BaselineDetails record={record} canReadRun={permissions?.includes('run.read') === true} /><div className="form-actions"><button disabled={blocked || !canWrite || !draft} onClick={() => setEditor('edit')}>编辑此草稿</button><button disabled={blocked || !canApprove || !hasSource || !canAdmit} onClick={() => setEditor('approve')}>审批此组织参考</button><button disabled={blocked || !canApprove || record.status === 'retired'} onClick={() => setEditor('retire')}>退休此参考</button><button disabled={loading || busy} onClick={() => void open(record.id)}>重新读取此参考</button></div></>}
    {editor && <BaselineForm key={`${editor}:${record?.id ?? 'new'}:${record?.version ?? 0}`} kind={editor} current={record} busy={busy} onSubmit={(command) => void submit(command)} onCancel={() => setEditor(null)} />}
  </section>
}
