import { useEffect, useId, useRef, useState } from 'react'
import { ApiError } from '../../api'
import { evidenceDisplayApi, type EvidenceDisplay, type EvidenceDisplayStatus, type EvidenceSelection } from '../../evidence-display-api'
import { runsApi } from '../../runs-api'
import { ErrorNotice, Loading } from '../Feedback'
import type { ReadContext } from '../history/RunHistory'
import { useFailure } from '../management/shared'
import { measured } from './ResultViews'

type Context = ReadContext & EvidenceSelection & { onDenied: (failure: unknown) => void }
const required = ['run.read', 'evidence.read', 'evidence.body']
const unavailable: Record<Exclude<EvidenceDisplayStatus, 'available'>, string> = {
  unavailable_policy_zero: '当前响应正文保留策略为 0 天，正文不可用。',
  unavailable_not_retained: '该正文没有保留，不能从摘要还原。',
  unavailable_not_captured: '此 Attempt 没有捕获到可用正文。',
  unavailable_uncertain: '执行结果不确定，没有可信正文可供展示。',
  unavailable_expired: '正文已超过保留期，不能继续读取。',
  unavailable_deleted: '正文已删除，服务器已核验删除凭证；不能从摘要还原正文。',
  unavailable_legacy_unverified: '历史记录没有可信脱敏证明，禁止回退读取原文。',
  unavailable_redaction_policy: '捕获时脱敏策略未通过，未保留可展示正文。',
  unavailable_safety_limit: '正文触及安全大小或资源上限，未生成展示副本。',
  unavailable_source_invalid: '来源一致性校验未通过，正文不可用。',
  unavailable_cancelled: '捕获已取消，没有可展示正文。',
  unavailable_capture: '可信正文捕获未完成，正文不可用。',
  unavailable_seal: '正文加密封存未完成，正文不可用。',
}
function problem(failure: unknown) {
  if (!(failure instanceof ApiError)) return failure
  if (failure.code === 'MI_EVIDENCE_LIMIT') return '正文读取数量已达上限，请稍后显式重试。'
  if (failure.code === 'MI_EVIDENCE_UNAVAILABLE') return '正文当前不可安全读取；可能已变更、到期或无法通过认证。不会回退读取原文。'
  return failure
}
export function EvidenceDisplayPanel(props: Context) {
  return <EvidenceDisplayScope key={`${props.organizationID}:${props.userID}:${props.runID}:${props.sampleID}:${props.attemptID}:${props.analysisRevision}:${props.isFinal}`} {...props} />
}
function EvidenceDisplayScope({ onDenied, ...context }: Context) {
  const onFailure = useFailure(context)
  const [opened, setOpened] = useState(false), [busy, setBusy] = useState(false), [denied, setDenied] = useState(false)
  const [data, setData] = useState<EvidenceDisplay | null>(null), [error, setError] = useState<unknown>(null)
  const operation = useRef<AbortController | null>(null), active = useRef(false)
  const titleID = useId(), errorID = useId(), heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => () => { operation.current?.abort(); active.current = false }, [])
  useEffect(() => { if (data) heading.current?.focus() }, [data])
  function close() {
    operation.current?.abort(); operation.current = null; active.current = false
    setData(null); setError(null); setOpened(false); setBusy(false)
  }
  async function read() {
    if (active.current || denied) return
    const controller = new AbortController()
    operation.current = controller; active.current = true
    setData(null); setError(null); setOpened(true); setBusy(true)
    try {
      const granted = await runsApi.permissions(context.organizationID, context.userID, controller.signal)
      if (controller.signal.aborted) return
      if (!required.every((permission) => granted.permissions.includes(permission))) throw new ApiError('MI_PERMISSION_DENIED', 403)
      const value = await evidenceDisplayApi.get(context.organizationID, context, controller.signal)
      if (!controller.signal.aborted && operation.current === controller) setData(value)
    } catch (failure) {
      if (controller.signal.aborted || operation.current !== controller) return
      setData(null); setError(failure)
      const unauthenticated = onFailure(failure)
      if (unauthenticated || failure instanceof ApiError && (failure.status === 401 || failure.status === 403)) {
        controller.abort(); setDenied(true); setBusy(false); onDenied(failure)
      }
    } finally {
      if (operation.current === controller) { active.current = false; if (!controller.signal.aborted) setBusy(false) }
    }
  }
  return <section className="result-card" style={{ minWidth: 0, overflowWrap: 'anywhere' }} aria-labelledby={titleID}>
    <div className="section-heading"><h5 ref={heading} tabIndex={-1} id={titleID}>Attempt {context.attemptID} · 授权正文</h5>
      {opened && <button onClick={close}>关闭并清除 Attempt {context.attemptID} 正文</button>}
    </div>
    <p className="field-help">摘要默认不加载正文。显式查看将重新核验 run.read、evidence.read、evidence.body 权限，并接受服务端保留策略与读取审计。正文只在当前面板内存显示，不写入浏览器存储或 S1 报告。</p>
    {!denied && <button disabled={busy} onClick={() => { void read() }}>{opened ? `重新核验并读取 Attempt ${context.attemptID} 正文` : `查看 Attempt ${context.attemptID} 的脱敏正文`}</button>}
    {busy && <Loading>正在核验当前权限并读取受控正文…</Loading>}
    <ErrorNotice error={problem(error)} id={errorID} />
    {denied && <p className="notice warning">当前会话或正文权限已失效，已清除正文并停止读取。请重新核验页面权限。</p>}
    {data && <>
      <p>分析修订 {data.analysis_revision} · {data.is_final ? '该样本最终选择的 Attempt' : '非最终 Attempt，不作为额外独立样本'}</p>
      {data.status !== 'available' ? <p className="notice warning">{unavailable[data.status]}</p> : data.content && <>
        <p className="notice warning">以下为受控脱敏副本，不是原始响应导出，也不代表已获人工审核批准。内容按纯文本显示，不解释 HTML 或 Markdown。</p>
        <dl className="run-metrics"><div><dt>HTTP 状态</dt><dd>{data.content.response.http_status || '未观测'}</dd></div><div><dt>解析状态</dt><dd>{data.content.response.parse_status}</dd></div><div><dt>停止原因</dt><dd>{data.content.response.finish_reason || '未观测'}</dd></div><div><dt>耗时</dt><dd>{measured(data.content.response.duration_ms, 0)} ms</dd></div><div><dt>首 Token</dt><dd>{measured(data.content.response.first_token_ms, 0)} ms</dd></div><div><dt>输入 / 输出 / 总 Token</dt><dd>{measured(data.content.response.prompt_tokens, 0)} / {measured(data.content.response.completion_tokens, 0)} / {measured(data.content.response.total_tokens, 0)}</dd></div><div><dt>推理 Token</dt><dd>{measured(data.content.response.reasoning_tokens, 0)}</dd></div><div><dt>流式结束标记</dt><dd>{data.content.response.stream_terminated ? '已观测' : '未观测'}</dd></div></dl>
        <p className="review-explanation">上游报告模型（仅为自述）：{data.content.response.model_reported || '未提供'}</p>
        <h6>脱敏响应正文</h6>
        <pre className="review-explanation" style={{ maxWidth: '100%', overflowX: 'auto' }}>{data.content.response.content}</pre>
        {data.content.response.content === '' && <p className="field-help">已认证展示副本中的响应正文为空字符串；这不等同于正文不可用。</p>}
        <h6>脱敏请求参数与正文（原规范字符串）</h6>
        <pre className="review-explanation" style={{ maxWidth: '100%', overflowX: 'auto' }}>{data.content.request_json}</pre>
        <p className={data.content.request_changed ? 'notice warning' : 'field-help'}>{data.content.request_changed ? '请求已发生脱敏替换；下方模板哈希与实际请求哈希不同，不能宣称该模板逐字等同于实际上游请求。' : '该副本的请求哈希与模板哈希相同；响应内容仍可能已脱敏。'}</p>
        <p className="result-hash">实际请求哈希：{data.content.request_hash}</p><p className="result-hash">脱敏模板哈希：{data.content.template_hash}</p><p className="result-hash">服务端认证展示载荷哈希：{data.payload_hash}</p>
        <p className="field-help">已省略传输 Header、请求 ID 等元数据。{data.content.response.event_summary_partial ? '流式事件摘要不完整，不能据此还原完整事件流。' : '流式事件仅为有界数值摘要，不包含原始分片。'} 本面板不提供正文下载或自动重放。</p>
      </>}
    </>}
  </section>
}
