import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, object } from '../../api'
import { comparisonApi, comparisonHref, comparisonLimitations, comparisonSelection, descriptiveDifference, type Comparison, type ComparisonSelection, type ComparisonSide } from '../../comparison-api'
import { packageLabels, riskLabels } from '../../runs-history-api'
import type { Versions } from '../../runs-api'
import { ErrorNotice, Loading } from '../Feedback'
import type { ReadContext } from '../history/RunHistory'
import { useFailure } from '../management/shared'

type Props = ReadContext & { selection?: ComparisonSelection }
export function ComparisonPage(props: Props) { return <ComparisonScope key={`${props.organizationID}:${props.userID}:${props.selection?.left ?? ''}:${props.selection?.right ?? ''}:${props.selection?.revision ?? 1}`} {...props} /> }
function ComparisonScope({ selection, ...context }: Props) {
  const onFailure = useFailure(context)
  const [left, setLeft] = useState(selection?.left ?? ''), [right, setRight] = useState(selection?.right ?? '')
  const [data, setData] = useState<Comparison | null>(null), [error, setError] = useState<unknown>(null)
  const [loading, setLoading] = useState(Boolean(selection)), [reload, setReload] = useState(0)
  const pinned = useRef<string | null>(null), title = useRef<HTMLHeadingElement>(null)
  const selectedLeft = selection?.left, selectedRight = selection?.right, revision = selection?.revision
  useEffect(() => {
    if (!selectedLeft || !selectedRight || revision !== 1) return
    const controller = new AbortController()
    void comparisonApi.read(context.organizationID, context.userID, { left: selectedLeft, right: selectedRight, revision }, controller.signal).then((value) => {
      if (controller.signal.aborted) return
      // Metadata/summary both belong to completed, immutable revisions. A retry
      // cannot quietly substitute a newer score under the same IDs/revision.
      const snapshot = JSON.stringify(value, (_key, item: unknown) => object(item) ? Object.fromEntries(Object.entries(item).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)) : item)
      if (pinned.current !== null && pinned.current !== snapshot) throw new ApiError('MI_INVALID_RESPONSE')
      pinned.current = snapshot; setData(value); title.current?.focus()
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      setData(null)
      const handled = onFailure(failure)
      if (handled || (failure instanceof ApiError && (failure.status === 401 || failure.status === 403))) pinned.current = null
      if (!handled) setError(failure)
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [selectedLeft, selectedRight, revision, context.organizationID, context.userID, reload, onFailure])
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    try {
      const pair = comparisonSelection(left, right, 1)
      setError(null)
      if (selectedLeft === pair.left && selectedRight === pair.right) { setData(null); setLoading(true); setReload((value) => value + 1) }
      else window.location.hash = comparisonHref(pair.left, pair.right)
    } catch { setError('请输入两个不同的 Run ID：仅十进制数字、无前导零或空格，最大为 9223372036854775807；本页只支持已发布的分析修订 1。') }
  }
  return <section className="panel" aria-labelledby="comparison-title">
    <div className="section-heading"><h2 id="comparison-title" ref={title} tabIndex={-1}>两任务固定修订对比</h2><a href="#/runs">← 返回检测历史</a></div>
    <p className="notice warning">仅对比用户明确选择的两个 Run 的已发布修订 1。全部差值是描述性右侧减左侧，不是显著性、因果关系、可信基线或新的评分；未校准开发结果不能证明模型真假或供应商内部配置。</p>
    <form className="history-filters" aria-label="选择两个固定修订任务" onSubmit={submit} noValidate>
      <label htmlFor="comparison-left">左侧 Run ID<input id="comparison-left" inputMode="numeric" maxLength={19} value={left} onChange={(event) => setLeft(event.target.value)} /></label>
      <label htmlFor="comparison-right">右侧 Run ID<input id="comparison-right" inputMode="numeric" maxLength={19} value={right} onChange={(event) => setRight(event.target.value)} /></label>
      <div className="form-actions"><button type="submit" disabled={loading}>读取两个固定修订</button></div>
    </form>
    <p className="field-help">每次显式读取最多 5 个 GET：一次当前组织权限、两份 Run 元数据和两份结果摘要。不遍历历史，不访问当前目标档案，不发起检测、重新分析、POST 或自动导出。左右顺序由选择决定，不自动按时间排序。</p>
    <ErrorNotice error={error} id="comparison-error" />
    {loading && <Loading>正在核对两侧身份、冻结版本与当前权限…</Loading>}
    {!selection && !loading && <p className="empty-note">请从历史选择两个已有结果，或输入两个 Run ID。未选择时不读取任何比较数据。</p>}
    {error instanceof ApiError && error.status === 404 && <p className="empty-note">至少一侧在当前组织下不存在可读取的已发布修订。不会显示半边结果或把缺失替换为 0。</p>}
    {error instanceof ApiError && error.status === 403 && <p className="notice warning">当前读取权限不足或已撤销，已清除两侧缓存。请核对组织和成员权限。</p>}
    {error instanceof ApiError && error.code === 'MI_INVALID_RESPONSE' && <p className="notice warning">两侧读取中的身份、终态、样本计数或冻结版本不一致，或同一修订发生变化。已停止展示，请核对后手动重读。</p>}
    {data && <ComparisonTables value={data} />}
    <p className="field-help">此页不是历史趋势统计、网关证据或成对基线分析；也不生成两个任务的差异报告文件。正式审核未完成。请求失败、切换组织/账号/任务或离开页面会清除本地显示，不影响服务端结果。</p>
  </section>
}
function measured(value: number | null) { return value === null ? '未测 / 不可估' : value.toFixed(1) }
function delta(left: number | null, right: number | null) {
  const value = descriptiveDifference(left, right)
  return value === null ? '不可计算（至少一侧未测）' : `${value > 0 ? '+' : ''}${value.toFixed(1)}`
}
function published(value: ComparisonSide) {
  return <><a href={`#/results/${value.run.id}/1`}>Run {value.run.id} · 修订 1</a><span className="cell-detail">结果发布于 <time dateTime={value.result.created_at}>{new Date(value.result.created_at).toLocaleString()}</time></span></>
}
export function ComparisonTables({ value }: { value: Comparison }) {
  const { left, right } = value
  const metrics = [
    ['隐藏指令风险', left.result.prompt_risk, right.result.prompt_risk],
    ['Token 参数风险', left.result.token_risk, right.result.token_risk],
    ['响应完整性风险', left.result.response_risk, right.result.response_risk],
    ['协议 / 证据风险', left.result.evidence_risk, right.result.evidence_risk],
    ['已发布综合风险', left.result.overall_risk, right.result.overall_risk],
    ['置信度指数（不是概率）', left.result.confidence, right.result.confidence],
  ] as const
  const completeness = { full: '完整', partial: '部分', insufficient: '证据不足' }
  const versionNames: Record<keyof Versions, string> = { rule_bundle: '规则包', template_bundle: '模板包', scoring: '评分', tokenizer_bundle: 'Tokenizer 包' }
  return <>
    <section className="result-card" aria-labelledby="comparison-limits"><h3 id="comparison-limits">可比性与解释限制</h3><ul>{comparisonLimitations(value).map((limit) => <li key={limit}>{limit}</li>)}</ul><p className="field-help">即使目标 ID、检测包和版本相同，本页也未验证两次实验的其他配置、提示内容或随机变量等价。版本变化不能直接归因行为变化；没有显著性或风险升降判定。</p></section>
    <div className="table-scroll"><table><caption>两个固定发布修订的描述性对比</caption><thead><tr><th scope="col">指标</th><th scope="col">左侧</th><th scope="col">右侧</th><th scope="col">右 − 左（描述性）</th></tr></thead><tbody>
      <tr><th scope="row">来源</th><td>{published(left)}</td><td>{published(right)}</td><td>不同 Run，不自动配对</td></tr>
      <tr><th scope="row">冻结目标 ID</th><td>{left.run.target_id}</td><td>{right.run.target_id}</td><td>{left.run.target_id === right.run.target_id ? '相同 ID，配置未比对' : '不同目标'}</td></tr>
      <tr><th scope="row">冻结检测包</th><td>{packageLabels[left.run.package]}</td><td>{packageLabels[right.run.package]}</td><td>{left.run.package === right.run.package ? '包名相同，具体参数未比对' : '覆盖范围可能不同'}</td></tr>
      {metrics.map(([label, a, b]) => <tr key={label}><th scope="row">{label}</th><td>{measured(a)}</td><td>{measured(b)}</td><td>{delta(a, b)}</td></tr>)}
      <tr><th scope="row">风险信号分类</th><td>{riskLabels[left.result.risk_level]}</td><td>{riskLabels[right.result.risk_level]}</td><td>分类不做数值相减</td></tr>
      <tr><th scope="row">完整性</th><td>{completeness[left.result.completeness]}</td><td>{completeness[right.result.completeness]}</td><td>缺失不视为无风险</td></tr>
      <tr><th scope="row">纳入分析有效样本 / 预期样本</th><td>{left.result.valid_samples} / {left.result.expected_samples}</td><td>{right.result.valid_samples} / {right.result.expected_samples}</td><td>{delta(left.result.valid_samples, right.result.valid_samples)} 个有效样本（非成功率）</td></tr>
      <tr><th scope="row">证据等级</th><td>{left.result.evidence_grade}</td><td>{right.result.evidence_grade}</td><td>仅开发 C / D，不升级为 A / B</td></tr>
    </tbody></table></div>
    <div className="table-scroll"><table><caption>各任务冻结版本（不是当前系统默认值）</caption><thead><tr><th scope="col">版本</th><th scope="col">左侧</th><th scope="col">右侧</th><th scope="col">一致性</th></tr></thead><tbody>{(Object.keys(versionNames) as (keyof Versions)[]).map((key) => <tr key={key}><th scope="row">{versionNames[key]}</th><td>{left.result.versions[key]}</td><td>{right.result.versions[key]}</td><td>{left.result.versions[key] === right.result.versions[key] ? '版本标识相同' : '版本不同，不归因行为'}</td></tr>)}<tr><th scope="row">Manifest SHA-256</th><td><p className="result-hash">{left.run.manifest_hash}</p></td><td><p className="result-hash">{right.run.manifest_hash}</p></td><td>{left.run.manifest_hash === right.run.manifest_hash ? '摘要相同，非基线授权' : '不是同一份冻结清单'}</td></tr></tbody></table></div>
  </>
}
