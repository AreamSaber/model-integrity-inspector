import { useEffect, useState, type FormEvent } from 'react'
import { warningMessages, type Quote, type RunEstimate, type Versions } from '../../runs-api'
import { packageLabels } from './RunConfiguration'

export function cost(value: number | null) { return value === null ? '价格未知，无法估算' : `${(value / 1000000).toFixed(6)} USD` }
export function EstimateSummary({ estimate }: { estimate: RunEstimate }) {
  return <>
    <dl className="run-metrics"><div><dt>规划请求</dt><dd>{estimate.requests.toLocaleString()}</dd></div><div><dt>输入 Token 预留</dt><dd>{estimate.input_tokens.toLocaleString()}</dd></div><div><dt>输出 Token 总预算</dt><dd>{estimate.max_output_tokens.toLocaleString()}</dd></div><div><dt>估算费用</dt><dd>{cost(estimate.cost_micros)}</dd></div><div><dt>最长执行时间</dt><dd>{estimate.duration_seconds} 秒</dd></div><div><dt>预留安全系数</dt><dd>{estimate.usage_safety_factor}</dd></div></dl>
    <p className={estimate.completeness === 'partial' ? 'notice warning' : 'field-help'}>{estimate.completeness === 'partial' ? '探针覆盖不完整：部分条件受预算、能力或模板限制；这不代表检测已通过。' : '规划覆盖完整不代表统计证据充分，也不是模型真实性结论。'}</p>
    {estimate.warnings.length > 0 && <ul className="run-warnings">{[...new Set(estimate.warnings)].map((warning, index) => <li key={warning}>{warningMessages[warning] ?? `服务端返回额外的受限条件提示（第 ${index + 1} 项），请联系管理员核对。`}</li>)}</ul>}
  </>
}
export function FrozenVersions({ versions, hash }: { versions: Versions; hash: string }) { return <details className="run-versions"><summary>查看冻结版本与 Manifest 摘要</summary><dl className="precheck-times"><dt>规则包</dt><dd>{versions.rule_bundle}</dd><dt>模板包</dt><dd>{versions.template_bundle}</dd><dt>评分</dt><dd>{versions.scoring}</dd><dt>Tokenizer 包</dt><dd>{versions.tokenizer_bundle}</dd><dt>SHA-256</dt><dd>{hash}</dd></dl></details> }

export function RunQuote({ quote, busy, uncertain, authorized, onConfirm, onReconfigure }: {
  quote: Quote; busy: boolean; uncertain: boolean; authorized: boolean; onConfirm: (acknowledged: boolean) => void; onReconfigure: () => void
}) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(timer) }, [])
  const expired = now >= Date.parse(quote.expires_at)
  function submit(event: FormEvent<HTMLFormElement>) { event.preventDefault(); onConfirm(uncertain || new FormData(event.currentTarget).get('confirm_cost') === 'on') }
  return <>
    <h3>确认预估：{packageLabels[quote.package]}</h3><p className="cell-detail">预估草稿 ID {quote.id} · 目标版本 {quote.target_version}</p>
    <EstimateSummary estimate={quote.estimate} />
    <dl className="precheck-times"><dt>实际请求上限</dt><dd>{quote.budgets.max_requests.toLocaleString()}</dd><dt>实际 Token 上限</dt><dd>{quote.budgets.max_tokens.toLocaleString()}</dd><dt>金额硬预算</dt><dd>{quote.budgets.max_cost_micros === null ? '未设置金额预算；不表示免费' : cost(quote.budgets.max_cost_micros)}</dd><dt>草稿到期时间</dt><dd>{new Date(quote.expires_at).toLocaleString()}（浏览器本地时区）</dd></dl>
    <FrozenVersions versions={quote.versions} hash={quote.manifest_hash} />
    {uncertain ? <p className="notice warning">创建结果不确定，服务端可能已经开始检测。请使用同一预估草稿手动恢复，不能通过新草稿再次创建。未到期且原先没有创建时，此操作仍可创建该草稿唯一的 Run；到期后只可恢复原有 Run，不会启动新检测。</p> : expired && <output className="notice warning">此预估已到期，不能再确认执行。请重新配置并生成新的预估。</output>}
    <form aria-label="确认检测费用" onSubmit={submit}><fieldset disabled={busy || !authorized || (expired && !uncertain)}><legend className="sr-only">正式检测费用确认</legend>
      {!uncertain && <label className="grant-option"><input type="checkbox" name="confirm_cost" /><span>我确认开始向该目标发起真实请求，并接受上游可能产生的费用。估算不保证最终账单，重试也可能计费。</span></label>}
      <button type="submit" className="primary-button" disabled={busy || !authorized || (expired && !uncertain)}>{busy ? '正在确认…' : uncertain ? '恢复同一预估的提交结果' : '确认费用并创建检测'}</button>
    </fieldset></form>
    {!authorized && <p className="empty-note">当前有效权限不足，不能确认此检测包或预算。请重新读取权限，或联系管理员。</p>}
    {!uncertain && <button disabled={busy} onClick={onReconfigure}>{expired ? '重新配置并预估' : '返回修改配置'}</button>}
  </>
}
