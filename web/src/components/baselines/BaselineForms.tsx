import { useEffect, useRef, useState, type FormEvent } from 'react'
import { baselineCreate, baselineExpiry, baselineText, type Baseline, type BaselineCreate } from '../../baselines-api'

export type BaselineCommand = { kind: 'create'; body: BaselineCreate } | { kind: 'edit'; name: string; expiry: string } | { kind: 'approve'; reason: string; business: string } | { kind: 'retire'; reason: string }
export type BaselineEditor = 'create' | 'edit' | 'approve' | 'retire'
const titles: Record<BaselineEditor, string> = { create: '从已发布 Run 创建草稿', edit: '编辑草稿', approve: '审批组织参考', retire: '退休组织参考' }
export function BaselineForm({ kind, current, busy, onSubmit, onCancel }: { kind: BaselineEditor; current: Baseline | null; busy: boolean; onSubmit: (command: BaselineCommand) => void; onCancel: () => void }) {
  const [name, setName] = useState(current?.name ?? ''), [run, setRun] = useState(''), [source, setSource] = useState<'official' | 'historical'>('historical'), [region, setRegion] = useState('')
  const [expiry, setExpiry] = useState(() => current?.expires_at ?? new Date(Date.now() + 30 * 86400000).toISOString())
  const [reason, setReason] = useState(''), [business, setBusiness] = useState(''), [confirmed, setConfirmed] = useState(false), [error, setError] = useState('')
  const heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => { heading.current?.focus() }, [])
  const highRisk = current?.overall_risk !== null && current?.overall_risk !== undefined && current.overall_risk >= 40
  function submit(event: FormEvent) {
    event.preventDefault(); setError('')
    if (busy) return
    if ((kind === 'create' || kind === 'approve' || kind === 'retire') && !confirmed) { setError('请阅读并勾选此操作的明确确认。'); return }
    if (kind === 'create') {
      const body: BaselineCreate = { name: name.trim(), run_id: run.trim(), analysis_revision: 1, source, region: region.trim(), expires_at: expiry.trim() }
      if (!baselineCreate(body)) { setError('请检查 Run ID、名称、区域和到期时间：名称最多 128 字节，区域最多 64 字节，到期必须在未来 365 天内。'); return }
      onSubmit({ kind, body }); return
    }
    if (kind === 'edit') {
      if (!baselineText(name, 128) || !baselineExpiry(expiry.trim())) { setError('名称必填且不超过 128 字节；到期时间必须带时区并在未来 365 天内。'); return }
      onSubmit({ kind, name: name.trim(), expiry: expiry.trim() }); return
    }
    if (!baselineText(reason, 256) || (kind === 'approve' && !baselineText(business, 512, highRisk))) { setError(highRisk ? '审批理由必填，风险达到 40 时还必须填写业务复核说明；分别不超过 256 / 512 字节。' : '操作理由必填且不超过 256 字节，业务说明不超过 512 字节，不得包含控制字符。'); return }
    onSubmit(kind === 'approve' ? { kind, reason, business } : { kind, reason })
  }
  return <section className="baseline-form" aria-labelledby="baseline-form-title"><h3 id="baseline-form-title" ref={heading} tabIndex={-1}>{titles[kind]}</h3>
    <p className="field-help">仅提交当前组织元数据，不发起检测或付费上游调用。不得填写 API Key、鉴权 Header 或请求/响应正文。离开本页会清除未保存内容。</p>
    {current && <p className="field-help">基于已读版本 v{current.version} · 基线 {current.id}，服务端将再次校验权限和版本。</p>}
    {error && <p role="alert" className="notice error">{error}</p>}
    <form aria-label={titles[kind]} onSubmit={submit} noValidate><fieldset disabled={busy}><legend className="sr-only">{titles[kind]}</legend>
      {(kind === 'create' || kind === 'edit') && <><label htmlFor="baseline-name">参考名称</label><input id="baseline-name" value={name} onChange={(event) => setName(event.target.value)} maxLength={128} autoComplete="off" />
        <label htmlFor="baseline-expiry">到期时间（ISO 8601，含时区）</label><input id="baseline-expiry" value={expiry} onChange={(event) => setExpiry(event.target.value)} maxLength={64} aria-describedby="baseline-expiry-help" /><p id="baseline-expiry-help" className="field-help">例如 2026-10-01T12:00:00+08:00；已批准参考不可直接延长有效期，应重新采样并建立新草稿。</p></>}
      {kind === 'create' && <><label htmlFor="baseline-run">已发布 Run ID</label><input id="baseline-run" value={run} onChange={(event) => setRun(event.target.value)} inputMode="numeric" maxLength={19} autoComplete="off" /><p className="field-help">只接受当前组织的已结束、已发布分析修订 1。参数、模型、版本、哈希和样本量由后端从真实冻结来源提取，不能手填。</p>
        <label htmlFor="baseline-source">来源声明（未验证）</label><select id="baseline-source" value={source} onChange={(event) => setSource(event.target.value as 'official' | 'historical')}><option value="historical">目标自身历史 · 组织声明</option><option value="official">官方接口 · 组织声明，未经系统验证</option></select>
        <label htmlFor="baseline-region">区域声明（未验证，可留空）</label><input id="baseline-region" value={region} onChange={(event) => setRegion(event.target.value)} maxLength={64} /><p className="field-help">留空将不能建立区域一致的适用性；任何填写都不是区域认证。</p></>}
      {(kind === 'approve' || kind === 'retire') && <><label htmlFor="baseline-reason">{kind === 'approve' ? '审批理由' : '退休理由'}</label><textarea id="baseline-reason" value={reason} onChange={(event) => setReason(event.target.value)} rows={3} maxLength={256} />
        {kind === 'approve' && <><p className="notice warning">来源风险：{current?.overall_risk ?? '证据不足'} / 100；有效样本 {current?.valid_samples} / {current?.expected_samples}。{highRisk ? '风险达到 40，业务复核说明必填。' : '仍需独立判断是否适合作为组织参考。'}</p><label htmlFor="baseline-business">业务复核说明{highRisk ? '（必填）' : '（可选）'}</label><textarea id="baseline-business" value={business} onChange={(event) => setBusiness(event.target.value)} rows={3} maxLength={512} /></>}
      </>}
      {kind !== 'edit' && <label className="grant-option baseline-confirm"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>{kind === 'retire' ? '我确认退休此参考，保留原审批历史；不能重新批准或静默恢复。' : '我确认来源与区域仅为组织声明、未经验证；当前开发规则未独立校准、模板公开。此操作不启用可信对照评分，不提升证据等级，也不代表项目正式批准。'}</span></label>}
      <div className="form-actions"><button type="submit">{busy ? '正在提交…' : titles[kind]}</button><button type="button" onClick={onCancel}>取消编辑</button></div>
    </fieldset></form>
  </section>
}
