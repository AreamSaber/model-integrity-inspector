import { useState, type FormEvent } from 'react'
import type { Target } from '../../targets-api'
import { packages, probeTypes, type EstimateInput, type RunOptions, type RunPackage } from '../../runs-api'

export const packageLabels: Record<RunPackage, string> = { quick: '快速检测', standard: '标准检测', deep: '深度检测', custom: '自定义检测' }
const probeLabels: Record<typeof probeTypes[number], string> = { sequence: '编号序列与输出上限', jsonl: 'JSONL 与输出上限', format: '精确格式契约', neutral: '中性任务行为', differential: '成对差分', style: '风格观察', self_report: '模型自报告（仅辅助）' }
export function defaults(kind: RunPackage): RunOptions { return { max_requests: kind === 'quick' ? 20 : kind === 'deep' ? 150 : 60, max_tokens: kind === 'quick' ? 15000 : kind === 'deep' ? 200000 : 50000, max_cost_micros: null, concurrency: 1, max_retries: 2, max_minutes: kind === 'deep' ? 45 : 15 } }
export function highCost(kind: RunPackage, options: RunOptions) { return kind === 'deep' || (options.max_requests ?? 0) > 60 || (options.max_tokens ?? 0) > 50000 || (options.max_cost_micros ?? 0) > 2000000 }
export function canConfigure(permissions: string[], kind: RunPackage, options: RunOptions) { return permissions.includes('run.create') && (kind !== 'custom' || permissions.includes('run.custom')) && (!highCost(kind, options) || permissions.includes('run.high-cost')) }

function integer(data: FormData, name: string, min: number, max: number) {
  const raw = String(data.get(name) ?? '')
  const value = Number(raw)
  if (!/^\d+$/.test(raw) || !Number.isSafeInteger(value) || value < min || value > max) throw '请输入范围内的整数预算、并发和重复次数。'
  return value
}
function money(raw: string): number | null {
  if (!raw.trim()) return null
  if (!/^\d+(?:\.\d{1,6})?$/.test(raw.trim())) throw '金额预算请填写非负 USD 数值，最多 6 位小数；价格未知时不能启用金额预算。'
  const [whole, fraction = ''] = raw.trim().split('.')
  const micros = Number(whole) * 1000000 + Number(fraction.padEnd(6, '0'))
  if (!Number.isSafeInteger(micros) || micros > 1000000000) throw '金额预算不得超过 1000 USD，请输入更小的数值。'
  return micros
}

export function RunConfiguration({ current, permissions, busy, initial, onEstimate, onError }: {
  current: Target; permissions: string[]; busy: boolean; initial?: EstimateInput; onEstimate: (input: EstimateInput) => void; onError: (message: string) => void
}) {
  const [kind, setKind] = useState<RunPackage>(initial?.package ?? 'quick')
  const selected = initial?.package === kind ? initial.options : defaults(kind)
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy || !permissions.includes('run.create') || current.status !== 'active') return
    try {
      const data = new FormData(event.currentTarget)
      const options: RunOptions = {
        max_requests: integer(data, 'max_requests', 1, 1000), max_tokens: integer(data, 'max_tokens', 1, 10000000), max_cost_micros: money(String(data.get('max_cost') ?? '')),
        max_minutes: integer(data, 'max_minutes', 1, 45), concurrency: integer(data, 'concurrency', 1, 100), max_retries: integer(data, 'max_retries', 0, 2),
      }
      if (kind === 'custom') {
        const families = data.getAll('probe_types')
        const languages = data.getAll('languages')
        if (families.length === 0 || !families.every((value) => probeTypes.some((type) => type === value)) || languages.length === 0 || !languages.every((value) => value === 'zh-CN' || value === 'en-US')) throw '请至少选择一个探针族和一种受支持语言。'
        options.probe_types = families as typeof probeTypes[number][]
        options.languages = languages as ('zh-CN' | 'en-US')[]
        options.repetitions = integer(data, 'repetitions', 1, 10)
        const mode = data.get('stream_modes')
        if (!['both', 'nonstream', 'stream'].includes(String(mode))) throw '请选择受支持的流式模式。'
        options.stream_modes = mode === 'both' ? [false, true] : [mode === 'stream']
        if (families.includes('sequence') || families.includes('jsonl')) {
          const levels = String(data.get('max_output_levels') ?? '').split(',').map((value) => value.trim())
          if (levels.length < 1 || levels.length > 8 || levels.some((value) => !/^\d+$/.test(value))) throw '请填写 1–8 个递增的输出档位，用英文逗号分隔。'
          const parsed = levels.map(Number)
          if (parsed.some((value, index) => !Number.isSafeInteger(value) || value < 16 || value > 131072 || (index > 0 && value <= parsed[index - 1]))) throw '输出档位须严格递增、不重复，并介于 16–131072。'
          options.max_output_levels = parsed
        }
      }
      if (!canConfigure(permissions, kind, options)) throw '当前有效权限不足：自定义需要 run.custom，深度或超出普通预算需要 run.high-cost。'
      onEstimate({ target_id: current.id, target_version: current.version, package: kind, options })
    } catch (error) { onError(typeof error === 'string' ? error : '检测配置无效，请检查输入。') }
  }
  return <>
    <p className="notice warning">预估仅创建短期草稿，不向目标发起请求。正式执行须再次确认费用；每位用户最多保留 20 个活跃草稿，草稿有效期约 10 分钟，请勿反复预估。</p>
    <div className="field"><label htmlFor="run-package">检测包</label><select id="run-package" value={kind} disabled={busy} onChange={(event) => setKind(event.target.value as RunPackage)}>{packages.map((value) => <option key={value} value={value} disabled={(value === 'deep' && !permissions.includes('run.high-cost')) || (value === 'custom' && !permissions.includes('run.custom'))}>{packageLabels[value]}</option>)}</select></div>
    <form key={kind} aria-label="配置检测并预估" noValidate onSubmit={submit}><fieldset disabled={busy || !permissions.includes('run.create') || current.status !== 'active'}><legend className="sr-only">检测请求配置</legend>
      <div className="form-grid">
        <NumberField name="max_requests" label="请求预算" value={selected.max_requests ?? 60} min={1} max={1000} />
        <NumberField name="max_tokens" label="Token 总预算" value={selected.max_tokens ?? 50000} min={1} max={10000000} />
        <div className="field"><label htmlFor="run-max-cost">金额预算（USD，可留空）</label><input id="run-max-cost" name="max_cost" inputMode="decimal" defaultValue={selected.max_cost_micros == null ? '' : String(selected.max_cost_micros / 1000000)} aria-describedby="run-money-help" /><p className="field-help" id="run-money-help">留空不表示免费。若启用金额上限，服务端必须已有可信价格记录。</p></div>
        <NumberField name="max_minutes" label="最长执行时间（分钟）" value={selected.max_minutes ?? 15} min={1} max={45} />
        <NumberField name="concurrency" label="运行并发" value={selected.concurrency ?? 1} min={1} max={100} />
        <NumberField name="max_retries" label="最大重试次数" value={selected.max_retries ?? 2} min={0} max={2} />
      </div>
      <p className="field-help">服务端会应用更严格的组织、目标和系统限额。预估不包含重试次数；每次实际尝试仍受请求、Token 和费用硬预算约束。</p>
      {kind === 'custom' && <CustomFields initial={selected} />}
      {kind === 'quick' && <p className="field-help">快速包用于初步观察，不能支持高置信度的“未发现异常”结论。</p>}
      <p className="field-help">发起预估前必须已有当前目标版本的通过预检；若缺失，服务端会拒绝并提示。不会自动补发可能计费的预检。</p>
      <button type="submit" className="primary-button" disabled={busy || !permissions.includes('run.create') || current.status !== 'active'}>{busy ? '正在处理预估…' : '生成预估（不调用上游）'}</button>
    </fieldset></form>
    {!permissions.includes('run.create') && <p className="empty-note">当前账号没有 run.create 权限，不能生成预估或创建检测。</p>}
  </>
}

function NumberField({ name, label, value, min, max }: { name: string; label: string; value: number; min: number; max: number }) { return <div className="field"><label htmlFor={`run-${name}`}>{label}</label><input id={`run-${name}`} name={name} type="number" min={min} max={max} step={1} defaultValue={value} /></div> }
function CustomFields({ initial }: { initial: RunOptions }) {
  const [families, setFamilies] = useState(initial.probe_types ?? [...probeTypes].filter((type) => type !== 'self_report'))
  const ladder = families.includes('sequence') || families.includes('jsonl')
  return <div className="run-custom">
    <fieldset><legend>自定义探针族</legend><div className="run-choice-grid">{probeTypes.map((type) => <label className="grant-option" key={type}><input type="checkbox" name="probe_types" value={type} checked={families.includes(type)} onChange={(event) => setFamilies((values) => event.target.checked ? [...values, type] : values.filter((value) => value !== type))} /><span>{probeLabels[type]}</span></label>)}</div></fieldset>
    <fieldset><legend>实验语言</legend>{(['zh-CN', 'en-US'] as const).map((language) => <label className="grant-option" key={language}><input type="checkbox" name="languages" value={language} defaultChecked={(initial.languages ?? ['zh-CN', 'en-US']).includes(language)} /><span>{language === 'zh-CN' ? '简体中文' : 'English'}</span></label>)}</fieldset>
    <div className="form-grid"><NumberField name="repetitions" label="每条件重复次数" value={initial.repetitions ?? 3} min={1} max={10} /><div className="field"><label htmlFor="run-stream-modes">流式模式</label><select id="run-stream-modes" name="stream_modes" defaultValue={!initial.stream_modes || initial.stream_modes.length === 2 ? 'both' : initial.stream_modes[0] ? 'stream' : 'nonstream'}><option value="both">流式与非流式</option><option value="nonstream">仅非流式</option><option value="stream">仅流式</option></select><p className="field-help">模式能力以真实预检为准；不支持的选择会明确失败，不会静默替换。</p></div></div>
    <div className="field"><label htmlFor="run-levels">输出上限档位（英文逗号分隔）</label><input id="run-levels" name="max_output_levels" defaultValue={(initial.max_output_levels ?? [64, 128, 256, 512]).join(',')} disabled={!ladder} aria-describedby="run-levels-help" /><p className="field-help" id="run-levels-help">仅编号序列和 JSONL 使用档位；未选这两类时本字段不适用，不发送档位设置。最多 8 档，每档 16–131072。</p></div>
    <p className="field-help">少于 3 次重复会降低覆盖充分性。自报告仅作辅助观察，不参与统计判断。</p>
  </div>
}
