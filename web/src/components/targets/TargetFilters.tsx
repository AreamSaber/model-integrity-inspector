import { useState, type FormEvent } from 'react'
import type { TargetFilters as Filters } from '../../targets-api'
import { ErrorNotice } from '../Feedback'
import { safeText } from './validation'

export const emptyFilters: Filters = { q: '', model: '', environment: '', status: '' }
export function TargetFilters({ value, disabled, onApply }: { value: Filters; disabled: boolean; onApply: (filters: Filters) => void }) {
  const [error, setError] = useState('')
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const filters = { q: String(data.get('q') ?? '').trim(), model: String(data.get('model') ?? '').trim(), environment: String(data.get('environment') ?? '').trim(), status: String(data.get('status') ?? '') }
    if (!safeText(filters.q, 128) || new TextEncoder().encode(filters.q).length > 128 || !safeText(filters.model, 128) || !safeText(filters.environment, 64) || !['', 'active', 'disabled'].includes(filters.status)) { setError('搜索最多 128 字节，模型最多 128 字符、环境最多 64 字符，均不得包含控制字符。'); return }
    setError(''); onApply({ ...filters, status: filters.status as Filters['status'] })
  }
  return <><form aria-label="筛选目标" onSubmit={submit}><fieldset disabled={disabled}><legend className="sr-only">服务端目标筛选</legend><div className="form-grid">
    <div className="field"><label htmlFor="target-query">搜索名称、模型或渠道</label><input type="search" id="target-query" name="q" defaultValue={value.q} maxLength={128} /></div>
    <div className="field"><label htmlFor="target-filter-model">精确模型名称</label><input id="target-filter-model" name="model" defaultValue={value.model} maxLength={128} /></div>
    <div className="field"><label htmlFor="target-filter-environment">精确环境</label><input id="target-filter-environment" name="environment" defaultValue={value.environment} maxLength={64} /></div>
    <div className="field"><label htmlFor="target-filter-status">目标状态</label><select id="target-filter-status" name="status" defaultValue={value.status}><option value="">全部启停状态</option><option value="active">启用</option><option value="disabled">停用</option></select></div>
    </div><div className="form-actions"><button type="submit">应用筛选</button><button type="button" onClick={(event) => { event.currentTarget.form?.reset(); setError(''); onApply({ ...emptyFilters }) }}>清空筛选</button></div></fieldset></form><ErrorNotice error={error} id="target-filters-error" /></>
}
