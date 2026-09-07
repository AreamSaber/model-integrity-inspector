import { useEffect, useRef, useState } from 'react'
import { ApiError } from '../../api'
import { catalogApi, type Provider } from '../../catalog-api'
import { ErrorNotice, Loading } from '../Feedback'
import { useFailure } from '../management/shared'
import type { CatalogContext } from './shared'

export function ProviderSelect({ context, initialID = '', onSelected }: { context: CatalogContext; initialID?: string; onSelected: (value: Provider | null) => void }) {
  const onFailure = useFailure(context)
  const [items, setItems] = useState<Provider[]>([]), [chosen, setChosen] = useState<Provider | null>(null), [selectedID, setSelectedID] = useState(initialID)
  const [query, setQuery] = useState(''), [search, setSearch] = useState(''), [cursor, setCursor] = useState(''), [next, setNext] = useState<string | null>(null)
  const [loading, setLoading] = useState(true), [error, setError] = useState<unknown>(null), [attempt, setAttempt] = useState(0), [pages, setPages] = useState(0)
  const initial = useRef<Provider | null>(null), seen = useRef(new Set<string>())
  useEffect(() => {
    const controller = new AbortController()
    void Promise.all([catalogApi.providers(context.organizationID, cursor, query, controller.signal), initialID && !initial.current ? catalogApi.provider(context.organizationID, initialID, controller.signal) : Promise.resolve(initial.current)]).then(([result, current]) => {
      if (controller.signal.aborted) return
      if (result.next_cursor && seen.current.has(result.next_cursor)) throw new ApiError('MI_INVALID_RESPONSE')
      initial.current = current
      setItems((previous) => cursor ? [...previous, ...result.items.filter((item) => !previous.some((old) => old.id === item.id))] : result.items)
      if (current) setChosen((previous) => previous ?? current)
      setNext(result.next_cursor && !seen.current.has(result.next_cursor) ? result.next_cursor : null)
    }).catch((failure: unknown) => { if (!controller.signal.aborted && !onFailure(failure)) setError(failure) }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [context.organizationID, initialID, cursor, query, attempt, onFailure])
  const selected = items.find((item) => item.id === selectedID) ?? (chosen?.id === selectedID ? chosen : null)
  useEffect(() => { onSelected(!loading && !error ? selected : null) }, [selected, loading, error, onSelected])
  const options = chosen && !items.some((item) => item.id === chosen.id) ? [chosen, ...items] : items
  function find() {
    const query = search.trim()
    if (new TextEncoder().encode(query).length > 128 || /[\p{Cc}\p{Cs}]/u.test(query)) { setError('供应商搜索不得超过 128 字节或包含控制字符。'); return }
    setQuery(query); setCursor(''); seen.current.clear(); setPages(0); setLoading(true); setError(null); setAttempt((value) => value + 1)
  }
  return <div className="catalog-provider-select"><div className="field"><label htmlFor="catalog-provider_id">所属供应商</label><select id="catalog-provider_id" name="provider_id" value={selectedID} disabled={loading || Boolean(error)} onChange={(event) => { const item = options.find((option) => option.id === event.target.value) ?? null; setChosen(item); setSelectedID(event.target.value) }}><option value="">请选择真实供应商</option>{options.map((item) => <option key={item.id} value={item.id}>{item.name} · ID {item.id}{item.status === 'disabled' ? '（已停用）' : ''}</option>)}</select></div>
    <div className="field"><label htmlFor="catalog-provider-search">查找供应商（服务端）</label><input id="catalog-provider-search" value={search} maxLength={128} onChange={(event) => setSearch(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') { event.preventDefault(); find() } }} /></div><div className="form-actions"><button type="button" disabled={loading} onClick={find}>搜索供应商选项</button><button type="button" disabled={loading || !next || pages >= 100} onClick={() => { if (next) { seen.current.add(next); setPages((count) => count + 1); setCursor(next); setLoading(true); setError(null) } }}>加载更多供应商</button></div>
    {loading && <Loading>正在读取供应商选项…</Loading>}<ErrorNotice error={error} id="catalog-provider-error" />{!loading && !error && items.length === 0 && <p className="empty-note">没有匹配的供应商。请先在供应商管理中创建，或修改搜索。</p>}
    <p className="field-help">选项来自当前组织的真实分页目录；启用模型必须关联启用供应商。搜索不会伪造未加载的数据。</p>
    {pages >= 100 && next && <p className="empty-note">已达到本页选项加载上限，尚有更多供应商；请缩小服务端搜索范围。</p>}
  </div>
}
