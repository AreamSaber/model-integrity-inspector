import { useCallback, useEffect, useRef, useState } from 'react'
import { catalogApi, priceLabel, type ModelProfile, type ModelSummary, type Provider } from '../../catalog-api'
import type { Page } from '../../targets-api'
import { Loading } from '../Feedback'
import { ListControls, ListFeedback, Pagination, useFailure, useManagementList } from '../management/shared'
import { DeleteCatalog, ModelForm, ProviderForm } from './CatalogForms'
import { CatalogError, useCatalogPermission, type CatalogContext } from './shared'

type Kind = 'providers' | 'model-profiles'
type Editor = { kind: 'providers'; mode: 'create'; record?: never } | { kind: 'model-profiles'; mode: 'create'; record?: never } | { kind: 'providers'; mode: 'edit' | 'view' | 'delete'; record: Provider } | { kind: 'model-profiles'; mode: 'edit' | 'view' | 'delete'; record: ModelProfile }
export function CatalogPage({ kind, ...context }: CatalogContext & { kind: Kind }) {
  const onFailure = useFailure(context), gate = useCatalogPermission(context)
  const load = useCallback((cursor: string, q: string, signal: AbortSignal): Promise<Page<Provider | ModelSummary>> => kind === 'providers' ? catalogApi.providers(context.organizationID, cursor, q, signal) : catalogApi.models(context.organizationID, cursor, q, signal), [kind, context.organizationID])
  const list = useManagementList(load, onFailure)
  const [editor, setEditor] = useState<Editor | null>(null), [loading, setLoading] = useState(false), [error, setError] = useState<unknown>(null), [notice, setNotice] = useState('')
  const active = useRef(false), request = useRef<AbortController | null>(null), heading = useRef<HTMLHeadingElement>(null), focus = useRef(false)
  useEffect(() => () => request.current?.abort(), [])
  useEffect(() => { if (!editor && focus.current) { focus.current = false; heading.current?.focus(); heading.current?.scrollIntoView?.({ block: 'start' }) } }, [editor])
  const label = kind === 'providers' ? '供应商' : '模型档案'
  function close() { focus.current = true; setEditor(null); setError(null); list.refresh() }
  async function open(recordID: string, mode: 'edit' | 'view' | 'delete') {
    if (active.current || (mode !== 'view' && !gate.allowed)) return
    const controller = new AbortController(); request.current = controller; active.current = true; setLoading(true); setError(null); setNotice('')
    try {
      if (kind === 'providers') { const record = await catalogApi.provider(context.organizationID, recordID, controller.signal); if (!controller.signal.aborted) setEditor({ kind, mode, record }) }
      else { const record = await catalogApi.model(context.organizationID, recordID, controller.signal); if (!controller.signal.aborted) setEditor({ kind, mode, record }) }
    } catch (failure) { if (!controller.signal.aborted && !onFailure(failure)) setError(failure) }
    finally { active.current = false; if (!controller.signal.aborted) setLoading(false) }
  }
  if (editor) {
    const props = { context, gate, onSaved: () => { setNotice(editor.mode === 'delete' ? '档案已删除；未级联删除关联数据。' : '档案已保存。能力和 tokenizer 声明不等于已验证结果。'); close() }, onCancel: close }
    if (editor.mode === 'view') return <CatalogDetails editor={editor} onClose={close} />
    if (editor.mode === 'delete') return <DeleteCatalog key={`${editor.kind}-${editor.record.id}`} {...props} kind={editor.kind} current={editor.record} />
    return editor.kind === 'providers' ? <ProviderForm key={editor.mode} {...props} current={editor.record} /> : <ModelForm key={editor.mode} {...props} current={editor.record} />
  }
  const blocked = loading || list.loading || Boolean(list.error)
  return <section className="panel" aria-labelledby="catalog-list-title"><div className="section-heading"><h2 id="catalog-list-title" ref={heading} tabIndex={-1}>组织{label}目录</h2><button disabled={blocked || gate.loading || !gate.allowed} onClick={() => { setNotice(''); setEditor({ kind, mode: 'create' }) }}>创建{label}</button></div>
    <p className="muted">当前组织独立维护的非敏感档案。目录读取不会连接上游或发起检测；仅实际 catalog.write 权限允许变更。</p>
    {notice && <output className="notice success">{notice}</output>}
    {gate.loading && <Loading>正在读取当前目录权限…</Loading>}<CatalogError error={gate.error} id="catalog-permission-error" />{!gate.loading && !gate.allowed && <p className="empty-note">当前为只读或权限未知；不会从系统管理员标记推断 catalog.write。</p>}
    <div className="form-actions"><button disabled={loading || gate.loading} onClick={gate.reload}>重新读取目录权限</button><a href={kind === 'providers' ? '#/model-profiles' : '#/providers'}>{kind === 'providers' ? '管理模型档案' : '管理供应商'}</a><a href="#/targets">管理关联目标</a></div>
    <ListControls list={list} label={label} /><ListFeedback list={list} label={label} /><CatalogError error={error} />{loading && <Loading>正在读取完整档案和最新版本…</Loading>}
    {list.result && list.result.items.length > 0 && <div className="table-scroll"><table><caption className="sr-only">当前组织{label}列表</caption><thead><tr><th scope="col">名称 / 标识</th><th scope="col">状态 / 元数据</th><th scope="col">操作</th></tr></thead><tbody>{list.result.items.map((item) => <tr key={item.id}><th scope="row">{item.name}<span className="cell-detail">ID {item.id} · v{item.version}</span></th><td>{item.status === 'active' ? '启用' : '停用'}{'provider_id' in item ? <><span className="cell-detail">{item.display_name || '未设置显示名称'} · openai_chat · 供应商 ID {item.provider_id}</span><span className="cell-detail">输入：{priceLabel(item.input_price_micros_per_million)}<br />输出：{priceLabel(item.output_price_micros_per_million)}</span></> : <span className="cell-detail">{item.description || '未填写描述'}<br />{item.contact || '未填写联系人'}</span>}</td><td><div className="row-actions"><button disabled={blocked} onClick={() => void open(item.id, 'view')} aria-label={`查看${label} ${item.name}`}>查看</button><button disabled={blocked || gate.loading || !gate.allowed} onClick={() => void open(item.id, 'edit')} aria-label={`编辑${label} ${item.name}`}>编辑</button><button disabled={blocked || gate.loading || !gate.allowed} onClick={() => void open(item.id, 'delete')} aria-label={`删除${label} ${item.name}`}>删除</button></div></td></tr>)}</tbody></table></div>}
    <Pagination list={list} /><p className="field-help">搜索由服务端完成：供应商按名称，模型按标识／显示名称。当前接口不提供供应商关联或启停状态筛选，本页不会对当前页伪装全量过滤。</p>
  </section>
}
function CatalogDetails({ editor, onClose }: { editor: Extract<Editor, { mode: 'edit' | 'view' | 'delete' }>; onClose: () => void }) {
  const heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => { heading.current?.focus(); heading.current?.scrollIntoView?.({ block: 'start' }) }, [])
  const record = editor.record
  return <section className="panel" aria-labelledby="catalog-details-title"><h2 id="catalog-details-title" tabIndex={-1} ref={heading}>档案详情：{record.name}</h2><dl className="precheck-times"><dt>ID / 版本</dt><dd>{record.id} / {record.version}</dd><dt>状态</dt><dd>{record.status === 'active' ? '启用' : '停用'}</dd><dt>创建时间</dt><dd>{new Date(record.created_at).toLocaleString()}</dd><dt>更新时间</dt><dd>{new Date(record.updated_at).toLocaleString()}</dd></dl>
    {editor.kind === 'providers' ? <dl className="precheck-times"><dt>描述</dt><dd>{editor.record.description || '未填写'}</dd><dt>联系人</dt><dd>{editor.record.contact || '未填写'}</dd></dl> : <><p className="notice warning">下列能力、公开限制和 tokenizer 均为目录声明，不是已验证的运行时能力，也不会批准或安装模板／tokenizer 制品。</p><dl className="precheck-times"><dt>供应商 ID</dt><dd>{editor.record.provider_id}</dd><dt>显示名称 / 协议</dt><dd>{editor.record.display_name || '未填写'} / {editor.record.protocol}</dd><dt>流式 / seed / 推理声明</dt><dd>{[editor.record.supports_stream, editor.record.supports_seed, editor.record.reasoning_model].map((item) => item ? '是' : '否').join(' / ')}</dd><dt>Tokenizer 声明</dt><dd>{editor.record.tokenizer_quality} · {editor.record.tokenizer_id || '未提供标识'}</dd><dt>公开输出上限</dt><dd>{editor.record.max_output_tokens ?? '未知'}</dd><dt>公开上下文窗口</dt><dd>{editor.record.context_window ?? '未知'}</dd><dt>输入价格</dt><dd>{priceLabel(editor.record.input_price_micros_per_million)}</dd><dt>输出价格</dt><dd>{priceLabel(editor.record.output_price_micros_per_million)}</dd></dl></>}
    <button onClick={onClose}>返回档案列表</button>
  </section>
}
