import { useState } from 'react'
import { catalogApi, priceDecimal, priceInput, type ModelInput, type ModelProfile, type Provider } from '../../catalog-api'
import { CatalogField, CatalogMutation, CatalogStatusField, fieldStatus, fieldText, value, type CatalogContext, type CatalogPermission } from './shared'
import { ProviderSelect } from './ProviderSelect'

interface FormContext { context: CatalogContext; gate: CatalogPermission; onSaved: () => void; onCancel: () => void }
export function ProviderForm({ current, ...props }: FormContext & { current?: Provider }) {
  return <CatalogMutation {...props} title={current ? '编辑供应商档案' : '创建供应商档案'} prepare={(form) => {
    const input = { name: fieldText(form, 'name', 128, true), description: fieldText(form, 'description', 2048), contact: fieldText(form, 'contact', 256), status: fieldStatus(form) }
    return (signal) => current ? catalogApi.updateProvider(props.context.organizationID, props.context.csrfToken, current, input, signal) : catalogApi.createProvider(props.context.organizationID, props.context.csrfToken, input, signal)
  }}>
    <p className="field-help">仅保存非敏感目录信息，不要在名称、联系人或描述中填写 API Key、密码或私钥。{current && `当前 ID ${current.id} · 读取版本 ${current.version}。`}</p>
    <CatalogField name="name" label="供应商名称" initial={current?.name} help="最多 128 个字符。" /><CatalogField name="description" label="描述（可选）" initial={current?.description} max={2048} /><CatalogField name="contact" label="联系人（可选）" initial={current?.contact} max={256} /><CatalogStatusField initial={current?.status} />
  </CatalogMutation>
}
function limit(form: HTMLFormElement, name: string, max: number) { const raw = value(form, name); if (!raw.trim()) return null; const result = Number(raw); if (!/^\d+$/.test(raw) || !Number.isSafeInteger(result) || result < 1 || result > max) throw `公开限制须为 1–${max} 的整数，留空表示未知。`; return result }
export function ModelForm({ current, ...props }: FormContext & { current?: ModelProfile }) {
  const [selected, setSelected] = useState<Provider | null>(null)
  const [quality, setQuality] = useState(current?.tokenizer_quality ?? 'unavailable')
  return <CatalogMutation {...props} title={current ? '编辑模型档案' : '创建模型档案'} prepare={(form) => {
    const status = fieldStatus(form), providerID = value(form, 'provider_id')
    if (!selected || providerID !== selected.id) throw '请先成功读取并选择真实供应商。'
    if ((!current || status === 'active') && selected.status !== 'active') throw '创建或启用模型必须关联启用的供应商，请更换供应商或先启用它。'
    const protocol = value(form, 'protocol')
    if (protocol !== 'openai_chat') throw '当前只支持 OpenAI Chat Completions 协议。'
    const tokenizerQuality = value(form, 'tokenizer_quality')
    if (!['unavailable', 'heuristic', 'compatible', 'exact'].includes(tokenizerQuality)) throw '请选择有效的 tokenizer 质量声明。'
    const tokenizerID = tokenizerQuality === 'unavailable' ? '' : fieldText(form, 'tokenizer_id', 128, true)
    const input: ModelInput = { provider_id: providerID, name: fieldText(form, 'name', 128, true), display_name: fieldText(form, 'display_name', 128), protocol, status,
      supports_stream: new FormData(form).get('supports_stream') === 'on', supports_seed: new FormData(form).get('supports_seed') === 'on', reasoning_model: new FormData(form).get('reasoning_model') === 'on',
      tokenizer_id: tokenizerID, tokenizer_quality: tokenizerQuality as ModelInput['tokenizer_quality'], max_output_tokens: limit(form, 'max_output_tokens', 1048576), context_window: limit(form, 'context_window', 4194304),
      input_price_micros_per_million: priceInput(value(form, 'input_price')), output_price_micros_per_million: priceInput(value(form, 'output_price')) }
    if (input.max_output_tokens !== null && input.context_window !== null && input.max_output_tokens > input.context_window) throw '公开输出上限不能大于公开上下文窗口。'
    return (signal) => current ? catalogApi.updateModel(props.context.organizationID, props.context.csrfToken, current, input, signal) : catalogApi.createModel(props.context.organizationID, props.context.csrfToken, input, signal)
  }}>
    <p className="notice warning">能力、限制和 tokenizer 质量均为管理员维护的声明，不是运行时验证结果；选择 exact 不会安装、信任或启用任何 tokenizer 制品。实际估算须使用服务端已校验的版本包。这里不编辑探针模板。</p>
    {current && <p className="field-help">ID {current.id} · 读取版本 {current.version}。若已有目标引用，修改供应商、模型标识或删除可能被保护规则拒绝；不会联动改写已有目标。</p>}
    <ProviderSelect context={props.context} initialID={current?.provider_id} onSelected={setSelected} />
    <div className="form-grid"><CatalogField name="name" label="供应商模型标识" initial={current?.name} /><CatalogField name="display_name" label="模型显示名称（可选）" initial={current?.display_name} /><div className="field"><label htmlFor="catalog-protocol">接口协议</label><select id="catalog-protocol" name="protocol" defaultValue="openai_chat"><option value="openai_chat">OpenAI Chat Completions</option></select></div><CatalogStatusField initial={current?.status} /></div>
    <fieldset><legend>公开能力声明</legend>{([['supports_stream', '支持流式'], ['supports_seed', '支持 seed'], ['reasoning_model', '推理模型']] as const).map(([name, label]) => <label key={name} className="grant-option"><input name={name} type="checkbox" defaultChecked={current?.[name] ?? false} /><span>{label}</span></label>)}</fieldset>
    <div className="form-grid"><div className="field"><label htmlFor="catalog-tokenizer-quality">Tokenizer 质量声明</label><select id="catalog-tokenizer-quality" name="tokenizer_quality" value={quality} onChange={(event) => setQuality(event.target.value as ModelInput['tokenizer_quality'])}><option value="unavailable">unavailable · 未提供</option><option value="heuristic">heuristic · 启发式声明</option><option value="compatible">compatible · 兼容声明</option><option value="exact">exact · 精确声明（非运行时批准）</option></select></div><div className="field"><label htmlFor="catalog-tokenizer-id">Tokenizer 标识声明</label><input id="catalog-tokenizer-id" name="tokenizer_id" maxLength={128} disabled={quality === 'unavailable'} defaultValue={current?.tokenizer_id ?? ''} aria-describedby="catalog-tokenizer-help" /><p className="field-help" id="catalog-tokenizer-help">unavailable 明确清空标识；其他质量必须填写标识。此字段不会触发制品上传或远程下载。</p></div></div>
    <div className="form-grid"><CatalogField name="max_output_tokens" label="公开输出 Token 上限（可选）" initial={String(current?.max_output_tokens ?? '')} max={10} help="1–1048576，留空表示未知并清空已有值。" /><CatalogField name="context_window" label="公开上下文窗口（可选）" initial={String(current?.context_window ?? '')} max={10} help="1–4194304，留空表示未知并清空已有值。" /><CatalogField name="input_price" label="输入价格（USD / 百万 Token）" initial={priceDecimal(current?.input_price_micros_per_million ?? null)} max={32} /><CatalogField name="output_price" label="输出价格（USD / 百万 Token）" initial={priceDecimal(current?.output_price_micros_per_million ?? null)} max={32} /></div>
    <p className="field-help">价格最多 6 位小数，精确转换为整数微美元／百万 Token。留空表示未知，0 才表示配置为零价；未知价格不能用于金额硬预算，但不等于禁止 Token 预算检测。价格不是上游最终账单保证。</p>
  </CatalogMutation>
}
export function DeleteCatalog({ kind, current, ...props }: FormContext & { kind: 'providers' | 'model-profiles'; current: Provider | ModelProfile }) {
  return <CatalogMutation {...props} destructive title={kind === 'providers' ? '删除供应商档案' : '删除模型档案'} prepare={(form) => {
    if (value(form, 'confirmation') !== current.name) throw '请输入与当前档案完全一致的名称，确认删除。'
    return (signal) => catalogApi.remove(kind, props.context.organizationID, props.context.csrfToken, current, signal)
  }}><p className="notice warning">确认删除 {current.name}？ID {current.id} · 读取版本 {current.version}。关联记录由服务端保护；不会级联删除模型或目标，也不会删除既有检测证据。</p><CatalogField name="confirmation" label="输入档案名称确认删除" /><p className="field-help">删除操作会从正常目录移除该档案；页面不提供恢复入口，请谨慎确认。</p></CatalogMutation>
}
