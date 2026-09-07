import { useRef, useState } from 'react'
import type { FieldErrors } from './validation'

export function CredentialFields({ errors }: { errors: FieldErrors }) {
  const [authType, setAuthType] = useState<'bearer' | 'custom_header'>('bearer')
  const [rows, setRows] = useState<number[]>([])
  const ordinal = useRef(0)
  return <fieldset className="credentials-fields" aria-describedby="credentials-help">
    <legend>新凭证（只写）</legend>
    <p id="credentials-help" className="field-help">不会读取或回填旧凭证。提交后清空所有密钥和自定义请求头；保存成功仅展示掩码。</p>
    <div className="field"><label htmlFor="auth_type">认证方式</label><select id="auth_type" name="auth_type" value={authType} onChange={(event) => setAuthType(event.target.value as 'bearer' | 'custom_header')}><option value="bearer">Bearer API Key</option><option value="custom_header">自定义认证请求头</option></select></div>
    {authType === 'custom_header' && <div className="field"><label htmlFor="header_name">认证请求头名称</label><input id="header_name" name="header_name" type="text" data-sensitive="true" autoComplete="off" maxLength={128} aria-invalid={Boolean(errors.header_name)} aria-describedby={errors.header_name ? 'header_name-error' : undefined} />{errors.header_name && <p className="field-error" id="header_name-error">{errors.header_name}</p>}</div>}
    <div className="field"><label htmlFor="api_key">新 API Key</label><input id="api_key" name="api_key" type="password" data-sensitive="true" autoComplete="new-password" maxLength={8192} aria-invalid={Boolean(errors.api_key)} aria-describedby={errors.api_key ? 'api_key-error' : undefined} />{errors.api_key && <p className="field-error" id="api_key-error">{errors.api_key}</p>}</div>
    <div className="section-heading"><h3>额外请求头</h3><button type="button" disabled={rows.length >= 32} onClick={() => { const next = ordinal.current++; setRows((previous) => [...previous, next]) }}>添加请求头</button></div>
    {rows.map((row, index) => <div className="header-row" key={row}>
      <div className="field"><label htmlFor={`extra_name_${row}`}>请求头名称 {index + 1}</label><input id={`extra_name_${row}`} name={`extra_name_${row}`} data-sensitive="true" autoComplete="off" maxLength={128} aria-describedby={errors.credentials ? 'credentials-error' : undefined} /></div>
      <div className="field"><label htmlFor={`extra_value_${row}`}>请求头值 {index + 1}</label><input id={`extra_value_${row}`} name={`extra_value_${row}`} type="password" data-sensitive="true" autoComplete="new-password" maxLength={8192} aria-describedby={errors.credentials ? 'credentials-error' : undefined} /></div>
      <button type="button" aria-label={`移除请求头 ${index + 1}`} onClick={() => setRows((previous) => previous.filter((value) => value !== row))}>移除</button>
    </div>)}
    {errors.credentials && <p className="field-error" id="credentials-error">{errors.credentials}</p>}
  </fieldset>
}
