import { useEffect, useRef } from 'react'
import { baselineLabels, baselineLimitations, type Baseline } from '../../baselines-api'

function Time({ value }: { value: string | null }) { return value ? <time dateTime={value}>{new Date(value).toLocaleString()}</time> : <>未发生</> }
export function BaselineDetails({ record, canReadRun }: { record: Baseline; canReadRun: boolean }) {
  const heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => { heading.current?.focus() }, [record.id, record.version])
  return <section className="baseline-details" aria-labelledby="baseline-details-title"><h3 id="baseline-details-title" ref={heading} tabIndex={-1}>参考详情：{record.name}</h3>
    <span className={`baseline-status baseline-status-${record.status}`}>{baselineLabels[record.status]}</span>
    <dl className="baseline-facts"><dt>基线 ID / 版本</dt><dd>{record.id} / v{record.version}</dd><dt>源 Run / 修订</dt><dd>{canReadRun ? <a href={`#/results/${record.run_id}/1`}>{record.run_id} · 修订 1</a> : <>{record.run_id} · 修订 1（没有来源结果读取权限）</>}</dd><dt>目标 ID</dt><dd>{record.target_id}</dd>
      <dt>来源 / 区域声明</dt><dd>{record.source === 'official' ? '官方接口（组织声明，未验证）' : '目标自身历史（组织声明，未验证）'} / {record.region || '未提供区域'}（未验证）</dd>
      <dt>模型 / 协议</dt><dd>{record.model} / {record.protocol}</dd><dt>有效 / 计划样本</dt><dd>{record.valid_samples} / {record.expected_samples}</dd><dt>来源机器风险</dt><dd>{record.overall_risk === null ? '证据不足，不是零风险' : `${record.overall_risk} / 100`}</dd>
      <dt>采样日期 / 创建时间</dt><dd><Time value={record.sampled_at} /> / <Time value={record.created_at} /></dd><dt>创建人 ID</dt><dd>{record.created_by}</dd><dt>最后修改</dt><dd><Time value={record.updated_at} /></dd><dt>到期时间</dt><dd><Time value={record.expires_at} /></dd>
      <dt>审批人 ID / 审批时间</dt><dd>{record.approved_by ?? '未审批'} / <Time value={record.approved_at} /></dd><dt>退休时间</dt><dd><Time value={record.retired_at} />{record.retired_at && ' · 原审批信息保留，不能恢复批准'}</dd>
      <dt>规则 / 评分版本</dt><dd>{record.rule_version} / {record.scoring_version}</dd><dt>模板 / Tokenizer 版本</dt><dd>{record.template_version} / {record.tokenizer_version}</dd><dt>冻结 Manifest SHA-256</dt><dd><code>{record.manifest_hash}</code></dd><dt>参数范围 SHA-256</dt><dd><code>{record.parameters_hash}</code></dd>
    </dl><ul className="baseline-limitations" aria-label="基线适用限制">{record.limitations.map((code) => <li key={code}>{baselineLimitations[code]}</li>)}</ul>
    <p className="field-help">审批说明与签名不在只读 DTO 中返回；此处不是任意正文或密钥查看入口。时间按浏览器本地时区显示，底层包含明确时区。</p>
  </section>
}
