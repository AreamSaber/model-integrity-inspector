import { useEffect, useRef, useState } from 'react'
import { ApiError } from '../../api'
import { systemStatusApi, type CheckReason, type CheckSource, type CheckState, type SystemCheck, type SystemStatus } from '../../system-status-api'
import { ErrorNotice, Loading } from '../Feedback'
import { useFailure, type ManagementContext } from '../management/shared'

export interface SystemStatusPageProps extends ManagementContext { organizationID: string }
const explanations: Record<string, string> = {
  MI_SYSTEM_STATUS_BUSY: '状态读取已达到并发保护上限。请稍后手动刷新，不会自动重试。',
  MI_SYSTEM_STATUS_TIMEOUT: '状态读取超过 2 秒服务端保护期限，未显示部分响应。请稍后手动刷新。',
  MI_PERMISSION_DENIED: '需要系统读取权限及当前组织的 run.read、audit.read 权限和有效成员资格。权限不足或已撤销，已清空状态数据。',
  MI_INVALID_RESPONSE: '状态响应的身份、字段或观测口径校验失败，已清空状态数据。请联系管理员。',
}
const states: Record<CheckState, string> = { ok: '已观测', error: '观测异常', unavailable: '不可观测', startup_verified: '仅启动时校验', not_applicable: '不适用' }
const sources: Record<CheckSource, string> = { authorized_database_snapshot: '授权数据库快照', selected_organization: '当前组织快照', local_process: '本地进程', local_process_startup: '本地进程启动记录', not_observed: '无观测来源' }
const reasons: Record<CheckReason, string> = {
  read_connection_only: '此次授权读取成功；不证明数据库可写、容量充足或后续持续可用。',
  migration_history_matches: '迁移历史与当前应用清单匹配；不替代全库完整性检查。',
  migration_history_mismatch: '迁移历史与当前应用清单不匹配；条数相同也可能存在校验差异。',
  local_runner_reports_ready: '当前进程的任务执行器报告就绪；不证明远端执行器、每个任务或上游服务可用。',
  local_runner_not_ready: '当前进程的任务执行器未报告就绪，可能尚未启动或已经停止。',
  server_role_has_no_local_worker: '此进程仅承担服务端角色，不应期待本地任务执行器。',
  remote_consumer_registry_unavailable: '尚无远端消费者注册与心跳观测；不能据此判断 PostgreSQL Worker 全部正常或离线。',
  active_jobs_not_runs_or_samples: '仅当前组织活动 Job 记录；不是 Run 数、调用成功率或独立样本数。租约过期不等于已验证执行器故障。',
  active_job_records_invalid: '活动 Job 记录校验失败，不展示零值或部分计数。',
  active_job_limit_exceeded: '活动 Job 超过 10,000 条保护上限，不展示截断计数；不是生产容量声明。',
  tail_only_not_full_chain: '仅校验当前组织审计头和末尾最多 2 个事件；不代表完整审计链通过。',
  audit_tail_invalid: '当前组织审计尾部校验失败；不能视为审计链健康。',
  audit_signer_unavailable: '审计签名校验能力不可用，未完成尾部校验。',
  current_key_file_and_all_credentials_not_probed: '仅记录启动时的密钥加载校验；未重新探测当前密钥文件或逐一解密全部凭证。',
  current_capacity_writeability_and_all_artifacts_not_probed: '仅记录启动时的报告存储校验；未探测当前容量、可写性或逐一验证全部报告。',
  organization_setting_not_bound_to_write_policy: '组织保留设置尚未绑定正文写入策略；设置为 0 不代表正文已经停止留存。',
  organization_periodic_quotas_not_implemented: '组织周期配额尚未实现；单个 Run 的预算和并发保护是另一项能力。',
  retention_handler_not_registered: '未注册保留期清理处理器，不能声称过期正文已被自动删除。',
  backup_restore_receipts_unavailable: '没有可读取的备份与恢复验证回执，不能声称已备份或可恢复。',
}

export function SystemStatusPage(props: SystemStatusPageProps) { return <SystemStatusScope key={`${props.organizationID}:${props.userID}`} {...props} /> }
function SystemStatusScope(context: SystemStatusPageProps) {
  const [data, setData] = useState<SystemStatus | null>(null), [error, setError] = useState<unknown>(null), [loading, setLoading] = useState(true), [reload, setReload] = useState(0)
  const onFailure = useFailure(context), heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => {
    const controller = new AbortController()
    void systemStatusApi.read(context.organizationID, context.userID, controller.signal).then((value) => {
      if (!controller.signal.aborted) { setData(value); heading.current?.focus() }
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      setData(null)
      if (!onFailure(failure)) setError(failure)
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [context.organizationID, context.userID, reload, onFailure])
  const explanation = error instanceof ApiError ? explanations[error.code] : undefined
  return <section className="panel" aria-labelledby="system-status-title">
    <div className="section-heading"><h2 id="system-status-title" ref={heading} tabIndex={-1}>系统运行状态</h2><button disabled={loading} onClick={() => { setData(null); setError(null); setLoading(true); setReload((n) => n + 1) }}>手动刷新系统状态</button></div>
    <p className="notice warning">仅部分观测，不提供“系统整体健康”结论。启动校验不代表当前状态；不可观测项不会补成正常。正式审核未完成。</p>
    <p className="field-help">系统管理员导航标记不是授权。每次读取均以服务端当前会话、系统权限和显式组织权限复验为准；不跨组织汇总。</p>
    {loading && <Loading>正在验证权限并读取系统状态…</Loading>}
    <ErrorNotice error={explanation ?? error} id="system-status-error" />
    {data && <StatusData data={data} />}
    <p className="field-help">仅首次进入和手动刷新时读取；不自动监控，不执行设置、清理、备份或恢复。刷新、切换组织或账号、会话失效、离开页面时清空旧视图。数据库与本地进程时间来源不同，不据此推断跨主机时钟同步。</p>
  </section>
}
function checkedAt(value: string | null) { return value === null ? '无观测时间' : <time dateTime={value}>{value}</time> }
function count(value: number | null) { return value === null ? '未知 / 无观测' : String(value) }
function CheckRow({ title, check }: { title: string; check: SystemCheck }) {
  return <tr><th scope="row">{title}</th><td>{states[check.state]}</td><td>{sources[check.source]}<span className="cell-detail">{checkedAt(check.checked_at)}</span></td><td>{reasons[check.reason]}</td></tr>
}
function StatusData({ data: d }: { data: SystemStatus }) {
  const checks: [string, SystemCheck][] = [['数据库读取', d.database], ['迁移历史', d.schema], ['本地 Worker', d.local_worker], ['远端 Worker', d.remote_workers], ['组织活动任务', d.organization_jobs], ['组织审计尾部', d.organization_audit], ['主密钥', d.master_key], ['报告存储', d.report_storage], ['正文保留策略', d.retention_policy], ['组织周期配额', d.organization_periodic_quotas], ['保留期清理', d.retention_cleanup], ['备份与恢复', d.backup_restore]]
  return <>
    <p className="notice warning">{d.observed_state === 'degraded' ? '已观测项中存在异常；不可观测项仍未知。' : '已观测项未返回错误；不可观测项仍未知。'}</p>
    <p>当前组织：{d.organization_id} · 当前用户：{d.user_id}</p>
    <p>数据库快照时间：{checkedAt(d.observed_at)} · 进程角色：{d.process_role === 'all' ? '服务端与本地 Worker' : '仅服务端'} · 数据库：{d.database_driver === 'postgres' ? 'PostgreSQL' : 'SQLite'}</p>
    <div className="table-scroll"><table><caption>系统状态的观测来源与局限</caption><thead><tr><th scope="col">检查项</th><th scope="col">观测状态</th><th scope="col">来源与时间</th><th scope="col">范围与局限</th></tr></thead><tbody>{checks.map(([title, check]) => <CheckRow key={title} title={title} check={check} />)}</tbody></table></div>
    <section className="result-card" aria-labelledby="system-job-counts"><h3 id="system-job-counts">当前组织活动 Job（不是 Run 或样本）</h3><dl className="run-metrics">{([['活动记录总数', d.organization_jobs.total_active_jobs], ['待执行', d.organization_jobs.pending_ready], ['延后执行', d.organization_jobs.pending_delayed], ['运行且租约有效', d.organization_jobs.running_leased], ['运行但租约过期', d.organization_jobs.running_expired]] as const).map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{count(value)}</dd></div>)}</dl><p className="field-help">重试不增加独立样本。此处不计算调用成功率，也不能将空队列解释为系统无故障。</p></section>
    <section className="result-card" aria-labelledby="system-audit-counts"><h3 id="system-audit-counts">当前组织审计尾部</h3><p>本次验证尾部事件数：{count(d.organization_audit.verified_tail_events)}</p><p>末尾事件时间：{checkedAt(d.organization_audit.last_event_at)}</p></section>
    <section className="result-card" aria-labelledby="system-policy"><h3 id="system-policy">迁移与保留策略声明</h3><p>迁移清单期望 {d.schema.expected_migrations} 条 · 有界读取到 {d.schema.observed_migrations} 条；不展示 SQL 或内部路径。</p><p>组织配置正文保留 {d.retention_policy.configured_body_days} 天 · 当前写入策略固定 {d.retention_policy.current_write_policy_days} 天。两者尚未绑定；此声明不证明清理已经执行。</p></section>
    <section className="result-card" aria-labelledby="system-build"><h3 id="system-build">当前进程版本</h3><p>应用 {d.build.version} · 提交 {d.build.commit ?? '未知'} · 构建时间 {d.build.built_at === null ? '未知' : checkedAt(d.build.built_at)}</p><p>规则 {d.build.rule_bundle} · 模板 {d.build.template_bundle} · 评分 {d.build.scoring} · Tokenizer {d.build.tokenizer_bundle}</p><p className="field-help">这是当前进程的版本声明，不改写历史 Run 的冻结版本，不代表统计规则已校准。</p></section>
  </>
}
