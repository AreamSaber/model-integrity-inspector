import { useEffect, useRef, useState } from 'react'
import { api, passwordChangeRequired, sessionInvalid, type Organization, type Role, type Session } from '../api'
import { AuthForm } from './AuthForms'
import { ErrorNotice, Loading } from './Feedback'
import { TargetsPage } from './targets/TargetsPage'
import { UsersPage } from './management/UsersPage'
import { OrganizationsPage } from './management/OrganizationsPage'
import { MembersPage } from './management/MembersPage'
import { CatalogPage } from './catalog/CatalogPage'
import { HistoricalRun, RunHistory } from './history/RunHistory'
import { ResultsPage } from './results/ResultsPage'
import { decimalID } from '../runs-history-api'
import { BaselinesPage } from './baselines/BaselinesPage'
import { ComparisonPage } from './comparison/ComparisonPage'
import { comparisonRoute } from '../comparison-api'

const navigation = [
  ['overview', '检测总览', '工作空间'],
  ['targets', '目标与模型档案', '检测'],
  ['providers', '供应商管理', '管理'],
  ['model-profiles', '模型档案管理', '管理'],
  ['runs', '检测任务', '检测'],
  ['reports', '结果与报告', '检测'],
  ['compare', '任务对比', '检测'],
  ['baselines', '基线管理', '治理'],
  ['rules', '规则与模板', '治理'],
  ['audit', '审计日志', '治理'],
  ['organizations', '组织与角色', '管理'],
  ['members', '组织成员', '管理'],
  ['organization-management', '组织管理', '管理'],
  ['users', '用户管理', '管理'],
  ['system', '系统', '管理'],
  ['account', '账号安全', '管理'],
] as const
function currentRoute() { return window.location.hash.slice(2) || 'overview' }

export function SessionLayout({ session, onSignedOut, onPasswordRequired }: { session: Session; onSignedOut: (notice: string) => void; onPasswordRequired: () => void }) {
  const [route, setRoute] = useState(currentRoute)
  const [organizations, setOrganizations] = useState(session.organizations)
  const [selectedID, setSelectedID] = useState(() => session.organizations.find((org) => org.status === 'active')?.id ?? '')
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState<'logout' | 'refresh' | null>(null)
  const pending = useRef(false)
  const activeRequest = useRef<AbortController | null>(null)
  const heading = useRef<HTMLHeadingElement>(null)
  const organization = organizations.find((org) => org.id === selectedID && org.status === 'active')
  const segments = route.split('/')
  const historicalID = segments.length === 2 && segments[0] === 'runs' && decimalID(segments[1]) ? segments[1] : null
  const resultID = segments.length === 3 && segments[0] === 'results' && decimalID(segments[1]) && segments[2] === '1' ? segments[1] : null
  const comparison = comparisonRoute(route)
  const validComparison = comparison && comparison.kind !== 'invalid'
  const activeRoute = historicalID ? 'runs' : resultID ? 'reports' : validComparison ? 'compare' : route
  const title = validComparison ? '两任务固定修订对比' : resultID ? '固定修订分析结果' : historicalID ? '检测进度与状态' : navigation.find(([key]) => key === route)?.[1] ?? '页面不存在'
  const management = { csrfToken: session.csrf_token, userID: session.user.id, systemAdmin: session.user.system_admin === true, onSignedOut, onPasswordRequired }
  useEffect(() => {
    const change = () => setRoute(currentRoute())
    window.addEventListener('hashchange', change)
    return () => window.removeEventListener('hashchange', change)
  }, [])
  useEffect(() => {
    document.title = `${title} · Model Integrity Inspector`
    heading.current?.focus()
  }, [title])
  useEffect(() => () => activeRequest.current?.abort(), [])

  async function action(kind: 'logout' | 'refresh') {
    if (pending.current) return
    pending.current = true
    const controller = new AbortController()
    activeRequest.current = controller
    setBusy(kind)
    setError(null)
    try {
      if (kind === 'logout') {
        await api.logout(session.csrf_token, controller.signal)
        if (!controller.signal.aborted) onSignedOut('已退出当前会话。')
      } else {
        const result = await api.organizations(controller.signal)
        if (!controller.signal.aborted) {
          setOrganizations(result.items)
          setSelectedID((previous) => result.items.some((org) => org.id === previous && org.status === 'active') ? previous : '')
        }
      }
    } catch (failure) {
      if (controller.signal.aborted) return
      if (sessionInvalid(failure)) onSignedOut('会话已失效或安全校验未通过，请重新登录。')
      else if (passwordChangeRequired(failure)) onPasswordRequired()
      else setError(failure)
    } finally {
      pending.current = false
      if (!controller.signal.aborted) setBusy(null)
    }
  }

  return <div className="workspace">
    <a className="skip-link" href="#main-content" onClick={(event) => { event.preventDefault(); document.getElementById('main-content')?.focus() }}>跳转到主要内容</a>
    <aside className="sidebar">
      <a className="brand-block" href="#/overview"><span className="brand-mark" aria-hidden="true">M</span><span>MII<small>Integrity Inspector</small></span></a>
      <p className="nav-caption">工作空间导航</p>
      <nav aria-label="主导航">{navigation.filter(([key]) => key !== 'users' || session.user.system_admin === true).map(([key, label, group]) => <a key={key} href={`#/${key}`} aria-current={activeRoute === key ? 'page' : undefined}><span>{label}</span><small aria-hidden="true">{group}</small></a>)}</nav>
      <p className="sidebar-foot">独立部署<br />模型 API 完整性检测</p>
    </aside>
    <div className="workspace-body">
      <header className="topbar">
        <div className="org-switch"><label htmlFor="organization-select">当前组织</label><select id="organization-select" value={organization?.id ?? ''} onChange={(event) => setSelectedID(event.target.value)} disabled={busy !== null}>
          <option value="">请选择组织</option>{organizations.map((org) => <option key={org.id} value={org.id} disabled={org.status !== 'active'}>{org.name}{org.status !== 'active' ? '（已停用）' : ''}</option>)}
        </select></div>
        <div className="user-menu"><span className="username">{session.user.username}</span><a href="#/account">账号安全</a><button onClick={() => void action('logout')} disabled={busy !== null}>{busy === 'logout' ? '正在退出…' : '退出登录'}</button></div>
      </header>
      <main id="main-content" className="main-content" tabIndex={-1}>
        <div className="page-heading"><p className="eyebrow">{organization?.name ?? '尚未选择组织'}</p><h1 ref={heading} tabIndex={-1}>{title}</h1></div>
        <ErrorNotice error={error} id="workspace-error" />
        {route === 'overview' ? <Overview organization={organization} username={session.user.username} /> :
          validComparison ? (organization ? <ComparisonPage key={`${organization.id}-${session.user.id}-${route}`} {...management} organizationID={organization.id} selection={comparison.kind === 'pair' ? comparison.selection : undefined} /> : <section className="panel"><p className="empty-note">请选择一个启用的组织以读取两任务对比。</p></section>) :
          route === 'runs' || route === 'reports' || historicalID || resultID ? (organization ? (resultID ? <ResultsPage key={`${organization.id}-result-${resultID}`} {...management} organizationID={organization.id} runID={resultID} /> : historicalID ? <HistoricalRun key={`${organization.id}-run-${historicalID}`} {...management} organizationID={organization.id} runID={historicalID} /> : <RunHistory key={`${organization.id}-${route}`} {...management} organizationID={organization.id} resultsOnly={route === 'reports'} />) : <section className="panel"><p className="empty-note">请选择一个启用的组织以读取检测历史和结果。</p></section>) :
          route === 'targets' ? (organization ? <TargetsPage key={organization.id} organizationID={organization.id} userID={session.user.id} csrfToken={session.csrf_token} onSignedOut={onSignedOut} onPasswordRequired={onPasswordRequired} /> : <section className="panel"><p className="empty-note">请选择一个启用的组织以管理检测目标。</p></section>) :
          route === 'providers' || route === 'model-profiles' ? (organization ? <CatalogPage key={`${organization.id}-${route}`} kind={route} {...management} organizationID={organization.id} /> : <section className="panel"><p className="empty-note">请选择一个启用的组织以管理目录档案。</p></section>) :
          route === 'baselines' ? (organization ? <BaselinesPage key={`${session.user.id}-${organization.id}`} {...management} organizationID={organization.id} /> : <section className="panel"><p className="empty-note">请选择一个启用的组织以管理参考基线。</p></section>) :
          route === 'account' ? <AuthForm mode="password" session={session} onSignedOut={onSignedOut} onPasswordRequired={onPasswordRequired} /> :
          route === 'users' ? <UsersPage {...management} /> :
          route === 'organization-management' ? <OrganizationsPage {...management} onChanged={(org) => {
            setOrganizations((current) => current.some((item) => item.id === org.id) ? current.map((item) => item.id === org.id ? org : item) : [...current, org])
            if (org.status !== 'active') setSelectedID((current) => current === org.id ? '' : current)
          }} /> :
          route === 'members' ? (organization ? <MembersPage key={organization.id} {...management} organizationID={organization.id} organizationName={organization.name} /> : <section className="panel"><p className="empty-note">请选择一个启用的组织以管理成员。</p></section>) :
          route === 'organizations' ? <>
            <section className="panel"><div className="section-heading"><h2>可访问的组织</h2><button onClick={() => void action('refresh')} disabled={busy !== null}>{busy === 'refresh' ? '正在刷新…' : '刷新组织'}</button></div>
              <p className="muted">来自当前会话授权范围。切换组织后将重新读取该组织的角色目录。</p>
              {organizations.length === 0 ? <p className="empty-note">当前账号没有可访问的组织，请联系管理员分配成员权限。</p> : <ul className="organization-list">{organizations.map((org) => <li key={org.id}><strong>{org.name}</strong><span>{org.status === 'active' ? '启用' : '停用'} · ID {org.id} · {org.timezone ?? '时区未提供'}</span></li>)}</ul>}
            </section>
            {organization ? <Roles key={organization.id} organization={organization} onSignedOut={onSignedOut} onPasswordRequired={onPasswordRequired} /> : <section className="panel"><p className="empty-note">请选择一个启用的组织以查看角色目录。</p></section>}
          </> : <Unavailable title={title} unknown={!navigation.some(([key]) => key === route)} />}
      </main>
      <footer className="workspace-footer">当前版本正在接入业务模块 · 权限以服务端校验为准</footer>
    </div>
  </div>
}

function Overview({ organization, username }: { organization?: Organization; username: string }) {
  return <>
    <section className="welcome-panel"><span className="section-number">01 / WORKSPACE</span><h2>欢迎回来，{username}</h2><p>{organization ? `当前工作空间：${organization.name}。后续检测与证据将在此组织范围内查看。` : '请先选择组织。如果没有可访问的组织，请联系管理员。'}</p><a className="button-link" href="#/organizations">查看组织与角色 →</a></section>
    <section className="panel"><div className="section-heading"><h2>检测数据</h2><span className="status-label">组织范围内读取</span></div><p className="muted">检测历史与已有分析结果可从下方入口读取。总览聚合统计和风险趋势尚未接入，不展示示例记录或虚假的零值。</p><div className="workflow-links"><a href="#/targets">目标与模型档案 <span>→</span></a><a href="#/runs">检测任务 <span>→</span></a><a href="#/reports">结果与报告 <span>→</span></a></div></section>
    <p className="security-note">这里的账号和组织信息来自真实会话。前端导航仅提供交互引导，不授予任何业务权限。</p>
  </>
}

function Unavailable({ title, unknown }: { title: string; unknown: boolean }) {
  return <section className="panel unavailable"><span className="status-label">{unknown ? '无效地址' : '尚未接入'}</span><h2>{unknown ? '未找到对应页面' : `${title}正在开发中`}</h2><p className="muted">{unknown ? '请从导航选择一个有效页面。' : '本页面尚未连接业务 API。不会展示示例记录，也不会发起检测、付费调用或其他业务操作。'}</p><a className="button-link" href="#/overview">返回检测总览 →</a></section>
}

function Roles({ organization, onSignedOut, onPasswordRequired }: { organization: Organization; onSignedOut: (notice: string) => void; onPasswordRequired: () => void }) {
  const [result, setResult] = useState<{ items: Role[]; next_cursor: string | null } | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [attempt, setAttempt] = useState(0)
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    const controller = new AbortController()
    void api.roles(organization.id, controller.signal).then((value) => {
      if (!controller.signal.aborted) setResult(value)
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      if (sessionInvalid(failure)) onSignedOut('会话已失效，请重新登录。')
      else if (passwordChangeRequired(failure)) onPasswordRequired()
      else setError(failure)
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [organization.id, attempt, onSignedOut, onPasswordRequired])
  return <section className="panel" aria-labelledby="roles-title">
    <div className="section-heading"><h2 id="roles-title">{organization.name} · 角色目录</h2><button disabled={loading} onClick={() => { setLoading(true); setError(null); setAttempt((value) => value + 1) }}>刷新角色</button></div>
    <p className="muted">这是组织可用的内置角色定义，不代表当前账号拥有这些角色或权限。分配和停用成员资格请前往<a href="#/members">组织成员</a>。</p>
    {loading && <Loading>正在读取组织角色…</Loading>}
    <ErrorNotice error={error} id="roles-error" />
    {Boolean(error) && result && <p className="empty-note">刷新失败。下方保留上次成功加载的目录，可能已经过期。</p>}
    {!loading && !error && result?.items.length === 0 && <p className="empty-note">服务端未返回角色定义。</p>}
    {result && result.items.length > 0 && <div className="table-scroll"><table><caption className="sr-only">组织角色和权限定义</caption><thead><tr><th scope="col">角色</th><th scope="col">权限定义</th></tr></thead><tbody>{result.items.map((role) => <tr key={role.name}><th scope="row">{role.name}</th><td>{role.permissions.join(' · ') || '未返回权限定义'}</td></tr>)}</tbody></table></div>}
    {result?.next_cursor && <p className="empty-note">服务端返回了更多目录项；此基础页面尚未提供分页浏览。</p>}
  </section>
}
