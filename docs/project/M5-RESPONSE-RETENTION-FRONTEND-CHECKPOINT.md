# 响应保留动态摘要前端 checkpoint

日期：2026-09-08。状态：前端生产代码及专项测试已完成并冻结；固定工具链typecheck/lint与5文件163测试通过，全web34文件891测试及构建通过。后端真实清理/仓储/API由root实现，不以浏览器mock测试冒充整条交付或正式审核。

## 所有权与固定接口

新增`web/src/response-retention-api.ts`及test、`web/src/components/results/ResponseRetentionPanel.tsx`及test；最小挂接`ReportsPanel.tsx`及其专项测试；`evidence-display-api.ts`增加闭集status、`EvidenceDisplayPanel.tsx`增加对应文案及其专项测试。没有修改基础API客户端、后端、OpenAPI、全局台账或ResultsPage。

固定GET `/api/v1/runs/{id}/response-retention?analysis_revision=1`，使用组织header及现有same-origin/no-store传输与8MiB上限；拒绝别名/非规范int64 ID、其它修订，不接受额外query或可配置URL。标准request_id仍由基础客户端验证。

data仅接受闭集S1字段：version=`mii.response-retention-summary.v1`、精确run_id/revision1、RFC3339 observed_at、policy_days0～180、正整数policy_version、Attempt与各类计数、RFC3339或null的last_deleted_at。每个计数必须为安全非负整数且不超过本Run Attempt数；展示副本deleted/expired/retained互斥总数不能超过Attempt数，使用减法避免先求和溢出。raw删除独立，不与展示副本计数相加。未知字段、遗漏字段、坏日期/日历别名、大小超限、传输失败均拒绝，不返回默认0摘要。

## 页面行为与权限边界

报告区显示“当前响应正文保留状态”，并明确“动态观察，不改变旧报告文件/哈希”。只有手动读取/刷新才先核验run.read+evidence.read，再读S1摘要；不挂载即fetch、不自动轮询、不发正文请求、不执行清理、不下载文件。刷新先清旧观察，未知或失败不保留旧计数伪装当前状态；0天不推断物理删除已完成，null删除时间显示未记录。

按root明确决定，原ReportsPanel及ResultsPage的report.export门槛保持不变，本轮不让缺export用户进入报告区；新摘要面板自身只需两个read权限，之后可由root在其它S1结果区复用。ReportsPanel仅提取原拒绝清理为共享callback，保持原401/403处理语义并避免子面板401重复触发sign-out。报告本身权限失效也会卸载摘要面板。

组织/用户/Run/修订切换即卸载并取消；显式取消或清除、401/403、密码/会话失效均清数据。AbortController加当前操作身份核对，迟到或不合作的响应不能回填，也不能覆盖取消后启动的新读取。只在面板内存显示，不写local/sessionStorage。

新增`unavailable_deleted`仅接受服务端验证后的null内容，文案明确“服务器已核验删除凭证”；没有删除凭证的原始缺行/503仍为读取失败，不从失败推导删除、也不伪造空正文。客户端不自造删除凭证。

## 实际验证

系统PATH中的Node已为24.20.0，固定toolchain正确拒绝；随后仅本命令PATH选择既有`.tools/node-v24.19.0-win-x64`，保持Node24.19.0/pnpm11.19.0与原脚本不变。

首轮新Panel的4个权限测试写成数组形式，被Vitest `it.each`展开为参数而非权限列表；已改为显式`{permissions}` fixture。无生产权限放宽。修复后typecheck、全web lint均通过，以下5文件共163测试PASS4.14s：

- response-retention-api.test.ts：规范路由/域、字段闭集、计数安全/互斥、raw独立、日期、0/7/30/180、401403/坏transport/取消。
- ResponseRetentionPanel.test.tsx：显式手动读取、只读权限、无轮询/正文、旧值清理、0与未知区分、四类scope切换、取消与迟到、双击、401403。
- ReportsPanel.test.tsx：旧报告交互完整回归、新摘要不改报告hash、不发正文/生成请求、原export gate不变、子拒绝清父缓存且不重复sign-out。
- evidence-display-api.test.ts：原全部闭集协议与新增deleted status的null约束。
- EvidenceDisplayPanel.test.tsx：原正文隔离、切scope等回归，删除凭证文案与无凭证503区分。

全web `test`实际34文件891测试PASS33.99s，随后`build`（tsc+vite）PASS706ms，session26523终态exit0。构建提示单JS chunk532.91kB超过500kB建议值；本轮未放宽阈值或临时拆包遮蔽提示，不把它当作功能验收失败。专有diff检查无错误。

没有运行数据库测试、浏览器真实清理验证或Git操作。后端API和删除凭证真实性由root的真实链路验证承担。所有前端源文件及本文已冻结，等待root接真实后端后统一复核。

## Root集成后验证

最终已补齐Attempt上限1536、合法日历/时区与亚毫秒未来时间反例，root完整复核后5文件183测试PASS4.13s。固定工具链全web34文件911测试PASS34.77s，typecheck/lint/build全部通过，JS533.23kB警告保留。真实应用双库清理已另取得全webassets/app三轮150.603s通过，不能将该后端测试说成浏览器页面端到端验收。
