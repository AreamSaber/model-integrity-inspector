# M0-04：Core race 独立任务预算

日期：2026-09-10。仅改变 CI 调度，不修改产品、测试选择器、测试体、数据库覆盖或超时阈值。

## 原始故障证据

- head `a4f748725b2cbfc98978f6298f3502cf2af17460` / CI `34449102328` 已终态 failure：17成功、2失败、1取消。
- quality job `102780438770` 从 `07:16:02Z` 开始，`07:41:08Z` 完成。静态检查、Test and build、Offline replay OS network isolation 均 success；Core race 步骤从 `07:30:19Z` 开始，`07:41:03Z` cancelled。
- root 直接取得日志：`07:30:16Z` Build completed，`07:30:20Z` 开始46个非repository/Worker包的race，`07:31:41Z` 两个cmd包通过，随后 `07:41:03Z` `The operation was canceled.`。该job耗尽原25分钟总预算；日志未给出race数据竞争或Go测试panic结论，不能虚构当前app包已经通过或已经触及其10分钟包期限。
- Ubuntu打包另因日志断言误报失败，由 `f213deb` 修复，见独立记录。不能只修该项就称整个旧run全绿；旧run不重启、不追认。

## 调整与不变项

1. quality 保留原静态检查、完整非race测试构建及OS级离线禁网验证，仍为Ubuntu原生、25分钟。原服务只供末尾race步骤使用，随race移至新独立任务。
2. 新 `core-race` 无 needs、无条件跳过，独立25分钟预算；自有原digest固定PostgreSQL18.6服务，原相同用户/DB/loopback/健康检查/一次性凭证结构，原固定Go与Actions。
3. 仍精确执行 `./scripts/test-race.ps1 -Group Core`。`test-race.ps1` 和 `race-shards.ps1` 字节不修改：完整包枚举、`-race -count=1 -timeout=10m`、默认SQLite及DSN-aware PostgreSQL范围全部不变；Worker六组、仓储六组及独立identity/API PG组不动。
4. `m0-04-required` 名称及远端分支保护不变。needs新增core-race，绑定真实 `needs.core-race.result` 并参与全success循环。失败、取消、跳过或缺失仍拒绝。总job数由20变为21，不是删除原任务。
5. 显式策略检查Core自身五步、固定服务/工具、完整命令和独立预算，并要求quality保留所有原检查；不能以其他job的相同字符串满足本job。

## 实际验证

- 先加“Core必须独立拥有job预算”回归，在原工作流上真实失败：`CI requires one explicit core-race job.`，不是将测试跳过。
- 修正工作流/校验器后，M0-04 **194项离线策略回归 PASS**，包括新增Core依赖/结果遗漏、伪造success、错误DSN/服务、跳过/吞错、过滤器、同job重复执行、失去独立预算，以及quality构建/静态/禁网遗漏等反例。
- 原race分片 **92项离线回归 PASS**；真实固定版本actionlint退出0；`git diff --check`退出0。调用记录证实Core和原Other中的对应测试调用仍完全一致，其他所有分片完整性不变。
- 这些不是本机原生race证据。本机CGO0无法原生race，未改该边界；实际调度时长、完整Core原生race及整个新head仍待新CI验证。如果新run出现具体包超时/失败，将按实际日志继续处理，不将调度改动当作产品已验收。
- 独立只读复核无确认阻断：四个变更文件及实际race/build调用全文检查；独立policy194、race92、actionlint均终态0。另在内存给原mutation执行记录真实异常，新增Core/quality反例均因对应步骤/服务/预算/门禁拒绝，不是其他job或缺工具导致误绿。
- 实际提交 **791f1ea05070cecf3d73db6439fc8e14eea2421d** 已推送，PR6实际OPEN/draft/head相符；新 **CI34453747044** 已真实in_progress。继续跟踪同一run，尚无终态结论，不用a4的旧失败或ce8的旧全绿替代本批证据。
