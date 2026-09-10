# M0-04：快照私有日志断言的时间戳误报

日期：2026-09-10。仅修测试，不更改生产日志、快照隐私、CI分片、超时或门禁。

## 真实 CI 证据与原因

已推送 head `a4f748725b2cbfc98978f6298f3502cf2af17460` 的 CI `34449102328`，Ubuntu打包job `102780438935` 实际失败。root直接回读该已完成job日志：`TestSnapshotReportInventoryRepresentation` 第534行 `slog leaked inventory`；repository总305.325s，其他包继续完成，打包脚本因Go测试非零退出。不是超时、包下载、真实数据库写入故障或data race。后续整个run已终态：17成功、2失败、1取消；quality另遇任务预算耗尽，见 M0-CI-CORE-JOB-BUDGET-NOTES.md，不能用本测试修复代替该项处理。

旧测试使用真实 JSON logger，再在**整行**搜索 `1234` 这个受控私有ID；标准 `time` 字段的亚秒数字也会命中它。生产 `LogValue` 只返回固定私有字符串，不含该ID。原日志没有输出被断言的完整行，不能伪造CI当时的具体纳秒；下面确定性反例证明这条断言确实会因合法时间戳失败。

## 确定性修复和反例

1. 先仅将原测试 logger 改为真实 `slog.Record`，时间固定为 `2026-09-10T12:34:00.123456789Z`，仍保留旧全行断言。**f2aeca exit1，0.108s**，稳定复现同一 `slog leaked inventory`，不修改任何生产表示方法。
2. 新测试专用 `snapshotInventoryLogText` 使用同一真实 JSONHandler 和含canary数字的时间，检查完整四字段日志 envelope、原时间/level/message均精确不变，再解析被记录的私有属性；属性必须是JSON字符串，拒绝原结构体/group等额外载荷。
3. 报告、审计、迁移、工件和Job库存的五处同义全行数字检查都改为检查该实际属性；审计/迁移/Job使用精确固定字符串，报告/工件仍保留canary数字与私有前缀检查。没有移除生产日志时间、mask真实载荷或宽化私有类型的序列化策略。
4. 新反例将真实泄露字符串作为slog.Value交给相同handler，断言提取后逐字保留canary与ID。测试助手不能先隐藏泄露再让安全断言通过。

## 实际验证

- 原报告表示+新提取负面反例，纯层100轮 **0.118s PASS**（d82a76）。固定时间每次都含原canary数字，不依赖“多重试碰巧通过”。
- 完整repository lint **0 issues**（ceefb5 exit0），未禁规则。
- 六个精确父级：原报告表示、新提取负面、审计/迁移交易与表示guard、工件表示/manifest、Job计数与表示guard，SQLite/纯层三轮 **0.734s PASS**（0d98ea exit0），未作 driver 子路径过滤。未配置DSN的PG分支不计为实际PG。

- 执行单元独占General时，当前routing加上述六父级 **双库三轮20.266s PASS**（session99593实际终态0）；没有driver子路径过滤，不与其他PG组并发。该组合同时覆盖PG交易guard与路由，不虚称每个纯表示用例各自需要DB。

新远端CI证据待新head真实执行。当前已完成的Ubuntu失败不重启或改写为成功；修复将以新head触发独立验证。
