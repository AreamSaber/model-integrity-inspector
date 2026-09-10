# Worker race 完整分组验证

2026-09-08。修复范围是 CI 执行组织，不是放宽 Worker 生产期限或声称旧 Windows renew 故障已定位。

## 实际失败

`52557c3` / CI `34183736103` 的 quality job 在 Worker 非仓储 race 回归触发包级累计 10 分钟超时（600.072s）。当时 long-retry-after/sqlite 子测试只执行 1 秒，不能说该子测试卡了十分钟。独立 Windows 打包 job 的 limited/sqlite renew DATABASE_UNAVAILABLE 另见 M5-RENEW-BOOKKEEPING-DIAGNOSTIC-NOTES.md，不能用分组宣布它已修复。

## 修改及不变量

- 完整 `go list ./...`，仅精确排除独立 required repository 包与稍后顺序测试的 Worker 本包；相同名称前缀的子包保留。
- 使用真正 `go test -race -count=1 -timeout=10m -list` 枚举 Worker 全部父级 Test/Example/Fuzz，按 ordinal 名字均分六组，执行前强制验证集合无遗漏、无重复、无空组。
- 六组在同一 quality job 顺序执行，所有调用仍为 `-race -count=1 -timeout=10m`。父级锚定选择保留全部嵌套子测试和默认 fuzz seeds。
- 其他非仓储包完整执行；identity/API 仍额外执行 PostgreSQL 一轮，结束或失败均清理 driver 环境变量。
- 任意枚举、普通包、六组之一或最后 PostgreSQL 回归失败立即失败；没有 retry-to-green、skip、过滤失败名字、改变 required gate 或六个 repository matrix job。

## 已有证据与边界

- root 离线分组策略 56 项通过，M0 门禁策略 107 项通过；独立 agent 复核并再次执行两套同样全部通过。
- 使用当前 Go 1.26.7 的真实 RE2 `-list`（**非 race，不执行测试体**）分别验证所有组：当前仓储 213 父级、Worker 61 父级，各自六组恰好覆盖一次。计数只是该工作树快照，CI 每次重新完整枚举。
- 当前本机 CGO_ENABLED=0 且没有可用 C 编译器，因此没有宣称 Windows 本地 race；实际 Linux race 的耗时、兼容性和完整结果须新远端 CI 证明。
- 这两份 PowerShell 脚本之外没有修改 workflow、超时、权限或分支保护配置。
