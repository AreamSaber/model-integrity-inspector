# M5 CI race 并行分组验证记录

状态：本地实现与离线验证完成，等待包含本单元的新远端 CI 验证。本文不宣称历史 Windows 失败或全部 Linux race 已修复，不修改里程碑审批、分支保护配置或外部 required check 名称。

## 1. 实际失败证据

读取的是 SHA `6fdfd6cbd08aab3b12cb88a02352823710ce779a` 的 [CI 34187516642 / quality 101938788798](https://github.com/AreamSaber/model-integrity-inspector/actions/runs/34187516642/job/101938788798)。该 run 最终 `failure`，quality 最终 `cancelled`，开始于 2026-09-08 04:35:38 UTC，结束于 05:00:42 UTC，历时 25 分 04 秒。

- 静态检查、Test and build、Offline replay OS network isolation 均成功。
- race 步骤自 04:41:24.929 UTC 开始，05:00:39.082 UTC 被取消；日志为任务取消，没有观察到该步骤的测试断言 FAIL 或单个进程 10 分钟超时 panic。
- 44 个非 repository / 非 Worker 包全部通过，进程从 04:42:34.332 至 04:51:08.557 UTC，约 514.22 秒。API 486.535 秒、app 195.935 秒、features 187.716 秒、identity 107.220 秒、evidencedisplay 8.307 秒均为该次实际 Linux race 包结果。
- Worker 分区实际执行情况如下。这里是旧 SHA 的 61 个顶层入口，不是离线合成枚举。

| 分区 | 顶层数 | 实际结果 | 日志中的包耗时 |
| --- | ---: | --- | ---: |
| 0 | 11 | PASS | 218.336 秒 |
| 1 | 10 | PASS | 109.148 秒 |
| 2 | 10 | PASS | 95.340 秒 |
| 3 | 10 | PASS | 98.106 秒 |
| 4 | 10 | 运行约 44.63 秒后被 job 取消，无完成结果 | 不适用 |
| 5 | 10 | 未开始 | 不适用 |

末尾显式 PostgreSQL identity/API 进程未开始。日志较早出现的“2 of 12”是离线脚本的合成用例，不能算作实际 Worker 验证。已经 PASS 的测试中出现的故障注入数据库日志也不能作为本次任务取消的根因证据。

现有串行总工作量超出了 quality 的 25 分钟任务预算。将 Worker 移出后，若仍保留最后的 PostgreSQL identity/API 在 quality 内，其剩余任务时间不足以保证原 10 分钟进程预算，因此该进程也独立为任务；没有上调任何期限。

## 2. 最小分组实现

`scripts/test-race.ps1` / `Invoke-MIICIRace` 的闭集组为 `Other`、`Repository`、`Core`、`Worker`、`IdentityPostgres`。

- `Other` 保留本地原完整顺序：枚举包与 Worker，运行所有非 repository / 非 Worker 包、Worker 六个顺序分区、显式 PostgreSQL identity/API。
- `Core` 仅运行完整包列表中排除两个精确包名后的全部包。名称前缀相似的子包仍保留，不能以目录前缀扩大排除范围。
- `Worker -Shard 0..5` 在每个任务内真实完整枚举该包的 Test / Example / Fuzz 顶层入口，按 ordinal 排序和模六分配，验证完整集合后运行指定非空分片。
- `IdentityPostgres` 运行原 `./internal/identity ./internal/integrity/api`，在 `try/finally` 中显式设置并清除 PostgreSQL identity driver。
- `Repository` 的既有六片算法及 workflow matrix 不变。

CI 的 quality 使用 `Core`；新增 `worker-race` 六片 matrix 和 `identity-postgres-race` 任务。每个新任务各自拥有独立 runner 与固定镜像的 PostgreSQL service，互不共享迁移锁或数据库；所有任务保留 25 分钟限制。每个实际测试进程与 race 枚举仍保留 `-race -count=1 -timeout=10m`。没有跳过测试、缩减输入、增加自动重试或改动原数据库测试范围。

选择表达式锚定完整顶层父项，不含 `/` 子测试过滤，因此保留其全部嵌套测试以及普通 `go test` 默认运行的 fuzz seed。普通回归原本不执行的 benchmark 或持续 fuzzing 没有被重新定义为已覆盖。

## 3. 必过门禁和失败关闭

外部名称仍是 `m0-04-required`，`if: always()` 不变。其 `needs` 与实际结果检查同时显式包含 quality、repository-race、worker-race、identity-postgres-race、dependency-scan、package、image，仅接受所有结果等于 `success`；失败、取消、跳过或缺失不能通过。

离线 CI 策略检查同步验证各 race 任务的原生 Ubuntu、25 分钟限制、独立固定 PostgreSQL service、真实 DSN 接线，禁止条件跳过和忽略错误。Worker 六片必须完整、唯一、`fail-fast: false`，不能通过 `include/exclude` 去掉分片。未知脚本组、隐式 GOFLAGS、缺少 PostgreSQL DSN、继承的 identity driver override 在运行前即失败。任何枚举或测试进程失败立即停止，driver override 仍执行清理。

这里只修改 workflow 的聚合依赖与本地纯策略验证；没有调用真实分支保护写入接口。

## 4. 2026-09-08 本地验证

最终版本的两个离线脚本连续三轮均通过，三轮连同行动检查与 parser 检查总墙钟 2.573 秒：

- `scripts/tests/test-race-shards.ps1`：87 个离线用例通过。包含 Core + Worker 0..5 + IdentityPostgres 与原 Other 的全部八个实际测试调用（参数及 driver）的完整 JSON 等价；包含丢片、重复、未知入口、未知组、每步失败即停，以及 Test / Example / Fuzz 和嵌套父项选择约束。
- `scripts/tests/test-m0-04-policy.ps1`：130 个离线用例通过。新增反例覆盖遗漏 Worker 或 identity 必过依赖、忽略结果、写死成功、仅跑零号片、删片/重复片/排除片、错误组、跳过任务或步骤、提高期限、丢失 service。此脚本对原分支保护入口的调用使用本地 mock，不产生远端写入。
- actionlint 检查 `.github/workflows/ci.yml`：退出码 0。
- 五个本单元 PowerShell 文件通过 PowerShell AST parser。
- 当前本机真实 `go list ./...`：46 包；Core 精确保留 44 包。
- 当前真实 Go RE2 **非 race** `-list`：repository 241 个父项，六片为 `41,40,40,40,40,40`；Worker 62 个父项，六片为 `11,11,10,10,10,10`。每片均通过真实 Go 的参数数组调用再次枚举，并与预期集合逐项比较，全部入口恰好一次；没有运行任何 test body 或访问数据库。

本机 `CGO_ENABLED=0`，因此没有把上述非 race 枚举冒充 `-NativeGo` 的 race 检查，也没有跨编译冒充 Linux 执行。workflow 在原生 Linux 的 repository / Worker 任务保留 `test-race-shards.ps1 -NativeGo`，届时执行真实 `-race` 枚举及六片 RE2 精确覆盖验证。

## 5. 待验边界

新并行 workflow 尚未在远端运行，不能由离线策略通过推导原生 race 成功或任务一定在时限内完成。推送后必须检查 Core、全部六个 Worker 分片、全部原 repository 分片、显式 PostgreSQL identity/API 及最终聚合门禁的真实终态和耗时；任何失败仍需保留日志独立定位。历史 Windows 打包辅助连接问题由独立单元记录，本单元不证明其原 CI 根因。
