# Windows CI 2026-09-10 诊断与报告测试清理

## 已核实的失败与边界

实际读取的是提交 `0268a09fc7d9524ad2fc7217779a684ed3022723` 的
[CI 34334609860 / Windows job 102411006255](https://github.com/AreamSaber/model-integrity-inspector/actions/runs/34334609860/job/102411006255)。
运行已终态 failure；Windows package 失败，总门禁按要求失败，其余 18 个 job 成功。
失败发生在 `package.ps1` 第一轮 `go test ./...`，尚未执行第二轮 webassets 测试和制品生成。

- app：实际 TLS 主流程的 `display_service_slots_and_copied_close` 在
  `Disclosure.WriteTo` 返回错误或长度不符时失败。该断言没有记录具体错误，不能仅由其消息认定复制句柄本身损坏。
  有界应用日志记录 `09:30:32.438` claim 失败、`09:30:32.717` Worker 退出且
  `class=database_unavailable,caller_done=false`；此后独立登录与后续 HTTP 请求为
  `network_dial`，清理获得 `MI_STARTUP_FAILED`。Worker 退出触发应用关闭监听的代码路径可以解释后续连接失败；
  尚不能证明 WriteTo 与 claim 哪个底层 SQL 先失败或二者的唯一共同原因。
- repository：整个包的默认 600 秒预算耗尽。当时正在运行的
  `TestResponseRetentionCleanupAllWritesAndCommitFailAtomically/display_delete/sqlite`
  仅运行 1 秒，栈为 Windows `FlushFileBuffers` → SQLite 提交 → `legacyBodyFixture` 初始化写。
  这是累计包超时，不是该子测试独自运行 600 秒，也没有证明死锁或具体文件系统故障。
- Worker：`swapped-signed-rows` 在 `finishDerivedTLSRun` 的真实 TLS handler 返回
  `DATABASE_UNAVAILABLE`，尚未进行 S1 损坏注入；不能作为算法错误证据。
  两项 lease 注入夹具的 UPDATE 观测为 `context_cancelled=true`、SQLite code 0，分别约
  2418/3373 毫秒；这证明观测时上下文已结束，但不足以区分 SQL 锁等待、连接等待和底层 I/O。
  另有 precheck 未 ready/未完成及 report 夹具的权限 DELETE 失败。
- capturefixture：实际回放采集在 estimate/confirm 前后执行准备检查返回
  `MI_EXECUTION_NOT_READY`，清理 Worker 返回错误，尚未达到目标回滚断言；日志未提供底层操作分类。

repository、Worker、API 测试进程实际重叠。全量 `-p 1` 可作为不改变测试集合、期限或 SQLite
FULL 同步策略的资源调度对照，但不能根据重叠事实或一次通过认定上述原生数据库原因已修复。
本单元没有修改构建、打包、CI、生产日志、Runner、数据库配置或任何业务期限。

## 已确认并修复的次生清理缺口

`TestReportWorkerPublicationInfrastructureFailuresStopConsumer` 原先启动 Runner 后只有
`defer cancel()`，仅正常路径消费 `done`。此次真实 `failure_audit` 在安装故障前的权限 DELETE
失败并调用 `t.Fatal`，因而跳过正常 join。已有 `eachWorkerDatabase` 注册的检查连接、Store、
临时目录清理可早于后台 Runner 完成；CI 同时报告 `worker.db` sharing violation。
这个确定的生命周期缺口不能解释最初 DELETE 失败；修复不宣称整个 Windows CI 已绿。

测试专用 `startReportRunnerFixture` 在启动 goroutine 前注册 cancel-and-join 清理，后注册的清理
先于已有报告存储、SQL 连接及临时目录清理执行。只有一个 goroutine 写入唯一终态，并关闭通知通道；
正常错误断言和清理读取同一关闭通知，不会争抢或重复等待一次性的 error send。
正常路径仍在原 5 秒内先验证未取消 Runner 的真实 `ErrConflict`/`ErrUnavailable`/fencing 错误，
不提前取消、替换错误或掩盖故障；清理等待沿用相邻 Runner 夹具既有 7 秒上限，超时仍失败。

## 验证

纯层先保留原 cancel-only 行为，用已确认取消后的受控屏障证明资源清理不得越过 Runner：

```
go test ./internal/integrity/worker -run '^TestReportRunnerCleanup' -count=1 -timeout=1m
FAIL 0.142s: resource cleanup overtook canceled Runner completion
```

加入 join 后三轮 PASS 0.174s；加入真实路径测试后只运行同一纯层三轮 PASS 0.178s，
最终 `errors.Is` 规范化后纯层三轮 PASS 0.179s，完整 Worker 包 vet 退出 0、lint `0 issues`。
屏障保持 25 毫秒仅是被测试的已知 goroutine 生命周期区间，不是数据库阶段的调度猜测。
另一个纯层用例验证正常结果在 context 仍 active 时被断言、终态只产生一次，之后清理取消 context，
不会二次消耗通知。

新增真实双库测试 `TestReportWorkerFaultFixtureEarlyReturnJoinsActualRunner` 使用原签名分析与真实报告
handler，实际写文件后在安装故障前提前返回。它检查 Runner 终态、consumer lease 释放、只读查询仍可用，
且清理未伪造报告发布。

在 root 授予的独占数据库窗口内，实际执行下列命令（真实 PostgreSQL DSN 仅从本地秘密文件装入环境，未输出）：

```
go test ./internal/integrity/worker -run '^(TestReportRunnerCleanup|TestReportWorkerFaultFixtureEarlyReturnJoinsActualRunner|TestReportWorkerPublicationInfrastructureFailuresStopConsumer|TestReportWorkerRevokedPublicationFailsOnlyThatJobAndContinues)$' -count=3 -timeout=5m -v
```

session33997 终态退出 0，包耗时 **29.694s**。输出逐项确认三个完整数据库父项全部执行，SQLite/PostgreSQL
各三轮通过：原四种基础设施/审计写入/fencing 故障、撤权后继续其他报告，以及新真实提前返回清理路径。
没有临时目录 sharing violation 或清理错误，随后明确释放数据库窗口。
该命令里的锚定 `TestReportRunnerCleanup` 不匹配两个带后缀的纯测试，未将其误算为覆盖；纯层另用
`go test ./internal/integrity/worker -run '^TestReportRunnerCleanup' -count=3 -timeout=1m -v` 验证，实际 PASS 0.167s。
此前纯层 20 轮稳定性检查也实际 PASS 0.614s。

本地目标回归不等价于完整 Windows 原生包、远端 CI 或历史第一 SQL 故障复现；后续需保持全部失败门禁并
读取新 Windows 运行的实际终态。

正式审核状态保持待统一审核。
