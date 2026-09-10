# 展示证据默认时钟：Windows 精确时间最小修正

2026-09-08。本单元由父任务批准，只调整DisplayCapabilities的nil默认clock；不改Worker、仓储、已冻结维护门禁/故障注入文件、Capture/Prepared/Seal/Open时段判据、加密格式、业务期限或系统时钟。没有Git操作。详细诊断与原始组件观察见 `M6-DISPLAY-SEAL-CLOCK-DIAGNOSTIC-NOTES.md`；旧注入遗漏及其测试修正是另一单元。

## 已证明与尚未证明

本地Go1.26.7 Windows time.Now读取shared-data wall clock，而[匹配本地PG18.6的Windows gettimeofday源码](https://raw.githubusercontent.com/postgres/postgres/REL_18_6/src/port/win32gettimeofday.c)使用[GetSystemTimePreciseAsFileTime](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimepreciseasfiletime)。本机自然采样真实读取这两个源，三轮各1024样本，最大领先507/509/507µs，实际Seal首个时间检查因capture晚于其Go时钟拒绝1023/1022/1022次；没有其它不可用或cancel。这个直接组件机制已经证实，但没有数据库网络/事务延迟，因此不能据此估计真实Worker失败率。

之前一次实际PG故障测试只记录unavailable_seal，没有Sealer两个时间观察；**不能倒推历史每次失败唯一由时钟造成**。本修正也不能解决跨主机真实时钟漂移，不能将远端未来记录自动视为当前。

## 精确实现边界

- `secret/display.go`：仅`NewDisplayCapabilities(nil)`的默认函数从time.Now改为包私有displayNow，并更新默认clock说明；显式可信now函数原样保留。
- `display_clock_windows.go`：通过既有golang.org/x/sys/windows调用GetSystemTimePreciseAsFileTime，以真实FILETIME转UTC time.Time；没有偏移、等待、重试、取max或修改系统时钟。
- `display_clock_other.go`（!windows）：仍返回time.Now。
- Sealer与Opener拿到相同默认函数。validDisplayBinding的scope/hash、capture>0、capture<=now、expiry>now、expiry>capture、最长180天、首次/末次检查，以及ctx/cancellation逻辑均没有修改；AAD、nonce、ciphertext、capture/expiry持久值也没有修改。
- 不改变其它purpose时钟、Job/维护租约、HTTP/request/Prepare预算、保留策略或SQLite/PG数据库时钟权威。

## 验证

1. 新 `TestDisplayDefaultWindowsClockBracketsRealCodec` 使用原公开nil-default构造器，以两次真实Windows精确读取夹住默认clock观察，然后实际Prepare/Seal/Open，32次检查不改binding。先在原码运行，0.084s FAIL：默认clock落在该实际前后区间之外。这是修前真实红测，不是更改系统时间的注入。
2. 改默认clock后，全secret三轮PASS1.203s、全evidencedisplay三轮PASS1.109s。默认Windows正控实际Seal/Open成功；不是只比较函数名或返回形状。
3. 新 `TestDisplayExplicitClockOverrideKeepsStrictValidity` 用固定可信override验证Seal/Open确实各观察两次，并在capture领先1µs、恰好expiry和cancel场景保持原拒绝。独立Worker诊断中的末次回拨/取消等负例三轮PASS0.100s。
4. `execution_display_seal_clock_windows_test.go`的自然观察刻意显式传入原time.Now；默认clock修正后它仍可观察旧精度差异。这是保留可重复机制证据及验证override不被替换，不代表新nil默认clock仍使用旧时间源。无领先样本的机器也正常报告阴性计数，不强制机器依赖失败。
5. 新!Windows测试保留time.Now前后夹住默认clock及真实Prepare/Seal/Open正控。5880已终态exit0：Windows和Linux/amd64目标的secret/Worker `go vet`、golangci-lint均0 issues，Linux/amd64 CGO=0的secret与Worker测试二进制交叉编译成功。没有native Linux执行或race/远端CI证据，crossbuild不冒充Linux测试通过。

6. 父任务完成audit有界读取红绿及扩大三轮后明确交接DB时段，启动9877顺序联测。既有 `TestRunWorkerDisplayActualCredentialsTLSAndUnchangedAnalysis` 双库三轮PASS5.617s，实际bearer/custom_header各含非流式/SSE。已逐项核对真实调用链：runTLSConfig未提供DisplaySealer，因此NewRunHandlers走新nil默认clock；Credentials.Use内实际Queue.WithLease→BindAttemptResponseCapture，在PG通过queueTime的clock_timestamp取得时间后写入私有capture，WorkerSeal/持久结算沿用该绑定；测试读取真实落库的scope/capture/expiry并实际Open认证，原响应/Tokenizer/usage/事件及脱敏断言均保留。没有合成DB时间或新增假capture测试。

7. **9877最终exit0**：随后完整 `go test ./internal/integrity/worker -count=1 -timeout=10m` 实际SQLite/PG双库单轮PASS168.803s。全程生产clock和Worker测试源码冻结，父任务audit.go新的有界读取也包含在当前编译与联测中。这里是当前默认时钟版本的完整Worker单轮，不引用修正前结果冒充。进程终态后已立即向父任务和evidence_capture明确释放DB时段，没有追加测试。实际PG链路现在有第6–7项集成证据，仍不代表native Linux/race或远端CI已通过，也不据此宣称跨主机时钟漂移已经解决。

## 文件归属与恢复入口

root 完整复核生产差异、平台默认时钟测试与两份Worker诊断后，再跑完整secret/evidencedisplay三轮1.330s/1.138s、Worker纯诊断三轮0.105s通过。上述真实Worker全包联测同时包含root在途审计有界读取，后者独立提交；不把组合工作树的结果归给只含clock的旧SHA。提交身份与新CI以台账为准。

修改既有 `internal/integrity/secret/display.go`；新增 `display_clock_windows.go`、`display_clock_other.go`、`display_clock_test.go`、`display_clock_windows_test.go`、`display_clock_other_test.go` 和本记录。此前新增的两个Worker诊断文件保留不变。所有Git由父任务处理。
