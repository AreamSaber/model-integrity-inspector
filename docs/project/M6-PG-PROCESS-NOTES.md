# M6-05 PostgreSQL 原生工具进程边界

开发状态：原生执行器已实现；正式审核待 V1.0 统一审核。本页只说明工具进程边界，不代表 PostgreSQL 备份、恢复或 M6-05 全部完成。

## 实现与限制

- `internal/integrity/pgbackup/process_common.go` 校验受信绝对 executable / working directory、完整替换且非 nil 的 environment、非 nil writer、最大 24 小时的 context deadline。调用不经过 shell，不搜索 PATH，不继承 `os.Environ()`，stdin 为 EOF。
- 两个 goroutine 各用固定 32 KiB buffer 复制 stdout / stderr；调用者负责提供有总长度限制且及时返回的独立 writer（或自行同步的共享 writer）。执行器不会从 stderr 产生错误文本。writer panic、短写和一般错误闭合为 `ErrOutput`，专有 `ErrLimit` 保留，OS / exit 错误闭合为 `ErrProcess`，取消优先为 `ErrCanceled`。返回前 join 两个 pump，调用者之后读取 writer 状态不会与 pump 并发。
- 无法中断任意阻塞在用户 Go 代码内的 writer；这不是可接受任意插件的 runner。未确认子树清空时主动关闭本地 read 端；正常清理后的 drain 也有 5 秒上限，超时关闭管道并 join，而不是在持有 write 端的后代上永久等待 EOF。不能确认清理完成时不会返回成功。
- 不支持的操作系统直接返回配置错误，不回退到无隔离 `exec.Command`。

### Windows

`StartupInfoEx` 同时携带 `PROC_THREAD_ATTRIBUTE_JOB_LIST` 与精确的 `HANDLE_LIST`；进程的初始线程执行前已经加入独有的 unnamed Job。Job 启用 `KILL_ON_JOB_CLOSE`，不启用任何 breakaway 标志。只有 stdin read 与 stdout / stderr write 三个 handle 允许继承；job、parent read 端、其他可继承句柄均不在白名单。`CREATE_NO_WINDOW` / `SW_HIDE` 不显示控制台。UTF-16 环境块是显式构建的全量替换，使用后清空。

JOB_LIST 值 `0x0002000d` 源自官方 WinSDK 的 `ProcThreadAttributeJobList = 13` 与 `PROC_THREAD_ATTRIBUTE_INPUT = 0x00020000`，不是猜测。该启动方式要求 Windows 10 / Server 2016 或更新平台；不支持时 fail closed，不使用 Start 后 Assign 的有逃逸窗口路径。

父进程结束后也会终止 Job 剩余成员。终止前从 owned Job 获取最多 1024 个 PID 并持有对应 process handles；任一 native API 错误 / 超界立即失败。成功查询但 assigned/count 不一致时，在同一原有 5 秒清理期限内重新读取该 Job 清单，不接受部分清单或扩大容量。对已打开 handle 用 `IsProcessInJob` 核实归属，避免枚举后 PID 复用造成对无关进程的等待。随后既检查 Job `ActiveProcesses == 0`，也等待保留的成员 process handles 为 signaled。只向 owned Job 发送终止，不向裸 PID 发送杀进程请求。若查询或清理未完成，显式关闭 Job 触发 kill-on-close 回退，再关闭本地管道；这不是清理成功证据。

早期代码只检查读取到的 `ActiveProcesses == 0` 时，实测仍会过早返回：父进程先退出时，分支进程的保留 handle 还未 signaled。加入成员终态等待后，具有三代进程真实握手、ACK 后允许父进程先退出的回归由红转绿；测试没有用启动 sleep 判断子进程已经存在。这说明必须保留真实成员终态检查，不单凭一个读取到的计数推断完整清理。

后续 root 三轮复测又出现 1 次 10 并发预热的闭合 `ErrProcess`（20.267s FAIL），旧实现目标测试 100 轮在 62.694s 内复现 4 次同类失败。临时闭合阶段诊断都定位到 Job 清单计数 guard，不是已证实的 `IsProcessInJob` 失败；没有取得足以唯一判定“系统清单并发变化”与“原 uintptr ABI 缓冲生命周期”的细分证据，因此不虚构唯一根因。已做两项对应修正：

1. 所有通过 x/sys `uintptr` 参数传入的 Job limits、accounting、PID inventory 缓冲均由 `runtime.Pinner` 显式固定，避免 Go 栈增长 / GC 期间地址失效。编译器 escape 输出确认三类对象均 moved to heap；仅有 KeepAlive 不足以固定栈地址。
2. 不一致的清单只能在原期限内重取，必须拿到完整一致清单；API 错误、容量超界和持续不一致到期仍闭合失败。新增 6 个确定性回放 / 错误边界，不通过放宽原并发数、循环次数、容量或终态断言制造成功。

### Linux

Go fork/exec 在 child exec 前设置独立 process group。`waitid(WEXITED | WNOWAIT | WNOHANG)` 保留 leader 的僵尸占位，确保向 `-PGID` 发出 SIGKILL 前 PID / PGID 不会因我们提前 reap 而被回收。发送唯一的 owned-group 终止信号之后，才调用 `command.Wait()` 回收 leader。回收后不再向该数值组发送任何信号，只用 signal 0 查询存在性，最多等待 5 秒。

Linux process group 约束受信的 pinned PostgreSQL 工具及正常继承该组的后代，不是任意恶意进程沙箱；显式 `setsid` / `setpgid` 逃逸需要额外 cgroup / namespace 策略，本 helper 不作此保证。若容器 init 不回收 orphan zombie，组可能迟迟不消失；这会闭合失败，不能据此宣称清空成功。Linux测试允许该明确失败结果，但仍检查所有已握手后代不再运行。

## 验证证据

Windows 原生实际执行当前 Go test executable，不调用 shell、不使用 PostgreSQL 服务：

```powershell
.tools/go/bin/go.exe test ./internal/integrity/pgbackup -run '^TestNativeProcess' -count=3 -timeout=3m
```

最终修正版三轮 `PASS 19.751s`：复杂 argv（空串、引号、反斜杠、Unicode、换行及 shell 样式字符）、cwd、EOF stdin、不继承父进程环境 canary、stdout / stderr 各 256 KiB 并行输出、不存在 executable、非零 exit、两路各自 panic / short / limit / error writer、真实三代取消、父先退出、无期限 read 被有界关闭后 join、无效配置和清单变化的 6 个边界。此前 19.598s 的通过不覆盖后续发现的失败。

额外验证：同一目标测试（原 10 并发资源检查加 6 个清单边界）在清单修正后 100 轮 `PASS 72.527s`；最终显式 Pinner 版本使用 `GOGC=1` 加强 GC 压力，30 轮 `PASS 20.812s`。这些是本机 Windows 的真实运行证据，不是 Linux 原生或 race 证据。

Windows 专属回归还覆盖外部 inheritable Event 未被 HANDLE_LIST 继承、重复执行后本进程实际 handle 总数不增长。早期总数检查曾遇到 Go runtime 每新增一条 OS 线程增加 6 个 handle 的初始化现象；对照 pinned Go `runtime/os_windows.go` 的线程事件、定时器和 wait completion packet 后，改为先运行 10 个并发真实子进程预热，再测 20 次串行执行（轮流成功、非零 exit、输出 limit、启动失败），仍严格要求总 handle 数不增长，不通过 GC/finalizer 掩盖泄漏。失败时同时输出线程数变化。

Windows `go vet` 与同包 golangci-lint 已通过（0 issues）。Linux `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c`、交叉 `go vet` 和 golangci-lint 已通过（0 issues）；交叉编译不是 Linux 原生测试或 race 证据。Linux 原生及 race 待后续 Linux CI。

真实 pinned pg_dump 18.6 联调另发现本机运行时依赖缺口：最小 environment 下退出 `0xC0000135`（DLL_NOT_FOUND），普通终端依赖 ambient PATH 中的 Microsoft 签名 VCRUNTIME140.dll。PE 导入表确认 pg_dump / liblz4 / libcrypto 依赖该 DLL，本机 System32 无该文件；补 WINDIR 无效，仅显式加入所定位的运行时目录后版本输出成功。首次定位未复制 DLL / 修改机器 PATH / 恢复 ambient environment。随后经明确授权由独立本地测试运行库脚本配置 app-local DLL，见 `M6-PG-TEST-RUNTIME-NOTES.md`；该修复不放宽 executeNative 的环境边界，也不代表获得产品再分发授权。

## 官方依据

- [UpdateProcThreadAttribute / JOB_LIST 和 HANDLE_LIST](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [官方 WinSDK WinBase.h](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/WinBase.h)
- [Job Objects：后代继承和 kill-on-close](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [TerminateJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject)
- [JOBOBJECT_BASIC_PROCESS_ID_LIST](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_process_id_list)
- [JOBOBJECT_BASIC_ACCOUNTING_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information)
- 本地 pinned Go 1.26.7 源码：`syscall/exec_linux.go`、`os/exec/exec.go`、`os/file_windows.go`、`internal/poll/fd_windows.go`、`runtime/os_windows.go`；本地 `golang.org/x/sys@v0.47.0/windows/exec_windows.go` / `types_windows.go` / generated syscall bindings。

下一步：由主线接入真实 pinned `pg_dump` 的版本核验、受控连接 / TLS、同步快照参数、归档输出限制及完整备份恢复工作流；本执行器不替代那些校验。
