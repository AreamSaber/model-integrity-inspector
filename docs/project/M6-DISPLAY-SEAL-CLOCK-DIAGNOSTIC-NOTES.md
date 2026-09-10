# Display unavailable_seal 时钟诊断（独立只读/纯测试单元）

2026-09-08。只新增两个 Worker test-only 文件及本记录；不修改已冻结维护门禁、execution_display_test.go、M6-MAINTENANCE-GATE-NOTES.md、生产 Capture/Prepared/Seal、期限、系统时钟或 Git。本单元没有数据库/网络请求或真实密钥读取。外部源码核对使用公开官方源码。

## 问题与已证实边界

上一单元原 display_insert 条件在实际 PostgreSQL 用例中出现 `unavailable_seal / COMPLETED / recorded / raw_exists=true`，未命中仅针对captured的SQL注入。该注入遗漏已单独修正，不在本单元重新修改。这里诊断的是为何可能出现unavailable_seal，而不是推翻合法不可用降级语义。

当前已独立证明：本机真实 Windows 精确系统时间可能领先随后读取的 Go time.Now；实际生产 Prepare/Seal 会因严格的捕获时间检查拒绝。这是可重复的本机组件机制反例。旧失败没有记录Sealer两个时间观察，**不能倒推历史每次失败均由该原因导致**，也尚未做当前真实PG查询到Worker的带时间诊断。

## 完整调用链与闭集分支

1. NewRunHandlers在未提供可信DisplaySealer时从EvidenceKeys.NewDisplayCapabilities(nil)创建有效独立display-purpose能力；nil默认clock为time.Now。生产cap不暴露KeyRing或raw key。
2. run.go真实Credentials.Use内先callRunSample完成真实响应，再captureRunResponseBody。后者在2秒captureCtx内通过Queue.WithLease调用BindAttemptResponseCapture；绑定失败是nil capture（之后可能not_captured），不是unavailable_seal。
3. BindAttemptResponseCapture先校验实际Job/Attempt/请求hash/模式/保留策略，再取queueTime。PostgreSQL为`SELECT clock_timestamp()`，UTC截到微秒；SQLite为本进程time.Now截到微秒。Scope/time装入私有capture，DisplayBinding投影；0天不进入seal。
4. captureRunDisplayUsingBinding独立2秒ctx，先验证真实snapshot及wire hash，再Prepare。snapshot/Prepare错误各走source_invalid、policy、limit、cancel等状态，并不走unavailable_seal。
5. Prepare成功后Worker取同一个Prepared的SourceHash与既有capture scope/time构造DisplayBinding，立即Seal，之后defer Close。Prepared内部只有受锁保护的bytes/hash，没有跨调用存活倒计时；Prepare自身临时context结束不会销毁返回Prepared。
6. Seal只有两类非nil对外错误：MI_DISPLAY_CANCELLED与MI_DISPLAY_UNAVAILABLE。Worker前者映射unavailable_cancelled，后者（以及未来其它非cancel错误）映射unavailable_seal。

Seal的MI_DISPLAY_UNAVAILABLE准确来源如下：

- nil/无效cap、nilctx、nilPrepared或版本错误；可信构造器正常路径已提前排除。
- 首次或加密后再次validDisplayBinding失败：scope/hash形状、zero clock、capture<=0、capture晚于当前时间、expiry<=当前时间、expiry<=capture、保留间隔超过180天。即使仅领先1微秒也拒绝，两个观察都使用相同可信clock函数。
- Prepared.Hashes与binding不一致（含已Close后Hashes为空）。正常Worker是同一个Prepared立即取hash/Seal，Close在后；没有观察到并发关闭或手工篡改。
- WithCanonicalForSeal拒绝无效/已关闭/过限payload，或其codec回调失败/异常；它将普通回调错误归并为ErrConsumer，Seal再归并为Unavailable。实际固定32字节AES key及固定AAD字段排除了常规无效key/JSON输入；仍保留异常防线。
- 外层recover捕获异常，例如注入的clock panic。真实Go1.26.7 crypto/rand.Read文档和本地实现说明随机源失败会不可恢复fatal，而非让该普通error分支悄悄返回unavailable_seal；不以全局替换rand.Reader做故障注入。

当前实际失败所见state可排除“Prepare的2秒超时直接伪装成unavailable_seal”：cancel有不同闭集路径。它不能单凭state区别未来capture、过期、绑定或codec异常。

## 真实时间源证据

- 本地固定Go1.26.7的 `.tools/go/src/runtime/time_windows_amd64.s`：time.Now墙上时间读取time_windows.h定义的KUSER_SHARED_DATA `_SYSTEM_TIME`，不是调用精确FILETIME函数。
- 本地已安装二进制只读`postgres.exe --version`得到PostgreSQL18.6。匹配版本[PostgreSQL REL_18_6 Windows gettimeofday源码](https://raw.githubusercontent.com/postgres/postgres/REL_18_6/src/port/win32gettimeofday.c)使用GetSystemTimePreciseAsFileTime并截为微秒；[timestamp.c](https://raw.githubusercontent.com/postgres/postgres/REL_18_STABLE/src/backend/utils/adt/timestamp.c)的clock_timestamp→GetCurrentTimestamp→gettimeofday链与仓储读取匹配。
- [Microsoft文档](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimepreciseasfiletime)将该函数定义为高精度UTC墙上时间，而非用于测量间隔的单调时钟。本诊断没有改系统时钟或放宽未来/过期判断。

## 纯测试与实际观测

`execution_display_seal_diagnostic_test.go`使用真实Adapter.BuildRequest建立匹配snapshot，在真实Credentials.Use调用Worker私有helper→真实Prepare→真实Seal；scope/time是明确test-only输入，不能充作真实DB minted capture。确定性场景：equal-clock正控确有密文、capture领先1微秒、正好过期、超过180天、zero/panic clock、加密后回拨、clock期间cancel、无效cap、request binding不符。另直接验证已Close的Prepared是非cancel不可用。响应/outcome必须保持不变，错误结果不能残留信封。

确定性测试三轮PASS0.093s。随后加入Windows自然观测，各轮上限1024次或1秒、外层2秒ctx，不要求机器必须产生反例，阴性结果也明确计数且通过，不能制造CI时序flake。它实际读取精确FILETIME，再由原time.Now驱动真实Sealer，记录两个实际clock调用的差值，仅输出有限计数与最大领先微秒数。

三轮自然观测（连同确定性测试PASS0.099s）：

| 轮次 | 样本 | precise领先 | 最大领先µs | Seal初次future拒绝 | 成功 | 末次future拒绝/其它不可用/cancel |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | 1024 | 1023 | 507 | 1023 | 1 | 0/0/0 |
| 2 | 1024 | 1024 | 509 | 1022 | 2 | 0/0/0 |
| 3 | 1024 | 1022 | 507 | 1022 | 2 | 0/0/0 |

初次future拒绝同时满足实际clockCalls==1和capture>该次真实Go时间；该返回位置在hash/codec之前，故在这些样本中可精确归因为首次validDisplayBinding时间拒绝。Sealer真正执行时偶尔跨过时钟更新，解释preciseAhead计数与拒绝数不必相等。本采样没有模拟PG网络/事务延迟，因此**不能用这里的比例估计实际Worker失败率**。

Worker vet+golangci-lint0 issues（3.009s）。本单元没有DB、完整Worker、native Linux/race或远端CI验证；旧完整Worker成功属于此前已冻结单元，不冒充这两个新测试的全套证据。

## 候选最小方案，尚未批准/实施

仅为DisplayCapabilities的nil默认clock提供平台实现：Windows读取GetSystemTimePreciseAsFileTime，非Windows保持time.Now，显式可信override原样保留。Sealer和Opener使用同一默认实现；不改变scope/AAD/cipher格式、CapturedAt/Expiry约束、context/deadline、lease、保留策略，不加容忍窗口、不偏移/取max时间、不重试。

该方案可以消除同Windows主机两时间来源精度差异；**不能解决远程PG与Worker真实时钟偏差**，也不应让未来/过期记录自动获准。需要父任务决定是否实现，随后补实际PG时间到Worker路径、严格未来/过期边界、显式clock覆盖不变、Windows默认clock正向及非Windows编译/真实测试。当前只交诊断，不作生产修复声明。
