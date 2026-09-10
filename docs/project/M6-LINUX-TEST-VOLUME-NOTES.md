# Linux Docker 测试临时盘容量协调

2026-09-08。这只调整镜像构建时全量测试包二进制的并发，不改变生产文件系统准入、SQLite步数/容量、24MiB以上真实测试输入、测试内部并发、原超时、race分片或required门禁。

## 依据与取舍

Docker backend的overlay不在生产私有文件准入名单，原Linux fixture正确回退经Statfs验证的/dev/shm。privatefile认证组合同时约50MiB；新repository在线快照实测主库26,247,168字节、副本同量，合计也约50MiB。两个独立test binary在默认64MiB共享tmpfs上重叠就超出容量；privatefile内部/外部测试同一二进制串行只解决包内，不能解决这项跨包竞争。这是由容量与执行方式证明的风险，尚未当作已发生的Linux CI故障根因。

选择在既有Docker执行层使用 `go test -p 1 ./...`。固定Go1.26.7的本地 `go help build` 明确-p约束可并行test binaries数量；全部./...包仍执行，包内goroutine、t.Parallel和并发故障案例不变，随后独立webassets套件不变。没有缩小文件、Skip、-short、-run过滤、吞错、增加共享盘或延长期限。代价是镜像构建测试可能较慢，实际耗时需新CI验证。

没有增加跨包flock、持久锁文件、按测试名称重入/cleanup计数等新状态。其它自定义Linux测试环境若也把这两个包放在同一64MiB临时盘，应同样运行 `go test -p 1 ./...`，或预先提供足够容量且满足原准入策略的本地测试卷；此构建配置不是任意宿主全盘容量保证。

## 验证边界

新增契约要求唯一完整串行命令及独立assets命令，对丢失全量/丢失assets、原默认并行、并行2、short、run过滤、单包替代、吞错和重复命令分别拒绝；原前端源码必须在全量测试之前COPY、runtime不带构建源码的断言保留。

先在原Dockerfile运行新契约真实失败0.090s，再修改recipe。首次完整contracts三轮0.677s仍失败，因为旧netns源码分发顺序断言绑定旧命令文字；已改用同一个完整串行命令常量，所有源码顺序/runtime隔离断言不变。最终完整contracts三轮 **1.099s PASS**、lint0。Windows只能执行契约与交叉编译，不能冒充Linux原生镜像运行或大文件重叠实测。CI34202061195是ebd81b3，不含本改动/在线snapshot；后续提交的新CI才是镜像耗时与全部原生测试的证据。
