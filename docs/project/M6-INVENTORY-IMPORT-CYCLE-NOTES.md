# M6 快照库存集成后的 Tokenrisk 测试依赖边界

2026-09-10，开发集成修正，正式审核仍待统一进行。

## 真实红测

root 的真实全仓 `go test ./...` 在 session94627 中报告 tokenrisk 测试 setup failed，
其它已启动的包继续执行；本单元没有终止或重启该进程。独立执行：

```
go test ./internal/integrity/analysis/tokenrisk -count=1 -timeout=1m
```

在 0.317 秒命令墙钟内退出 1，实际 Go 编译器错误链为：

```
tokenrisk standard_test.go
→ secret service.go
→ repository snapshot_report_inventory.go
→ report validate.go
→ scoring analyze.go
→ tokenrisk
```

该循环来自 `standard_test.go` 原本使用内部 `package tokenrisk`，却为真实探针编译器导入上层
`secret.NewKeyRing`。新增报告快照库存复用实际报告验证器后，测试依赖回到自身包。
这是内部测试包的依赖循环，不是生产 tokenrisk 算法需要依赖数据库；也不能通过移除签名、
改用手写探针、减少 Standard60 样本或复制报告算法解决。

## 最小修正

仅将跨模块 `standard_test.go` 改为外部 `package tokenrisk_test`；使用原生产导出的 `Sample`、
`Version`，并在新 `standard_export_test.go` 提供四个窄 test-only 转发函数，分别调用原本的
`sample`、`testDigest`、`ladder`、`analyzeTest`。桥接不复制计算或夹具逻辑，也不会进入普通生产构建。

其它内部测试保留原包及私有算法访问能力。实际 probe compiler、随机测试 KeyRing、内置模板、
离线 tokenizer、structure analyzer 和全部设置不变；唯一模拟部分仍是原来的受控上游响应。
两个完整 Standard60 顶层测试、三个场景（fixed-256、healthy、stream-only）、所有样本/阶梯/
置信区间/分组/权重/开发未校准断言逐项保留，没有添加 skip、重试或放宽误差阈值。
未修改任何生产文件、repository/report/scoring 包、模块声明或第三方依赖。

## 实际绿测与静态检查

```
go test ./internal/integrity/analysis/tokenrisk -count=3 -timeout=1m -v
go vet ./internal/integrity/analysis/tokenrisk
golangci-lint run --allow-parallel-runners ./internal/integrity/analysis/tokenrisk
go list -f '{{.TestGoFiles}} {{.XTestGoFiles}}' ./internal/integrity/analysis/tokenrisk
go test ./internal/integrity/analysis/tokenrisk -list .
```

- 完整包三轮 PASS，包耗时 **0.700s**。实际输出包含 Standard60 三场景每轮执行；fixed-256
  保留两个候选 family、strength 41.00 和 development/uncalibrated 边界。
- 原 builtin runtime golden 继续通过，固定 JSON 哈希
  `7f08924aa981a93a6163be30cb47783a149cedebcd4b744af3336ac3279c7c45` 未变。
- 原完整内部测试和两个 fuzz seed 每轮通过；普通 `go test` 执行的是 seed，不冒充持续 fuzzing。
- vet 退出 0；lint `0 issues`；diff whitespace 检查通过。
- `go list` 确认仅 `standard_test.go` 在 XTestGoFiles；新桥接在 TestGoFiles，生产 GoFiles 不变。
- 真枚举保留 15 个 Test 顶层入口和 1 个 Fuzz 顶层入口，没有过滤嵌套测试。
- 将新旧 Standard60 文件仅规范化包名、增加的 import、类型限定及四个转发调用后，实际全文逐字比较相等；
  所有原输入设置、控制流、输出构造和断言内容未发生其它变更。

本单元未访问数据库或执行网络/付费调用。全仓编译、完整 Windows 打包和新远端 CI 仍由 root
继续验证，不能由该包通过推导全仓或完整候选版完成。
