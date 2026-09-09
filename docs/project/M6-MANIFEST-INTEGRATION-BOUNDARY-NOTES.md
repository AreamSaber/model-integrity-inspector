# M6 manifest 组合测试依赖边界修复

日期：2026-09-09。范围仅为 `backupmanifest` 的测试包边界；本单元不改变生产依赖、manifest 格式、数据库状态或备份发布流程。

## 真实失败与原因

修复前，本机 Go `1.26.7 windows/amd64` 执行 `go vet ./internal/integrity/backupmanifest`，退出码为 1：

```text
backupmanifest integration_test.go
  -> secret service.go
  -> repository snapshot_audit_inventory.go
  -> backupmanifest
import cycle not allowed in test
```

新增审计 inventory 生产依赖后，原内部测试包把上层 `secret` 重新引入被测包，导致测试专属循环。无需反转或删除现有生产依赖。

## 实施边界

- `integration_test.go` 改为外部测试包 `backupmanifest_test`，组合测试和 `FuzzManifestDecode` 均通过公开 `Encode`、`Decode`、`Entries`、`VerifyStream`、类型、限制及错误常量调用产品代码。
- `export_test.go` 仅导出测试函数变量 `TestOnlyFixture = fixture`，每次调用复用现有函数生成的新 synthetic manifest。该桥接只进入测试二进制，不添加生产测试后门、验证捷径或运行时配置。
- 外部测试使用标准库 `sha256.Sum256` / `hex.EncodeToString` 独立计算哈希，不桥接生产私有 `digest`。跨包结构字面量改成具名字段，值不变。
- Go 不允许顶层 `func TestOnlyFixture() Manifest` 作为测试函数：第一次迁移验证真实报错 `wrong signature for TestOnlyFixture`。随后按仓库已有 privatefile 测试桥方式使用函数变量；没有跳过测试或修改任何失败断言。

`go list` 确认生产文件仍只有 `entries.go manifest.go preflight.go stream.go validate.go`；内部测试为 `export_test.go manifest_test.go stream_test.go`，外部测试为 `integration_test.go`。

## 保留的原始测试证据

- 真实模板 registry 的 66 / 128 字符版本编码、查回与哈希保留；129 字符 artifact、65 字符 key version 仍被拒绝。
- 真实 AEAD 封装的五种 inventory 用例全部保留：`valid`、`changed_payload`、`missing_entry`、`extra_entry`、`wrong_kind`。每个样本先确认 AEAD 框架认证完整，再以独立 exact-entry 比对和生产流验证器判断 manifest 一致性。
- 全部条目均已接受之后，外层额外字节或截断结尾仍必须产生 `ErrCallback`；完整条目集合不能掩盖归档终止/外层 EOF 失败。
- fuzz 的五个源码种子、256 KiB 原输入边界、精确闭集错误、canonical 重编码、哈希与有界 entry plan 断言均未改变。
- 对修改前后全部测试/fuzz 函数体做文本核对：仅规范化包名前缀、fixture/digest 调用名、该处字面量具名字段及空白后，结果完全相等。没有删除或弱化子项、断言、超时或边界。

这些仍是使用 synthetic 文件内容的真实密码学与流组合测试，不是数据库快照恢复测试、真实审计链验证或完整备份协调器验收。

## 本机验证终态

命令从仓库根目录执行，PATH 前置 `.tools/go/bin`，`go` 为 `.tools/go/bin/go.exe`，lint 为 `.tools/golangci-lint/golangci-lint.exe`。

| 验证 | 实际命令 | 终态 |
| --- | --- | --- |
| 全部包测试三轮 | `go test ./internal/integrity/backupmanifest -count=3` | PASS，包报告 0.277 秒 |
| 有界短 fuzz | `go test ./internal/integrity/backupmanifest -run '^$' -fuzz '^FuzzManifestDecode$' -fuzztime=10s -parallel=2 -timeout=2m`，另设 `GOMAXPROCS=2` | PASS，11.126 秒；7 个含缓存 baseline，1,158 次执行，新增 2 个 interesting inputs |
| 原红命令重验 | `go vet ./internal/integrity/backupmanifest` | PASS，退出码 0 |
| lint | `golangci-lint run ./internal/integrity/backupmanifest` | PASS，`0 issues.` |

全仓验证和 Git 集成由 root 后续执行，本记录不把包级通过等同于全仓通过。本单元没有运行数据库测试、读写数据库、改动服务配置或执行 Git 写操作。

root 后续核验：完整读取原测试、迁移差异、test-only bridge 和本文后，全仓
`go vet ./...` / `golangci-lint ./...` 曾取得终态 0 issues；本次再跑 manifest
完整三轮 0.312 秒 PASS，三包静态检查再次通过。后续 CSV 上层改动仍需独立验证。
