# M5-08 / REP-007 CSV 报告内核检查点

## 范围与当前结论

本单元实现 CSV 软件导出内核，不是独立用户电子表格文件制作。已完整核对
PRD §9.8、report 包 README、S1 类型、验证/归一化、canonical JSON、HTML
及既有测试。REP-007 的 P1 CSV 部分不因旧文档的后续版本措辞被移出当前
开发目标。

本单元仅新增三个 Go 文件和本文；没有改动已有 report 文件、数据库、
repository、API、Worker、前端、全局台账或 Git 状态。代码没有文件系统、
网络、环境变量、密钥或时钟访问，也没有外部进程和新依赖。

**这不是 CSV 产品交付完成或审核批准。** 持久化、授权、发布任务、下载 API、
媒体类型/附件策略、前端入口、集成验收仍由上层后续单元完成。PDF 亦不在本单元。

## 调用与所有权

```go
snapshot, err := report.NewDevelopmentSnapshot(scope, projection)
if err != nil {
    return err
}
csvArtifact, err := report.GenerateCSV(snapshot)
if err != nil {
    return err
}
data := csvArtifact.Bytes()
contentHash := csvArtifact.ContentHash()
fileHash := csvArtifact.FileHash()
csvProfile := csvArtifact.SchemaVersion()
```

`GenerateCSV(*Snapshot) (*CSVArtifact, error)` 只读取已构造并冻结的 S1 Snapshot。
不增加自由文本字段，不接受用户上传 JSON、任意列选择、秘密正文或审批开关。
输入来源与权限仍由受权调用层负责，内核不认证数据库来源或签名。

`CSVArtifact` 字段全部私有；`Bytes()` 每次返回独立副本。Snapshot 支持并发
只读生成，输入在构造后被修改不会影响输出；不允许构造期间并发修改输入。
nil/零值 artifact 不返回版本或虚构的制品元数据。

## 版本化全内容长表

CSV profile 为 `mii.report.csv.v1`，UTF-8、无 BOM、逗号分隔、CRLF 记录结尾，
包括最后一条记录。使用 Go 标准库 `encoding/csv.Writer` 的 CSV 引号转义，
不拼接未转义单元格。格式约定参考 [RFC 4180](https://www.rfc-editor.org/rfc/rfc4180)。

固定表头、固定四列顺序：`csv_schema,path,value_type,json_value`。每个节点一行，
每行重复 CSV profile。根节点先输出，路径为空字符串；其后递归先序遍历，
对象按现有 canonical JSON 的键顺序，数组保留语义索引顺序。

| 节点 | `value_type` | `json_value` |
| --- | --- | --- |
| 对象，包括空对象 | `object` | `{}` 容器标记；内容由后续子节点提供 |
| 数组，包括空数组 | `array` | `[]` 容器标记；内容由后续子节点提供 |
| 字符串，包括空字符串与 ID | `string` | 包含实际 JSON 双引号的完整 JSON 字符串词法 |
| 数字 | `number` | 现有 canonical-json.v1 的有限、安全数字词法 |
| 布尔值 | `boolean` | `true` 或 `false` |
| 空值 | `null` | `null` |

`path` 使用 [RFC 6901 JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901)：
每段前置 `/`，键中的 `~` 编码为 `~0`，`/` 编码为 `~1`；不做 URI 编码或
Unicode 归一化。数组索引为从零起、无前导零的十进制字符串。
根空路径与对象的空键路径 `/` 不混淆。读取时先把 `~1` 还原为 `/`，再把
`~0` 还原为 `~`，不能倒序。

所有对象/数组都有容器行，因此空对象、空数组、null、空字符串不会混淆。
所有最终 JSON 字段都被导出，不是仅样本摘要：范围和版本、时间、组织/Run/
报告 ID、四维及总体风险、统计分母、发现、限制与替代解释、所有逻辑样本和
Attempt、建议、免责声明、开发声明、当前 `review=null` 与
`review_state=not_included` 均保留。CSV 不新增人工审批或可信校准结论。

## 原有内容哈希不变

先使用既有 `canonical(snapshot.doc)` 得到不含 `content_hash` 的内容及 SHA-256；
再采用与既有 `Generate` 相同的结构加回 `content_hash`，得到同一最终 JSON。
CSV 从这些最终 JSON 字节的 token 流生成，不生成 HTML，也不改变既有
`Generate`、JSON/HTML 字节、schema 或 canonical golden。

`ContentHash()` 因而与同一 Snapshot 的 JSON/HTML 内容哈希相同。
`FileHash()` 是完整 CSV 实际字节的独立 SHA-256，不是 JSON 文件哈希，也不在
CSV 内自引用。`SchemaVersion()` 返回 CSV profile，而 JSON 文档的
`schema_version`、`canonical_version` 仍作为普通节点完整出现。

测试通过标准 CSV reader 回读四列，并以独立父子树重建算法恢复原最终 JSON
的每一个字节；该算法不调用生产 `canonical()`，不使用 float64 解析数字，
并在移除 `content_hash` 节点后独立计算 SHA-256。哈希只证明字节一致，
不代表真实性、独立审核或产品发布批准。

## 单元格安全与资源边界

字符串 `json_value` 解码 CSV 后的第一个实际字符仍为 JSON 双引号，不只是
CSV 运输层的包围引号。`=`, `+`, `-`, `@` 等字符串和控制字符不会因此变成
以公式前缀开头的裸单元格；控制字符由 JSON 转义保留。大 ID 始终是 JSON
字符串，不经浮点转换。负数只允许原 canonical 数字语法，诸如 `-1+...`、
`NaN`、无限值、非规范指数或不安全整数被拒绝。

这属于格式级防御，**没有执行 Excel/LibreOffice 实测**；不承诺所有电子表格
产品或人为剥除 JSON 引号后仍安全。消费方应按此 profile 导入并保存原字节，
不应把 JSON 字符串解包后重新输出为未防护 CSV。

复用现有 16 MiB 有界 writer，不放宽 4 MiB S1 输入预算；最终 JSON token
读取前检查其 16 MiB 上限。CSV 流式写行，不收集全量行或另建完整 JSON 树。
私有 renderer 额外约束深度不超过 24、路径不超过 4096 字节，拒绝重复/非排序
对象键、多根文档、非法 UTF-8，以及当前固定 ASCII schema 不会出现的路径
NUL/CR/LF/Tab（避免 CRLF writer 静默归一化键）。它不是通用 JSON 导入 API。

检查每次 CSV 写入以及 `Flush()` 后的 `Error()`；任何失败不返回部分字节或
artifact。资源超限为固定 `MI_REPORT_RESOURCE_LIMIT`；输入/渲染错误亦为
现有闭集错误，不包含原始内容。测试专门绕过私有构造边界的恶意/超大数据
仅用于 renderer 防御回归，不意味着公共 S1 输入约束被放宽。

## 已执行验证

Windows 原生、Go 1.26.7：

- `go test ./internal/integrity/report -count=3 -cover`：PASS，3.646 秒，
  包级语句覆盖 94.7%。包含原有 JSON/HTML/canonical golden 及全部新增 CSV tests。
- 覆盖完整 final JSON/内容哈希独立重建、精确 CRLF golden、Pointer 的空键/
  斜杠/波浪号、空/null、最大 signed-int64 字符串 ID、16 个并发生成与输出副本、
  512 样本全量重建、公式/控制字符 canary、闭集数字与解析失败。
- 使用真实 16 MiB 限制测试精确边界、超过一字节、CSV 双引号展开超限；
  不是降低 cap 或模拟 writer 错误。失败不发布部分 artifact。
- `go vet ./internal/integrity/report` 通过；限定该包的 golangci-lint 为 0 issues。
  首次 lint 因 shell PATH 未包含仓库私有 Go 而没有运行；补充仅该命令进程的
  Go PATH 后重新执行通过，没有静态检查豁免或机器 PATH 变更。
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0` 的测试交叉编译、vet、lint 通过。
  这仅是 Linux 编译/静态检查，不是 Linux 原生执行。
- Windows 本机 `CGO_ENABLED=0`，未发现 gcc/clang，因此未声明 race detector
  通过。实际并发读取测试已运行，race 检测仍应由既有原生 Linux CI 执行。

本单元测试未访问数据库、网络服务或用户文件；仅测试工具正常生成忽略目录中
的交叉编译制品。所有受控 shell 执行均已终态。

root 集成复核：完整读取三个新增 Go 文件和本文后，实际重跑整个 report 包三轮
4.014 秒 PASS，保留全部 JSON/HTML/canonical 回归；report/backupmanifest/pgbackup
三包 vet 与 lint 均通过（0 issues）。上层 CSV 产品接入另行实施，不由此追认。
