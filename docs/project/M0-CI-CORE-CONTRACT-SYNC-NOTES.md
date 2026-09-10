# M0-04：独立 Core 任务的 Go 契约同步

日期：2026-09-10。原 `791f1ea` 调度拆分的遗漏修复；不修改产品、原生测试、超时或运行覆盖。

新 CI34453747044 已暴露后续真实失败。Core job102795191896 在保留原10分钟包上限后，app 包600.066s超时，当时当前父级 `TestApplicationActualTLSZeroDayRetentionThroughPublishedArtifacts` 仅33s/PG子级8s；这是包累计预算问题，不是该父级已经执行10分钟，也没有据此确认data race。完整app分片仍需下一修复，单独job预算尚不足以解决包累计运行时长。

同时 quality102795192132、image102795192097、Core 中的两个Go契约失败：`TestPGBackupNativeWorkflowIsMandatory` 和 `TestReplayNamespaceWorkflowIsMandatory`。root 在791f1ea只执行PowerShell策略和actionlint，漏同步并漏跑这两个Go契约。这是本轮CI改动的集成遗漏，不是关闭/豁免测试的理由。原pg-backup-native本身仍成功，其契约失败来自复用的quality/required检查。

## 修复

- 原netns校验错误假定Core必须仍在quality，并硬编码旧required集合。现要求Core单独job及其真实required结果；原OS禁网步骤仍必须在quality构建之后，完整5分钟/pwsh/实际脚本、不接受PolicyOnly/skip/非fatal。
- 原质量最后一个step的字符串截取会连同新job前的YAML注释一起比较。现解析实际YAML映射，并精确比较该step全部字段，允许注释而不允许隐藏执行字段、重复步骤或换命令。
- 新独立Core Go契约精确比较完整解码job，固定OS/25分钟/服务digest与端口/Go/actions/五步/原Core命令/DSN。17个作用在Core自身的真实变异覆盖隐藏flags、skip/吞错、错误服务、遗漏策略、旧Other组、串行依赖等。required另补Core遗漏/伪造success/忽略结果反例；原PG和netns所有反例保留。

## 证据与边界

- 在独立8b8a9fb检出运行原两个契约，真实失败 **0.096s / c34b98 exit1**，和CI相同，不受其他agent尚未落完整的repository文件影响。主树先前55b0f4是编译间隙失败，未进入该测试，不计为契约真红。
- 同独立检出应用这两个契约文件后，**全部contracts三轮1.145s PASS**，vet0、lint0（f01694终态）。没有只跑新用例或用离线policy代替所有Go契约。
- CI旧失败不重启或追认。此修复不解决app race包累计预算；仍需保留全部父级/子树的精确分片及新CI实际证明。
