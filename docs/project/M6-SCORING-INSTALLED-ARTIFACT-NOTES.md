# M6-05：安装评分资源与租户规则分离归档

2026-09-10。新 `bundle.InstalledScoringArtifact` 为固定安装实现提供完整的
原始参考规则数据载体；不等于完整备份／历史兼容／规则发布或独立算法校准。

## 原要求和身份

TECH SPEC 19.2/19.5 与 M6-05 要求完整规则版本及配置备份。评分参数不是只有
一个全局 version：不同组织可保留同版本名、不同参数的原始 rule artifact。
本单元明确分离安装实现的 builtin reference 与必须逐组织另存的实际规则：

- 从调用方实际已安装的 `Artifacts.rule` 取原字节；校验已有 BuiltinHash，
  不调用 Builtin/NewResolver/defaultManifest 用当前默认内容替代损坏输入。
- `mii.scoring-installed.v1` 载体包含 installed implementation ID、算法版本、
  完整原参考规则字节及其原 hash，以及评分／Token／特征工作上限。
  原规则字节已包括真实 scoring/token 参数、行为／结构／生成器版本及模板、
  tokenizer 引用；不把引用说成已包含模板/词表的内容，它们由独立资源载体归档。
- 外部 expected ref 分别绑定原 Rule、Scoring、TokenRules 摘要及载体摘要/大小。
  本次新格式 **2,928 bytes**，SHA-256
  `c1d2977d3cb0256e2b94c5ab77ba4ba95aa4364289b5389643405594036954ba`。
  原 builtin rule SHA-256 `fda4b1aaf5290b762c4fb687a9164298e4dcc1f14f7273c870f938ea23bc8d88` 未改。
- owned bytes、64 KiB 固定载体上限、完整 canonical 字节比较及受支持原规则 hash
  拒绝尾随数据、重复／大小写别名、改参数、改上限和自行重算外部 hash 的替代内容。
  fmt/slog 脱敏；禁止隐式 JSON/YAML；显式 Bytes 为受控资源输出。

`NewReferenceRuntime` 重新验证归档，使用其中的原参数构造独立 Token/Scoring/
Analyzer 引擎；方法名明确它不是任意历史规则 resolver。原生算法仍需要匹配的
应用代码和 release/commit 身份，数据载体不能执行未知历史代码，也不授予 A/B
等级、校准或发布权限。各租户候选必须从各自原 rule artifact 独立恢复。

## 验证

- 用独立 literal 外层字段、明确资源上限和已有冻结原规则字节验证完整 canonical
  载体，再固定本次新格式 hash。实际恢复的引擎经过真实编译器／离线 tokenizer／
  特征 builder 生成的 Batch，其完整分析 JSON 与原引擎逐字一致，仍为未校准开发结果。
- 两个独立组织式 resolver 使用相同 `1.0.0-dev.42` 和不同 baseline factor（.4/.7），
  实际分析保留不同参数及规则摘要，不能归并为全局 installed reference。
- 原资源／私有归档损坏、owned副本、四路独立恢复、nil／取消／超限、每个外部身份
  字段及自重算摘要的 wire 反例覆盖；未引入网络、数据库、路径或新依赖。
- 两次初始三轮失败是新测试使用不符合原 development semver 的字符串，随后按已有
  正式正则改为合法 fixture；未修改生产版本准入。不是产品安全缺陷的红绿证据。
- 新增 nil/empty/fuzz 用例后完整 bundle 三轮 **0.578s PASS，87.0%**；此前完整三轮
  0.425s、vet/lint 退出 0。载体 fuzz 实际 **306 executions／6.316s PASS**，没有夸大覆盖。
  后续增加最终返回前 context 检查及新格式 pinned hash 断言；独立复核未发现阻断问题，
  建议的“开始之后取消”已补为真实 cancelable context 的多个确定性检查点反例。
  最终完整 bundle 三轮 **0.444s PASS，88.0%**，vet 退出 0、lint 返回 0 issues。
  另行 bundle/manifest/tokenizer/tokenrisk/report/contracts 全组合三轮终态成功，
  分别 1.276s/4.920s/11.563s/1.175s/5.181s/1.333s（会话 95808）。

## 仍需完成

实际备份协调器将本载体以 installed/scoring identity 入档，并将每个租户原规则
独立入档；完成所有 Run/Estimate/Baseline 的版本引用闭包、未知历史兼容、恢复验证
和启用。这些未被本单元或局部测试替代；完整功能、双库备份恢复及统一审核仍未完成。
