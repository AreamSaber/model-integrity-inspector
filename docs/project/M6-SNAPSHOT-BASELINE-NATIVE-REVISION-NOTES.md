# M6-05：保留基线原生修订号

日期：2026-09-10。修复剩余资源闭包设计第6节明确指出、此前尚未验证的历史兼容边界。

原foundation中结果和baseline的 `analysis_revision INTEGER`：SQLite实际允许正int64，PostgreSQL原INTEGER列自身限制int32。m12新增的baseline `version` 明确有int32 CHECK，但它不是analysis_revision，不能把此范围移到历史修订。原artifact引用observer在两处SQL投影将revision限为2147483647，因而拒绝SQLite合法原记录。

## 实际反例与修复

- 新反例在真实schema11上写原结果/unsigned baseline，包含1、2147483647，SQLite另含2147483648与9223372036854775807，再执行原完整迁移并开启真实只读快照。另以原现代canonical scope写入最大原生修订，明确为存储夹具，不宣称真实服务MAC批准/算法产物。
- 主树第一次运行被其他agent未落齐的derived代码阻断，未进入DB，不计逻辑真红。root独立8b8a9fb检出只加自己反例后，两父级实际SQLite失败 `SNAPSHOT_ARTIFACT_REFERENCE_INVALID`，**0.372s / 32e9fa exit1**。
- 私有投影Revision改int64、位置不变；两处SQL用原正int64范围，PostgreSQL继续由原物理列强制int32。现代scope仅在比较时转int64，不修改公共DTO/已批准schema/原canonical字节或历史记录。
- legacy仍unsigned/incomplete，不因高revision或旧approved标签获得信任。现代scope必须匹配同组织/Run/真实result的原revision与所有摘要；反例将row改回另一真实存在的revision1而原scope不变，仍拒绝。

## 已取得证据

- 独立检出应用同一修复后，**全部 `TestSnapshotArtifactReferences|TestSnapshotResultReferences` 父级SQLite三轮21.714s PASS**，repository vet0（67563终态）。原范围内来源摘要和原JSON关系回归均保留，未只验新增正向。
- 主树两个新增父级SQLite三轮 **0.950s PASS**（6ad729第二命令）；同session完整contracts三轮1.246s PASS与本基线功能无数据库证据关系。
- PostgreSQL实际最大原生修订及完整双库回归尚待General独占窗口；不把SQLite运行中的PG skip计为PG通过。General已交给app协调器单元，root未并发操作。
- 临时独立检出 `.tools/review-baseline-8b8a9fb` 暂保留供后续隔离双库验证，含root自有基线修复/反例及已验证的两个CI契约文件。不是产品制品；主树/其他agent成果未隐藏、覆盖或删除。

本修复只是合法历史的引用观察兼容，不是完整资源闭包、MAC验真或完整恢复验收。
