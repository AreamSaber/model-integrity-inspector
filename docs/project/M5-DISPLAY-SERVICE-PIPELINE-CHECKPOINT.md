# 正文展示服务实际链路补测 checkpoint

日期：2026-09-08。状态：新增 helper 已实际挂接，root 独占数据库时段运行 `go test ./internal/app -run '^TestApplicationActualTLS' -count=1`（session24068），真实 SQLite/PostgreSQL、0/30 天全部通过 30.875s。此为新增服务测试的真实终态，不代表整个功能正式验收。

## 所有权与调用入口

本agent仅新增`internal/app/evidence_service_pipeline_test.go`和本文件，未修改root的app/run/api/原pipeline文件。

`exercisePipelineDisplayService(t *testing.T, cfg Config, store *repository.Store, db *sql.DB, p *pipelineHTTP, selection repository.DisplaySelection)`由root在`exercisePipelineDisplay`现有HTTP审计故障恢复成功后、组织保留策略改0天之前调用。`store`必须是实际`app.store`，selection是已真实发布结果的Run/Sample/Attempt/revision1。

新helper使用原HTTP cookie→真实`identity.Service.Principal`→固定审计actor→`BindControlAuthority`；`LoadKeyFile`派生窄`DisplayOpener`，与生产一样构造`run.EvidenceService`。可用正文来自先前实际TLS Worker捕获/AEAD封装，不填任何手工repository envelope，不读取raw回填。0天场景仍验证真实unavailable输出的授权与生命周期，但不将其误称为成功解密正文。

## 已编写的实际链路断言

- Prepare恰好4个槽，第5次固定拒绝且没有grant；按值复制后Close只释放一次，其它prepared对象仍可成功输出；各终态后重新填满4槽验证没有泄漏或双释放。
- 成功Prepare后分别移除run.read/evidence.read/evidence.body持久权限，WriteTo必须零writer调用、零bytes、零receipt/audit。该项是测试隔离schema内的已提交SQL撤权故障，保存并恢复精确原role/member权限行，不声称走过管理HTTP。
- 原ctx取消不能换活ctx继续，未经绑定ctx、同actor另一次真实HTTP登录得到的不同session、已取消Write ctx均不得输出或授权。
- 首次writer调用时通过独立`sql.DB`读取已提交receipt+audit数量、精确ID:canonical-hash审计绑定，并完整验证审计链；故此不是只在事务callback内观察未提交记录。
- writer正常、含敏感canary的error/panic、short-write、负数或超长n分别有固定安全结果；terminal后借出的私有编码buffer清零，重复Write拒绝且槽可恢复。短写固定`io.ErrShortWrite`，其它consumer失败固定`ErrEvidenceUnavailable`。
- 实际writer阻塞在首次调用时，对复制句柄再Write不得取消原writer；显式复制Close可取消writer，但writer退出前不得提前释放admission槽。测试主动解闸确保异常路径不会留下无限等待goroutine。

## 尚未验证与边界

编译检查 `go test ./internal/app -run '^$'` 通过 0.092s。初次 lint 只报告 helper 尚未接线导致的 5 个 unused，未添加 lint 抑制；root 挂接后的 app lint 为 0 issues。原 shared-source 仓储/lookup 组合三轮 73.345s 和原 actualapp 三轮 75.585s 均不包含本 helper；新增场景由 root 后续独占实际 app 单轮 30.875s 证明，未混用旧测试证据。

当前实际上游响应较小，足以覆盖首次输出与复制生命周期；本helper没有制造超大cipher或伪造开箱结果，也不把“小正文首次调用”宣称为多块中途撤权证明。若后续需要多块撤权，应另建实际TLS大响应并遵守生成器/Tokenizer/响应大小真实限制，再测试64KiB边界。数据库grant不能与socket写原子耦合，不声称撤销能追回已发bytes；authorized回执也不宣称浏览器已接收。

未执行Git。仓储Source值复制追加修复与其红绿测试由`M5-DISPLAY-READ-REPOSITORY-CHECKPOINT.md`单独记录，不混入本helper的尚未执行状态。
