# Windows CI 失败诊断（不是已修复结论）

2026-09-08。原始运行 CI34198605262，提交 dc65d752b1b697186c5f3b8d0a83846da9fb9d5e。已实际读取日志及权威终态：quality success，Windows package failure，required failure；其它 Linux package/image/dependency/identity-postgres/Worker及repository全部race分片 success。不能把早期 quality 尚在运行、或 gh 观察发生 TLS 超时解释成最终状态。

## 原始失败事实

- Windows Build versioned package 的 `go test ./...`：16项 SQLite staging 顶层测试在 `profile_ancestry` 返回 `MI_PRIVATE_FILE_PERMISSIONS`，未到工作区创建。原日志没有祖先层、owner或ACE证据，尚未定具体权限根因。
- Worker SQLite：precheck取消夹具 UPDATE失败；derived deadline用例在TLS已开始后安装禁止raw/display INSERT的DDL失败，尚未进行实际deadline更新；HTTP limited/malformed用例未收口，Runner的claim/check_lease返回DATABASE_UNAVAILABLE。
- 上述辅助连接已有busy_timeout=5000/FK配置。原日志未保留driver code、失败context或单操作耗时，不能复用旧零busy_timeout原因，或把压力、锁竞争、期限任一项猜成定因。该CI未出现display_insert或unavailable_seal失败行。

## 本次 test-only 诊断

`sqlite_staging_acl_diagnostic_windows_test.go` 与既有fixture失败分支一行接线：仅读取openChain已持有句柄，不新开路径、不修ACL、不换路径重试。最多258层、每层64个ACE，输出固定owner/principal类别、原策略敏感位掩码及inherit-only/ignored/risk；不输出路径、用户名、SID、全ACL或原始错误。合成descriptor验证分类、闭集、输出限额及TrustedInstaller仅OS根owner语义；还没有在真实GitHub runner取得新日志。

`worker/sql_diagnostic_test.go` 与3个旧测试文件最小接线：真实UPDATE/DDL失败点保留原driver error，只有具体modernc.Error可归入native BUSY/LOCKED；伪Code接口/错误文字不能冒充native。仓储已脱敏的Unavailable/LeaseLost等标为repository_boundary，不推断底层原因。context单独记录观测状态；Runner返回点记录的是runner_lifetime，不是SQL等待耗时，且cleanup可能已开始取消，不能作为因果证明。日志耗时范围0..600000ms仅限制输出；不改变任何操作/测试期限、失败断言、返回error、重试或CI门禁。

## 实际验证和边界

- ACL纯诊断三轮0.520s、显式文件集vet/lint0；当时完整包受新snapshot引入的测试循环阻挡，该限定集不冒充完整包。
- root随后修正独立集成测试包边界，完整Windows privatefile三轮3.592s PASS/lint0，包含ACL诊断和全部旧集成测试；Linux完整包交叉编译/vet0，不算Linux运行。
- Worker纯分类/闭集/不可格式化错误反例三轮0.147s PASS，完整包编译/vet/lint0；本说明写入时尚未执行本诊断组合的真实Worker数据库回归。

下一步：将诊断提交到开发分支，读取新Windows真实日志，再按证据修具体问题。尚不声称CI已通过、Windows根因已修复或备份恢复完整交付；不修改正式审核状态。
