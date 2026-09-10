# 管理事务自然到期收口：实现与红绿证据

日期：2026-09-08。范围是管理事务 P2 修复，不代表 M6 阶段完成或正式审核批准。

## 问题与最小修复

`internal/integrity/repository/identity_management.go` 的 `managementTransaction` 在持有用户、会话锁后验证自然到期，然后执行具体管理 callback。新增组织政策锁以及已有审计锁均可能让 callback 跨过会话截止；旧实现 callback 成功即提交，未重新验证最初授权的自然到期。

修复在成功 callback 返回后、GORM 提交前，对最初读入的 `session.ExpiresAt` 再做 `After(time.Now())` 判断；不满足则返回既有 `ErrManagementSession`，使 callback 的业务 SQL、审计事件和链头一起回滚。

- 身份时间语义仍是现有 `time.Now()`；没有引入 PostgreSQL 政策时钟或其他时间源。
- callback 的原错误优先返回；没有改变原权限、锁顺序、请求超时和错误映射。
- 不重新加载并否定本次合法 callback 主动造成的会话撤销；不接受本次 callback 修改数据库截止时间对原授权窗口的延长。
- 检查位于 SQL 提交前的应用事务边界。它不宣称强行打断任意数据库等待、保证物理提交瞬间与墙钟绝无间隙，或覆盖不经该共用事务的其他身份操作。

## 新回归与真实红测

专有测试文件：`internal/integrity/repository/identity_management_expiry_test.go`。沿用已有 `eachDatabase` 独立 SQLite 数据库与真实 PostgreSQL 隔离 schema；本次显式配置了实际 PostgreSQL，未以跳过代替该引擎验证。测试和工具输出不包含 DSN、session hash、密钥或 SQL 原始敏感错误。

1. `TestManagementNaturalExpiryRollsBackAfterAuthorizedWork`
   - PostgreSQL：独立事务实际锁住组织行；真实 `ManageUpdateOrganization` 在另一条固定连接进入。用 `pg_blocking_pids` 证明管理连接已通过身份预校验，并在会话尚未到期时等待该组织持有者；自然跨期后释放组织锁。
   - SQLite：真实共用管理事务 callback 在会话有效期内完成政策与审计 SQL，断言 SQL 完成时尚未过期，在同一待提交事务中等待自然跨期。
   - 两端均要求 `ErrManagementSession`，组织 days/cutoff/version/time、链头及成功审计事件全部不变，并验证审计完整性。
2. `TestManagementExpiryCheckPreservesAuthorizedSelfRevocation`
   - 有效原会话授权的可信共用 callback 主动撤销自己的会话并追加审计，仍允许正常提交；防止错误地将最终全量重认证当作自然到期检查。
3. `TestManagementExpiryCheckKeepsOriginalAuthorityDeadline`
   - callback 修改其数据库会话截止时间后跨过原期限，必须回滚该延长与审计；防止以新截止时间替换当前操作的原授权窗口。

在生产代码尚未修改时执行：

```text
go test ./internal/integrity/repository -run '^TestManagement(NaturalExpiry|ExpiryCheck)' -count=1 -v
```

真实双库红测：exit 1，9.969s。跨期案例均实际提交政策、链头与成功审计，且延长期限案例也错误提交；有效期内自撤销控制例通过。不是“会话事先过期被拒绝”的替代测试。

## 绿测与当前冻结边界

生产最小修复后：

```text
go test ./internal/integrity/repository -run '^TestManagement(NaturalExpiry|ExpiryCheck)' -count=3 -v
```

真实 SQLite + PostgreSQL 三轮全部通过，29.283s。

```text
golangci-lint run ./internal/integrity/repository ./internal/identity ./internal/integrity/api
```

通过，0 issues。

相关管理、保留政策、主动会话撤销三包回归：

```text
go test ./internal/integrity/repository ./internal/identity ./internal/integrity/api -run '^(TestManagement|TestResponseRetention|TestRevokeOwnSessions)' -count=1
```

通过：repository 31.787s（真实双库）、identity 4.742s（SQLite）、API 3.573s（SQLite）。另显式设置 `MII_IDENTITY_TEST_DRIVER=postgres` 执行：

```text
go test ./internal/identity ./internal/integrity/api -run '^TestManagement' -count=1
```

通过：identity 6.001s、API 4.382s（均真实 PostgreSQL）。这里区分各包选库方式，不将默认 SQLite 的服务/API 测试误报为 PostgreSQL 证据。

上述三个专有文件已冻结供主任务复核。未修改保留政策/迁移/其他 agent 文件，未执行 Git 操作。并行发现的 PostgreSQL 组织 `FOR UPDATE` 与审计外键 `FOR KEY SHARE` 反向等待问题交由主任务处理，不由本单元宣称修复。
