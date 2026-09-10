# M6-05：原维护来源的闭集域路由

日期：2026-09-10。范围：新增 `BackupDrainSource.JobType()`，并使原已支持的旧retention终态条件从观察到Apply可达；不是完整备份完成或恢复许可。

- JobType仅返回七个既有常量；nil/未知/大小写或空白别名/含NUL均返回空值。无Job DTO、原文、owner、SQL、当前事实或新授权。各Apply仍重验原私有Store/operation/generation/owner、原行与当前维护权限。
- `TerminalRequired` 本身不足以区分两种执行类和五种非执行类；协调器按这个闭集类型路由，不先尝试execution再把失败当其他域，也不以Unsupported回退。
- 原loader对全部legacy返回Unsupported，导致原retention organization sentinel已支持的null lease/cancellation/exhaustion/inactive队列终止条件无法被协调器调用。现仅对同组织哨兵、原Legacy、无未结算执行意图、pending或expired running、且命中上述原条件者返回TerminalRequired。保持Legacy身份，不造现代batch；普通retryable、live、静态terminal、错误ObjectID和其他legacy仍Unsupported。

实际验证：闭集纯矩阵；六个现有真实producer→过期/耗尽→原Load的类型且getter不写DB；九项legacy分类矩阵。以上与六个库存日志守卫完整父级双库三轮 **20.266s PASS**（99593终态0），无driver过滤。

非执行单元另通过真实legacy enqueue/Claim→普通过期拒绝→原null-lease重新Load→Apply→旧source重放拒绝→无后续候选，SQLite三轮0.463s及全非执行双库三轮66.143s；见terminal notes。root新旧全部71个drain父级实际枚举，排除另有原自然租约证据的三个慢父级后，**68个完整快父级SQLite三轮41.855s PASS**（93691第一命令）；包括所有新增两类执行/五类非执行/闭集路由及原source/pause/legacy反例，不以纯路由测试代替应用层七类实际集成。

同session后续app vet因并行尚未冻结测试构造类型不符失败（features.DerivedRecord误传repository.DerivedRecord），已通知该文件owner修复；不追认为app验证成功。归档协调、完整资源收集和用户可操作的备份恢复仍待后续接线。
