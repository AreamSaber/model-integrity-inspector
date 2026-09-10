# Application race 完整分片

日期：2026-09-10。属于 M0-04 持续 CI 维护，不改变 V1.0 功能范围或正式审核状态。

## 实际失败与方案

791f1ea 的 CI34453747044 已终态 failure：21 个 job 中 15 成功、6 失败。
root 回读全部失败相关日志：Core 的 app 包在600.066s触及原10分钟总上限，
当时正在运行的父级仅33s；这不是该父级单独运行10分钟或已确认data race。
quality、image、Ubuntu与Windows打包均命中遗漏同步的Go契约，required跟随失败。
两契约先前已通过d679709修复，不把旧run追认为成功。

新增 application-race 六个独立Ubuntu必需任务，各有原固定PostgreSQL18.6服务、
loopback端口、固定Go和NativeGo枚举验证，25分钟job限额与fail-fast=false不变。
Core动态枚举全部包，只移出精确repository/worker/app三个包名；同名前缀子包保留。
Application动态枚举所有Test/Example/Fuzz父级，ordinal确定性分为六组，-run完整
锚定父级，保留所有子测试与fuzz种子；每进程-race/-count=1/-timeout=10m不变。
没有skip、重试或提高超时。完整Other兼容入口先枚举两大包，再顺序执行Core、
六Worker、六Application和额外PostgreSQL identity/API，与独立CI任务一一等价。
required新增真实APPLICATION_RACE结果依赖与成功检查，不允许字面success代替。

## 验证证据

- 新Application脚本回归在旧入口实际失败：313057，ValidateSet未接受Application。
  新job策略在旧workflow实际失败：b3a511，缺少application-race。
- Go新契约在旧workflow实际失败：6a4a3f，0.092s，缺真实job与新required；非编译失败。
- 实现后初始115项分片与217项策略通过。独立复核发现旧非分片Shard反例只认异常，
  在内存删掉实际guard后仍误绿（8b18df）；已补精确错误/零调用及三类入口参数绑定。
  补强后119项分片回归通过（7c0cea）；实际生产guard原本正确。
- 独立复核修后的内存变异：fbc549删除非零Shard检查，在精确错误/零调用断言真红；
  129ce1删除ValidateRange，在ParameterBinding断言真红。原版119分片/217策略再次
  通过ff9c20；外层真实参数绑定Application/5准确透传（564560，仅Native stub）。
- Go contracts全部三轮：agent5559c8，1.655s；root20618，1.647s；vet和lint0。
  新契约完整解码job/gate，31个job和10个gate变异确认有效YAML及正确失败对象，
  另拒绝重复job、重复strategy和多文档YAML，未把解析失败冒充目标策略生效。
- root真实非race Go RE2枚举24662/708b4d：当时主树79个app父级，六组完整且无重复；
  这是带并行WIP的实际枚举，不是测试体执行，也不冒称原生race或最终提交父级计数。
- actionlint通过；新原生race时长、真实双库及完整打包仍须本提交推送后的新CI证明。

API包在旧Core race中通过但接近10分钟上限，继续观察真实CI；不预先删除用例。
主分支保护和草稿PR方式不变。此单元不代表完整产品/备份恢复/全范围验收通过。
