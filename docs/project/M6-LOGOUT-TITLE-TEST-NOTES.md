# 退出会话标题断言时序

2026-09-08。CI34202061195 / ebd81b3 的 quality 实际失败在 Test and build（不是 static/race）：App.test.tsx:571，account logout-all 用例已找到“登录工作空间”heading，但立即断言title仍读到“账号安全”；34文件中1文件失败，911项中910通过，33.94s。

源码中App的非会话title在useEffect同步document外部状态，SessionLayout的会话title也在useEffect；登录heading属于render出的DOM。React的[useEffect说明](https://react.dev/reference/react/useEffect)明确effect相对浏览器绘制并非一律同步。因而找到heading不能单独充当标题effect完成的等待条件。这是结合真实失败和源码的时序解释，不声称生产标题永久错误。

仅修测试：退出当前会话及退出所有会话的最后标题断言用现有waitFor等待精确“登录”title；logout-all额外先确认旧账号/强制改密title确实出现。原API次数、权限头、正文、会话树移除、密码canary消失和原错误分支断言全部保留。未改App/会话生产逻辑、测试全局超时、重试次数或期望标题；如果title持续不正确仍会在原期限内失败。

本地原代码全前端一次911项通过63.79s，说明本机该次未复现；最初传给pnpm test的参数多了--，实际运行的是全量而不是声称的定向三项，按真实输出记录。CI原始失败保留作为红测证据。修改后使用pnpm exec vitest明确选择文件/测试名，最终命令和结果另补。

修后实际终态：`pnpm --dir web exec vitest run src/App.test.tsx -t 'logout-all|document title after logging out'` 选中8项通过（其余34项未选中），2.71s；随后 `pnpm --dir web test` 完整34文件911项 **32.96s PASS**，没有过滤/Skip/retry开关。typecheck、lint、build全部通过；构建JS533.23kB，原500kB提示保留，未调整警告阈值。新的远端CI结果另计，不能以本机通过追认旧CI失败已变绿。
