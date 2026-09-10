# CSV contract source in Docker build stage

2026-09-09。2357652 对应 CI34333125156 的 image job102406136237 已实际终态失败。
通过 GitHub job logs 读取到完整 `go test -p 1 ./...` 的唯一失败：
TestReportCSVSchemaGeneratorRetainsClosedFormats 无法打开
../../scripts/read-contract-schemas.go。Worker、其它已输出的 Go 包均通过，不能将
日志中此前成功的包当作整镜像成功；quality/Windows 当时仍在运行。

原因是 CSV 新契约用 AST 核对真实生成器不丢失格式，但 backend build stage
此前只复制 package.ps1/test-replay-netns.ps1，没有复制这个新测试输入。
修复仅增加该脚本的精确 COPY，位于完整 Go 测试之前。scratch runtime 的 COPY
列表、用户、依赖、全包范围、包串行/内部并发、webassets 测试与失败传播不变。
没有跳过 Docker 中的 CSV 契约或把脚本缺失改成 skip。

新增 csv_distribution_test.go 对当前固定 Docker recipe 验证：脚本必须只在
backend 完整测试前精确复制一次，不在 runtime 分发。8 个反例包含缺失、注释
伪装、错误文件、晚于测试、仅位于 web stage、重复、runtime 复制与遗漏完整测试；
LF/CRLF 均接受。这是固定配方回归，不宣称通用 Docker parser 或完整容器安全验证。

真实红→绿：未改 Dockerfile 时新测试 **0.075s FAIL**；加入 COPY 后完整 contracts
三轮 **0.851s PASS**，vet/lint0。当前机器未发现 Docker 命令，没有伪造本地镜像
运行；必须以包含该修复的新 CI image 终态作为实际构建证据。

CSV 功能证据见 M5-CSV-INTEGRATION-NOTES.md。此修复不代表完整 M6 标准交付、
Compose 干净环境部署或 V1.0 已完成；正式审核仍统一待开发完成。
