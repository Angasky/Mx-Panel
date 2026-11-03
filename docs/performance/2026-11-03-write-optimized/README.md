# 写入和内存优化复测

正式 HTTP 样本源码：`2fec8c201b4eb6d2c046ec0b7d252fb3b0ba0cd6`；上一轮参考源码：`2625d884b80898daba917634807b74bf181cba1b`。同一台 Windows 机器、相同配置与测试脚本，100 / 1,000 节点，三轮交替 Python / Go，共 6,336 次本轮请求，失败 0 次。保留真实备份、镜像、fsync 和回滚。两轮独立执行，机器负载会影响数字，不将所有差异归因于优化。

## 结果

- 1,000 节点、单并发：真实节点修改 51.41 → 34.85 ms（约减少 32%）；完整 YAML 保存 67.22 → 48.62 ms（约减少 28%）。
- 以上两个场景的服务进程采样 RSS 分别 39.4 → 18.7 MiB、48.9 → 23.0 MiB；这是场景前后采样最大值，不是精确峰值。
- 100 节点真实修改 17.05 → 15.66 ms；提升幅度小于 1,000 节点，存储成本仍明显。
- 读取没有新增优化；本轮 1,000 节点快照平均 1.56 → 1.95 ms，YAML 读取 1.57 → 2.32 ms。未变更保存 2.33 → 3.62 ms，P95 2.78 → 6.96 ms；原始样本中出现约 13 / 26 ms 的尾部请求。保留退步，不声称全面加速，后续需针对 GC / 分配与调度继续定位。
- 本轮 Python 1,000 节点真实修改 65.85 ms、完整 YAML 保存 141.14 ms。Go 与 Python 的持久化策略不同，完整协议验证尚未对齐，这不是严格功能对等的语言基准。

## 证据

`results.json` 保留逐请求样本；`summary.json` 含本轮数据、上一轮 Go 参考数据及原始文件摘要；`report.html` 为离线交互报告。

`micro-before.txt`、`micro-emitter-only.txt`、`micro-after.txt` 是工作区辅助基准，每规模 40 次修改，保留镜像和真实落盘，不替代正式 HTTP 测量。相同基准代码在原实现、仅队列补丁、完整优化三个阶段执行。1,000 节点每次分配分别约 25.34 / 7.00 / 3.10 MB（十进制字节）；耗时约 44.58 / 41.80 / 30.33 ms。前两次带 CPU / 内存剖析，最后一次不带剖析，微基准耗时只作定位参考。

`yaml-compat.jsonl` 为未修改 YAML v3.0.6 的 8 组原始输出摘要，修改后工具输出逐字节相同。覆盖 0 / 1 / 100 / 1,000 节点、大整数、Unicode、多行密码、时间、浮点、注释、别名、自定义标签及多文档 / 缩进。完整原库测试及队列上限回归通过；源文件清单中只有 emitterc.go 被修改。

提交后缓存只接受确定可还原的标准标量与容器，浮点、时间及自定义类型仍重新解析文件。镜像全部持久化成功后才发布独立副本，外部文件修改仍通过内容 SHA-256 失效。

```sh
go test ./...
(cd third_party/yaml && go test ./...)
go test ./internal/config -run '^$' -bench BenchmarkChangedSave -benchtime=40x -benchmem
go run ./tools/bench/yaml-compat
python tools/bench/report.py docs/performance/2026-11-03-write-optimized/results.json --baseline docs/performance/2026-11-03-optimized/results.json --output work/rebuilt-write-report --note '本轮优化 YAML 事件队列和提交后缓存，保留备份、镜像与 fsync；参考数据为上一轮读取缓存版。'
```

Windows 上可分别进入 third_party/yaml 后运行测试，避免依赖 shell 子目录语法。所有测试使用隔离数据，本轮未部署线上后台。
