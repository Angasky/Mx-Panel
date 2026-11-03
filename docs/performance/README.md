# 后台性能记录

2026-11-03 的 Windows 本机对比位于 `2026-11-03/`：

- `report.html`：离线交互报告，可切换节点规模、并发和平均 / P95 / 吞吐指标。
- `results.json`：三轮逐请求样本、环境和计时方法。
- `summary.json`：由原始样本汇总的数据，附原始文件 SHA-256。

结果对应源码提交 `db9bed5c1f2ddf9ad418bb875c91389d742fa554`。生产 HTTP Handler 在隔离数据目录运行；没有访问线上服务器或读取真实订阅。完整复跑方法见 `tools/bench/README.md`，报告可通过以下方式重建：

```sh
python tools/bench/report.py docs/performance/2026-11-03/results.json --output work/rebuilt-performance-report
```

此次测量不是语言微基准，也不包含公网、SSH、TLS 握手、代理转发或周期任务。Python 已有缓存与无变更保存优化，Go 保存额外执行 fsync；这些实现差异在报告中保留并明确标注。后续 Go 缓存优化应使用相同测试重新对比，保留这份原始基线。


2026-11-03 缓存优化后的复测位于 `2026-11-03-optimized/`，源码提交 `2625d884b80898daba917634807b74bf181cba1b`。沿用相同测试与配置，三轮共 6,336 次请求，失败 0 次；报告额外展示原基线的 3,168 次 Go 参考请求，两轮独立执行，机器负载会影响差异。

1,000 节点、并发 1 的 Go 平均 HTTP 耗时：快照 19.84 → 1.56 ms、YAML 读取 17.19 → 1.57 ms、完整订阅下载 16.67 → 1.74 ms、未变更保存 52.04 → 2.33 ms。真实节点修改 52.78 → 51.41 ms，完整 YAML 保存 67.02 → 67.22 ms，流量保存 5.04 → 5.55 ms；后两项没有取得提升，不把两轮噪声解释成优化收益。

本轮相同 1,000 节点场景中，Python 快照 5.04 ms、真实节点修改 64.37 ms、完整 YAML 保存 141.51 ms。100 节点真实修改仍是 Python 更快（14.59 vs Go 17.05 ms）。连续写入后 Go 的场景采样 RSS 高于 Python（1,000 节点完整 YAML 保存约 48.9 vs 36.9 MiB），不声称全面超越，也不把采样 RSS 当作精确峰值。32 MiB 缓存是估算准入预算，并非整个进程 RSS 限制。

```sh
python tools/bench/report.py docs/performance/2026-11-03-optimized/results.json --baseline docs/performance/2026-11-03/results.json --output work/rebuilt-optimized-report
```

`--baseline` 会验证环境、测试方法和配置摘要一致后再加入参考数据。原基线文件保持原样，优化后报告的原始数据与汇总同时保留。
