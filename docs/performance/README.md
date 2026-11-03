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
