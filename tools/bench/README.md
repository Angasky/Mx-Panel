# Python / Go 后台性能对比

在同一台机器上，分别启动生产 HTTP Handler。测试使用独立临时目录、30 份配置记录及指定节点数；不会使用线上配置、服务器 SSH 或公开订阅 token。全部请求通过回环 HTTP，使用模拟可信反向代理的 HTTPS 转发头；不测 TLS 握手、代理转发或公网延迟。

```powershell
$env:GOCACHE=Join-Path (Get-Location) 'work/go-cache-recovery'
& ./work/go-runtime/go/bin/go.exe build -trimpath -ldflags '-s -w' -o work/bench-runtime/mxioc-perf.exe tools/bench/server.go
python -X utf8 tools/bench/compare.py --go-bin work/bench-runtime/mxioc-perf.exe --output work/python-go-performance.json
```

需要项目 Python 依赖及 psutil。也可使用系统 Go 编译；Linux 可将可执行文件名改为 `mxioc-perf`。先确保输出二进制目录存在。

- 默认 100 / 1,000 节点，三轮交替运行顺序；每个场景预热五次。只启动 HTTP 服务，不启动定期更新或远端计量任务。
- 读取分别使用 1 / 4 并发、每轮 60 请求；写入单并发、每轮 12 请求。使用相同有效账号和 600,000 次 PBKDF2 参数，登录耗时不计入场景。
- 节点修改、流量修改和 YAML 保存每次都更改真实字段，避免把 Python 的“内容未变跳过写入”当作正常保存速度；内容未变的节点保存单列为 node-noop 场景。
- 请求均建立新连接并读取完整响应，客户端语义验证在计时区间之外；核对节点数量、返回结构与主文件 / 镜像一致性。失败响应不当作成功测速。
- 原始输出包含逐请求耗时、失败率、P50 / P95、吞吐、服务进程 CPU 时间和采样 RSS。RSS 为场景前后的采样最大值，不是精确峰值；低耗时场景的 CPU 计数受系统计时分辨率限制。
- 保留两版当前实现的缓存、备份、文件镜像与持久化策略。Go 配置写入对备份和镜像执行 fsync，Python 使用缓存与原子替换但未执行同等 fsync；写入延迟不能简单归因于语言性能。结果是当前实现的对比，不是语言本身的跑分。
- 临时数据在结束时删除，结果 JSON 可用于复核分布及重新绘图。配置路径、机器负载与操作系统都会影响结果；Windows 本机结果不能直接推断 Linux 线上表现。
