# Dingzhi Ban · Go 定制版

原生 Go 后端与中英文管理界面。运行和构建管理器不依赖 Python；旧 Python 后端、旧安装器与开发测试文件已从当前仓库移除。原版独立维护于 [mxioc-vpn-manager](https://github.com/Angasky/mxioc-vpn-manager)。

## 功能

- 节点、订阅、策略组、路由规则、DNS 和分享链接管理。
- 多订阅套餐、流量额度、到期处理、独立用户与服务器管理。
- Xray / sing-box 配置、中转、主备与失败恢复。
- 三种主题，统一易读的中文和英文字体；搜索支持中文输入法。

## 构建与安装

需要 Linux 和 `go.mod` 声明的 Go 工具链。构建双架构安装包：

```sh
bash install.sh local-build
```

输出位于 `dist/go-local-build/`。取对应架构压缩包，核验 SHA256 后解压，在解压目录执行：

```sh
sudo bash install-go.sh fresh
```

迁移旧数据使用 `install`，更新使用 `update`。详见 [安装说明](docs/go/DEPLOY.md)。Go 默认监听 `127.0.0.1:62578`，反代模板见 `deploy/nginx.conf.example`。源码构建本身不安装服务。

## 内核兼容与状态

Reality / Snell 的兼容补丁和原生 Go 构建工具位于 [tools/core-compat](tools/core-compat/README.md)。这些独立内核补丁不会随管理器自动安装；需要对应内核才能生效。

主要实现已迁移。真实面板、SSH、systemd、公网和客户端 App 的完整实机验收仍有边界，详见 [当前状态](docs/go/REMAINING.md)。本地测试与性能验证记录保留在文档中，测试源文件按仓库维护要求保留在本地，不发布进仓库。GitHub CI 只执行源码构建和静态检查，不将其冒充全量功能测试。

已有 Git 历史中的 Python 文件和测试仍属于历史版本；当前分支源码已清理，未重写历史。GitHub 语言比例在默认分支更新后重新统计。
