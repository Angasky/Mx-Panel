# Go 预览版安装与更新

使用 `bash deploy/build-go-release.sh 版本号` 生成 Linux amd64 和 arm64 安装包及 `SHA256SUMS`。在 GitHub 推送 `go-v*` 标签时，发布流程会先跑测试，再生成预发布包。

从可信发布页取得安装包和对应的 `SHA256SUMS`，先在同一目录执行 `sha256sum -c --ignore-missing SHA256SUMS`，确认输出中实际包含所选包并显示 `OK`。然后解压，在解压目录中执行以下命令之一。

- 首次安装使用 `sudo bash install-go.sh fresh`。安装器在终端读取账号和密码。
- 迁移使用 `sudo bash install-go.sh install`。先备份 `/opt/mxioc-rule-manager` 和 `/etc/mxioc-rule-manager.auth.json`，再停止并禁用旧版 systemd 服务。Go 会使用原有数据和账号。
- 更新使用新包中的 `sudo bash install-go.sh update`。安装器校验旧数据、切换发布目录并检查本机 HTTP。启动检查失败时尝试恢复上一个 Go 版本。
- 卸载使用 `sudo bash install-go.sh uninstall`。该操作停用并移除 Go 服务，保留订阅数据、凭据和已解包版本。

Go 监听 `127.0.0.1:62578`。已有 HTTPS 反代可在测试通过后手动改到该端口。安装器不会修改域名、证书或反代。旧数据切回 Python 前，先停止并禁用 Go，并核对备份与 Go 运行期间写入的数据。

当前仍为迁移预览版。功能和实机缺口见 [REMAINING.md](REMAINING.md)。

## 一键安装与 mx-p 菜单

```sh
curl -fsSL https://raw.githubusercontent.com/Angasky/Mx-Panel/main/deploy/quick-install.sh | sudo bash
```

在 SSH 交互终端运行。自动判断新装、旧数据迁移或更新；旧数据迁移需要先备份并停用旧服务。首次安装后输入 `mx-p`，非 root 使用 `sudo mx-p`。旧预览包用户可执行该命令升级并安装快捷入口。

IP/极速模式用自签名 HTTPS，域名模式自动申请与续期 Let’s Encrypt 证书（需同意条款，80/443 可用且 DNS 正确）。无需 Python、Nginx 或 certbot。TLS 网关独立运行，监听配置保存在 `/opt/mxioc-go/access.json`，证书在 `/opt/mxioc-go/certificates/`。

菜单保留旧 vpn 的安装模式、升级、重置凭据、保留数据卸载和彻底卸载；额外提供备份、状态、日志和重启。为保持 Go 后台 HTTPS 认证策略，旧 IP HTTP 模式改为 HTTPS。卸载前生成仅 root 可读的数据备份，彻底卸载仍保留该备份和缓存发布目录。

`fresh` / `install` / `update` 成功后自动注册 `/usr/local/bin/mx-p`。菜单嵌入 Go 二进制，本地打开无需网络；升级时才下载 GitHub 发布包。直接 HTTP/仅 SSH 转发后端端口无法登录，应使用 HTTPS 网关或已有 HTTPS 反代。

验证范围：本地真实 TLS 与登录、凭据重置、隔离安装/更新/卸载脚本检查；没有在本机实际启停生产 systemd 服务，公网域名 ACME 签发仍需目标服务器验证。
