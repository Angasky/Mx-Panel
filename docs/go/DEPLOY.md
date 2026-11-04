# Go 预览版安装与更新

使用 `bash deploy/build-go-release.sh 版本号` 生成 Linux amd64 和 arm64 安装包及 `SHA256SUMS`。在 GitHub 推送 `go-v*` 标签时，发布流程会先跑测试，再生成预发布包。

从可信发布页取得安装包和对应的 `SHA256SUMS`，先在同一目录执行 `sha256sum -c --ignore-missing SHA256SUMS`，确认输出中实际包含所选包并显示 `OK`。然后解压，在解压目录中执行以下命令之一。

- 首次安装使用 `sudo bash install-go.sh fresh`。安装器在终端读取账号和密码。
- 迁移使用 `sudo bash install-go.sh install`。先备份 `/opt/mxioc-rule-manager` 和 `/etc/mxioc-rule-manager.auth.json`，再停止并禁用旧版 systemd 服务。Go 会使用原有数据和账号。
- 更新使用新包中的 `sudo bash install-go.sh update`。安装器校验旧数据、切换发布目录并检查本机 HTTP。启动检查失败时尝试恢复上一个 Go 版本。
- 卸载使用 `sudo bash install-go.sh uninstall`。该操作停用并移除 Go 服务，保留订阅数据、凭据和已解包版本。

Go 监听 `127.0.0.1:62578`。已有 HTTPS 反代可在测试通过后手动改到该端口。安装器不会修改域名、证书或反代。旧数据切回 Python 前，先停止并禁用 Go，并核对备份与 Go 运行期间写入的数据。

当前仍为迁移预览版。功能和实机缺口见 [REMAINING.md](REMAINING.md)。
