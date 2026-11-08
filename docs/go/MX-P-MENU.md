# mx-p 管理命令与一键安装

命令：`curl -fsSL https://raw.githubusercontent.com/Angasky/Mx-Panel/main/deploy/quick-install.sh | sudo bash`

下载固定版本 v0.1.2 的对应架构安装包，核对精确 SHA256 条目、包内文件名与文件类型；脚本从终端读取密码，支持管道执行。检测已有 Go 安装则更新，已有旧数据则要求先备份停用旧服务后迁移。

`mx-p` 菜单嵌入 Go 程序，快捷脚本仅调用 current/mxioc --menu，无需每次联网获取脚本。旧版 vpn 的 IP/域名/极速部署、升级修复、重置账号、保留数据卸载、彻底卸载均有对应菜单。IP/极速模式改用自签名 HTTPS，而不是绕过后台 HTTPS 登录要求。另提供状态、日志、重启和备份。

打开菜单时，MXIOC 字标以青白色柔光从左到右逐字渐亮、渐暗，约 2 秒后显示菜单。动画由 Go 原生生成，不下载资源；动画期间输入的菜单选项会保留。设置 `MX_PANEL_NO_ANIMATION=1` 或 `NO_COLOR=1` 可关闭动画，非交互输出自动使用静态字标，窄终端使用单行字标。

HTTPS 网关纯 Go 实现：IP 模式本地生成 ECDSA 证书，域名模式使用 autocert 自动签发续期。转发时删除外部传入的 Forwarded 与 X-Forwarded-*，由网关重新设置 HTTPS 信息。安装不依赖 Python/Nginx/certbot。现有 HTTPS 反代用户不必启用此网关。

菜单配置网关前核验端口并保存旧配置，失败恢复旧服务与 IP 证书。重置账号先停止后台，在原子凭据事务内更换账号并使旧会话失效。卸载先备份，彻底卸载额外确认，仍保留备份及发布缓存。安装器不会覆盖不属于本项目的 mx-p 命令。

验证：全包 go test -race、go vet、Shell 语法检查通过；真实本地 TLS→Go 后台→登录→Secure Cookie→认证接口链路通过；凭据重置及会话失效通过；隔离安装/升级/卸载快捷命令与文件持久化、损坏包摘要拒绝、PTY 菜单打开退出通过。测试代码与日志按用户要求只在本地保存。

没有在当前服务器安装或启动生产服务；域名 ACME 签发、公网 DNS 与 systemd 目标主机验收仍需实际环境。arm64 为交叉构建。
