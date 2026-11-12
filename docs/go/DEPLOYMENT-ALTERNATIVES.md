# Docker Compose 与 Alpine OpenRC

从 v0.1.29 起，Release 附带 `mxioc-deployment-v0.1.29.tar.gz`，内含两种部署方式。主程序包的文件清单保持兼容，旧 systemd 安装仍使用 `mx-p` 更新。下面流程适用于新安装；不自动搬动现有服务器或更换服务管理器。

## 下载部署工具

在空目录下载以下两项，校验后解压。版本更新时统一替换版本号。

```sh
version=v0.1.29
base="https://github.com/Angasky/Mx-Panel/releases/download/go-$version"
curl -fL "$base/mxioc-deployment-$version.tar.gz" -o "mxioc-deployment-$version.tar.gz"
curl -fL "$base/SHA256SUMS" -o SHA256SUMS
awk -v n="mxioc-deployment-$version.tar.gz" '$2==n {print;found++} END {if(found!=1)exit 1}' SHA256SUMS > deployment.sha256 &&
sha256sum -c deployment.sha256 &&
tar -xzf "mxioc-deployment-$version.tar.gz"
```

校验必须显示部署工具包 `OK`。没有预先上传的容器镜像：下方脚本从正式 Release 下载、核对 SHA256，再在本机构建镜像；只需要 Docker、Compose v2、curl 和 tar，无需 Go/Python。首次构建需要访问 Alpine 镜像及软件源。

## Docker Compose

```sh
sh deploy/container/build-image.sh v0.1.29
cd deploy/container
cp access.example.json access.json
```

编辑 `access.json`，将 `host` 改为服务器公网 IP，保留 `port: "8443"`、`domain: false`。随后：

```sh
docker compose run --rm setup
# 输入自己设置的管理员密码，至少 12 个字符；默认账号 admin。
docker compose up -d --wait
docker compose ps
```

访问 `https://服务器IP:8443/admin/`。IP 模式是自签名证书，浏览器会提示不受信任；可信证书请使用下方域名模式。再次执行初始化会拒绝覆盖已有账号；也可以用 `docker compose run --rm setup init 自定义管理员名`。

应用进程使用 UID/GID 10001，后台只绑定容器内 `127.0.0.1:62578`。HTTPS 网关共享后台的网络命名空间，不公开后台端口、不挂载 Docker Socket、不使用 privileged。数据与证书使用两个命名卷，`docker compose down` 保留数据；**不要使用 `down -v`，它会删除数据卷**。

### 域名 HTTPS

编辑 `access.json`：

```json
{"host":"panel.example.com","port":"443","domain":true,"email":"you@example.com"}
```

在 Compose 同目录的 `.env` 中填写：

```dotenv
MX_PANEL_IMAGE=mx-panel:v0.1.29
MX_PANEL_HTTPS_PORT=443
MX_PANEL_TLS_PORT=443
MX_PANEL_HTTP_PORT=80
```

域名须正确解析到服务器，公网 80/443 可达且没有其他程序占用。执行 `docker compose up -d --force-recreate`。网关自动申请、缓存并续期 Let's Encrypt 证书；本次没有使用真实域名重新验证公网签发。`MX_PANEL_BIND` 可限制宿主机监听地址；默认 `0.0.0.0`。

### 更新、备份与恢复

先停止写入并备份（密码文件和加密密钥均在此卷中）：

```sh
docker compose stop gateway panel
umask 077
docker compose run --rm -T --no-deps --user 0 --entrypoint tar setup -czf - -C /var/lib/mx-panel . > mx-panel-data-backup.tar.gz
docker compose start panel gateway
```

证书卷也应通过 Docker 卷备份工具单独备份。保留 Compose 项目名、数据卷及 `access.json`、`.env`，不要把含凭据的备份提交到仓库。

下载新版本的部署工具；用 `build-image.sh 新版本` 构建镜像，将 `.env` 中 `MX_PANEL_IMAGE` 改为对应标签，运行 `docker compose up -d --force-recreate --wait`。后台与网关必须一起重建，以保持共享的网络命名空间。更新失败时可改回旧镜像标签重新启动；如果要恢复数据，先停止服务，在空数据卷中解压备份并保留 UID/GID 10001，再执行 `setup check` 校验。

容器内不支持 systemd 的网页一键更新/卸载或 `mx-p` 系统管理；请使用 Compose 更新、停止和看日志。远程节点仍通过 SSH/Agent 管理；容器不是代理内核安装环境，不会自动把宿主机服务映射进去。

## Alpine Linux / OpenRC

当前安装脚本以 Alpine Linux 的用户管理和 OpenRC 为目标，不声称兼容所有 OpenRC 发行版。需要 root、已启动的 OpenRC、空的专用安装目录。

```sh
apk add --no-cache openrc curl ca-certificates jq util-linux openssh-client
```

下载对应 `mxioc-go-v0.1.29-linux-amd64.tar.gz`（ARM64 改 `arm64`），使用 Release 的 SHA256SUMS 校验，解压到空的 `bundle` 目录。将部署工具的脚本放到包旁边：

```sh
cp deploy/install-openrc.sh bundle/
cp -R deploy/openrc bundle/
cp deploy/container/access.example.json /root/mx-panel-access.json
# 编辑 /root/mx-panel-access.json 的公网 IP 或域名/端口。
sh bundle/install-openrc.sh fresh admin /root/mx-panel-access.json
```

脚本交互设置管理员密码，使用独立账号 mxpanel 运行后台，安装并启动 `mx-panel`、`mx-panel-gateway` 两个 OpenRC 服务，检查后台与 IP 模式 HTTPS 健康状态。HTTPS 网关为监听标准端口使用 root。首次配置失败不会覆盖已有 systemd/Python 数据；检测到旧安装会拒绝 fresh。

路径：

- 程序：`/opt/mx-panel-openrc/releases` 和 `current` 符号链接。
- 数据及账号：`/var/lib/mx-panel`。
- HTTPS 配置和证书：`/etc/mx-panel-openrc`。
- 日志：`/var/log/mx-panel/panel.log`、`gateway.log`；请配置系统 logrotate 定期轮换。

```sh
rc-service mx-panel status
rc-service mx-panel-gateway status
rc-service mx-panel restart
rc-service mx-panel-gateway restart
```

更新时下载并校验新的主程序包和部署工具，解压、复制脚本后执行：

```sh
sh bundle/install-openrc.sh update
```

更新会先验证数据、停止服务并备份到 `/var/backups/mx-panel`，再切换版本、启动和检查。失败尝试恢复旧程序及服务脚本；备份留存供人工恢复数据，不能将程序回退等同于任意未来版本的数据格式降级。更新当前会启动这两个服务，若希望维持停机状态，请不要执行更新命令。

禁用服务使用 `rc-service ... stop` 和 `rc-update del ... default`。卸载时先备份，再手动删除对应程序及服务脚本；默认不提供自动删数据命令。原 `mx-p` 菜单及网页 systemd 更新/卸载不适用于本安装方式。

## 验证范围

实际 Docker Engine/Compose、Alpine 容器内真实 OpenRC 服务验证；使用隔离账号和数据。覆盖 HTTPS 登录、普通用户权限、主要网页流程、重复初始化拒绝、重建持久化及 OpenRC 更新/失败回退。容器内 OpenRC 不能替代整机重启验收；域名公网签发与 ARM64 实机仍需各自环境验证。
