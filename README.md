<div align="center">

# Mx-Panel

**你的节点，你的订阅，一个控制台。**

原生 Go 后端 · 可视化节点管理 · 多订阅与流量控制

[![Go](https://img.shields.io/badge/Backend-Go-00ADD8?style=flat-square&logo=go&logoColor=white)](go.mod)
[![Linux](https://img.shields.io/badge/Linux-amd64%20%7C%20arm64-334155?style=flat-square&logo=linux&logoColor=white)](https://github.com/Angasky/Mx-Panel/releases)
[![Preview](https://img.shields.io/badge/Release-Preview-F59E0B?style=flat-square)](https://github.com/Angasky/Mx-Panel/releases)

[**下载安装**](https://github.com/Angasky/Mx-Panel/releases) · [界面预览](#界面预览) · [快速开始](#快速开始) · [使用文档](#使用文档)

</div>

---

## 一个面板，管理日常配置

| 节点与订阅 | 服务器与流量 | 分流与维护 |
| :--- | :--- | :--- |
| 分享链接导入、节点编辑与排序 | 服务器接入与独立用户管理 | 策略组、路由规则与 DNS |
| 多订阅、套餐与二维码分享 | 流量额度、倍率与到期处理 | 中转、主备与失败恢复 |
| 中文搜索、三种界面主题 | Xray / sing-box 配置管理 | 配置校验、备份与版本更新 |

支持的节点协议：

`VLESS` · `VMess` · `Trojan` · `Shadowsocks` · `Hysteria2` · `TUIC` · `Snell` · `Mieru` · `SOCKS5` · `HTTP(S)`

订阅适配 Mihomo / Clash、V2Ray 系列与 Shadowrocket。不同协议、内核及客户端的能力边界见[客户端适配说明](docs/client-compatibility.md)。

## 界面预览

**科技主题** · 深色界面，集中展示节点与常用操作。

![科技主题的节点管理界面](docs/assets/theme-high.png)

<table>
  <tr>
    <th width="50%">简洁主题</th>
    <th width="50%">暖粉主题</th>
  </tr>
  <tr>
    <td><img src="docs/assets/theme-low.png" alt="简洁主题界面"></td>
    <td><img src="docs/assets/theme-pink.png" alt="暖粉主题界面"></td>
  </tr>
</table>

<sub>主题示意截图使用示例数据；实际界面以当前发布版为准。三种主题均支持中文输入法搜索，并使用易读的中英文字体。</sub>

## 快速开始

### 一键安装（推荐）

在 root 的 SSH 终端执行：

```bash
curl -fsSL https://raw.githubusercontent.com/Angasky/Mx-Panel/main/deploy/quick-install.sh | bash
```

非 root 用户把最后的 `bash` 改为 `sudo bash`。自动识别 amd64 / arm64，下载 Releases 预编译程序并核验 SHA256；无需 Go、Python 或 Nginx。设置管理员账号后进入管理菜单。

以后输入：

```bash
mx-p
```

菜单提供 IP HTTPS、域名 HTTPS 自动证书、极速部署、升级修复、重置账号、备份、状态、日志、重启及两种卸载方式。IP/极速模式使用自签名证书（浏览器会提示不受信任）；域名模式使用 Let’s Encrypt，需要 DNS 指向本机并放行 80/443。IP 模式默认端口为 5656。

### 手动下载安装


**无需安装 Go 或 Python。** 准备一台使用 systemd 的 Linux 服务器，并具备 root / sudo 权限。

| 服务器架构 | 选择安装包 |
| :--- | :--- |
| Intel / AMD，`uname -m` 显示 `x86_64` | **linux-amd64.tar.gz** |
| ARM，`uname -m` 显示 `aarch64` | **linux-arm64.tar.gz** |

前往 [Releases 下载页](https://github.com/Angasky/Mx-Panel/releases)，下载对应压缩包、`SHA256SUMS` 和 `INSTALL-zh-CN.txt`。服务器需要 bash、curl、tar、coreutils 和 util-linux。

### 2. 校验并安装

以下以 `v0.1.7` 的 amd64 包为例；其他版本或架构请替换文件名。

```bash
# 在安装包与校验文件所在目录执行，确认对应压缩包显示 OK
sha256sum --check --ignore-missing SHA256SUMS

mkdir -p mx-panel-install
tar -xzf mxioc-go-v0.1.7-linux-amd64.tar.gz -C mx-panel-install
cd mx-panel-install

sudo bash install-go.sh fresh
```

按提示设置管理员账号与至少 **12 个字符**的密码，没有默认账号密码。`fresh` 用于首次安装；已有数据请使用下方对应操作。

### 打开管理界面

安装后运行 `mx-p`，选择 IP、域名或极速模式配置访问地址，使用菜单显示的 **HTTPS 地址**登录。Go 后端仍仅监听 `127.0.0.1:62578`，HTTPS 网关由独立的 `mx-p-gateway` 服务提供。

若已有 Nginx，可沿用自己的 HTTPS 反代，参考 [配置示例](deploy/nginx.conf.example)。**直接 HTTP 或仅 SSH 转发后端端口不能完成管理登录**。

<details>
<summary><strong>已有部署：迁移、更新与卸载</strong></summary>

在对应安装包的解压目录执行：

| 操作 | 命令 | 说明 |
| :--- | :--- | :--- |
| 迁移旧版数据 | `sudo bash install-go.sh install` | 先备份数据和凭据，停止并禁用旧版服务 |
| 更新 Go 版本 | `sudo bash install-go.sh update` | 从新版本安装包执行 |
| 卸载 Go 服务 | `sudo bash install-go.sh uninstall` | 默认保留数据 |
| 查看服务状态 | `sudo systemctl status mxioc-go --no-pager` | 查看启动状态与近期日志 |

迁移前备份 `/opt/mxioc-rule-manager` 和 `/etc/mxioc-rule-manager.auth.json`。完整流程见[安装与更新说明](docs/go/DEPLOY.md)。

</details>

<details>
<summary><strong>开发者：从源码构建</strong></summary>

使用 `go.mod` 声明的 Go 工具链，在仓库根目录执行：

```bash
bash install.sh local-build
```

双架构安装包及校验文件输出到 `dist/go-local-build/`。此命令只构建，不安装系统服务。

</details>

## 使用文档

| 想了解什么 | 从这里开始 |
| :--- | :--- |
| 安装、迁移、更新与卸载 | [部署指南](docs/go/DEPLOY.md) |
| 协议与客户端适配 | [客户端兼容说明](docs/client-compatibility.md) |
| Reality / Snell 兼容内核 | [补丁与构建工具](tools/core-compat/README.md) |
| 迁移进度与尚未完成的实机验收 | [当前状态](docs/go/REMAINING.md) |
| 性能测试与优化记录 | [索引优化与性能对比](docs/go/INDEX-CACHE-20261108.md) |

> [!NOTE]
> 当前为 **Go 预览版**。amd64 安装包已验证隔离初始化、数据检查与网页启动；arm64 已交叉构建，尚未实机运行。真实面板、SSH、systemd、公网及客户端 App 的完整验收仍在推进。代理内核需另行配置，兼容补丁不会随管理器自动安装。

---

<div align="center">

基于 [mxioc-vpn-manager](https://github.com/Angasky/mxioc-vpn-manager) 迁移 · 当前管理器后端使用 **Go**

[下载版本](https://github.com/Angasky/Mx-Panel/releases) · [反馈问题](https://github.com/Angasky/Mx-Panel/issues)

</div>

### 功能对照与新主题

新增暖橙主题、节点协议筛选及 sing-box 客户端配置导出。完整差异和待办见 [妙妙屋X 功能对照](docs/go/MMWX-COMPARISON.md)。这不表示对方全部功能已实现。

### 多用户与订阅授权

管理员登录后，在 **设置 → 用户与权限** 中新建普通用户、分配订阅、禁用账号或重置密码。普通用户使用同一个登录页面，只能查看已授权订阅的用量、复制地址和下载客户端配置，无法修改节点、服务器或系统设置。

- 新密码至少 12 个字符；普通用户需要重置密码时联系管理员。
- 保存账号或授权变更后，该用户的登录会话立即失效，重新登录后使用新权限。
- 禁用或删除账号不会作废已复制的公共订阅链接。需要彻底撤销订阅访问时，请同时轮换订阅地址。
- 用户记录保存在数据目录 `panel-users.json`，文件权限为 `0600`。完整迁移/备份时应保留该文件；单份订阅 YAML 备份不包含账号。

设置中还提供原创 **暖橙主题**；节点页支持协议筛选；客户端导出新增 **sing-box**。详细适配边界见[功能对照记录](docs/go/MMWX-COMPARISON.md)。

### 历史监控

进入 **服务器监控 → 选择服务器 → 历史记录**，点击 **启用后台采样**。默认关闭；启用后无需保持网页打开，后台约每 30 秒使用已核对指纹的 SSH 采样，最多 3 台并发，服务器较多时周期会延长。

- 保留最近 24 小时 CPU、内存和网速曲线，以及最近 30 个 UTC 自然日的网卡流量观测。
- 失败或不可确认的区间显示为缺口；不把停机、重启、计数器回退、网卡切换和跨日间隔补算成完整流量。
- 网卡流量与订阅计费分开，表中显示有效观测时长与缺口次数，不应当作完整账单。
- 暂停采样保留尚未过期的记录；“清空并停用”删除该服务器历史并停止采样。
- 数据保存在 `monitor-history/`，文件权限 `0600`；普通用户无法读取或修改。服务器删除后，残留记录在 30 天未更新后清理。
