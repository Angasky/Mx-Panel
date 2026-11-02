# Go 重构状态

基准：老仓库 `Angasky/mxioc-vpn-manager` 的 `8c199c643fceaa1de9afa009850d835b07f0dcb2`。
目标：完整 Go 后端发布到 `Angasky/dingzhi-ban`，不保留 Python 运行时依赖。

**此分支仍在重构中，尚不能替代完整面板。Go HTTP 服务已经独立运行，不调用 Python；正式安装器仍使用 Python。**

## 已实现并验证

- Go module，最低语言版本 1.24；本次使用 Go 1.27.3 构建测试。
- `internal/legacycrypto`：旧版 PBKDF2-HMAC-SHA256 密码格式，240000 / 600000 次迭代；Fernet 的 AES-CBC / HMAC-SHA256 加解密兼容，不改变凭据密钥。
- 测试向量由 Python `cryptography.fernet` 和 `hashlib.pbkdf2_hmac` 生成，只包含固定示例密钥，不读取生产凭据。验证中文、特殊字符、空值、块边界、错误密码、篡改签名及截断数据。
- `internal/storage`：读取 JSON 保留未知字段和大整数，串行化读改写，临时文件 0600、刷盘后原子替换。并发更新及失败不写入测试通过。
- `api-inventory.json` 记录老版本接口路径，用于后续按 HTTP 方法、鉴权与副作用逐一建立对照测试。
- `cmd/mxioc`：原生 Go HTTP 服务、超时限制、优雅退出，默认开发端口 `127.0.0.1:62578`，不会占用现有 Python 服务端口。
- 原生接口：POST login / logout，GET account / profiles / snapshot / raw，节点 POST / PUT / DELETE，POST nodes/validate / nodes/move。其余接口仍未迁移。
- 鉴权：HTTPS、严格来源检查、安全 Cookie、随机会话及摘要索引、12 小时过期、8 会话上限、登录失败锁定、密码计算并发限制、JSON 请求大小上限。
- 配置：读取旧 profiles.json 与 YAML，保留未知配置，节点 CRUD、重命名引用、排序及策略组成员顺序同步；镜像文件写入失败回滚、备份、并发更新保护。高级协议校验仍需继续对齐 Python。
- 验证：实际 HTTPS / Cookie 登录读取退出、来源与限流测试、节点 HTTP 流程、并发保存、镜像失败恢复、JSON 数值到 YAML 的类型保持；Windows 本机测试及 Linux amd64 / arm64 编译通过。

```sh
go test ./...
go vet ./...
```

## 本轮新增

- 管理员改密与改用户名：保存新凭据后撤销全部旧会话，测试验证重启后新凭据可登录。
- 策略组、规则、DNS、原始 YAML 写入、规则排序；规则快照字段已与旧前端 value/action/options 契约对齐。
- 单节点策略组、节点批量删除；策略组循环引用和主备组件保护。
- 订阅新建、复制、重命名、Slug 管理和删除；禁止复制活动远端用户凭据，保留未知索引字段和大整数。
- 基础分享链接解析/导出：VLESS、VMess、Trojan、HY2、TUIC、SS、Snell、SOCKS5、HTTP(S)。Python 生成的固定示例验证密码、PSK、IPv6 与基本协议字段；高级协议选项仍需继续对齐。
- 节点链接批量导入、同名改名、单节点分享与白底 SVG 二维码；非默认订阅的二维码显式传递 profile。
- 真实 HTTPS、HTTP 接口、配置事务、凭据更换和 URI 兼容测试通过。

## 开发运行

使用隔离数据目录和旧认证文件的测试副本；节点接口会写入索引指向的 YAML 文件，因此索引内的配置路径也应指向测试副本。

```sh
go build -o mxioc-go ./cmd/mxioc
./mxioc-go -root /path/to/test-data -auth /path/to/test-auth.json -local-development
```

真实反向代理接入须使用 HTTPS，并显式启用 `-trust-loopback-proxy`；仅信任来自回环地址的 HTTPS 转发标头。正式安装器尚未切换。现阶段只验证已迁移接口，原前端的完整工作流仍依赖尚未迁移接口。

## 尚未完成，阻止替换正式后端

- 其余 HTTP 路由、持久化会话策略及完整前端契约。
- 公开订阅与格式转换、Mieru 与高级协议参数的链接适配、完整协议校验。
- SSH 指纹固定、面板会话与 CSRF 兼容、远端内核应用 / 回滚、任务队列。
- 共用入站独立用户、流量采集、计费倍率、月度重置、额度及到期撤销。
- 硬件监控、Reality / SNI 探测、主备及中转、更新与备份。
- Go 版安装器、systemd 单二进制启动、旧数据迁移、Linux amd64 / arm64 发布及完整回归。

正式替换标准：上述能力通过原接口对照、并发 / 故障测试和真实内核数据链路验证；不以调用 Python 子进程或反向代理 Python 代替迁移。

原定制版备份分支：`go-rewrite-backup-20261102`。
