# Go 重构状态

基准：老仓库 `Angasky/mxioc-vpn-manager` 的 `8c199c643fceaa1de9afa009850d835b07f0dcb2`。
目标：完整 Go 后端发布到 `Angasky/dingzhi-ban`，不保留 Python 运行时依赖。

**此分支是重构中的源码，不是已完成的 Go 版。当前安装器仍运行 Python，不应将其宣称为 Go 服务端。**

## 已实现并验证

- Go module，最低语言版本 1.24；本次使用 Go 1.27.3 构建测试。
- `internal/legacycrypto`：旧版 PBKDF2-HMAC-SHA256 密码格式，240000 / 600000 次迭代；Fernet 的 AES-CBC / HMAC-SHA256 加解密兼容，不改变凭据密钥。
- 测试向量由 Python `cryptography.fernet` 和 `hashlib.pbkdf2_hmac` 生成，只包含固定示例密钥，不读取生产凭据。验证中文、特殊字符、空值、块边界、错误密码、篡改签名及截断数据。
- `internal/storage`：读取 JSON 保留未知字段和大整数，串行化读改写，临时文件 0600、刷盘后原子替换。并发更新及失败不写入测试通过。
- `api-inventory.json` 记录老版本接口路径，用于后续按 HTTP 方法、鉴权与副作用逐一建立对照测试。

```sh
go test ./...
go vet ./...
```

## 尚未完成，阻止替换正式后端

- HTTP 路由、会话、CSRF、登录限流和原有前端契约。
- YAML 配置、节点与策略组、订阅转换、Snell / Mieru / HY2 分享链接、二维码。
- SSH 指纹固定、面板会话与 CSRF 兼容、远端内核应用 / 回滚、任务队列。
- 共用入站独立用户、流量采集、计费倍率、月度重置、额度及到期撤销。
- 硬件监控、Reality / SNI 探测、主备及中转、更新与备份。
- Go 版安装器、systemd 单二进制启动、旧数据迁移、Linux amd64 / arm64 发布及完整回归。

正式替换标准：上述能力通过原接口对照、并发 / 故障测试和真实内核数据链路验证；不以调用 Python 子进程或反向代理 Python 代替迁移。

原定制版备份分支：`go-rewrite-backup-20261102`。
