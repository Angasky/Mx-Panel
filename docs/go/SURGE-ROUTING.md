# Surge 分流配置（v0.2.20，实验性）

入口：订阅总览 → 客户端订阅与扫码导入 → **Surge 分流配置（实验性）**。独立下载地址为 `/convert/<订阅令牌>/surge-routing`，文件扩展名 `.conf`。原有 `surge` 基础节点导出仍保持原来的独立手动组与兼容节点跳过行为。

新格式使用严格转换：任一节点、组、规则或引用不兼容时整份拒绝导出，兼容报告展示原因，不静默删除规则、跳过节点或退回直连。访问沿用订阅有效期、额度撤销及 IP 白名单，HEAD 与 GET 行为一致。

## 支持范围

- 节点复用现有 Surge 转换器：兼容 SS、Trojan TCP/TLS、HTTP/HTTPS、SOCKS5/TLS、Snell v1–v5，仍校验全部参数；并非所有原始协议参数都有对应字段。
- `select` 手动策略组，保留成员顺序、嵌套引用及首个默认成员，支持 DIRECT/REJECT 成员。
- `url-test` 自动测速策略组，保留测试 URL、间隔和容差，支持嵌套引用；不支持 REJECT 成员。省略时显式导出 300 秒、50 毫秒，容差为 0 时保留 0。
- DOMAIN、DOMAIN-SUFFIX、DOMAIN-KEYWORD，规范化域名匹配值为小写；支持节点/组、DIRECT、REJECT 路由动作。
- IP-CIDR / IP-CIDR6 必须显式 `no-resolve`，校验地址族并规范化网段。
- 末尾唯一 MATCH 映射为 FINAL，不猜测默认出口；保留规则顺序。

节点与组使用稳定的唯一前缀加经过清理的原名称，避免重复与 INI 注入。未知引用和策略组循环会拒绝。导出不修改源订阅、不连接或改动远端服务器。

## 测速配置与语义

按 Surge 当前官方文档，组内旧 `url=` 参数已无效。因此导出通过 `[General]` 的 `proxy-test-url` 和 `internet-test-url` 保留原测试 URL，要求所有测速组使用相同 URL；不同 URL 时整份拒绝，不选择其中一个覆盖其他组。

Surge 的测试采用 HEAD 请求，并按使用情况和测试结果年龄触发重测，测量及选择算法与 Mihomo 不完全相同。`interval` 是结果有效期，不代表严格定时探测；不保证两个客户端始终选中同一节点。客户端已保存的手动选择可能优先于首个成员。

间隔范围 1–86400 秒，容差范围 0–65535 毫秒。其他策略组选项（lazy、timeout、expected-status、use 等）、fallback/load-balance 等类型暂不支持。URL 中的凭据、片段、配置分隔符或控制字符拒绝导出。

## 仍未转换

DNS/TUN、嗅探、规则集、代理提供者、GEOIP/GEOSITE、端口/进程/逻辑规则、节点 dialer-proxy、面板远端主备及服务器链路。启用了面板 DNS/WebRTC 防护覆盖的订阅拒绝这个分流导出，防止误以为已继承保护。需要完整保持原配置时使用 Mihomo 原始订阅。

本功能补齐 Surge 的部分策略组与规则转换，不是与妙妙屋或 Mihomo 的完整等价。它也不会让 Surge 支持其本身不支持的节点协议。

## 验证与参考

测试覆盖嵌套手动/测速组、默认值与零容差、测试 URL 一致性、域名大小写、IPv4/IPv6、源数据不变、确定性导出、非法/未知引用、循环、配置注入、禁止部分导出、原基础导出兼容、下载文件名、GET/HEAD 与 IP 白名单。

真实 Chromium 使用隔离后端完成新入口、兼容报告、下载与不支持规则拒绝流程，六主题 × 320/390/768/1440 像素布局通过。没有可运行的 Surge iOS/macOS 客户端，未完成实机导入或真实流量验收，不将输出检查称为 Surge 内核校验。

实现依据公开官方文档（2026-11-14 查阅）：
- https://manual.nssurge.com/policy-groups/select.html
- https://manual.nssurge.com/policy-groups/url-test.html
- https://manual.nssurge.com/rules/ip.html
- https://manual.nssurge.com/rules/final.html
