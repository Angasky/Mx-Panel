# Surge 分流配置（v0.2.21，实验性）

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

DNS/TUN、嗅探、规则集、代理提供者、GEOIP/GEOSITE、进程规则、节点 dialer-proxy、面板远端主备及服务器链路。启用了面板 DNS/WebRTC 防护覆盖的订阅拒绝这个分流导出，防止误以为已继承保护。需要完整保持原配置时使用 Mihomo 原始订阅。

本功能补齐 Surge 的部分策略组与规则转换，不是与妙妙屋或 Mihomo 的完整等价。它也不会让 Surge 支持其本身不支持的节点协议。

## 验证与参考

测试覆盖嵌套手动/测速组、默认值与零容差、测试 URL 一致性、域名大小写、IPv4/IPv6、源数据不变、确定性导出、非法/未知引用、循环、配置注入、禁止部分导出、原基础导出兼容、下载文件名、GET/HEAD 与 IP 白名单。

真实 Chromium 使用隔离后端完成新入口、兼容报告、下载与不支持规则拒绝流程，六主题 × 320/390/768/1440 像素布局通过。没有可运行的 Surge iOS/macOS 客户端，未完成实机导入或真实流量验收，不将输出检查称为 Surge 内核校验。

实现依据公开官方文档（2026-11-14 查阅）：
- https://manual.nssurge.com/policy-groups/select.html
- https://manual.nssurge.com/policy-groups/url-test.html
- https://manual.nssurge.com/rules/ip.html
- https://manual.nssurge.com/rules/final.html


## v0.2.21：端口、源地址与逻辑组合

新增映射：

| Mihomo 条件 | Surge 条件 |
| --- | --- |
| DST-PORT | DEST-PORT |
| SRC-PORT | SRC-PORT |
| SRC-IP-CIDR | SRC-IP，支持 IPv4/IPv6，规范化网段 |
| NETWORK,tcp / udp | PROTOCOL,TCP / UDP |
| AND / OR / NOT | 保留组合关系及嵌套顺序 |

端口支持 1–65535、闭区间及 `/` 分隔集合，例如 `80/443/1000-2000` 转为三个端口条件的 OR；最多 28 段，拒绝倒序、空段、0 或超范围端口。源端口范围同样支持；`>=` 等 Surge 专用语法不是 Mihomo 此输入格式，不接受其作为转换输入。

例如：

```text
AND,((NETWORK,udp),(DST-PORT,443/8443)),REJECT
```

导出为：

```text
AND,((PROTOCOL,UDP),(OR,((DEST-PORT,443),(DEST-PORT,8443)))),REJECT
```

另一个例子：`AND,((SRC-IP-CIDR,192.168.1.10/32),(DOMAIN-SUFFIX,example.com)),选择` 可仅为特定来源设备的目标域名选择策略。来源规则适用于网关或其他设备通过 Surge 代理的场景，本机应用未必具有可区分的来源地址。

输入每条规则最多 8192 字节、逻辑嵌套最多 8 层、最多 128 个条件；端口集合展开最多增加一层 OR，保持在 Surge 官方最大 10 层之内。NOT 只有一个子条件，AND/OR 至少两个；不支持的子条件不因嵌套而被忽略。IP 子条件仍须显式 `no-resolve`，选项保留在子条件内；顶层 IP 规则选项仍位于策略之后。拒绝规则集、进程、MATCH 子条件及额外未适配参数。

Surge 源端口规则要求支持该能力的版本（官方标注 iOS 5.8.4+ / Mac 5.4.4+）；PROTOCOL,TCP/UDP 使用其官方“包含 HTTP/HTTPS 或 QUIC/STUN 等子协议”的匹配语义。不能据此声称已继承面板 WebRTC/DNS 防护设置。

专项测试覆盖单端口、边界、范围/集合、IPv4/IPv6 源地址、网络大小写、NOT 和深层组合、IP 选项位置、无效语法/超限、源数据不变及实际下载内容。真实浏览器覆盖下载结果、不支持项拒绝、六主题四宽度；仍未完成 Surge 客户端实机验收。

参考（2026-11-14 查阅）：
- https://manual.nssurge.com/rules/source-and-port.html
- https://manual.nssurge.com/rules/protocol-and-network.html
- https://manual.nssurge.com/rules/logical.html
