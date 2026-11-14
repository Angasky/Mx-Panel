# sing-box 分流导出（v0.2.19，实验性）

在订阅转换列表选择 **sing-box 分流配置（实验性）**。这是独立于旧版基础节点导出的新链接；两种格式共同受「安全与客户端兼容 → sing-box 导出」开关控制。下载接口为 `/convert/<订阅令牌>/sing-box-routing`，JSON 格式，适用的配置已通过本地 sing-box 1.14.4 `check` 校验。

## 转换范围

- 所有节点必须能由既有 sing-box 转换器完整导出；不跳过不兼容节点。
- 保留 `select` 手动策略组及嵌套引用、成员顺序、首个默认成员。
- v0.2.11 新增 `url-test` → sing-box `urltest`：传递 HTTP/HTTPS 测试 URL、间隔和容差。未填写时导出默认间隔 300 秒、容差 50 毫秒；这是明确的导出默认值，不保证两端缺省行为完全一致。间隔限 1–86400 秒，容差限 0–65535 毫秒。测速运行和闲置暂停行为遵循 sing-box，不保证与 Mihomo 选中节点完全一致。生成标签包含原名称及唯一前缀。
- 保留规则顺序：DOMAIN、DOMAIN-SUFFIX、DOMAIN-KEYWORD、DST-PORT、SRC-PORT、SRC-IP-CIDR（IPv4/IPv6）、NETWORK（tcp/udp）。支持 DIRECT、REJECT 以及已转换节点/策略组动作。
- IP-CIDR/IP-CIDR6 只转换显式 `no-resolve` 的规则，避免域名解析语义变化。
- 末尾必须有唯一 MATCH，指定已转换策略或 DIRECT 作为默认出口。
- 本地入口仍为回环 mixed 2080，不包含 TUN 设置；需要客户端将流量送入该入口。

## 不支持时拒绝导出

远程/文件规则集、代理提供者、GEOIP/GEOSITE、进程名/进程正则及通配规则、故障切换/负载均衡组、QUIC 落地链路、远端主备及策略组扩展选项（包括 lazy、timeout、expected-status 等）暂不转换。遇到不支持内容时整份导出不可用，管理页兼容报告显示原因；不会静默丢弃规则或退回全直连。

此格式不转换原 DNS 设置。启用了面板 DNS/WebRTC 防护覆盖的订阅拒绝此导出，避免把未继承保护的配置当作等价替代。其他自定义 DNS/TUN/嗅探设置也未转换，需要在客户端自行配置；要求完整保持这些设置时使用原始 Mihomo 配置。原来的 sing-box 基础节点导出保持不变。

导出遵循订阅有效期、额度撤销与 IP 白名单。HEAD 和 GET 一致，不修改源订阅或服务器内核。

## 验证

已覆盖嵌套组与引用、循环/未知引用拒绝、规则顺序和默认出口、拒绝策略、不支持字段/规则/节点整份失败、原始数据不变、旧导出兼容、导出开关、真实 sing-box 内核 check（包括新增自动测速组、源地址和源端口规则）、JSON 下载/HEAD 与 IP 白名单拒绝。未完成 Android/iOS 第三方客户端实机导入和真实代理流量测试，不宣称全客户端完全等价。

## v0.2.12：逻辑组合规则

支持 AND、OR、NOT 及嵌套组合，保留条件关系、顺序和最终动作。例如：

```text
AND,((NETWORK,udp),(DST-PORT,443)),REJECT
OR,((DOMAIN,example.com),(DOMAIN-SUFFIX,example.org)),选择
NOT,((DOMAIN-SUFFIX,cn)),选择
```

子条件使用本页列出的已支持类型，不包含单独路由动作；IP 子条件仍需显式 no-resolve。NOT 仅接受一个子条件，AND/OR 至少两个。每条规则最多 8192 字节、8 层逻辑嵌套、128 个条件。未知子条件、非法括号或超限均拒绝整份导出，不省略条件。真实 sing-box 1.14.4 check 覆盖三类逻辑、嵌套和拒绝动作；未进行手机客户端实机联网验收。

## v0.2.13：内嵌规则集

支持 Mihomo `rule-providers` 中 `type: inline` 的三种 behavior，并生成 sing-box 内联规则集，不请求任何外部文件：

- `domain`：精确域名和 `+.example.com` 后缀；其他通配写法拒绝转换。
- `ipcidr`：IPv4/IPv6 CIDR，自动规范化网段。
- `classical`：本页已有基础及逻辑条件，不包含路由动作；IP 条件必须显式 no-resolve。不支持规则集之间继续引用。

顶层 `RULE-SET,名称,策略` 和逻辑组合内的 RULE-SET 子条件均可引用。含目标 IP 条件的规则集在引用处也必须明确 no-resolve，避免改变域名解析行为。集合内条目按“任意条目匹配”解释，不重新排序条目；生成标识按名称稳定排序，重复导出结果稳定。

最多 64 个集合、合计 4096 条，每条最多 8192 字节。文件/HTTP 提供者、未知字段、空集合、未知引用、未支持语法和超限都拒绝整份导出。真实 sing-box 1.14.4 check 覆盖三种集合及逻辑引用；仍不代表第三方手机客户端实机验收完成。

## v0.2.14：端口集合、桌面进程路径和网络大小写

SRC-PORT、DST-PORT 新增 `/` 分隔的端口集合与 `-` 范围，如 `80/443/1000-2000`。转换为 sing-box 同一端口条件组中的 port 和 port_range（两者为 OR），最多 28 段，仅接受 1–65535，拒绝倒序、空段和非法字符。NETWORK 支持 TCP/UDP 的大小写组合，并规范化为小写；修复此前大写值被拒绝的问题。

PROCESS-PATH 支持桌面系统绝对路径，包含 Windows 路径与空格。Mihomo 的精确路径比较忽略大小写，而 sing-box 字面路径比较区分大小写，因此用转义后、首尾锚定、忽略大小写的 process_path_regex 保留匹配语义。检测到顶层、逻辑子条件或内嵌集合中的进程路径时开启 route.find_process。

此能力仅适用于支持进程查询的 Linux/Windows/macOS 客户端，是否能取得进程信息取决于运行权限和流量入口。本地 mixed 代理入口并不保证所有连接都可查询进程。不能把 Android 包名直接当作桌面进程路径；PROCESS-NAME、进程正则及通配规则仍拒绝转换，不声称已支持 Android 应用路由。真实内核 check 与路径大小写/转义测试通过，未进行各平台客户端实机进程识别验收。


## v0.2.19：节点中转关系

新增将节点的 `dialer-proxy` 转为 sing-box 出站 `detour`。支持引用已转换节点、select / url-test 策略组或 DIRECT；保持原名称映射及策略组成员顺序。不修改源订阅，也不创建或部署远端中转服务。

例如「落地」节点设置 `dialer-proxy: 入口` 后，连接落地服务器的流量先经过「入口」。多级节点可逐级引用；节点与策略组使用统一依赖图，直接自引用、节点互引，以及「落地引用组、组又包含落地」的间接循环均拒绝整份导出。缺失、空、非字符串、REJECT 等不支持引用也拒绝，不移除中转参数后继续直连。

当前支持 SS、Trojan、VMess、VLESS、SOCKS5、HTTP 落地节点，节点其他参数仍须通过原完整出站转换器检查。暂拒绝 Hysteria2/TUIC 等 QUIC 落地通过 detour 的组合，也拒绝链路落地同时启用 TFO。链路上的 UDP 可用性仍受每一跳协议及客户端限制，不保证 TCP 可用就代表 UDP 可用。面板远端主备/服务器链路记录、代理提供者、fallback/load-balance 策略组及 DNS/TUN 全量配置仍未转换。

验证包括直接节点、嵌套选择组、测速组、DIRECT 引用，节点与组混合循环、未知引用、unsupported 组合、源数据不变和 GET/HEAD 下载。实际 sing-box 内核检查通过；隔离双 SOCKS5 代理的真实 HTTP 请求确认入口连接落地、落地连接目标，没有绕过入口。为保持导出器的地址限制，真实通信测试仅将生成配置中的测试服务器地址替换为回环地址并指定空闲入口端口，其余 detour 和策略保持生成结果。未完成手机端或所有协议组合的真实联网验收。


## v0.2.25：通配域名条件

新增 DOMAIN-WILDCARD，转换为完整字符串匹配且忽略大小写的 domain_regex。支持 `*`（零个或多个 ASCII 字符）和 `?`（恰好一个 ASCII 字符）；点、连字符等按字面量处理，不把用户输入当作正则。可用于顶层、AND/OR/NOT 子条件及 inline classical 规则集。

例如 `*.example.com` 匹配 a.example.com 和 a.b.example.com，但不匹配 example.com；`api?.example.com` 匹配 api1.example.com，不匹配 api12.example.com。星号可跨越点，不将它误改为“恰好一层子域名”。

当前限定 ASCII 域名，国际域名请使用 Punycode；输入 1–253 字节，只允许字母、数字、点、连字符、下划线、星号及问号，不接受 no-resolve。原 Mihomo 通配实现按字节匹配，不能将其直接放宽为 Unicode 字符正则，因此不承诺原始 Unicode 主机名的等价匹配。

此功能是 DOMAIN-WILDCARD 条件，不改变 inline domain 提供者的专用语法；该提供者仍只接受精确域名及 +. 后缀。使用通配条件时选择 classical 集合。Surge 不会因为共享解析器而误接受尚未适配的通配条件，仍整份拒绝。

测试覆盖根域/多级子域、问号长度、大小写、正则字面量转义、锚定、非法字符/长度、逻辑与 classical 引用、源配置不变、下载接口及跨格式拒绝。真实 sing-box 内核 check 通过；没有手机客户端实际联网验收。
