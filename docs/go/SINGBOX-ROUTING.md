# sing-box 分流导出（v0.2.12，实验性）

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

规则集/提供者、GEOIP/GEOSITE、进程规则、故障切换/负载均衡组、链式节点、远端主备及策略组扩展选项（包括 lazy、timeout、expected-status 等）暂不转换。遇到不支持内容时整份导出不可用，管理页兼容报告显示原因；不会静默丢弃规则或退回全直连。

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
