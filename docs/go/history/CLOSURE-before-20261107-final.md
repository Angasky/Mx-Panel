# 历史记录：已被当前状态表取代

以下为收尾前的原始记录，不代表当前缺口。当前状态见上级目录 REMAINING.md。

# 集中收尾核对（2026-11-06）

本地分支 `local/migration-continue`，Python 基线 `0869964`，Go 基线 `92ccd3e`。未提交、未推送、未部署。本文件不是“全部完成”声明。

## 本轮完成与证据

| 能力 | 验证边界 | 日志（工作区 artifacts/） |
| --- | --- | --- |
| 面板保留数据卸载 | 当前账号密码、Origin、确认文字、输入类型、标准安装限定；共享更新队列与持久任务；错版本、错任务、重复 claim 拒绝 | closure-uninstall-guards-recheck.log、closure-uninstall-tests.log |
| 卸载脚本 | 临时路径与 systemctl 替身验证服务移除、版本变化拒绝、data/auth/releases 保留；未操作本机服务 | closure-uninstall-script.log |
| 维护页 | 表单隐藏、提交、清空密码、禁止重复提交；卸载状态使用卸载文案 | closure-ui-final.log |
| sing-box QUIC UDP 与 Reality | HY2、TUIC 真实 UDP echo；Reality TCP；双用户独立计量、撤销一个用户、末用户暂停/恢复/移除 | closure-accounting.log |
| Xray QUIC UDP 与 Reality | HY2 使用 sing-box 客户端真实 UDP echo；Reality 使用 Xray 客户端；相同用户生命周期 | closure-xray-accounting-recheck.log |
| 全量回归 | 开启 Xray 26.10.31、sing-box 1.14.4、Mihomo 1.19.33 本地真实内核 | closure-all-native.log |
| 竞态与静态检查 | 全包 race（未开启真实内核环境变量）、go vet | closure-all-race.log、closure-vet.log |

UDP 测试使用 IPv4 回环目标，不等于公网 UDP、防火墙、IPv6 或客户端 App 验收。systemd 生命周期脚本已改用卸载工作进程，但尚未实际执行。卸载后管理页面本身停止服务，最终任务状态保留在 `/opt/mxioc-go/update-status.json`。

## 已定位的跨内核兼容问题

sing-box 1.14.4 客户端连接 Xray 26.10.31 Reality 服务端失败。日志 `closure-xray-accounting.log` 保留原始失败；不能将同内核测试通过视为这个组合通过。

从真实 Xray 二进制的 `go version -m` 得到其 REALITY 依赖为 `v0.0.0-20261014101318-83f621788ca8`。该提交 `tls.go` 约 217–235 行要求 ClientHello 在可选 X25519 前带 X25519MLKEM768，否则回退。sing-box 1.14.4 的 `common/tls/reality_client.go` 约 149–161 行主动移除 X25519MLKEM768 曲线及 key share。这与本地请求收到 fallback 证书、Reality 认证失败的现象一致。

上游证据：

- https://github.com/XTLS/REALITY/blob/83f621788ca8/tls.go
- https://github.com/SagerNet/sing-box/blob/v1.14.4/common/tls/reality_client.go

现有转换器传递 Reality 公钥、short ID、SNI 和指纹；当前 sing-box 内核没有可用配置字段将这个行为改成 Xray 要求的握手。不能通过信任 fallback 证书、关闭校验或悄悄降级来冒充修复。需要选定并验证相互兼容的内核版本，或单独维护内核补丁；本轮没有改动第三方内核或生产安装版本。

复现：同时设置 `MXIOC_TEST_XRAY`、`MXIOC_TEST_SING_BOX` 后执行：

```bash
MXIOC_TEST_REALITY_CROSS_CORE=1 go test ./internal/remote -run '^TestXrayRealityAccountingAndRevocationWithRealCore$' -count=1 -v
```

这是已知失败的专门复现开关。默认完整测试不会启用它，也不覆盖这个组合。

## 实际剩余工作与完成条件

| 类型 | 明确差异 | 完成条件 |
| --- | --- | --- |
| Python 行为兼容 | `/servers/bind` 整入站绑定仍拒绝；Go 目前按独立认证用户管理 | 整入站的计量、到期撤销、额度暂停、恢复与解绑均实现；不能只保存一个绑定字段 |
| 已补本地实现，待外部验收 | 原始面板 `inbound` 新增 API 与网页入口已迁移，保留凭据且不自动绑定订阅 | 本地字段验证、认证/Origin、端口冲突、加密记录、断连/重启核对、不重放请求、远端凭据变化检测及 DOM 重试已覆盖；实际 3x-ui 创建/导出待独立环境验收 |
| Python 模板兼容 | 面板单密码 `shadowsocks` 模板已补 API、网页和真实 Xray TCP/UDP 验证；sing-box 传统 SS 仍没有与 Go 相同的多用户模型 | 独立端口隔离方案或明确的整入站绑定模型，配套计量和撤销；Xray AEAD / SS2022 已有独立用户实现不等于此项完成 |
| Python 行为兼容 | 网页清空数据卸载未实现，当前明确拒绝 `purgeData=true` | 划定 Python/Go 共享数据的归属、删除范围和恢复方案；当前保留数据卸载已实现 |
| 旧数据迁移 | 旧 SS 绑定缺身份凭据，旧中转缺可信创建记录 | 引入人工提供并核验的归属证据或重建迁移流程；不得凭相同端口猜测用户和资源归属 |
| 故障恢复 | 已下发但结果不明的主备草稿不能直接取消 | 远端持久化取消屏障与迟到写入互斥；SSH 断开后远端仍可能运行的故障测试 |
| 内核兼容 | 上述 sing-box→Xray Reality 失败 | 修复选定版本组合并通过跨核真实流量、计量与撤销测试 |
| Go 扩展与高级编辑 | 各类未知扩展参数、部分有用户协议切换未开放 | 为具体支持的参数建立配置保留、分享往返与真实内核矩阵；不笼统称“所有高级传输”已迁移 |
| 超出直接翻译 | 共用加密端口按用户限速 | 选择独立端口隔离或内核原生用户限速；Python 自身也拒绝共用入站这一操作 |
| 外部验收 | SSH / 3x-ui / 内核安装、systemd 更新回滚卸载、低资源及断连恢复、客户端 App | 独立可重置 Linux 测试环境与客户端验收；当前生产 Python 服务不用于破坏性测试 |
| 发布与切换 | 只生成本地产物 | 按用户后续要求执行发布和切换；当前“不要推送”约束下不执行 |

Python `remote_manager.py:build_inbound` 的模板只有 Reality、Trojan TLS、VLESS WS TLS、HY2、TUIC、VMess TCP、传统 Shadowsocks。Go 已增加的多种 TCP/WS/gRPC/XHTTP TLS 模板属于扩展，不能将它们所有可能的变体都算成 Python 尚未迁移的模板。方法入口清单 `api-method-inventory.json` 只证明入口对照，不证明响应、异常、并发和故障语义全等。

## 本地交付

- 最新本地二进制：工作区 `artifacts/mxioc`。
- 双架构包：`dist/go-local-20261106-closure/`，含 SHA256SUMS。
- 未清理历史失败日志，便于分辨首次失败、修复后通过和仍未解决的兼容项。

## 原始入站新增续迁证据

新增 `internal/remote/inbound_raw_create.go`、`internal/subscriptions/inbound_raw_create.go` 及对应测试。`/servers/users` 明确拒绝原始对象，防止管理员操作被误认为订阅用户授权；`/servers/inbounds` 返回 `bound=false`、`enforcementEnabled=false`。网页失败重试固定原始配置、服务器、订阅上下文和操作 ID。输入含原始凭据时只保存在既有加密创建日志中。

日志位于工作区 artifacts：`raw-panel-focused.log`、`raw-panel-final-focused.log`、`raw-panel-ui.log`、`raw-panel-all.log`、`raw-panel-native.log`、`raw-panel-race.log`、`raw-panel-vet.log`。新增双架构包目录为 `dist/go-local-20261107-raw-panel/`。先前集中收尾包保留。

## 面板单密码 Shadowsocks 续迁（2026-11-07）

新增 `internal/remote/panel_shadowsocks.go`，只在首次创建意图生成密码，重试读取既有加密配置。模板验证、分享往返、断连/重启密码保持和 HTTP 认证/订阅无副作用测试见 `panel-ss-focused-recheck.log`。真实内核测试通过模板→链接→客户端配置完整路径验证 TCP 和 UDP 回环流量；这不代表公网或面板部署验收。首次运行的回环地址校验失败保留在 `panel-ss-focused.log`，修正测试夹具后重跑通过。其他日志：`panel-ss-ui.log`、`panel-ss-all.log`、`panel-ss-race.log`、`panel-ss-vet.log`。本地产物为 `dist/go-local-20261107-panel-ss/`，无提交、推送或生产变更。

## 面板旧计量清理续迁（2026-11-07）

`internal/remote/legacy_meter.go` 原先无条件进入独立内核通道，导致面板旧绑定完成用户计量迁移后仍无法清理旧端口规则。现按服务器类型选择原生或面板通道，复用配置核验、操作互斥和精确规则删除流程。新增面板入口互斥及订阅迁移/清理回归；清理响应不明确时保存归属，随后可以重试。测试使用替身，不执行宿主机或生产 nftables。日志：`panel-meter-focused.log`、`panel-meter-retry.log`、`panel-meter-all.log`、`panel-meter-race.log`、`panel-meter-vet.log`。最新本地双架构包：`dist/go-local-20261107-panel-meter/`。

## 旧绑定迁移回执（2026-11-07）

修复迁移已持久化但 HTTP 响应丢失后原请求无法核对的问题。成功提交与回执同一次写入，绑定迁移后 generation；重复请求只返回本地完成状态，不调用远端或结算。通过重新实例化配置仓库模拟重启，覆盖认证计量连续结算、切换计数来源、面板保留旧规则及独立内核场景；另覆盖身份变化、错误 token、跨订阅、暂停和撤销拒绝。日志：`migration-receipt-focused.log`、`migration-receipt-all.log`、`migration-receipt-race.log`、`migration-receipt-vet.log`。包目录：`dist/go-local-20261107-migration-receipt/`。不代表剩余旧数据接管或整入站绑定已迁移。

## 旧用户计量登记恢复（2026-11-07）

旧绑定从入站计数切换为独立内核用户计数时，现先做本地唯一归属预检，再调用可重入的现有用户登记，不再因普通读取失败提前阻断登记日志恢复。登记必须存在原认证用户且匹配身份，不传入创建凭据。新增故障替身模拟远端写入后断连，重开仓库后成功迁移、不重复计费、原 YAML 不变；Xray/sing-box 用户缺失、身份变化和停用均拒绝。日志：`legacy-registration-focused.log`、`legacy-registration-guards.log`、`legacy-registration-all.log`、`legacy-registration-race.log`、`legacy-registration-vet.log`。本地包 `dist/go-local-20261107-legacy-registration/`。未进行实机故障验收，仍需独立环境。

## 现有用户登记适配层验收（2026-11-07）

上一轮控制器恢复测试使用整体后端替身，本轮进一步覆盖真实 `changeCoreUser` / `enableCoreStats` 调用链，只替换 SSH 与统计查询返回。两种状态分别验证：统计接口已经存在时登记旧用户，以及首次启用统计再登记旧用户。Xray/sing-box 均通过；sing-box 配置替换后断连与统计查询失败均保留日志，重新打开管理器后可完成。外部配置字节漂移拒绝覆盖，成功重复调用不再写远端配置，原凭据、唯一计量归属和无关托管元数据保留。

测试文件：`internal/remote/legacy_enrollment_recovery_test.go`、`internal/remote/core_stats_init_test.go`。日志：`enrollment-adapter-focused.log`、`enrollment-adapter-recovery.log`、`enrollment-adapter-race.log`、`enrollment-adapter-vet.log`。本轮没有改动运行时代码，因此没有重复生成安装包；最新运行时包仍为 `dist/go-local-20261107-legacy-registration/`。整入站绑定、无凭据旧资源接管、主备结果不明草稿取消等开发缺口保持未完成。

## 旧计量清理本地收尾（2026-11-07）

`ClearLegacyMeter` 现先完成绑定/其他旧所有者核验；若保留标记仍在，而持久化 meters 对象已明确移除目标登记，则只清除本地残留标记并返回 reconciled=true。其余情况仍走实时认证计数及远端确认清理。测试覆盖重开仓库、计数离线、登记仍在/目标 null/登记缺失/错误类型、无保留标记、撤销/待删除/错误 token/未确认/其他旧所有者，且历史费用不变、未重复发远端清理。日志 `meter-finalize-focused.log`、`meter-finalize-all.log`、`meter-finalize-race.log`、`meter-finalize-vet.log`；本地包 `dist/go-local-20261107-meter-finalize/`。未执行生产规则修改。

## 旧计量清理回执核验（2026-11-07）

修正上一轮仅凭 meters 缺项收尾的判断：远端确认后，删除 meters 项与保存 `goMeterCleared[inboundId]=port` 在同一次登记写入中提交。重复远端清理、订阅本地收尾要求 ID/端口匹配的回执；登记目标仍存在（含 null）不放行。已有登记但无回执仍可正常执行完整清理，登记已缺失且无回执则拒绝猜测结果。覆盖持久回执重启恢复、错端口/错 ID/缺失/异常回执、目标 null、订阅费用不变和失败不丢标记。日志 `meter-receipt-focused.log`、`meter-receipt-all.log`、`meter-receipt-race.log`、`meter-receipt-vet.log`；本地包 `dist/go-local-20261107-meter-receipt/`。本轮不涉及生产规则操作。

## 批量历史清理恢复保护（2026-11-07）

`CleanupBindings` 跳过仍有入站删除待核对或本地节点清理待完成标记的记录。控制器返回 retainedPending 历史记录数量，页面反馈保留数量。新增持久化重启测试，确认恢复依据保留、费用和 YAML 不变、恢复标记清除后可正常清理，且操作不调用远端。日志 `history-recovery-focused.log`、`history-recovery-ui.log`、`history-recovery-all.log`、`history-recovery-race.log`、`history-recovery-vet.log`；本地包 `dist/go-local-20261107-history-recovery/`。

## 旧限速回执与迁移衔接（2026-11-07）

新增 confirmedBandwidthClear 共用判断，SetBandwidth 清除重试及 MigrateLegacyBinding 使用明确持久回执同步本地残留速率。必须存在对象型 bandwidths 和 goBandwidthCleared、目标策略键不存在、回执端口匹配。测试包括重开仓库、远端清理不可用但可本地收尾、错误 ID/端口/空值/缺登记回执拒绝、费用保持以及完整旧绑定迁移。日志 `bandwidth-reconcile-focused.log`、`bandwidth-reconcile-all.log`、`bandwidth-reconcile-race.log`、`bandwidth-reconcile-vet.log`；本地包 `dist/go-local-20261107-bandwidth-reconcile/`。未执行生产限速修改。

## 旧迁移数据预检与原子收尾（2026-11-07）

严格校验显式 bandwidths/meters/bandwidth 对象及目标计量端口，防止类型断言失败静默绕过迁移前置条件；有清理回执的残留速率只在迁移成功的 settle 回调中更新，随归属和基线同一次提交。异常数据测试确认失败前不读取远端、不修改本地；原有带回执完整迁移测试增加归属冲突失败时原速率保留断言。日志 `migration-preflight-all.log`、`migration-preflight-race.log`、`migration-preflight-vet.log`；本地包 `dist/go-local-20261107-migration-preflight/`。未推送或部署。

## 旧限速清理归属核验（2026-11-07）

清除限速与设置限速现在共用归属检查，包含跨订阅活动/待创建/待删除绑定及同订阅冲突；即使有清理回执也先核验归属。已结束历史仍允许正常清理。日志 `bandwidth-ownership-all.log`、`bandwidth-ownership-race.log`、`bandwidth-ownership-vet.log`；本地包 `dist/go-local-20261107-bandwidth-ownership/`。整入站绑定、无凭据旧资源接管等主要缺口仍未完成。


## 旧转义分享链接兼容（2026-11-07）

2026-11-07（旧转义分享链接兼容）：补齐 Python parse_node_link 支持的外层成对引号和转义 URI 粘贴；单条、批量（含 Mieru 多端口）、Markdown 与文本/Base64 外部订阅统一识别。仅在 scheme 明确使用反斜杠转义时还原旧转义，普通 URI 与百分号编码凭据不改写；裸链接末尾单引号保留。新增导入保存分享、凭据保持、失败行号与多端口回归。此项为输入兼容，不增加高级传输或整入站生命周期能力。

验证记录：`escaped-paste-target.log`、`escaped-paste-all.log`、`escaped-paste-race.log`、`escaped-paste-vet.log`，位于工作区 artifacts。未执行真实远端生命周期操作；未推送、未部署。整入站绑定、无凭据旧资源接管、sing-box 传统 SS 隔离及未知结果草稿取消等主要缺口仍在。

本轮本地构建：`go-migration/dist/go-local-20261107-escaped-paste/`（仓库内路径为 `dist/go-local-20261107-escaped-paste/`），amd64 / arm64 归档及内部 SHA256 校验通过；最新可执行文件为工作区 `artifacts/mxioc`。


## 旧 QUIC 节点转 sing-box 中转（2026-11-07）

2026-11-07（旧 QUIC 节点转 sing-box 中转）：兼容 Python YAML 的隐式 TLS、servername 别名与 Hysteria2 的整数 Mbps 带单位速率。省略 TLS 仍生成启用 TLS 的配置，显式 false/null/错误类型继续拒绝；SNI 冲突或非字符串拒绝。速率支持正整数字符串、数值及 N Mbps，不四舍五入，不忽略异常字段；小数、其他单位、零/负数及溢出拒绝。新增旧 YAML 转换和输入不变测试，并使用真实 sing-box 1.14.4 验证 Hysteria2/TUIC 的 TCP、UDP、计量及撤销。

验证记录位于工作区 artifacts：`legacy-quic-target.log`、`legacy-quic-runtime.log`（UDP）、`legacy-quic-tcp-runtime.log`、`legacy-quic-all.log`、`legacy-quic-race.log`、`legacy-quic-vet.log`。此项兼容旧节点配置，不代表共用端口按用户限速；整入站绑定、旧资源接管、传统 SS 隔离、未知结果草稿取消仍未完成。仅本地保存，不推送、不部署。

本轮本地双架构包：仓库内 `dist/go-local-20261107-legacy-quic/`；归档及内部 SHA256 校验通过。最新可执行文件：工作区 `artifacts/mxioc`。


## HTTP/HTTPS 出站兼容（2026-11-07）

2026-11-07（HTTP/HTTPS 导入到中转及 Xray 主备导出）：修复 HTTP 解析器设置 udp=false 后被通用出站转换拒绝的问题。HTTP CONNECT 的 TCP-only 属性现在可转换到 Xray 与 sing-box；显式请求 HTTP UDP 仍拒绝，其他协议的 UDP 限制不放宽。保留未适配 headers/证书指纹及跳过证书验证的拒绝行为。新增 URI→出站认证/SNI/源数据不变测试、v2rayN/v2rayNG 主备导出测试；真实 Xray 26.10.31 和 sing-box 1.14.4 验证 HTTP/HTTPS CONNECT 成功，以及错误密码、不可信证书、错误 SNI 拒绝。

验证日志位于工作区 artifacts：`http-outbound-runtime.log`、`http-outbound-ha.log`、`http-outbound-all.log`、`http-outbound-race.log`、`http-outbound-vet.log`。本地内核回环测试不代表真实 SSH 面板部署已验收。整入站绑定、无凭据旧资源接管、传统 SS 隔离及未知结果草稿取消仍未完成；本轮未推送、未部署。

本轮双架构本地包：仓库内 `dist/go-local-20261107-http-outbound/`，归档及内部 SHA256 校验通过；工作区 `artifacts/mxioc` 已更新。


## sing-box 出站 UDP 策略兼容（2026-11-07）

2026-11-07（sing-box 出站 UDP 禁用）：旧节点 udp=false 现在映射为 sing-box 原生 network=tcp，支持 SOCKS5、SS、VMess、VLESS、Trojan、Hysteria2、TUIC；省略/true 保持默认。仅在 sing-box 转换的临时副本上绕开 Xray 无法表达此选项的检查，原始节点不改写，其他扩展和 TLS 检查仍执行；Xray 继续拒绝无法表达的 UDP 禁用。七协议 true/false 原生配置检查通过，SOCKS5 真实回环验证启用→禁用→再启用时 TCP 保持可用、禁用阶段无 UDP 到达目标。此项是旧节点 UDP 策略兼容补齐，不声称 Python 已有同等中转强制限制。

验证日志位于工作区 artifacts：`sing-udp-policy-runtime.log`、`sing-udp-policy-config.log`、`sing-udp-policy-all.log`、`sing-udp-policy-race.log`、`sing-udp-policy-vet.log`。实流量策略测试覆盖 SOCKS5，其余协议为原生配置及映射验证。整入站绑定、无凭据旧资源接管、传统 SS 隔离及未知结果草稿取消仍未完成；未推送、未部署。

本轮双架构本地包：仓库内 `dist/go-local-20261107-sing-udp-policy/`，归档及内部 SHA256 校验通过；工作区 `artifacts/mxioc` 已更新。


## 旧 Trojan 隐式 TLS 兼容（2026-11-07）

2026-11-07（旧 Trojan 隐式 TLS）：Python 分享链接解析生成的 Trojan 节点常省略 tls，Go 通用出站转换此前会生成 security=none 或拒绝带 SNI/ALPN 的旧节点。现在仅在 Trojan 的 tls 字段缺省时，使用副本补 TLS 默认值，供 Xray/sing-box 中转及 v2rayN/v2rayNG 主备导出使用；保留显式 false 的原有语义，null/错误类型及跳过校验仍拒绝，源节点不改写。真实内核覆盖 Trojan TCP/WS/gRPC（Xray 客户端到 Xray/sing-box 服务端），sing-box 同核另验证认证计量及撤销。

这是修复 Python 数据与客户端默认语义的衔接，同时修正旧 Python 出站转换同类缺陷，并非照搬其明文默认行为。日志位于工作区 artifacts：`trojan-implicit-target.log`、`trojan-implicit-runtime.log`、`trojan-implicit-ha.log`、`trojan-implicit-all.log`、`trojan-implicit-race.log`、`trojan-implicit-vet.log`。整入站绑定、无凭据旧资源接管、传统 SS 隔离及未知结果草稿取消仍未完成；未推送、未部署。

本轮双架构本地包：仓库内 `dist/go-local-20261107-trojan-tls/`，归档及内部 SHA256 校验通过；工作区 `artifacts/mxioc` 已更新。


## 旧 QUIC 单字符串 ALPN（2026-11-07）

2026-11-07（旧 QUIC 单字符串 ALPN）：兼容 Python 的 Hysteria2/TUIC alpn 单字符串写法，配置导入规范为数组，分享 URI 保留协议及顺序，sing-box 中转直接转换也做同样规范且不改源节点。修复分享导出仅接受 []any 导致字符串/[]string 静默丢失 ALPN；错误类型、空协议、控制字符、逗号和超过 255 字节的协议明确拒绝。保留空数组及未填写时原有默认行为。

验证日志位于工作区 artifacts：`quic-alpn-target.log`、`quic-alpn-runtime.log`、`quic-alpn-all.log`、`quic-alpn-race.log`、`quic-alpn-vet.log`。TUIC 无隐式 ALPN，实核夹具两端显式声明 h3 后测试客户端单字符串，不能以静默删除 ALPN 解决真实服务器不匹配。整入站绑定、无凭据旧资源接管、传统 SS 隔离及未知结果草稿取消仍未完成；未推送、未部署。

本轮 Hysteria2/TUIC 真实 TCP、UDP、认证计量及撤销测试通过。双架构本地包：仓库内 `dist/go-local-20261107-quic-alpn/`，归档及内部 SHA256 校验通过；工作区 `artifacts/mxioc` 已更新。


## 保留数据卸载失败回滚（2026-11-07）

2026-11-07（保留数据卸载失败回滚）：安装脚本在停止服务前保存 unit 权限、current 原始链接及 active/enabled 状态；停止、部分删除、daemon-reload 或可捕获终止失败时，在同一发布锁内恢复文件并按原状态恢复启用/运行。恢复失败明确报错并保留 .remove.* 中的 unit 副本，不假报成功。隔离测试覆盖五类故障与四种初始运行/启用组合，含 SIGTERM；已有成功卸载、版本变化拒绝及数据保留测试继续通过。

日志位于工作区 artifacts：`uninstall-rollback-target.log`、`uninstall-rollback-all.log`、`uninstall-rollback-race.log`、`uninstall-rollback-vet.log`。测试通过临时路径和 systemctl 替身执行脚本；未执行真实卸载或部署。SIGKILL/断电后的自动恢复及真实 systemd 验收不在本轮覆盖内；清空与 Python 共用数据的 purgeData 仍拒绝，不能视作此缺口已完成。整入站绑定、无凭据旧资源接管、传统 SS 隔离及未知结果草稿取消仍未完成。

本轮双架构本地包：仓库内 `dist/go-local-20261107-uninstall-rollback/`，归档及内部 SHA256 校验、安装脚本内容核对通过；工作区 `artifacts/mxioc` 已更新。未推送。
