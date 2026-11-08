# 历史记录：已被当前状态表取代

以下为收尾前的原始记录，不代表当前缺口。当前状态见上级目录 REMAINING.md。

# Go 全量迁移缺口表

核对日期：2026-11-06。此表记录交付缺口，不能以接口存在或单元测试通过代替实机验收。

当前仍有 **12 类未闭环事项**，不是 12 个小功能，也不能据此计算完成百分比。

- **7 类含开发缺口**：独立内核模板 / 编辑、缺凭证旧绑定迁移、旧中转与关联资源清理、结果不明的主备草稿取消、高级传输转换、共享入站单用户限速、接口契约与并发 / 故障验证。
- **5 类主要待验收**：独立内核安装、3x-ui 安装、总控 systemd 更新 / 卸载、正式发布与切换、远端服务器及客户端整链路。

本地真实 Xray 26.10.31 / Mihomo 1.19.33 内核已通过主备优先、故障接管、主入口恢复、全故障拒绝与恢复连通测试，确认无直连回退；使用临时 SOCKS 路径替身，不代表真实服务器转发链路或客户端 App 验收完成。可设置 `MXIOC_TEST_XRAY`、`MXIOC_TEST_MIHOMO` 后运行 `go test ./internal/subscriptions -run 'Test(Xray|Mihomo)HAFailoverRecoveryAndRejectWithRealCore' -count=1 -v` 复测。

| 模块 | 当前状态 | 尚需完成 |
| --- | --- | --- |
| 独立 Xray / sing-box 配置 | 已有整配置 SSH 读写、校验、回滚接口、旧托管入站只读列表与原生配置比对、核对通过后可查看连接及整配置托管入站保护、手工原生入站的新建、编辑和引用检查删除，以及 VMess TCP、VLESS / VMess TCP TLS、Trojan TLS、VLESS / VMess / Trojan WS TLS、VLESS / VMess / Trojan gRPC TLS、Xray XHTTP TLS（WS / XHTTP 模板创建可填写 Host）、Xray / sing-box Reality、Xray / sing-box Hysteria2 和 sing-box TUIC 托管创建与订阅绑定；已核对的托管入站支持改名、带重试的端口 / WS 路径和 Host / gRPC 服务名 / XHTTP 路径、模式和 Host 编辑、基础 TLS ALPN 创建与编辑、基础 TLS 的 TCP / WS / gRPC 传输互换及无用户入站的 VLESS / VMess / Trojan 协议互换（保留 WS Host 与受支持的自定义 ALPN）、删除和订阅节点清理，并在刷新及后台同步时按绑定身份清理手动删除的入站 | 其余托管模板、其他协议切换及高级传输配置编辑、其余配置映射及实机回滚 |
| 独立内核用户与计量 | 面板独立用户已实现；独立内核已有 StatsService、首次导入启用统计、到期撤销与月额度暂停恢复流程，以及认证用户旧绑定迁移。Xray / sing-box 均开放 SS2022 独立用户，Xray 另有传统 SS 三种 AEAD 独立用户模板；真实内核已验证独立计数与末用户撤销，sing-box 另外 12 组常用协议 / 传输也完成本地回归 | 缺少身份凭证的旧 SS / 其他绑定迁移、sing-box 传统 SS 的替代隔离方案、sing-box 1.14.4 → Xray 26.10.31 Reality 兼容、实机计量及 UDP 防火墙验收（本地同内核 Reality 与 HY2 / TUIC UDP 目标报文已通过） |
| 服务器中转 | Web 面板创建与带身份摘要的中转删除清理已接入，支持中断后继续清理，早期 Go 中转可依据创建记录恢复归属摘要，链式代理页可创建和删除已核对的独占链路，支持选择 sing-box Reality / VMess TCP 入口；独立 Xray 和 sing-box 支持 Reality 中转入口、落地出站及专属路由的原子写入、核对与删除，sing-box 支持 HY2 / TUIC 落地 | 缺少可信创建记录的旧中转迁移、限速 / 计量关联资源及实机验收 |
| 多入口主备 | 已支持固定出口的有序路径创建、保存草稿与继续创建，全部确认后激活；已激活主备组可逐路径删除并重试；可取消未下发或已确认路径的草稿，支持 Web 面板及独立 Xray / sing-box 入口，新增 sing-box Reality 协议选择并兼容旧草稿 | 直接取消已下发但结果不明的草稿（含 SSH 断开后仍运行的远端写入）、缺少归属的旧路径清理、客户端 App 与真实节点链路验收 |
| 高级客户端转换 | 通用链接（含 VMess gRPC、基础 VLESS XHTTP、ALPN 与 TLS 参数、Python 参数别名及 WS / gRPC 默认值兼容、HY2 / TUIC 内嵌证书与 SHA-256 指纹往返、HTTP(S) 代理请求头与证书校验参数、SOCKS5 UDP / TLS、Reality hybrid 开关、TUIC 查询参数密码和别名、HY2 用户信息密码、VMess Host 回退 SNI、无括号 IPv6 明确端口兼容、Markdown / 同行多链接提取）、Shadowsocks / SS2022 多用户连接读取及导出、小火箭主备配套导出、Xray 主备 JSON 已实现 | 其余高级传输参数、客户端 App 导入与真实节点链路切换验收 |
| 独立内核安装任务 | 已执行原生任务，最多两个并行，显示阶段时间线、脱敏日志与失败原因；sing-box 使用临时工具链构建带计量 / QUIC / uTLS 的固定版本，候选配置先验证，失败恢复旧二进制、配置与服务状态，首次安装无示例节点；隔离脚本失败测试已覆盖 | 真实 Linux systemd 安装、低内存 / 磁盘不足及中断恢复验证 |
| 3x-ui 面板安装 | 已接入安装任务、预设凭据登录、API 与 HTTPS 检查 | 完整 SSH / HTTP 联调与真实安装验收；X-ui / X-Panel 维持只接入已有面板 |
| 总控更新、卸载 | 已有命令行校验更新、服务检查、失败回滚及保留数据的卸载；新增面板保留数据卸载、账号复核、独立工作进程及版本核验，以及面板手动检查、定时检查、忽略版本；标准 Linux 安装可从面板确认更新，由独立 systemd 任务校验并应用发布包，保存跨重启状态 | 真实 systemd 流水线实际运行、清空数据卸载兼容及线上更新验收（生命周期脚本已接入卸载工作进程，尚未执行） |
| Go 正式安装器与发布 | 已有首次安装、现有数据预检、Linux 双架构打包与预发布工作流 | GitHub 预发布实际运行、线上正式切换及回滚验收 |
| 限速及计量资源清理 | 已有元数据保护及旧版专属入站的限速新增、修改和清理，以及切换到认证用户后的旧端口计量清理 | 共用入站单用户限速及实机验收 |
| 真实环境验收 | 本地 SSH / HTTP 替身与部分真实内核测试通过 | 实机硬件监控、Linux SNI 脚本、面板兼容、UDP 防火墙及客户端整链路 |
| 性能和接口对照 | 已有 AST 方法清单与入口覆盖、批量删除 / HEAD / 节点验证契约、已有连接与独立用户导入兼容、多订阅冷读写及取消回归 | 全部接口业务语义对照、整入站绑定兼容及原始新增的真实面板验收、更大规模性能与远端长任务故障验证 |

已迁移的认证、配置管理、普通订阅导出、策略组分流编辑、可复用策略模板、套餐、面板独立用户、二维码、Mieru 简单链接等不在此缺口表重复列出。详细实现边界见 [STATUS.md](STATUS.md)。

## 本轮边界补充（2026-11-06）

- `servers/import` 已支持核验后的非托管连接，以及已有独立用户入站的隔离用户导入；`servers/bind` 仍返回明确拒绝。旧版整入站绑定的计量、撤销及迁移必须一起实现，不能只补一个绑定记录。
- 缺少用户身份凭据或可信创建记录的旧绑定 / 中转不能自动猜测接管；需补充可验证的归属迁移方案。
- 已下发且结果不明的草稿仍保留待核对。SSH 断开不证明远端进程已停止，直接丢弃草稿会遗留资源；完整取消还需远端持久化取消屏障。
- 共用加密端口不能仅靠端口限速实现每用户限速，Python 原实现也拒绝该情形。此项需独立端口隔离或支持用户限速的内核方案，不能仅翻译原函数解决。
- 本地内核与竞态检查不能代替独立测试服务器上的安装、systemd 更新回滚及客户端 App 验收；现有生产服务没有被替换。

QUIC 默认参数兼容：HY2 补 h3、TUIC 补 bbr / native。TUIC 未指定 ALPN 时保留内核协商默认，不强制 Python 的 h3；真实 sing-box 回归曾确认强制补值会破坏现有默认入站握手。显式配置继续保留。

## 集中收尾核对

详见 [CLOSURE.md](CLOSURE.md)：区分实际 Python 漏迁、Go 扩展、旧数据证据缺失及外部验收。不能将本表的“其余模板”解读为 Python 还有无限数量的模板，也不能将本地测试通过解释为全量迁移完成。

## 原始面板入站新增（本轮续迁）

已补 POST `/admin/api/servers/inbounds` 的 `inbound` 对象及网页入口。保留配置和原认证凭据，不自动创建或绑定订阅用户；字段白名单、256 KiB 限制、显式端口冲突拒绝、加密持久创建意图、断连/重启后核对且不重放已发送请求均已接入。已确认记录的配置或凭据变化时拒绝复用。独立内核继续使用原生入站管理，不通过此面板接口写入。原始配置不走模板证书申请或 SNI 扫描，其证书、路径、协议配置需由管理员提供并在实际面板核验。此项不能代替整入站绑定。

## 面板单密码 Shadowsocks 模板（2026-11-07）

已补 Python 的 `shadowsocks` 模板在面板服务器上的新增 API 与网页表单：AES-128-GCM、服务端随机密码、TCP/UDP、自动/指定端口、加密持久记录和断连核对；真实 Xray TCP/UDP 转发通过。此路径为管理操作，返回 `bound=false`、`enforcementEnabled=false`，不会自动导入订阅。独立 sing-box 传统 SS 的隔离用户方案、整入站绑定以及真实 3x-ui 验收仍未完成，不能据此将 SS 整体标记完成。

## 面板旧端口计量清理（2026-11-07）

补齐面板服务器在旧绑定迁移后的计量规则清理通道，覆盖 3x-ui / X-ui / X-Panel。必须已切换到可核验的认证用户计数；缺计数或清理结果不明继续保留归属记录。此项只清理已有可信 meters 记录对应的规则，不自动接管缺凭据的旧 SS、不补整入站绑定。实际 nftables/SSH 故障验收仍待独立环境。

## 旧绑定迁移响应丢失恢复（2026-11-07）

已补成功迁移的持久回执：网页响应丢失后用原确认标识重试，重启后仍可返回成功，不重复计费或操作用户；回执限定原订阅及迁移后绑定身份，撤销/暂停/待删除时不复用。原来缺少凭据或可信归属的旧绑定仍不能自动接管，未下发成功的迁移仍需按实际远端状态核对。

## 旧用户计量登记中断恢复（2026-11-07）

已修复“远端计量配置写入后断连、普通读取因状态差异失败、迁移无法进入恢复流程”的调用顺序。先验证唯一归属，再进入既有登记日志核对，成功后建立新计数基线；不重建缺失用户、不接管变更凭据。此项补计量登记重试，不等于结果不明的主备草稿取消或整入站绑定已完成。

## 旧计量清理本地收尾恢复（2026-11-07）

已补远端确认清理且服务器登记已保存、但订阅标记保存失败的重试路径：显式 meters 对象不再含目标键时，可在认证计数离线情况下收尾。登记缺失或异常不作成功证据；目标键为 null 也不算已删除。仅更新残留标记，保留费用，不改变仍未完成的整入站绑定、无凭据旧资源接管等边界。

## 清理回执核验修正（2026-11-07）

上节的“meters 不含目标”条件已收紧：现在还必须有 `goMeterCleared` 中入站 ID 和端口均匹配的持久回执。登记缺项或 null 不是清理成功证据。回执只由确认远端清理的流程写入，不为历史缺回执记录自动补造；此类历史记录仍待核对。

## 历史清理保留恢复依据（2026-11-07）

批量清理失效绑定现保留远端入站删除待核对、本地节点清理待完成的记录，并反馈保留数量；完成恢复后可再清理。防止清理历史记录使已实现的重试流程丢失依据。单条显式移除仍是独立的放弃本地归属操作，未改变原语义。此项不表示未知结果主备草稿可取消，也不表示全量迁移完成。

## 旧限速清除后的迁移收尾（2026-11-07）

已补服务器限速清除回执与订阅残留速率的同步：明确 bandwidths 登记无目标项且 goBandwidthCleared 的入站 ID、端口匹配时，可本地完成清除重试，旧绑定迁移自动同步残留速率。无回执或仍有关联策略继续要求核验，不猜测旧状态。共用端口按用户限速、无凭据旧资源接管等主要缺口仍未实现。

## 旧迁移前置核验与原子收尾（2026-11-07）

显式存在的限速/计量登记必须是对象，错误类型不再当作没有记录；计量端口不匹配拒绝迁移。凭清理回执同步残留速率现在与成功迁移同一次提交，失败时不提前改本地速率。缺省字段兼容旧版记录，显式 null 或异常内容需先核对数据。

## 旧限速清理归属核验（2026-11-07）

清除限速与设置限速现在共用归属检查，包含跨订阅活动/待创建/待删除绑定及同订阅冲突；即使有清理回执也先核验归属。已结束历史仍允许正常清理。日志 `bandwidth-ownership-all.log`、`bandwidth-ownership-race.log`、`bandwidth-ownership-vet.log`；本地包 `dist/go-local-20261107-bandwidth-ownership/`。整入站绑定、无凭据旧资源接管等主要缺口仍未完成。


## 旧转义分享链接兼容（2026-11-07）

2026-11-07（旧转义分享链接兼容）：补齐 Python parse_node_link 支持的外层成对引号和转义 URI 粘贴；单条、批量（含 Mieru 多端口）、Markdown 与文本/Base64 外部订阅统一识别。仅在 scheme 明确使用反斜杠转义时还原旧转义，普通 URI 与百分号编码凭据不改写；裸链接末尾单引号保留。新增导入保存分享、凭据保持、失败行号与多端口回归。此项为输入兼容，不增加高级传输或整入站生命周期能力。

验证记录：`escaped-paste-target.log`、`escaped-paste-all.log`、`escaped-paste-race.log`、`escaped-paste-vet.log`，位于工作区 artifacts。未执行真实远端生命周期操作；未推送、未部署。整入站绑定、无凭据旧资源接管、sing-box 传统 SS 隔离及未知结果草稿取消等主要缺口仍在。


## 旧 QUIC 节点转 sing-box 中转（2026-11-07）

2026-11-07（旧 QUIC 节点转 sing-box 中转）：兼容 Python YAML 的隐式 TLS、servername 别名与 Hysteria2 的整数 Mbps 带单位速率。省略 TLS 仍生成启用 TLS 的配置，显式 false/null/错误类型继续拒绝；SNI 冲突或非字符串拒绝。速率支持正整数字符串、数值及 N Mbps，不四舍五入，不忽略异常字段；小数、其他单位、零/负数及溢出拒绝。新增旧 YAML 转换和输入不变测试，并使用真实 sing-box 1.14.4 验证 Hysteria2/TUIC 的 TCP、UDP、计量及撤销。

验证记录位于工作区 artifacts：`legacy-quic-target.log`、`legacy-quic-runtime.log`（UDP）、`legacy-quic-tcp-runtime.log`、`legacy-quic-all.log`、`legacy-quic-race.log`、`legacy-quic-vet.log`。此项兼容旧节点配置，不代表共用端口按用户限速；整入站绑定、旧资源接管、传统 SS 隔离、未知结果草稿取消仍未完成。仅本地保存，不推送、不部署。


## HTTP/HTTPS 出站兼容（2026-11-07）

2026-11-07（HTTP/HTTPS 导入到中转及 Xray 主备导出）：修复 HTTP 解析器设置 udp=false 后被通用出站转换拒绝的问题。HTTP CONNECT 的 TCP-only 属性现在可转换到 Xray 与 sing-box；显式请求 HTTP UDP 仍拒绝，其他协议的 UDP 限制不放宽。保留未适配 headers/证书指纹及跳过证书验证的拒绝行为。新增 URI→出站认证/SNI/源数据不变测试、v2rayN/v2rayNG 主备导出测试；真实 Xray 26.10.31 和 sing-box 1.14.4 验证 HTTP/HTTPS CONNECT 成功，以及错误密码、不可信证书、错误 SNI 拒绝。

验证日志位于工作区 artifacts：`http-outbound-runtime.log`、`http-outbound-ha.log`、`http-outbound-all.log`、`http-outbound-race.log`、`http-outbound-vet.log`。本地内核回环测试不代表真实 SSH 面板部署已验收。整入站绑定、无凭据旧资源接管、传统 SS 隔离及未知结果草稿取消仍未完成；本轮未推送、未部署。


## sing-box 出站 UDP 策略兼容（2026-11-07）

2026-11-07（sing-box 出站 UDP 禁用）：旧节点 udp=false 现在映射为 sing-box 原生 network=tcp，支持 SOCKS5、SS、VMess、VLESS、Trojan、Hysteria2、TUIC；省略/true 保持默认。仅在 sing-box 转换的临时副本上绕开 Xray 无法表达此选项的检查，原始节点不改写，其他扩展和 TLS 检查仍执行；Xray 继续拒绝无法表达的 UDP 禁用。七协议 true/false 原生配置检查通过，SOCKS5 真实回环验证启用→禁用→再启用时 TCP 保持可用、禁用阶段无 UDP 到达目标。此项是旧节点 UDP 策略兼容补齐，不声称 Python 已有同等中转强制限制。

验证日志位于工作区 artifacts：`sing-udp-policy-runtime.log`、`sing-udp-policy-config.log`、`sing-udp-policy-all.log`、`sing-udp-policy-race.log`、`sing-udp-policy-vet.log`。实流量策略测试覆盖 SOCKS5，其余协议为原生配置及映射验证。整入站绑定、无凭据旧资源接管、传统 SS 隔离及未知结果草稿取消仍未完成；未推送、未部署。


## 旧 Trojan 隐式 TLS 兼容（2026-11-07）

2026-11-07（旧 Trojan 隐式 TLS）：Python 分享链接解析生成的 Trojan 节点常省略 tls，Go 通用出站转换此前会生成 security=none 或拒绝带 SNI/ALPN 的旧节点。现在仅在 Trojan 的 tls 字段缺省时，使用副本补 TLS 默认值，供 Xray/sing-box 中转及 v2rayN/v2rayNG 主备导出使用；保留显式 false 的原有语义，null/错误类型及跳过校验仍拒绝，源节点不改写。真实内核覆盖 Trojan TCP/WS/gRPC（Xray 客户端到 Xray/sing-box 服务端），sing-box 同核另验证认证计量及撤销。

这是修复 Python 数据与客户端默认语义的衔接，同时修正旧 Python 出站转换同类缺陷，并非照搬其明文默认行为。日志位于工作区 artifacts：`trojan-implicit-target.log`、`trojan-implicit-runtime.log`、`trojan-implicit-ha.log`、`trojan-implicit-all.log`、`trojan-implicit-race.log`、`trojan-implicit-vet.log`。整入站绑定、无凭据旧资源接管、传统 SS 隔离及未知结果草稿取消仍未完成；未推送、未部署。


## 旧 QUIC 单字符串 ALPN（2026-11-07）

2026-11-07（旧 QUIC 单字符串 ALPN）：兼容 Python 的 Hysteria2/TUIC alpn 单字符串写法，配置导入规范为数组，分享 URI 保留协议及顺序，sing-box 中转直接转换也做同样规范且不改源节点。修复分享导出仅接受 []any 导致字符串/[]string 静默丢失 ALPN；错误类型、空协议、控制字符、逗号和超过 255 字节的协议明确拒绝。保留空数组及未填写时原有默认行为。

验证日志位于工作区 artifacts：`quic-alpn-target.log`、`quic-alpn-runtime.log`、`quic-alpn-all.log`、`quic-alpn-race.log`、`quic-alpn-vet.log`。TUIC 无隐式 ALPN，实核夹具两端显式声明 h3 后测试客户端单字符串，不能以静默删除 ALPN 解决真实服务器不匹配。整入站绑定、无凭据旧资源接管、传统 SS 隔离及未知结果草稿取消仍未完成；未推送、未部署。


## 保留数据卸载失败回滚（2026-11-07）

2026-11-07（保留数据卸载失败回滚）：安装脚本在停止服务前保存 unit 权限、current 原始链接及 active/enabled 状态；停止、部分删除、daemon-reload 或可捕获终止失败时，在同一发布锁内恢复文件并按原状态恢复启用/运行。恢复失败明确报错并保留 .remove.* 中的 unit 副本，不假报成功。隔离测试覆盖五类故障与四种初始运行/启用组合，含 SIGTERM；已有成功卸载、版本变化拒绝及数据保留测试继续通过。

日志位于工作区 artifacts：`uninstall-rollback-target.log`、`uninstall-rollback-all.log`、`uninstall-rollback-race.log`、`uninstall-rollback-vet.log`。测试通过临时路径和 systemctl 替身执行脚本；未执行真实卸载或部署。SIGKILL/断电后的自动恢复及真实 systemd 验收不在本轮覆盖内；清空与 Python 共用数据的 purgeData 仍拒绝，不能视作此缺口已完成。整入站绑定、无凭据旧资源接管、传统 SS 隔离及未知结果草稿取消仍未完成。
