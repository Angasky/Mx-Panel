# 本地集成交付核对（2026-11-07）

最新订阅索引优化及性能复测见 [INDEX-CACHE-20261108.md](INDEX-CACHE-20261108.md)，管理器本地包为 `dist/go-local-20261108-index-cache/`；历史测量与包名保留。

2026-11-08 更新：已制作并验证 Reality/Snell 本地兼容补丁，详情见 [CORE-COMPAT-20261108.md](CORE-COMPAT-20261108.md)。下方原版内核失败记录保留；修复需使用兼容内核，未部署或改变默认安装版本。

最新性能补齐、全量回归和新发现的 Snell 复用边界见 [PERFORMANCE-AUDIT.md](PERFORMANCE-AUDIT.md)。本轮本地包为 `dist/go-local-20261107-performance-audit/`；下方历史包名保留作审计记录。

代码位于 `vpn-manager-migration/go-migration/`，分支 `local/migration-continue`。Python 基线 `0869964`，Go 基线 `92ccd3e`。本轮及之前的未提交改动均保留，未提交、未推送、未部署，未停止或替换 Python 生产服务。

当前能力与尚未闭环事项见 [REMAINING.md](REMAINING.md)。本地实现、替身测试、真实回环内核测试、外部实机验收分别记录，不把本地测试等同于生产切换完成。旧核对记录保存在 [history](history/CLOSURE-before-20261107-final.md)。

## 已执行验证

日志均在工作区 `artifacts/`。

| 检查 | 证据 |
| --- | --- |
| 全量普通 Go 测试 | `final-all.log`（最终源码）；早期全量记录 `final-compat-tests.log` |
| 专属整入站套餐继承、小数限速、失败后重开重试、切换不限速 | `final-plans.log` |
| 全包竞态检测 | `final-race.log` |
| TLS 修正后远端包竞态复查 | `final-race-remote-recheck.log` |
| 限速展示字段与敏感恢复字段隔离，配置/订阅包竞态复查 | `final-bandwidth-display.log` |
| 静态检查 | `final-vet.log` |
| 管理界面 DOM 测试 | `final-ui.log`，包括专属整入站标签及不显示旧迁移按钮 |
| HTTP/HTTPS 真实连接 | `final-tls-native.log`，Xray/sing-box 成功、错误密码/证书/SNI 拒绝；sing-box 显式跳过校验成功；Xray 此选项在转换阶段拒绝 |
| 单密码 SS 真实 TCP/UDP | `final-single-ss-native.log`，Xray/sing-box 服务端，分享连接导出再解析后连接 |
| 双架构构建 | `final-build.log` |

首次全量真实内核回归 `final-all-native.log` 揭示 Xray 26.10.31 已删除 allowInsecure。已修正为明确拒绝，sing-box 独立映射为 insecure，保留这份失败证据。修正后全量真实内核回归已通过，记录为 `final-all-native-recheck.log`；之后限速展示字段修正由最终普通全量与配置/订阅竞态测试覆盖。

真实内核版本为 Xray 26.10.31、sing-box 1.14.4、Mihomo 1.19.33。使用临时目录和回环端口；系统安装/卸载及 nft 脚本只使用临时路径和命令替身，没有执行生产变更。默认真实内核测试不包含下述已知失败的 Reality 组合。

## 已知上游差异

sing-box 1.14.4 客户端连接 Xray 26.10.31 Reality 服务端失败。Xray 的 REALITY 依赖 `83f621788ca8` 要求 X25519MLKEM768 优先，而该 sing-box 版本主动移除该曲线和 key share。跨核专门复现开关是 `MXIOC_TEST_REALITY_CROSS_CORE=1`，测试 `TestXrayRealityAccountingAndRevocationWithRealCore`。未用关闭证书校验或信任 fallback 来伪装修复。

上游依据：

- https://github.com/XTLS/REALITY/blob/83f621788ca8/tls.go
- https://github.com/SagerNet/sing-box/blob/v1.14.4/common/tls/reality_client.go

Xray 26.10.31 另已删除 allowInsecure；旧 Python 节点若要求关闭证书校验，当前可由 sing-box 表达，Xray 转换明确返回错误，不能静默改变策略或输出无法启动的配置。

## 本地文件

- 源码：当前工作目录，包含全部新增未跟踪文件与修改。
- 双架构发布包：`dist/go-local-20261107-install-recovery/`，Linux amd64 / arm64，附 SHA256SUMS；只是本地版本名，不代表所有外部验收已经完成。
- 包内包含程序、网页、service、安装脚本、版本与架构标识；未执行安装脚本。
- 最终校验记录：`artifacts/final-package-check.log`。

外部实机验收、旧面板未知结果请求的终止确认和兼容 Reality 内核组合仍未完成；完全无证据的旧资源不自动接管。完整边界列表见 REMAINING.md。

## 后续安装恢复与兼容核核验

Xray 安装现固定 26.10.31，官方包 SHA256：amd64 `e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214`，arm64 `1811c8f1da0c3b6dc707ebaf1c8390e987ba39859a8f0a7aadd8526157f2ec8d`。摘要取自同版本官方 `.zip.dgst`；amd64 下载实物已复核。保留旧 unit 和原有地理数据，先检查配置再替换程序；首次使用空入站配置，不加载示例用户。既有配置若依赖缺失资源会在替换前失败，不静默丢弃字段。

两核安装均覆盖成功、校验/解包或构建失败、配置失败、服务失败、初始停用、SIGTERM、回滚失败；回滚失败保留原始恢复副本，SIGKILL/掉电和真实 systemd 仍需外部验收。日志 `install-both-rollback.log`；最终普通全量 `install-closure-all.log`，远端包 race `install-closure-race.log`，vet `install-closure-vet.log`，界面 `install-closure-ui.log`。

跨核 Reality：sing-box 1.14.4 → Xray 26.4.25 已通过真实请求、双用户计量、暂停恢复和撤销。日志 `reality-compatible-26.4.25-recheck.log`。旧版 Freedom 回环放行字段为 `ipsBlocked`，复测仅在测试夹具使用 `MXIOC_TEST_XRAY_LEGACY_FREEDOM=1`；不改变任何生产出站策略。另设 `MXIOC_TEST_REALITY_CROSS_CORE=1` 并指定两个内核路径运行 `TestXrayRealityAccountingAndRevocationWithRealCore`。26.9.30 和 26.7.28 仍握手失败，保留对应日志。旧版并非全协议推荐，默认安装版本未降级。

后续双架构包为 `dist/go-local-20261107-install-recovery/`；构建日志 `install-closure-build.log`，包校验 `install-closure-package-check.log`。未部署或推送。

## 批量主备取消的持久屏障补齐

此前第一条远端路径失败会导致后续路径尚未登记取消。现在先校验整批 operation ID，再逐条持久登记取消/未发送请求 tombstone，完成全部本地屏障后才开始远端核对。测试覆盖首条离线、重启后三条路径均保持取消标记、迟到本地创建拒绝，以及整批包含无效 ID 时不落盘。已有双核取消/断连清理、面板迟到结果核对继续通过。此修正不把结果不明的远端面板请求当作已经终止。

证据：`cancel-batch-fence.log`、`batch-cancel-all.log`、`batch-cancel-race.log`、`batch-cancel-vet.log`。最新本地包 `dist/go-local-20261107-batch-cancel/`；构建与校验日志 `batch-cancel-build.log`、`batch-cancel-package-check.log`。旧包保留，均未部署。

## 旧数值参数兼容补齐

sing-box 非 QUIC 中转此前校验字符串端口后仍原样输出，导致内核拒绝；现在输出规范整数，保留源节点不变。八协议 × 三种端口表示的真实 sing-box 配置检查通过，错误类型、越界和小数端口继续拒绝，证据 `legacy-port-native.log`。

Python 套餐 `rate_kbps` 支持字符串小数，Go 现仅对 speedMbps 增加相同输入兼容，验证后保存为 JSON 数字；普通额度/价格类型要求不变。控制器前置检查统一使用精确 Kbps 解析，错误不再被忽略；共用用户拒绝非零速率，专属整入站继承字符串小数速率、重试和清除有覆盖。全量回归 `numeric-compat-all.log`，配置/远端/订阅 race `numeric-compat-race.log`，vet `numeric-compat-vet.log`。最新本地包 `dist/go-local-20261107-numeric-compat/`，未推送或部署；既有外部验收与历史未知结果边界未改变。

## 批量取消原子落盘及并发验证

批量取消进一步改为同一互斥锁内准备整批日志，核验通过后一次原子替换；容量不足、后续记录归属错误不再留下部分取消记录。取消与面板创建登记竞争时，先创建则记录取消意图，先取消则拒绝后续登记，不丢失取消标记。重复 ID 和重试保持幂等；原有远端结果未知边界不变。

验证日志：`cancel-atomic-focused.log`、`cancel-atomic-concurrent.log`（20 次并发竞争，race）、`cancel-atomic-all.log`、`cancel-atomic-race.log`、`cancel-atomic-vet.log`。最新包：`dist/go-local-20261107-atomic-cancel/`，本地保存，未推送或部署。

## HTTP 代理请求头到 sing-box 中转

HTTP/HTTPS 节点的 headers 现可转换为 sing-box 原生请求头，覆盖旧链接 Host/User-Agent 和普通字符串自定义头；转换复制对象，不改源节点。名称规范化并拒绝大小写重复、非法名称、控制字符、错误类型和过长内容；认证与连接控制字段不允许覆盖内核行为。Xray 仍明确拒绝未适配的 headers，不静默丢弃。

真实 Xray/sing-box CONNECT 回归通过，sing-box 的 HTTP 和 HTTPS 场景均验证 User-Agent/X-Legacy-Route 到达代理，代理认证仍有效；错误密码、证书、SNI 继续拒绝。Host 映射另有导入转换单元测试，未声称独立验证所有 HTTP 代理的 Host 路由语义。

证据：`http-headers-native.log`、`http-headers-all.log`、`http-headers-race.log`、`http-headers-vet.log`。最新本地双架构包 `dist/go-local-20261107-http-headers/`；未推送、未部署。既有 REMAINING.md 中的远端未知结果和实机验收边界仍在。

## Reality SNI 别名与 TLS ALPN 转换补齐

通用出站此前 Reality 只取 servername，现兼容旧节点 sni，并拒绝两字段冲突及非字符串/控制字符输入，适用于 Xray 与 sing-box 中转。普通 TLS 的 ALPN 复用统一协议列表验证，支持 []string/JSON 数组，拒绝空协议、控制字符、逗号和超长项；转换结果不引用原数组。Reality 的 ALPN 不扩展支持。

验证：`tls-alias-all.log`、`tls-alias-race.log`、`tls-alias-vet.log`；真实内核 `tls-alias-native.log`，第二个 Reality 用户显式仅保留 sni，测试独立计量及撤销。该验证使用 Xray 同核、sing-box 同核，不将已知失败的新版跨核组合标记通过。最新本地包 `dist/go-local-20261107-tls-alias/`，未推送、未部署。

## Xray HTTP 请求头及主备导出补齐

核对 Xray 26.10.31 的 HTTPClientConfig.Headers 和实际 CONNECT 实现后，开放普通 HTTP/HTTPS 请求头映射。Xray 把头值视为 Go 模板执行，转换器将导入字符串包装为模板字面常量，防止 `{{.Target}}` 等内容被意外插值。自定义 Host 在该实现中不会覆盖 Request.Host，因此仍明确拒绝；sing-box 原有 Host 支持保持不变。认证与连接控制头继续禁止覆盖。

Xray/sing-box HTTP 与 HTTPS 真实 CONNECT 均验证自定义头和字面花括号原样到达，错误密码、证书、SNI 拒绝；v2rayN/v2rayNG 主备导出保留普通头、保留认证、通过真实 Xray 配置检查，包含不支持 Host 的组仍整体拒绝。日志 `xray-http-headers-native.log`、`xray-http-headers-ha.log`、`xray-http-headers-all.log`、`xray-http-headers-race.log`、`xray-http-headers-vet.log`。

最新双架构本地包 `dist/go-local-20261107-xray-http-headers/`，构建/校验日志 `xray-http-headers-build.log`、`xray-http-headers-package-check.log`。只保存本地，未部署或推送；既有远端未知结果、跨核 Reality 和外部验收边界未改变。

## Python TUIC 默认行为与混淆参数迁移

Python core_adapter.sing_quic_outbound 对缺省 TUIC 拥塞控制使用 bbr、UDP 模式使用 native。此前 Go 省略拥塞字段会触发 sing-box 原生 cubic 默认值；现显式保留 Python 默认，同时支持 bbr/cubic/new_reno 和 native/quic 的显式选择。null、错误类型、空或未知枚举拒绝，不默默改成原生默认。Hysteria2 仅接受 salamander 与非空字符串混淆密码；孤立 obfs-password 不再被忽略。源节点不修改。

证据：`quic-defaults-native.log`（真实 HY2/TUIC UDP、独立计量、撤销及默认缺省节点）；`quic-defaults-tcp.log`（真实 TUIC TCP）；`quic-defaults-all.log`、`quic-defaults-race.log`、`quic-defaults-vet.log`。最新本地包 `dist/go-local-20261107-quic-defaults/`，未推送、未部署。既有跨核兼容和外部验收边界不变。

## 持续迁移审计批次（2026-11-07，本批不代表完整关闭）

本批补齐主备流量/到期说明、Snell 统一校验和无损分享保护、畸形归属证据拒绝清理；监控边界和 Mieru 已补逐行为证据。详见 [BEHAVIOR-REVIEW.md](BEHAVIOR-REVIEW.md)。

验证：`goal-geo-parity.log`、`goal-client-snell.log`、`goal-monitor-audit.log`、`goal-snell-normalize.log`、`goal-ownership.log`、`goal-snell-mieru-native.log`、`goal-behavior-race.log`、`goal-behavior-vet.log`。全量竞态通过后新增的归属防护另经 `goal-ownership.log` 竞态验证。真实 Mihomo 检查的是加载配置，不是远端握手。

本地交付：`dist/go-local-20261107-behavior-audit/`，两架构外层/内层 SHA256、HTML 一致性和 amd64 `--help` 均通过；`../artifacts/mxioc` 已更新。构建与校验日志 `goal-behavior-build.log`、`goal-behavior-package-check.log`。未运行安装、未提交或推送、未操作生产 Python。

继续项：bandwidth.py 的六个行为需补数值语法边界及脚本真实分阶段失败证据；core_adapter/shared_users/panel_user_runtime/remote_manager/server 的入口仍需完整逐项审计。目标保持 active。

## 持续行为审计：认证、索引与面板契约（2026-11-07）

最新已校验本地包为 `dist/go-local-20261107-auth-profile/`，Linux amd64/arm64；`artifacts/mxioc` 已更新为该包 amd64 程序。构建 `goal-auth-profile-build.log`，外层/包内 SHA256、网页一致性与 amd64 --help 校验 `goal-auth-profile-package-check.log`；未安装、提交或推送。

此包包括此前精确十进制、限速/内核脚本故障测试、用户列表校验、IDNA/面板地址、主备排序与自动分组、URL 转义 Base64 兼容，以及本批旧密码哈希升级、Unicode 账号规则、持久化登录事务、启动时旧订阅索引迁移、安装日志脱敏及面板入站列表契约修复。逐项差异与证据见 BEHAVIOR-REVIEW.md。

普通全量 `goal-auth-profile-all.log` 已通过；之后启动迁移位置改为 RunBackground，确保 --check-data 不写文件，并补只读回归测试。静态检查 `goal-auth-profile-vet.log`、DOM 冒烟 `goal-auth-profile-ui.log` 通过；最终配置/远端/Web 竞态检查 `goal-auth-profile-race.log` 以实际结束结果为准。此包仅为持续工作的本地检查点，不代表完整迁移或外部验收完成。

## 备份、导入与月度计费续补

最新已校验本地包更新为 `dist/go-local-20261107-policy-parity/`，已校验外层与包内摘要、网页一致性、amd64 --help，artifacts/mxioc 同步；日志 `goal-policy-final-build.log`、`goal-policy-final-package-check.log`。本批增加成功保存后全局 100 份备份保留、恢复拒绝链接、订阅导入内置动作名称保护、批量链接导入默认/别名/重命名/名称返回，以及未强制限制月套餐重置与后台唤醒。

最终全量 `goal-policy-final-all.log`、vet `goal-policy-final-vet.log` 已通过；配置/订阅竞态 `goal-backup-retention-race.log`、批量/认证头针对性竞态 `goal-import-bearer-race.log`、最终订阅全包竞态 `goal-policy-wake-final-race.log` 通过。网页未改，沿用本批之前的 `goal-auth-profile-ui.log`。之前全配置/远端/Web 竞态 `goal-auth-profile-race.log` 已完整结束并通过。最终包未部署、未推送，剩余行为审计与实机边界仍不算完成。

## 服务器保存/移除互斥与操作兼容续补

最新本地双架构包 `dist/go-local-20261107-server-serialization/` 已构建并校验；外层/内层摘要、网页一致性及 amd64 --help 见 `goal-server-serialization-package-check.log`，artifacts/mxioc 已同步。新增服务器保存/移除与尚未登记绑定的首次创建共享服务器锁，修复检查和写入之间的窗口；另补批量删除 trim/原列表返回顺序、任意整数规则移动偏移，以及诊断日志凭据字段脱敏和 UTF-8 截断。

证据：订阅全包竞态 `goal-server-save-race.log`、`goal-forget-creation-race.log`；配置竞态 `goal-rule-offset-race.log`；日志针对性竞态 `goal-diagnostic-final-race.log`；Web 回归 `goal-server-save-web.log`；最终全量 `goal-server-serialization-all.log`、vet `goal-server-serialization-vet.log`。仍只保存本地，完整目标继续，外部验收未完成。

## 历史数据完整性和套餐小数最终校验

全量 goal-legacy-decimal-final-all.log、vet goal-legacy-decimal-final-vet.log 通过；构建 goal-legacy-integrity-build.log，内外校验 goal-legacy-integrity-package-check.log 通过，对应 go-local-20261107-legacy-integrity 双架构本地包。包校验首次引用了不存在的 templates/index.html，改为仓库实际 index.html 后重新完整校验通过；没有把首次校验失败当成成功。amd64 帮助启动通过，已同步 artifacts/mxioc。随后继续修改的规则/入站等行为需后续包覆盖。

## 规则、排序、入站账号、模板和任务展示最终校验

最新本地产物 `dist/go-local-20261107-template-job/`，覆盖规则显式空字段/逗号空匹配拒绝、provider-only 策略组排序保留、HTTP/SOCKS 畸形账号拒绝匿名导出、多文档 YAML 模板拒绝、安装任务按当前类型显示。

- 最终全量：`goal-template-job-final-all.log`。
- 配置包竞态：`goal-template-edit-final-race.log`（包含模板与规则最终代码）。
- 远端包竞态：`goal-template-job-final-race.log`（包含任务展示最终代码）。
- 最终静态检查：`goal-template-job-final-vet.log`。
- 双架构构建：`goal-template-job-build.log`。
- 包检查：`goal-template-job-package-check.log`；外层及内部 SHA256、界面及安装脚本与源码一致、amd64 帮助启动通过；artifacts/mxioc 同步为本包。

上述检查均通过。没有安装、部署、提交或推送；未执行真实 SSH/面板/systemd 变更。既有跨核 Reality 不兼容及外部验收边界仍保留。中间 edit-inbound 包未执行完整包校验，不将其作为本批交付依据。

## 注册表完整性与退出等待（2026-11-07）

最新本地包 `dist/go-local-20261107-registry-shutdown/` 已通过双架构内外 SHA256、HTML/安装脚本一致性、amd64 帮助启动检查，artifacts/mxioc 已同步。额外使用临时目录和回环随机端口验证 SIGTERM/SIGINT 正常退出，未执行部署脚本或改变现有服务。

证据：全量 `goal-registry-shutdown-final-all.log`；其后模板索引校验的 config/web/subscriptions 回归 `goal-template-registry-final.log`；配置/远端/订阅竞态 `goal-registry-shutdown-race.log` 及最终模板索引 `goal-template-registry-race.log`；原失败 Web 场景 20 次竞态 `goal-web-shutdown-repeat.log`；最终静态检查 `goal-registry-shutdown-final-vet.log`；构建 `goal-registry-shutdown-build.log`；包与进程退出 `goal-registry-shutdown-package-check.log`。首次全量临时目录清理竞争的失败日志 `goal-registry-transaction-all.log` 保留，修正退出等待后已通过。

范围与剩余限制见 BEHAVIOR-REVIEW 和 REMAINING，未标记全部迁移完成；未提交、未推送、未部署。

## 本批最终包（含证书错误过滤）

最终源码全量测试 `goal-registry-cert-final-all.log`、vet `goal-registry-cert-final-vet.log` 通过；最后证书改动竞态 `goal-certificate-error-race.log` 通过。双架构最终包 `dist/go-local-20261107-registry-cert/`，构建 `goal-registry-cert-build.log`、内外校验与帮助启动 `goal-registry-cert-package-check.log` 通过，artifacts/mxioc 同步更新。此前 registry-shutdown 的隔离 SIGTERM/SIGINT 验证仍适用，最后修改仅涉及证书错误展示，未改退出逻辑。未提交、推送、部署。
