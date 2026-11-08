# Python 行为逐项复核

最新订阅索引优化及性能复测见 [INDEX-CACHE-20261108.md](INDEX-CACHE-20261108.md)，管理器本地包为 `dist/go-local-20261108-index-cache/`；历史测量与包名保留。

2026-11-08 更新：已制作并验证 Reality/Snell 本地兼容补丁，详情见 [CORE-COMPAT-20261108.md](CORE-COMPAT-20261108.md)。下方原版内核失败记录保留；修复需使用兼容内核，未部署或改变默认安装版本。

最新性能补齐、全量回归和新发现的 Snell 复用边界见 [PERFORMANCE-AUDIT.md](PERFORMANCE-AUDIT.md)。本轮本地包为 `dist/go-local-20261107-performance-audit/`；下方历史包名保留作审计记录。

基线和完整入口见 [ACCEPTANCE-MATRIX.md](ACCEPTANCE-MATRIX.md)。本表只记录已经读取原实现并核对的行为，不把未检查项推定为完成。

## server_monitor.py

| 入口 | Go 实现与证据 | 结论 |
| --- | --- | --- |
| derive_metrics | remote/metrics.go:deriveHostMetrics；TestMetricsParsingAndDeltas、TestMetricsHotplugAndIntervalBoundary、TestMetricsOverflowIsUnknownAndFailureRecovers | 同启动且 0 < 间隔 <= 60；CPU/网络增量、热插拔未知值、回退、首次预热一致。Go uint64 汇总溢出返回未知，Python 任意精度整数可继续汇总；不是按零显示。Go 四舍五入与 Python ties-to-even 的半值舍入仍有显示差异 |
| HostMonitor.__init__ | hostMonitor/metricEntry；TestMetricsCacheCoalescingFailuresAndIsolation | 固定 5 秒 TTL、128 项缓存、互斥锁；Python 可注入 TTL/clock，Go 当前内部固定；无用户配置入口缺失 |
| HostMonitor.sample | Manager.Metrics、hostMonitor.sample、metricView；上述缓存测试及失败恢复测试 | 缓存深复制、失败保留 stale、失败缓存、恢复清除错误、15 秒采样超时；Go 并发刷新立即返回 stale/繁忙，Python 最多等 1 秒。Go 连接及名称变更隔离缓存；Python 名称未入 key |
| REMOTE_SAMPLE（模块常量，随 sample 审计） | hostSampleScript、parseHostSample；TestHostSampleScriptOnLinux、TestMetricsRejectBrokenSamples | 不依赖远端 Python，直接读 /proc。Go 要求默认路由 UP 位；磁盘使用本地 df 而非所有 mount 的 statvfs，网络文件系统和部分 overlay 显示有差异。缺 ip 工具可降级；真实 SSH 环境未验收 |

本轮监控竞态测试：`../artifacts/goal-monitor-audit.log`。没有声称远端所有发行版采样等价。

## client_adapter.py

| 入口 | Go 实现与证据 | 结论 |
| --- | --- | --- |
| usage_nodes | subscriptions/export.go:usageNodes；TestClientExportFilteringSnellPasswordAndUsageNodes、TestUsageNodesIndependentRemaining | 三个回环信息节点；已修复 remaining 与 total 错误关联。Go 计量字段使用整数；到期时间以秒保存 |
| usage_label | subscriptions/export.go:usageLabel；TestHAExportsIncludePythonUsageLabel | 本轮补齐 B/KiB/MiB/GiB/TiB、无限额、长期、UTC 到期说明，接入两种 Xray 主备 remarks 和 Shadowrocket 配置注释 |
| shadowrocket_name | subscriptions/shadowrocket.go:shadowrocketName；TestRocketPairedExportsPreserveOrderCredentialsAndScope | SHA256 命名空间、控制字符替换、64 Unicode 字符截断已核对；Python 固定向量一致 |
| managed_failovers | managedHAGroups；TestRocketInvalidPathRejectsWholeGroup | 顺序、状态、唯一性、有效绑定、同出口、独立路径一致；Go 额外拒绝重复组件名及空出口，避免歧义 |
| shadowrocket_config | convertRocketHA；上述配对导出和使用量测试 | fallback 固定顺序、间隔、拒绝不支持 UDP、FINAL 选择组及命名空间；已补流量注释。未运行真实 App |
| xray_failover | subscriptions/xray.go:xrayFailover、convertXrayHA | 2–8 路径、逐阶段 balancer/loopback、全失败 blackhole、观测与端口已对照；已有主备测试，本轮补 remarks。底层协议和实际故障切换证据需继续逐项关联 |
| xray_path | remote.NodeOutbound | 转换器复用；此前 TLS/HTTP/QUIC 回归覆盖部分参数。逐项扩展拒绝与 Python 差异仍需继续复核，不能标为全量等价 |

本轮客户端及 Snell 回归：`../artifacts/goal-client-snell.log`。

## mieru_adapter.py

| 入口 | Go 实现与证据 | 结论 |
| --- | --- | --- |
| validate | links.NormalizeMieru；TestMieruNormalizationAndLossyShareRefusal | 端口/范围互斥、枚举、凭据字节上限、默认 MTU 移除、UDP 布尔和 Base64 已逐段核对；Go 保留未知 YAML 扩展但分享拒绝 |
| parse_nodes | links.parseMieru/ParseMany；TestMieruPythonVectorsAndRoundTrips、TestMieruRejectsInvalidOptionsWithoutLeakingCredentials | 多组一一对应、上限 256、profile、选项、Unicode 名称、IPv6、凭据及规范化已有 Python 向量；Go 额外拒绝未知查询参数和无效 UTF-8，避免静默丢参 |
| to_uri | links.exportMieru；上述往返测试 | 用户密码转义、IPv6、端口范围、协议及选项保留，关闭 UDP 拒绝；Go 额外拒绝链接无法承载的 YAML 扩展、过长名称和链接。真实 Mieru 服务端通信仍缺证据 |

## snell_adapter.py

`parse` 与 `parse_policy` 已发现并修复：认证段/查询 PSK 冲突、密码式认证、空或非单数字版本、孤立混淆 Host、未知协议参数、低版本 UDP/reuse、大小写布尔兼容，以及先分 fragment 再分 query。新测试 `TestSnellURIRejectsConflictingOrLossyParameters`。高级混淆验证、分享无损边界与真实内核仍需继续逐项核对，整个模块尚未验收完成。

### Snell 后续补齐

新增 `links.NormalizeSnell` 并统一接入 `links.Parse`、`links.Export`、`config.ValidateNode`，对应 Python `validate`：PSK 字节上限、版本、UDP/reuse/tfo 类型、空混淆删除、域名规范化、ShadowTLS 版本/ALPN、Restls version-hint、JLS 用户名。`to_uri` 的完整顶层和混淆字段白名单已补齐，未知字段留在 YAML 中，禁止通过分享丢失。测试：`TestSnellAdvancedObfuscationValidationAndLosslessExport`、`TestSnellMalformedOptionsAndUnknownExportFields`、`TestSnellEditingUsesCompleteValidation`。

使用 `golang.org/x/net/idna` 的 Lookup profile 处理国际域名，新增 x/net v0.60.0 和间接 x/text v0.43.0；保留原 x/crypto v0.58.0。该 IDNA profile 与 Python 内置 IDNA2003 对部分字符（例如 ß）的映射存在差异，不能声称逐字符相同。

真实 Mihomo 1.19.33 的 `-t` 已验证无混淆、http、tls、shadow-tls、restls、jls 六种 Snell v5 配置，以及 Mieru TCP/UDP × 单端口/范围四种配置：`../artifacts/goal-snell-mieru-native.log`。这证明配置可加载，不证明真实远端握手或 UDP 通信。Snell 默认名称仍使用 Go 的主机:端口，Python 使用“导入的 Snell 节点”；查询顺序和 tfo 布尔编码在链接字符串上不同，语义相同。

## managed_nodes.py

| 入口 | Go 实现与证据 | 结论 |
| --- | --- | --- |
| node_identity | managednodes.Identity；TestPythonCompatibleIdentityAndLegacyUserProof | 字段顺序、版本前缀、UTF-8 长度和 SHA256 与已有 Python 向量一致；合法规范化节点适用。Python 对非法 false/0 字段按空字符串处理，Go 对非法字段的格式化不同，不据此授权接管 |
| references | config/ownership.go、config/legacy_binding.go 生成 importedNodes | 保存名称和 Identity；更名不改变凭据归属 |
| owns_node | managednodes.Owns；TestMalformedReferencesNeverAuthorizeLegacyCleanup、TestLegacyOwnershipAllSupportedCredentials | 有引用时只凭 identity，无引用才按旧用户端口/email/凭据/flow 验证；五协议及 HY2 auth 兼容有测试。本轮修复非数组 importedNodes 意外进入旧凭据回退；畸形记录一律拒绝授权 |

证据：`../artifacts/goal-ownership.log`。这里只核对本地归属，不等于远端生命周期全部验收。

## bandwidth.py（初步复核，未关闭）

`policy` 对照 `remote.bandwidthProtocols`；`rules` 对照 `legacyBandwidthRules`，现有 `TestLegacyBandwidthRendererMatchesPythonAndClearRetries` 验证文本和数字排序。Go 额外接受 Xray raw 网络名和 hysteria 类型。`scaled_number`/`multiplier_units`/`rate_kbps` 分散在 billing/config/subscriptions，仍需集中校验边界；Go big.Rat 与 Python Decimal 接受的字符串语法并不完全相同。

`apply_script` 已逐段读取。Go 使用旧/新规则一致性核对、命名空间规范化、事务和回执重试；Python 出错尝试回滚，Go 当前不执行同样的回滚流程。必须继续对限速脚本执行分阶段失败测试，明确重试、重启和持久文件行为；现有 Go runner 替身主要验证确认/重试，不能替代脚本本身的故障执行证据。

### 带宽数值与脚本执行补验

新增 `billing.ScaledDecimal`/`BandwidthKbps`，接口与套餐限速共用精确十进制解析。支持 Python 原有字符串、正号、空白、小数尾零、科学计数法和下划线数字；拒绝 big.Rat 原先误接受的分数与十六进制。保留 0.1–10000 Mbps 端口策略、0–100 倍率、千分精度，并限制 256 字符和 ±256 指数以避免不受控分配（此极端输入限制不同于 Python Decimal）。`TestPythonDecimalBandwidthAndMultiplier`、`TestBandwidthRatePythonNumericRepresentations` 和套餐回归通过；证据 `goal-decimal-race-recheck.log`。首次构建发现遗留未使用 import，已移除并复测。

新增真实 shell 执行测试 `TestBandwidthScriptFailureAndRetry`，仅替换临时路径及 nft/systemctl/unshare/mv 命令，不操作本机服务或网络。11 个场景覆盖首次成功、检查/启用/应用/持久化失败、外来规则拒绝、已有规则更新的相同故障、持久化失败后模拟重启。验证无假成功、旧/新状态核对、同请求重试收敛。证据 `goal-bandwidth-script-expanded.log`。模拟重启仅重新加载持久文件，不是实际 systemd 重启；nft 语法/事务仍需实机环境。Go 保留可核对的失败状态并重试，不等同于 Python 自动回滚。

## shared_users.py

| 入口 | Go 对照与证据 | 结论 |
| --- | --- | --- |
| settings | remote.userSettings | 对象或 JSON 字符串解码；本轮补齐 clients 非数组/非对象记录拒绝，避免 namespace 检查当作空列表。TestMalformedPeerListsCannotBypassUserNamespaceChecks |
| digest | canonicalJSON、identity | Python 排序紧凑 JSON、Unicode、浮点格式已有兼容实现；超范围整数和深度拒绝是明确边界 |
| endpoint_identity | EndpointIdentity；TestPythonOwnershipHashesRemainCompatible | 原六字段身份一致；Go 的受管 SS 增加显式 guard，与原协议隔离 |
| user_identity | UserIdentity；上述 hash 测试 | id/password/email/flow，存在 auth 时纳入；字段非法类型不作为正常输入保证 |
| find_user | FindUser；TestUserIdentityRejectsReusedInboundAndSharedCredentials | 先核对入站，再唯一 email/hash/凭据；missingOK 仅允许缺用户；专属绑定额外拒绝新增其他用户 |
| check_email_namespace | CheckEmailNamespace、CheckEmailTarget | email 在所有入站唯一；本轮补损坏 peers 列表拒绝，避免不完整视图下授权 |
| new_user | NewUser | 随机 UUID/password/email/subId；VLESS 保留首个启用用户 flow，空 Reality TCP 默认 Vision，HY1 拒绝；Go 扩展受管 SS。已有协议测试，本轮加入畸形 peers 创建拒绝 |
| counters | UserCounters；TestMissingOrInvalidCountersNeverBecomeSuccessfulZero | 先验证身份，唯一 email 计数，非负整数；不使用入站总量替代，不把缺失记为零；Go int64 上限与 Python 任意精度不同 |

证据 `goal-user-audit.log`（竞态检查，含用户/面板写入/运行同步及上述脚本测试）。

## panel_user_runtime.py

已逐段核对 `api_address`→runtimeAddress、`runtime_status`→runtimeStatus、`check_authorized`→runtimeAuthorized、`sync_user`→syncRuntime：仅回环 API；唯一 email/UUID/password/auth/flow 验证；停用/过期/耗尽拒绝恢复；只补确认缺失的单个用户，随后复读验证，冲突不覆盖，404/旧 API 返回未知状态。`TestRuntimeRepairOnlyMissingOwnedUserAndVerifyOnce`、`TestRuntimeMismatchUnsupportedAndInterruptedWrite`、`TestRuntimeAuthorizationLimitsAndLoopbackAddresses`、`TestRuntimeConfigFailuresAndPublicAPIAreNotUsedForRepair`、`TestHY2RuntimeAuthRepair` 本轮通过。Go 更严格拒绝负数/数值溢出/额外 JSON 文本；实际 X-Panel 服务端版本差异仍需外部验收。

## core_adapter.py（继续审计）

`CoreAPI.__init__` 对照 readCore/parseLegacyCoreState：读取固定内核路径、Base64/JSON 对象校验、2 MiB 上限、UseNumber 与本地加密状态；Go 内部不再模拟一个通用面板 request 对象，而由各操作调用专用后端。

`sing_inbound` 对照 legacyNativeInbound/legacySingTLS：启用用户过滤、UUID/password/flow、Reality/TLS/WS/gRPC 和监听默认值已逐段核对。该函数用于重建旧配置并核验精确归属，不可随意把旧行为改成新模板。Go 另支持显式受管 SS 多用户，已有 guard 隔离。

`CoreAPI.check_user_stats_support`/`enable_user_stats`/`user_stats` 对照 checkCoreStatsTools、enableCoreStats、planCoreStats、queryCoreCounters、parseCoreCounters：拒绝覆盖非受管统计 API，固定回环，先配置后验证统计服务，缺失方向仅在确认 API 成功后为零；重复 email 或计数拒绝。sing-box 改用固定 SSH 转发的 Go gRPC 查询，无需外部 Xray 查询工具。已有 TestEnableCoreStatsRecoversAfterInterruptedWrite、TestFirstImportEnablesStatsBeforeGrantingUser、TestLegacyEnrollmentEnablesStatsAndRecoversAfterRestart、TestCoreCountersRequireLiveLocalAPIAndUniqueUsers、TestPlanCoreStatsRefusesForeignAPIs 等测试，完整证据关联继续补充。

`CoreAPI.apply` 对照 coreWriteScript/applyCoreVerified 与各 patch 操作：配置 hash 乐观锁、远端 flock、原配置快照、候选内核校验、替换和服务确认、失败回滚及本地 journal。本轮新增 TERM/INT 退出处理和回滚期间信号保护。`TestCoreWriteScriptActualRollback` 实际执行隔离脚本，双核各 8 场景覆盖成功、候选拒绝、restart/is-active/verify 失败、TERM、回滚服务失败和并发 hash 冲突；核对原配置、恢复副本、候选清理和成功/失败标记。证据 `goal-core-write-script.log`。此前只检查脚本语法，现已补执行证据；仍不是实机 systemd 验收。

`CoreAPI.request` 的入站/出站/路由增改删、随机 ID、端口冲突及 pending commit 分散在 core_inbound_*、core_relay、inbound_create 等实现中；不得因通用 apply 测试通过将所有分支标记完成。余下继续按请求分支关联行为证据。

## certificate_manager.py

`certificate_script`→certificateScript/certificateShell：已逐段核对固定 ACME commit/SHA256、DNS 与本机地址确认、TCP 80 占用拒绝、不强制重复签发、证书有效期/域名/公私钥验证、服务用户私钥权限、首次 ready 标记和续期 timer。现有 TestCertificateShellAndValidation 比较完整 shell 与 Python 引用（不执行 Python）；真实公网 ACME 与 systemd 安装仍未验收。

`prepare_certificate`→StartCertificate/runCertificate/ReadyCertificate：Go 改为进程级后台任务，保留 290 秒超时、成功标记和固定证书路径；增加每服务器互斥、同参数去重、最多四个任务、失败密钥脱敏、服务器版本绑定和重启后重新确认。TestCertificateDeduplicationBusyGuardsAndSuccess、TestCertificateCancellationAndRedactedFailure 等覆盖上述行为。

本轮补齐国际域名输入，certificateDomain 通过 IDNA Lookup 转换后再检查标签/长度，所有任务查询及路径复用规范化结果。TestCertificateInternationalDomainNormalization 验证中文域名、Punycode、尾点和非法输入；证据 `goal-certificate-idn.log`（竞态）。IDNA Lookup 与 Python IDNA2003 个别字符映射差异沿用 Snell 审计备注，不能声称所有 Unicode 域名逐字一致。

## reality_probe.py

三个入口 `_probe_pair`、`probe_script`、`probe_batch_script` 合并对应 `realityProbeScriptForCore`（单目标仍走批次），逐段核对完成：随机互不重复回环端口、独立 X25519/UUID/short ID、绑定公网 IP 的伪装目标、黑洞 403 证明真实认证路径、两次请求确认、最多 20 目标/四并发、两个临时内核进程与退出清理。Go 扩展 sing-box 服务端，通过 Xray 回环黑洞 sink 验证转发；所有 SOCKS 监听均等待就绪，检查 TCP/UDP 已占用端口并核对进程存活。仅 TLS 成功不能升级为 Reality 成功。测试 `TestRealityProbeScriptIsolationAndRouting`、`TestSingBoxRealityProbeIsolationAndRouting` 及 sni_test.go 的缓存/强制刷新/私网 DNS/取消/槽位/预检覆盖状态逻辑；实核证据记录于 `goal-probe-native.log`，只涉及本机临时 TLS 服务与内核，不是远端公网探测验收。

## remote_manager.py：保存与地址解析补齐

`RemoteManager.save` 对照 Manager.Save 发现并补回 Python 的限速身份保护：有 bandwidths 时不允许更换 host/SSH 端口/内核，Go 另限制指纹变化；名称及密码更新仍可用。`TestBandwidthOwnershipSurvivesRejectedServerIdentityChanges` 核对拒绝后 servers.json 字节不变、记录不丢失；证据 `goal-server-bandwidth-guard.log`。

`parse_panel_address` 新增统一 parsePanelAddress，保存和 NewPinnedPanel 共用：HTTP(S)、默认/显式端口、IPv6、IDNA、禁止 URL 凭据/查询/片段/控制字符/反斜线/路径 . 与 ..；检查解码后的路径，保留合法 RawPath 转义，尾斜杠规范化。保存 panelPath 使用转义形式，与 Python 一致。`TestPanelAddressPythonPathsAndInternationalHosts`、`TestServerSaveRejectsUnsafePanelPaths` 及原面板/运行时回归见 `goal-panel-address.log`。仍使用已固定 SSH 主机密钥的回环连接，不直接拨号 URL 主机。

### remote_manager.save 登记字段续审

补齐 host 的空白/IPv6 方括号规范化、nodeAddress 的独立 IPv4/IPv6/IDNA 域名规范化、domain 的 IDNA 与标签验证；保持 SSH、面板 URL、客户端节点地址互不替换。`TestServerEndpointsNormalizeIndependently` 及 remote 全包回归通过：`goal-registration-all.log`。Go 继续允许已有 SSH 域名登记（Python 原版仅 IP），不是将该扩展误记为等价。

## server.py：配置编辑与排序

已对照 reorder_nodes/sync_group_node_order/move_node、mutate_group/mutate_rule/move_rule/mutate_dns。本轮补齐节点 targetName 排序的缺省 before；新增 Repository.MoveNode，在同一仓库锁内读取受管 failover 名称，排序普通组并跳过主备组，避免改变主备优先级而被整个事务拒绝。原 protectedComponents 仍限制直接编辑受管路径和组，未放宽保护。`TestNodeOrderPreservesManagedFailoverPriority` 验证排序可保存、主备顺序保持、普通组内置/嵌套位置保持、直接改主备优先级拒绝。

DNS 编辑原本把非对象 dns 或 nameserver-policy 当作空对象覆盖，现遇异常旧格式明确拒绝；`TestDNSMalformedStateIsNotOverwritten` 验证错误不改原数据。规则/策略组 CRUD、规则乐观锁和引用更新已有 edit/group_rules 测试；Go 对 move_rule 仅允许 ±1（Python 接受任意整数偏移），属于更严格 UI 操作边界。证据 `goal-config-order.log`。

### 节点自动分组默认值

`mutate_node`/`add_node_to_groups` 再核对发现默认值和组类型差异：公开 POST /admin/api/nodes 缺少 addToGroups 时现按 Python 默认为 true；底层显式自动分组仅加入普通 select 组，跳过 fallback/url-test/load-balance/relay 和广告组。内部受管操作仍可省略该参数以避免未经选择的关联。`TestAddingNodeOnlyJoinsOrdinarySelectGroups`、`TestPythonNodeCreateDefaultGroupMembership` 验证接口默认、显式 false 和 fallback 保持；配置/Web/订阅全包日志 `goal-node-group-parity.log`，针对性竞态 `goal-node-membership-race.log`。

### 外部订阅文本与抓取

`fetch_subscription` 对照 subsource.Client.Fetch：20 秒级客户端期限、8 MiB 读取上限、严格 UTF-8/BOM、原 User-Agent；Go 增加 DNS 固定拨号、拒绝私网/混合私网 DNS、重定向核验和错误凭据脱敏，属于有意更严格的外部抓取边界。

`parse_subscription_text` 对照 subsource.Parse：YAML 节点别名、外部 dialer-proxy 移除、Reality 规范化、链接/Base64、Mieru 多端口均已迁移；Go 对所有协议调用配置校验，而 Python 主要对 Snell/Mieru 完整校验，Go 的节点上限/诊断上限和无节点错误更严格。本轮补齐 URL 转义的 Base64 订阅及 `name = snell , ...` 空格策略行识别；`TestPythonEscapedBase64AndSpacedSnellPolicy` 和 subsource 全包竞态通过日志 `goal-subsource-base64.log`。

### 认证与持久化会话续审

`authenticate` 的旧 PBKDF2 登录升级此前缺失，现低于 600000 迭代的合法凭据成功验证后重算盐/哈希；completeLogin 同事务保存升级凭据、重新绑定原有有效会话、清除本次登录的失败计数并保留其他限流记录。写入前检查完整磁盘凭据，成功后才发布内存。`TestLegacyLoginUpgradesWithoutLosingSessionsOrOtherLimits` 验证重启及原/新会话；`TestLoginTransactionRejectsChangedDiskWithoutPublishing` 验证外部凭据变化不会被覆盖。

`update_auth` 已补用户名 3–64 Unicode 字符、禁止冒号与空白；全空白的新用户名不再按省略处理。密码长度以字符计数，仍保留 Go 256 字符上限（Python 无上限）。修改用户名时旧迭代凭据也升级；账号修改撤销会话并同步清空持久化及内存限流记录。登录用户名上限改用字符计数。`TestAccountUnicodeAndPythonUsernameRules` 覆盖中文长用户名、短 Unicode 密码和非法用户名；针对性测试证据 `goal-auth-upgrade.log`。完整竞态检查另见后续日志，不能只凭此记录认定已通过。

Python 旧会话仍要求重新登录一次；Go 的 12 小时/8 会话限制、SHA256 token 持久化、HttpOnly/SameSite/Secure cookie 及注销重启测试保留。Go 限流在哈希前计数并持久化，兼顾 IP 与账号，而 Python 仅进程内记录失败客户端；这是已知更严格的行为差异。

### 安装日志与面板接入契约

`clean_log` 对照 redactInstallLog：补齐带引号的 JSON/字典密码键、secret 字段和 CR 行分隔，已知配置凭据继续先做精确替换。`TestInstallLogPythonQuotedSecretsAndCarriageReturns` 验证敏感值不残留、普通诊断保留。

`attach_existing`/`install_worker` 对照 AttachPanel/verifyInstalledPanel 时发现面板 success=true 但 obj 非列表仍可通过；现在统一在 Panel.request 的入站列表分支拒绝 null/对象/字符串。Panel.raw 同时拒绝尾随 JSON 或垃圾文本，避免部分解码接受畸形响应。`TestPanelListRejectsMalformedSuccessAndTrailingJSON` 与远端全包回归证据 `goal-panel-contract-all.log` 通过。

安装任务已有 45 分钟上限、两任务限制、同服务器操作互斥、后台阶段标记、未知进程重启不重放、日志上限/脱敏、完成标记及面板登录/API 验证。Go 仅支持安装固定的 3x-ui/Xray/sing-box，x-ui/x-panel 走已有接入；详细日志在结束后发布，运行中只发布允许的阶段。真实 SSH/面板/systemd 安装仍未实机验收。

### 订阅索引历史迁移

`load_profiles` 的缺失/短自定义 slug 自动升级及历史身份变化绑定修复此前遗漏。新增 Repository.MigrateLegacyProfiles，在 RunBackground 启动工作线程前执行一次原子迁移；生成唯一 50 字符标识，只有已记录指定身份冲突的 active 绑定改为 identity_changed，保留既有 invalidatedAt。普通读写不隐式落盘，--check-data 继续只读；避免失败操作改变索引字节。`TestLegacyProfileReadPersistsSafeSlugsAndInvalidatedBindings` 验证持久化与无关绑定保持。首轮普通读取落盘导致两个事务测试失败，已改启动迁移；修正后全量测试 `goal-auth-profile-all.log` 通过，启动位置最后调整另需回归。

create_profile/update_profile/delete_profile 已逐段对照：独立文件复制、受管绑定禁止复制/删除、主订阅保护、slug 唯一与切换已覆盖 profiles_test。Go 只清理生成目录内文件，并先移除公开索引后清理文件，防止外部路径删除与部分删除仍公开；名称限制 300 字节和控制字符比 Python 非空更严格。普通读取共用索引严格解析，尾随 JSON 拒绝。

### 策略模板与组内规则

已逐段核对 `group_rule_lines`/`replace_group_rules` 与 scopedGroupRule/replaceGroupRules：域名简写、类型大写、no-resolve/src、去重、保留其他组规则顺序、MATCH 不归组替换。Go 额外校验 expectedGroupRules，避免并发覆盖，RULE-SET 必须存在。

`validate_policy_groups`/`policy_template_config`/`policy_template_seed`/查询保存对照 policy_templates.go：128 组/5000 规则/40 模板、组字段白名单、HTTP(S) 无凭据测速地址、成员与环引用校验、唯一末尾 MATCH、遗漏组 DNS selector→DIRECT、从当前配置提取时去节点凭据并给非 select 组默认测速 URL。模板 CRUD 与建订阅使用模板由 internal/web/policy_templates_test.go 覆盖。Go 单条规则限制按 4096 字节（Python 字符），256 KiB 模板计入 id/name 和 Go JSON 转义，属于更严格的大小边界。没有发现新的正常 UI 流程缺口。

### 更新与卸载机制

逐段对照 current_version/fetch_latest_release/update_status/dismiss_update/start_update/start_uninstall/update_checker_loop。Go 刻意使用 dingzhi-ban 的 `go-vX.Y.Z` 双架构发布包及 SHA256 清单，替代 Python 分支 commit 与远端安装脚本下载；不提供同版本 force 重装。更新检查间隔 6 小时、请求节流 30 秒、忽略版本持久化；状态字段使用 Go UI 对应的版本/任务结构。仅标准 Linux root 安装启用应用/卸载，固定 systemd 单元，持久队列唯一认领，客户端断开后不丢任务，下载大小/归档成员/路径/版本/架构限制，更新失败尝试恢复原版本。

卸载保留数据默认不移动已有数据到 Python 风格备份目录；清空数据须显式选择，选择在启动前持久化。Go 服务/路径归属核验与共享安装保护由 deploy/install-go.sh 实现；releaseupdate 的临时路径脚本测试覆盖逐阶段回滚、清空及交叉任务拒绝。普通全量日志已覆盖 releaseupdate；真实 systemd 更新/卸载未执行。本轮未新增这一领域实现，不把既有测试视为所有部署环境已通过。

### 配置缓存、写入与备份

`get_cached_config`/cache_config_entry/snapshot_view/snapshot_json 对照 config/cache.go 与 snapshotBase：Go 使用内容 SHA256，不信任同 size/mtime 外部改写；32 项与约 32 MiB 权重预算（Python 8 项），配置快照与当前 profile/流量元数据分别组合，客户端拿到深复制。已有 cache_test.go 覆盖外部改写、LRU、无变化保存、镜像修复、事务失败不发布缓存与精确整数。HTTP 压缩仍由已有响应层处理；不声明缓存策略和 Python 相同。

`write_config` 对照 mutateGuardedLocked：保存前 0600 备份、各镜像原子写入、后续镜像失败恢复此前镜像，成功后发布缓存。Python 没有相同的多镜像失败回滚保障。`prune_backups` 原先仅列表截断 100 项而未清理磁盘，现成功保存后按时间保留全局最新 100 份普通 .yaml 文件，忽略目录和符号链接，清理失败不撤销成功保存。恢复新增普通文件校验，拒绝借符号链接跨订阅读取。`TestSuccessfulSavePrunesOldBackupsWithoutFollowingLinks` 与配置/订阅全包竞态 `goal-backup-retention-race.log` 通过；失败编辑不清理历史。

### 外部订阅导入续审

preview/import_subscription 与 sourceImportRoutes/ImportSubscription 对照：预览协议统计、rename/skip/replace、重新核对分组、同批单事务、30 名称返回上限、受管和主备组件保护。发现批次末尾漏了完整引用校验，可接受名为 DIRECT/REJECT 等内置动作的节点；已补内置动作名称校验，在落盘前拒绝，保持原订阅字节。Go 对未知 conflict 显式拒绝，Python 落到 rename；保留为严格参数边界。

外部导入首次尝试复用完整 checkReferences 时，回归发现会额外拒绝已有旧规则中的未知动作；Python validate_config 本来也不校验该类规则动作。最终收窄为新节点内置动作名称冲突校验，保留原有未知规则。修正后配置/Web 全包 `goal-import-batch-parity.log` 通过。

`import_node_links` 对照 importNodes 发现并补齐：link 旧参数回退、addToGroups 默认 true（显式 false 保留）、重复名称 -02/-03 格式、names 前 50 项及零成功时空数组。`TestPythonBatchLinkAliasDefaultsNamesAndRename` 验证公开请求、分组、重命名和返回名称。Go 保留对策略组名称冲突的额外保护，以及无有效候选链接时 400 的边界；不将所有 Python 宽松类型强转当作兼容承诺。

`request_session_token` 补齐 Bearer 内容首尾空白去除；只要显式 Bearer 头存在即优先，空头也不退回 cookie，符合 Python。`TestPythonBearerWhitespaceAndExplicitHeaderPrecedence` 覆盖空头、错误 token 和其他认证类型。

### core_adapter.py 请求分支映射续审

getNewX25519Cert→inbound_templates.go 的 crypto/ecdh.X25519 随机密钥；list/get→coreInventory 与托管 ID 查找，Go 同时呈现 present/disabled/conflict，不把陌生原生入站自动当作受管。xraySetting/pending/restart→core_relay 的归属验证和持久 journal，Go 无独立通用“任意写出站然后重启”公开接口，整个中转操作保持同一事务。

add→createCoreInbound：端口与全部原生入站比对，ID 由幂等 key 确定（Python 随机 ID），检查现有/已删除 ID、tag、取消状态，校验 TLS 证书和统计能力，先保存 journal 再远端写入并复读；已有成功请求核对原配置后复用。update/delete→changeManagedCoreInbound/editManagedCoreInbound：校验完整版本与原生一致性、端口保持、关联带宽/计量/中转保护、删除 tombstone 与引用检查，未知结果不盲重放。上述分支的中断重试由 core_inbound_create_test.go、core_inbound_edit_test.go、core_user_recovery_test.go 及各协议/传输测试覆盖。sing_outbound/sing_quic_outbound 对应 singRelayOutbound/singQUICRelayOutbound，并复用 NodeOutbound 严格参数检查，保留此前 TLS/UDP/QUIC 实核证据及已知限制。仍需完整远端实机验收，不能仅靠分支映射判整体完成。

### 套餐、额度与月度后台任务

apply_subscription_plan/update_traffic/validate_traffic_update/_update_traffic 对照 subscriptions/policy.go：套用套餐前结算旧独立倍率、专属限速逐项确认、保留使用量/到期/周期锚点、暂停和撤销状态保护、安全整数与日期上限。Go 普通额度编辑始终仅本地保存；既有绑定倍率冻结，独立倍率走 SetMultiplier，套餐才更新全部绑定倍率，避免将普通默认倍率编辑变成隐式远端事务。这是与 Python 的旧默认倍率切换结算流程的已记录差异。policy_test.go 与 dedicated_binding_test.go 覆盖结算失败、费率切换、限速失败重试和不限速清除。

reset_monthly_traffic/enforcement_loop 核对发现 Go 原先只对 enabled+enforce 的套餐重置，而 Python 重置所有到月套餐。现同步先做日历重置再判断是否采集，未强制限制套餐也按 UTC 月末锚点清零，过期不重置。`TestMonthlyResetWithoutEnforcementAndExpiredGuard` 与订阅全包竞态 `goal-monthly-reset-race.log` 通过。

补齐 Python ENFORCEMENT_WAKE：成功额度/套餐写入，以及用户限制登记后，非阻塞通知后台；重复事件合并，当前轮结束即复查，不在 HTTP 保存中等待 SSH。初始 sweep 吸收启动前通知，仍保留 15 秒周期及四并发。`TestQuotaSaveWakesBackgroundEnforcementWithoutWaitingForInterval` 实际启动后台并在 3 秒内观察第二次采集（小于周期），订阅竞态 `goal-policy-wake-race.log` 通过；用户登记通知后续调整另有最终回归。

### 批量删除、国旗与诊断续审

`delete_nodes_from_doc`/bulk_delete_nodes 已补输入名称 trim、忽略空白、去重，以及按原节点列表顺序返回删除名称；原测试此前错误地断言请求顺序，现依据 Python 实现修正，链式依赖、missing 和失败无部分写入断言保留。`TestBulkDeletePythonContractAndAtomicity` 配置/Web 全包 `goal-bulk-order-parity.log` 通过。Go 非字符串输入仍明确拒绝，不复刻 Python 任意类型 str 转换。

add_country_flags/country_flag/name_with_country_flag 对照 FlagTargets/ApplyCountryFlags/geo.Resolver：最多八并发、同服务器去重、国家代码校验、既有旗帜替换、冲突跳过、引用更新与主备保护。Go 另做目标 identity 乐观核验、国家请求速率/缓存上限、取消后不保存；已用 flags_test 和 geo lookup_test 覆盖，未新增外网请求。

`diagnostics` 与 Web /servers/diagnose 核对发现原先只替换已知 SSH/面板密码，漏了日志里的其他 secret/private_key 等字段。新增 CleanDiagnosticLog，共用安装日志敏感字段/终端转义/CR 清理，在清理之后截断 64 KiB，并保持 UTF-8 边界。已接入 API 返回；TestDiagnosticLogSanitizesBeforeBounding 覆盖敏感日志和输出限制。远端/Web 全包 `goal-diagnostics-bulk.log` 通过，最后 UTF-8 边界调整另行复测。

### 服务器移除与首次创建并发

detach_remote_server 的 Python ENFORCEMENT_LOCK 覆盖尚未登记绑定的创建。Go ForgetServer 原先只锁扫描到的订阅，当首个创建仍持有 server lock、尚未写入绑定时可能漏掉；现先取得同一 server lock，再扫描并锁订阅，保持 server→profile 顺序。TestForgetServerWaitsForCreationBeforeFirstBindingExists 在无绑定、创建持锁时验证移除超时且注册表保留；现有已登记 pending 创建测试继续保留。

### 规则移动偏移完整兼容

此前 MoveRule 只接受 ±1 被记为严格边界，现补齐 Python 任意整数偏移、默认 0、越界钳制和交换语义。目标计算在加法前钳制，避免极端整数溢出。TestPythonRuleMoveOffsetsClampAndSwap 覆盖多步、正负越界、机器整数两端和省略参数；不再保留“仅 ±1”作为未迁移边界。

服务器保存同样存在 GuardServerUpdate 检查与 Manager.Save 分离的窗口。新增 Controller.SaveServer，先取得 server lock，再读取最新服务器与全订阅绑定检查，持锁完成注册表保存；Web POST/PUT /servers 已使用该入口。TestServerIdentitySaveSerializesBeforeFirstOwnership 覆盖首次创建尚无绑定时保存等待、取消后地址不变、绑定出现后重新检查；订阅全包竞态 `goal-server-save-race.log` 通过。此锁与 Batch/入站创建使用相同实例，非仅 manager 的远端连接锁。

### 历史索引与 JSON 完整性续审

cachedEntry 对空 files/空路径显式报错，避免复制历史模板或查询导入目标时越界 panic；TestMalformedLegacyProfileFilesDoNotPanicOrCreateCopies 覆盖三种缺路径形式、失败不修改索引及目标逐项报错。索引拒绝重复非空 ID，防止 CheckData 反复读取第一条而漏掉后续损坏记录；TestCheckDataRejectsDuplicateProfileIDsWithoutHidingBrokenRecord 保证只读失败。配置竞态 goal-empty-profile-files-race.log、配置/Web/订阅回归 goal-profile-integrity-all.log 通过。

bootstrap 与账号编辑统一按 Unicode 字符判断用户名和密码最小长度，保留初始化密码 1024 字节读取上限、拒绝无效 UTF-8；TestBootstrapUnicodeCredentialRulesAndNoOverwrite 证明汉字凭据往返及失败不覆盖，goal-bootstrap-unicode-race.log 通过。

remote.object 的 JSON 字符串之前只读首对象，已补完整 EOF 校验；TestInboundJSONRejectsTrailingDocumentsBeforeIdentityAndExport 验证入站导出与用户身份都拒绝尾随文档，合法空白保留，remote 全包竞态 goal-inbound-json-race.log 通过。服务器索引和解密用户文档也改完整 JSON 校验，避免截掉尾部后重新保存；已有 readCore 本来就检查 json.Valid，未重复修改。

### 套餐十进制剩余入口统一

normalizedPlan 的 speedMbps 和 PlanUnits 此前仍经 planDecimal 旧路径，导致 `+.125`/`1_0` 等 Python Decimal 形式未完全兼容，字符串倍率被拒绝。现分别复用 billing.BandwidthKbps/ScaledDecimal，并把速率、倍率规范为合法 JSON 数字（不把带加号/下划线的原字符串伪装 json.Number）。金额和 GiB 仍保持数字类型规则。TestPlanSpeedAcceptsPythonDecimalFormValues 扩展形式、TestPlanMultiplierUsesPythonDecimalStrings 验证保存重读和非法形式；配置/订阅全包竞态 goal-plan-decimal-final-race.log 通过。

共用用户创建的 preflight 同样改用 planSpeedKbps，兼容旧数据 `0.0`/`0.000` 不限速；非零共用限速仍拒绝。TestLegacyZeroDecimalSpeedAllowsSharedProvisioning 经真实控制器与替身后端验证三种零小数形式。

### 规则、节点排序、模板及入站账号续审

逐段核对 mutate_rule/build_rule、group_rule_lines、reorder_nodes/sync_group_node_order、mutate_dns、mutate_group。规则类型和动作仅在字段缺省时使用默认，显式空白不再意外保存为 DOMAIN-SUFFIX/DIRECT；MATCH 空动作也明确拒绝（Python 此分支曾允许空动作，Go 保留有效规则要求）。策略组规则拒绝仅逗号/空格的匹配值，逻辑复合规则中的逗号仍保留。TestRuleExplicitEmptyDoesNotBecomeDefault 经 Repository.Mutate 检查失败不写文件、缺省成功保存，TestGroupRulesRejectCommaOnlyMatch 覆盖空值和复合规则。节点排序不再给 provider-only 组注入 proxies:null；TestNodeOrderPreservesProviderOnlyGroup 验证原组字节不变且节点实际移动。DNS 续审确认字符串分行、旧域名替换与删除一致，损坏旧结构明确拒绝覆盖；策略组仍有引用/循环/托管组件和乐观规则检查。

blankProfile 原先 yaml.Unmarshal 只取首个文档，与 Python yaml_load 不同；已增加完整 EOF 检查。TestBlankTemplateRejectsTrailingYAMLWithoutCreatingProfile 覆盖第二文档及损坏尾部，拒绝后索引不变、未创建配置文件。普通模板字段限制、128组/5000规则、最后唯一 MATCH、DNS 旧组选择器回退 DIRECT 与当前配置种子过滤均已核对；真实客户端行为仍按已有验收范围。

InboundNodes 对 HTTP/SOCKS 的 accounts 格式错误曾被当作空数组，并导出匿名节点；现非数组及非对象账号明确报错，不返回部分节点。合法缺省/null/空数组和空对象匿名账号保留，正常账号凭据完整导出。TestInboundMalformedAccountsNeverExportAsAnonymous 覆盖上述边界。远端全包竞态 goal-inbound-accounts-race.log 通过；普通全量 goal-edit-inbound-final-all.log 通过。后续模板/任务显示修正另行最终回归。

### 服务器任务展示续审

对照 RemoteManager.public/list：List 原先按 serverId 取最后任务，缺少 Python 的 installType 筛选。现只显示当前安装类型的任务；旧任务缺省类型为 3x-ui。TestServerListShowsOnlyCurrentInstallTypeJobs 覆盖旧任务、当前 Xray、其他服务器/类型任务，以及 sing-box 无匹配任务时不误展示。服务器密文凭据、敏感字段白名单、Fernet 旧数据和本地持久化路径继续使用既有实现。

### 历史索引失败事务与唯一身份

UpdateProfile/DeleteProfile 原先在 profileFrom 结构转换之前写索引，历史 files 类型错误时会先更名/移除后才返回失败。现结构转换在写入前完成，保留删除时先撤销公开索引再清理生成文件的原设计。TestMalformedProfileMutationDoesNotPublishFailedChange 覆盖更名、删除拒绝后索引字节与原配置文件保留。创建使用新构造的已知字段，不存在同一历史记录转换窗口。

服务器 load 现在验证所有服务器记录为对象、ID 为非空字符串且唯一。此前 Record 只返回首个匹配项，而 ForgetServer 删除所有匹配项，重复 ID 可导致读写/解绑对象不一致。TestAmbiguousServerRegistryBlocksReadSaveAndForget 覆盖重复、null、数字/空白 ID，失败不调用订阅解绑回调且不改变注册表。此为损坏历史数据的保护，不自动修复或猜测归属。

policyTemplates 之前通过 rows 把错误类型当作空数组，新保存会覆盖历史坏结构；现索引读取阶段拒绝非列表、非对象项、缺失或重复 ID。TestMalformedPolicyTemplateRegistryIsNotSilentlyReplaced 验证列表查询和保存都失败且原字节保留；缺省及 null 仍按未配置处理。相关 config/web/subscriptions 回归 goal-template-registry-final.log、配置竞态 goal-template-registry-race.log 通过。

### 入站列表在中转清理之前核验

对照 RemoteManager.inbounds/delete_inbound 与 Go inbounds：Go 会恢复 deletePending 中转清理，之前先收集可解析记录、忽略其余项，可能把畸形条目当成缺失入站并进入清理。现 panelLiveInboundIDs 在任何清理前校验完整列表的对象类型、正整数 ID 和规范化后的唯一性；任一错误不返回部分集合。TestPanelCleanupInventoryRejectsAmbiguousIdentity 覆盖 null/JSON字符串项、0/bool/小数及 1/01 重复，合法空清单保留。归属散列、远端结果未知和取消屏障仍使用既有保护，未放宽清理条件。

### 后台退出等待与进程生命周期

本批全量 goal-registry-transaction-all.log 曾出现 TestTemplateCreationHTTPAuthenticationAndImportContract 的临时目录删除失败：取消后台上下文不等于计量 sweep 已完成，唤醒后仍可能落盘。新增 Controller.WaitStopped，以每轮 Start 的完成通道等待 sweep 及其四个工作协程退出；完成前不允许再次启动，等待受调用方 context 约束。Web 测试在删除临时目录前取消并等待，唤醒测试也使用同一机制。

同时核对主进程发现 ListenAndServe 在 Shutdown 开始关闭监听器时就返回，原 main 随即退出、未等待 Shutdown 完成。现 main 等待 shutdownDone，HTTP Shutdown 后等待计量停止，共享原 10 秒退出上限；超时记录错误。此机制只保证 HTTP 和订阅计量等待，不声称远端未知请求已终止或其他安装任务已完成。

TestWaitStoppedJoinsInFlightSweepAndAllowsRestart 使用阻塞后端验证取消后不能提前返回、超时可见、旧轮退出前拒绝重启、退出后可重启。goal-registry-shutdown-race.log 的配置/远端/订阅竞态通过；Web 原失败场景连续 20 次 race 通过（goal-web-shutdown-repeat.log）。最新发布二进制在临时目录、127.0.0.1:0 下分别接收 SIGTERM/SIGINT 并以 0 退出（goal-registry-shutdown-package-check.log）；没有操作现有服务。

### 自动证书任务错误展示续审

再次核对 certificate_job/prepare_certificate：Go 的域名规范化、任务去重、服务器版本绑定、64项任务上限、四并发、独立于 HTTP 请求的生命周期、成功标记、32域名保留以及 ReadyCertificate 的服务器/域名检查均有实现。发现错误展示仍只替换已知 SSH/面板密码，且截断后才替换；现先对完整错误和输出替换已知秘密，再复用 CleanDiagnosticLog 的敏感键/终端控制过滤，最后限制 2000 字符。TestCertificateFailureSanitizesCredentialLinesBeforeTruncation 覆盖超长私钥行、ACME secret、错误对象中的 API token、CR/ANSI 与普通 DNS 故障保留，证书测试竞态 goal-certificate-error-race.log 通过。远端真实 ACME 签发/续期仍未验收。

后台唤醒测试的最终清理也改为 WaitStopped，针对退出和唤醒的竞态复测 goal-shutdown-wake-final.log 通过。
