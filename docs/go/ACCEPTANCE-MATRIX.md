# 完整迁移验收矩阵

最新订阅索引优化及性能复测见 [INDEX-CACHE-20261108.md](INDEX-CACHE-20261108.md)，管理器本地包为 `dist/go-local-20261108-index-cache/`；历史测量与包名保留。

2026-11-08 更新：已制作并验证 Reality/Snell 本地兼容补丁，详情见 [CORE-COMPAT-20261108.md](CORE-COMPAT-20261108.md)。下方原版内核失败记录保留；修复需使用兼容内核，未部署或改变默认安装版本。

最新性能补齐、全量回归和新发现的 Snell 复用边界见 [PERFORMANCE-AUDIT.md](PERFORMANCE-AUDIT.md)。本轮本地包为 `dist/go-local-20261107-performance-audit/`；下方历史包名保留作审计记录。

本表服务于持续目标，不以单个修复或发布包作为迁移完成。Python 基线 0869964，Go 基线 92ccd3e；现有本地未提交改动均保留。全量行为索引见 [python-behavior-inventory.json](python-behavior-inventory.json)：13 个模块、309 个顶层函数和类方法，由 AST 生成，不导入生产程序。候选实现路径不是行为等价证明。嵌套辅助函数随所属行为审计。

重建索引：在 Go 仓库运行 `python3 tools/migration/behavior_inventory.py ../python-original docs/go/python-behavior-inventory.json`。索引保存源文件 SHA256，后续若 Python 变化必须重审对应模块。

| Python 模块 | Go 对照范围 | 当前验收情况与下一步 |
| --- | --- | --- |
| server.py | web/config/subscriptions/subsource/geo | 方法入口清单已有路由测试；309 行为索引中的服务端函数仍须逐项核对成功响应、异常、配置和并发语义。国家查询混合 DNS 差异已修复；本轮补历史索引失败事务及模板坏结构保护，不能据此判定整个模块完成 |
| remote_manager.py | remote/subscriptions | 入站、用户、中转、限速、安装及重试已有大量测试；面板未知请求终止无完整证据。本轮补服务器唯一身份、清理前清单校验及证书错误过滤；真实 SSH/面板验收未完成 |
| core_adapter.py | remote/core*、sing_relay_outbound | 已补 TUIC 默认、HTTP 头、SNI/ALPN、计量、撤销；仍需把每个原生 API 与持久状态操作逐项关联到证据 |
| shared_users.py | remote/users*、subscriptions、billing | 逐函数身份/命名空间/凭据/计数已审计，畸形 peers 列表拒绝已补；远端联动仍按集成范围验收 |
| panel_user_runtime.py | remote/panel*、users* | 面板替身与部分真实内核覆盖；实机 3x-ui/x-ui/x-panel 差异待验收 |
| managed_nodes.py | managednodes/config | 节点归属、引用和历史格式已逐函数核对，畸形 importedNodes 不再进入旧凭据回退；远端清理按单独集成证据验收 |
| bandwidth.py | remote/legacy_bandwidth*、billing/config | 专属整入站速率、倍率和精确计费已有测试；真实 nft 故障与系统重启待独立环境。Python 本身禁止共用端口按用户限速 |
| certificate_manager.py | remote/certificates* | 临时证书/脚本测试已有；真实域名签发续期及安装需外部环境 |
| reality_probe.py | remote/sni_probe* | 真实回环握手已有；远端完整探测未验收，新版跨核差异另见 REMAINING |
| server_monitor.py | remote/metrics* | 已读取原始采样及 derive_metrics 代码，Go 有 Linux 文本解析/缓存/增量测试；重启、热插拔、过期、错误缓存与大计数已补回归，远端发行版采样仍未实机验收 |
| client_adapter.py | subscriptions | 主备顺序、信息节点、客户端配置已有测试；真实 App 导入及全链路切换待验收，按函数审计未完成 |
| mieru_adapter.py | links/mieru*、config | 分享、多端口和字段保护已逐函数核对并通过 Mihomo 配置加载；实际客户端通信待验收 |
| snell_adapter.py | links/uri*、snell_policy*、config | URI/策略行/版本及高级混淆已审计并通过 Mihomo 配置加载；真实远端握手仍缺证据 |

逐项复核结论及有意差异见 [BEHAVIOR-REVIEW.md](BEHAVIOR-REVIEW.md)，当前已逐段复核监控、客户端适配、Mieru/Snell、共享用户、限速、证书及探测；server.py 和 remote_manager.py 按认证、索引、配置、导入、套餐、安装等行为继续补齐；规则/策略组/DNS/排序、模板字段与种子、服务器任务展示及入站账号本轮已追加逐行为结论，core_adapter.py 已补请求分支映射。不能把“读过实现”视为全部实机验证通过。

## 当前审计证据

- 无残留 Go 测试进程：本轮开始时检查进程列表，无运行中的 `go test`；不重复启动被误认为中断的工作。
- `server.py:public_ip_for_server` 与 `geo.Resolver.Lookup` 对照发现混合 DNS 差异：已改为按返回顺序选择首个公网地址，保留纯私网拒绝；仅向固定 country.is 服务发送公网字面 IP。测试覆盖 IPv4、IPv4 映射 IPv6、私网优先、公网优先和无公网，`goal-geo-parity.log`。
- 现有生产 Python 未启动、导入、修改或停止；AST 索引只读取源码。

## 完成判定

每个模块都必须有逐行为结论：已实现并验证、已知差异、缺证据或未实现。当前所有模块仍在集中审计阶段。已知不兼容和外部验收见 [REMAINING.md](REMAINING.md)。只有功能、数据、UI、故障恢复、必要验证和本地交付均有充分证据，才可结束持续目标；单次全量测试通过不能证明完整迁移。
