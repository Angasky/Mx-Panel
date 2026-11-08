# 性能补齐与功能回归（2026-11-07）

最新订阅索引优化及性能复测见 [INDEX-CACHE-20261108.md](INDEX-CACHE-20261108.md)，管理器本地包为 `dist/go-local-20261108-index-cache/`；历史测量与包名保留。

2026-11-08 更新：已制作并验证 Reality/Snell 本地兼容补丁，详情见 [CORE-COMPAT-20261108.md](CORE-COMPAT-20261108.md)。下方原版内核失败记录保留；修复需使用兼容内核，未部署或改变默认安装版本。

本轮借鉴 Python 的按需处理方式优化 Go，保持纯 Go 部署。源码与产物只保存在本地；未提交、未推送、未部署，未改动 Python 原仓库或运行中的生产服务。

## 修复与优化

- 原始 YAML 管理接口缓存序列化 JSON，每次仍读取文件并核验内容摘要；缓存有容量上限，返回副本，避免响应修改污染缓存及同大小/时间外部修改不刷新。
- 原始订阅下载不再深复制用不到的完整配置对象，保留标识唯一性、撤销、额度、过期与配置格式校验；转换接口仍取得独立配置副本。
- 未变更的节点保存仅验证并比较提交节点，确认全部镜像字节一致后返回；真实修改、异常镜像仍走原事务、备份与持久化路径。测试覆盖非法端口、备份/mtime 不变、镜像修复、真实密码修改。
- Xray 26.10.31 公网明文 VLESS/Trojan 改为转换阶段明确拒绝，避免导出后无法启动。按官方地址例外匹配，但保留项目本来的地址限制；不影响 sing-box。新增原生 Xray 配置验证与两核隔离测试。两条旧测试夹具改为真实受支持的 TLS 或私有域名，而非放松校验。
- 浏览器测试更新已过时的 sing-box SS 算法断言、订阅页面接口模拟、独立用户导入流程；加入弹窗捕获，避免未模拟请求触发 alert 后测试挂起。覆盖三种主题、42 个页面/主题组合、390px 手机布局等。

## 新发现与明确限制

- Python 原仓库普通回归：352 项，15 项跳过。启用真实内核后：354 项、2 个失败子用例和 1 个错误、3 项跳过。失败包含新版 Xray 公网明文限制（Go 已拦截）和 Snell 原生回环空响应；保留原始失败日志，未改 Python 基线掩盖结果。
- Python 真实浏览器/API 工作流单独开启后，7 项通过，包括登录、三主题额度编辑、限速设置/清除、刷新会话和退出。它验证的是 Python HTTP 服务，不冒充 Go 端到端浏览器结果。
- Go Snell v1–v5 增加真实 Mihomo HTTP 通信检查。先等待数据面真实成功，再执行三次无重试断言；关闭 v4/v5 可选连接复用后十轮通过（每轮五版本）。仅监听端口开放不足以证明内核已就绪。
- **Mihomo 1.19.33 Snell v4/v5 可选复用仍有问题**：在就绪后继续请求仍可出现 EOF/502，已保留复现记录。通过 `MXIOC_TEST_SNELL_REUSE=1` 运行 `TestGoSnellHTTPWithRealMihomo -count=10` 可复查。未自动删除用户的 reuse 配置，未把该问题写成已解决；无复用通过不证明复用通过。
- sing-box 1.14.4 → Xray 26.10.31 Reality 的已知跨核握手不兼容仍在，默认回归未开启 `MXIOC_TEST_REALITY_CROSS_CORE=1`，不代表该组合通过。
- 真 SSH、各面板实机、真实 systemd 安装更新卸载、公网 UDP/IPv6、各客户端 App 的完整验收仍缺少独立可重置环境。接口入口和测试数量不等于所有 Python 行为已逐项验收。

## 可复查证据

以下路径相对于 `vpn-manager-migration/artifacts/`：

- 最终 Go 全包竞态与真实内核：`overnight-final-all.jsonl`、`overnight-final-all.stderr`。
- 静态检查：`overnight-final-vet.log`。
- 浏览器：`overnight-browser-fonts.json`；其中旧视觉用例最终结果由 `overnight-browser-visual-final.json` 取代，截图在 `overnight-ui-screenshots/`。`overnight-ui.json` 为 DOM 测试。
- Python 普通/原生：`overnight-python-tests.log`、`overnight-python-native.log`；追加真实浏览器：`overnight-python-extra.log`。
- Snell 无复用十轮：`overnight-snell-no-reuse.log`；保留复用失败：`overnight-snell-final.log`，早期启动/复用混合失败：`overnight-snell-go.log`。
- 双架构本地包：`go-migration/dist/go-local-20261107-performance-audit/`，外部及包内摘要、网页/安装脚本一致性和 amd64 帮助输出见 `overnight-package-check.log`。arm64 仅交叉构建与包校验，未执行。

原性能基线保存在 `performance-20261107/`；优化后结果单独保存在 `performance-20261107-optimized/`，不覆盖旧测量。

## 最终统计及性能实测

全包 `go test -race`（启用三个真实内核）通过：505 个顶层测试，含子用例共 1173 个通过、1 个跳过；13 个测试包通过，5 个包无测试。跳过项是方法路由清单中的外网更新检查，更新行为由隔离更新测试另行覆盖。16 个 Chromium 界面脚本和 1 个 DOM 脚本通过；视觉脚本以单独最终复测结果为准。`go vet ./...` 通过。全量最后一次源码复核为 `overnight-final-current.jsonl`（未变化包可命中 Go 测试缓存），长时间实核原始记录为 `overnight-final-all.jsonl`。

性能方法与旧基线一致：100/1000 节点、30 份订阅、三轮 Python/Go 交替、读取并发 1/4、每场景预热 5 次；正式 11,040 请求，0 失败。保留真实备份、镜像和落盘，不关闭校验换速度。下面为 1000 节点、并发 1、平均毫秒：

| 操作 | 原 Go | 本轮 Go | 本轮 Python |
| --- | ---: | ---: | ---: |
| 订阅列表 | 1.73 | 2.04 | 1.81 |
| 节点快照 | 2.12 | 2.79 | 3.16 |
| 读取 YAML | 3.19 | 2.49 | 1.89 |
| 下载完整订阅 | 2.37 | 1.91 | 1.61 |
| 保存流量 | 1.71 | 1.67 | 1.88 |
| 真实节点修改 | 17.26 | 19.13 | 42.13 |
| 未变更节点保存 | 5.18 | 2.49 | 1.29 |
| 完整 YAML 保存 | 38.44 | 32.79 | 118.85 |

未变更保存约降低 52%，读取 YAML 约降低 22%，原始订阅约降低 19%；这是两次运行的观测差值，不是消除环境波动后的因果估计。订阅列表、快照和真实节点保存也有变慢，全部保留。当前 Go 在列表、原始 YAML、下载订阅、未变更保存四项仍慢于 Python，不能宣称性能短板全部消除。Go 真实节点修改和完整 YAML 保存分别约为 Python 的 2.2 倍、3.6 倍速度。仅代表本机后台 HTTP 和存储操作，不代表代理吞吐、实机 SSH 或生产并发。
