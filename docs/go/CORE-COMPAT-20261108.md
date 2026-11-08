# 2026-11-08 内核兼容修复

本轮针对两项已复现的内核问题制作本地兼容版本，未部署，未推送，未替换原版内核，未改变管理器自动安装版本。补丁、固定源码摘要和构建工具见 `tools/core-compat/`。

## Reality

原版 sing-box 1.14.4 会移除 X25519MLKEM768，Xray 26.10.31 要求该 share 存在且在可选独立 X25519 之前。兼容版保留它，认证密钥仍优先采用独立 X25519，缺省才采用混合 share 私钥。只保留混合 share 却优先用混合私钥的初次实验失败，日志保留；最终版本遵循服务端实际选择规则。

真实跨核测试覆盖连接、两个用户独立计量、撤销、暂停与恢复；追加错误公钥、短 ID、SNI 拒绝测试，五轮通过。sing-box 普通 TLS/QUIC 等协议计量与撤销三轮通过。没有新增信任根，没有关闭认证，没有将 fallback 当成功。

## Snell

Mihomo Snell 服务端进入 tunnel 后会触发用于 peek 的读超时；它原来直接作用于密文连接，部分帧读被打断后可能出现 `cipher: message authentication failed`。本地补丁把超时放在解密后的包装层，并保留 UDP 帧写入接口。原版和添加诊断日志的原版均能复现；不是管理器 YAML 的 reuse 参数丢失。

兼容版 Snell v1–v5 开启适用的复用，HTTP 连续通信及 v3–v5 的 1/1200/3000 字节 UDP 回环，30 轮通过。新增错误 PSK 拒绝测试。测试启动阶段允许等待真实数据面就绪，其后三次 HTTP 断言不重试；失败不被重试掩盖。Mihomo transport/snell 上游测试通过竞态检测。

## 使用范围

这些修复需要使用兼容内核：Reality 修在 sing-box 客户端；Snell 修在 Mihomo 服务端。仅替换管理器程序无效。未声称所有 Snell 第三方服务端存在相同问题，也未承诺所有 TLS 指纹都支持当前 Reality。官方版本本身没有被修复，未来升级需重新验证。

产物：`artifacts/core-compat-20261108/`，附逐架构 manifest、许可证及源码补丁；amd64 实测，arm64 仅交叉构建。可用 `tools/core-compat/build.go` 从固定上游模块重新生成。

日志相对 `artifacts/`：
- `nov08-reality-compat.log`：第一次密钥选择实验失败（保留）。
- `nov08-reality-compat-v2.log`：最终密钥选择成功。
- `nov08-reality-repeat.log`：跨核 Reality 和 sing-box 协议计量三轮。
- `nov08-reality-negative.log`：错误公钥/短 ID/SNI 与正常生命周期五轮。
- `nov08-snell-debug.log`：原版服务端帧认证错误复现。
- `nov08-snell-tcp-udp.log`：补丁版 TCP/UDP 三十轮。
- `nov08-snell-release-repeat.log`：最终构建产物三十轮，包括错误密码。
- `nov08-mihomo-unit.log`：上游 Snell 单元竞态检查。
- `nov08-all-compat.jsonl`：开启 Reality 跨核和 Snell 复用的全包竞态检查。
- `nov08-vet.log`：管理器静态检查。

性能剩余差距和实机面板/SSH/systemd 验收仍按 PERFORMANCE-AUDIT.md 与 REMAINING.md 记录；本轮内核兼容通过不代表所有迁移验收完成。

## 最终结果

启用两个兼容开关的全包竞态检查通过：506 个顶层测试，含子用例 1179 项通过、1 项跳过，无失败。跳过仍为方法清单中的外网更新检查；13 个测试包通过，5 个包无测试。最终交付二进制的 Snell 正确/错误密码与 TCP/UDP 共 30 轮通过。静态检查通过。amd64/arm64 四个二进制及补丁 SHA256 已验证；arm64 未实机运行。
