# 本地内核兼容补丁（2026-11-08）

这些补丁修复上游内核行为，不属于管理器 Go/Python 运行时迁移。不会自动部署或修改安装器默认版本。

- sing-box 1.14.4：保留 ClientHello 的 X25519MLKEM768；Reality 认证优先使用独立 X25519 私钥，仅缺省时使用混合 share 的 X25519 私钥，与 Xray 26.10.31 匹配。证书认证回调不变，不信任 fallback，不新增跳过验证。旧指纹若不支持必要 share 仍可能无法连接。
- Mihomo 1.19.33：Snell 服务端探测读取的 deadline 放到解密后的连接层，避免密文帧被超时截断而丢失帧状态；保留 UDP WritePacketFrame 接口，防止包装连接后丢失数据包边界。修的是 Mihomo Snell 服务端，不证明任何第三方 Snell 服务端都有相同问题。

## 重建

需要 Go、cp、patch、网络或完整模块缓存。模块经 Go checksum 校验，补丁前后文件 SHA256 均严格核对；输出附模块/源码/二进制摘要与许可证。

```sh
go run ./tools/core-compat --go /absolute/path/to/go --output /absolute/path/to/output --arch amd64
```

可选 `--arch arm64` 仅交叉构建，不等于在 arm64 实机执行通过。

## 验证

设置 `MXIOC_TEST_XRAY` 为原版 Xray 26.10.31，`MXIOC_TEST_SING_BOX` 为兼容 sing-box，`MXIOC_MIHOMO_BIN`/`MXIOC_TEST_MIHOMO` 为兼容 Mihomo：

```sh
MXIOC_TEST_REALITY_CROSS_CORE=1 MXIOC_TEST_SNELL_REUSE=1 go test -race ./...
MXIOC_TEST_SNELL_REUSE=1 go test -race ./internal/config -run 'TestGoSnell' -count=30
```

未修改原有内核二进制；采用补丁要求实际使用对应兼容内核，单独更新管理器不修复客户端/服务端内核。发行版升级时应重新评估并重新验证，不能直接对未知版本应用补丁。
