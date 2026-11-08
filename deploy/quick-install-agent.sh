#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo '请使用 root 执行'; exit 1; }
[[ -f /etc/mxioc-agent.json && ! -L /etc/mxioc-agent.json ]] || { echo '请先将面板生成的配置保存为 /etc/mxioc-agent.json（权限 0600）'; exit 1; }
for dependency in curl tar sha256sum systemctl; do command -v "$dependency" >/dev/null || { echo "缺少 $dependency"; exit 1; }; done
version=${MX_PANEL_VERSION:-v0.1.13}
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] || { echo '版本号无效'; exit 1; }
case "$(uname -m)" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo '仅支持 Linux amd64 / arm64'; exit 1;; esac
[[ $(uname -s) == Linux ]] || { echo '仅支持 Linux'; exit 1; }
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
package="mxioc-agent-$version-linux-$arch.tar.gz"
base="https://github.com/Angasky/Mx-Panel/releases/download/go-$version"
curl -fLsS --retry 3 --connect-timeout 15 --max-time 180 --proto '=https' "$base/$package" -o "$stage/$package"
curl -fLsS --retry 3 --connect-timeout 15 --max-time 60 --proto '=https' "$base/SHA256SUMS" -o "$stage/checksums"
cd "$stage"
awk -v file="$package" '$2 == file && length($1) == 64 {print}' checksums > expected
[[ $(wc -l < expected) == 1 ]] || { echo '发布包校验信息缺失或重复'; exit 1; }
sha256sum -c expected
[[ $(tar -tzf "$package" | sort) == $'SHA256SUMS\ninstall-agent.sh\nmxioc-agent' ]] || { echo '发布包文件列表异常'; exit 1; }
mkdir extracted
tar -xzf "$package" -C extracted --no-same-owner
for item in mxioc-agent install-agent.sh SHA256SUMS; do [[ -f extracted/$item && ! -L extracted/$item ]] || { echo '发布包包含异常文件'; exit 1; }; done
bash extracted/install-agent.sh
