#!/usr/bin/env bash
# Download verified prebuilt releases. No Go or Python toolchain is required.
set -Eeuo pipefail
umask 077
main() {
    [[ $EUID == 0 ]] || { echo '请以 root 运行，或使用 curl ... | sudo bash' >&2; exit 1; }
    [[ $(uname -s) == Linux && -d /run/systemd/system ]] || { echo '需要使用 systemd 的 Linux 服务器' >&2; exit 1; }
    local action=${1:-auto} version=${MX_PANEL_VERSION:-v0.1.4} arch package base stage
    [[ $action =~ ^(auto|fresh|install|update)$ ]] || { echo '用法：quick-install.sh [fresh|install|update]' >&2; exit 1; }
    [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo '版本号无效' >&2; exit 1; }
    case $(uname -m) in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo '不支持当前 CPU 架构' >&2; exit 1 ;; esac
    if ! command -v curl >/dev/null || ! command -v flock >/dev/null || ! command -v tar >/dev/null; then
        if command -v apt-get >/dev/null; then
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates tar coreutils util-linux
        elif command -v dnf >/dev/null; then
            dnf install -y curl ca-certificates tar coreutils util-linux
        elif command -v yum >/dev/null; then
            yum install -y curl ca-certificates tar coreutils util-linux
        else echo '请先安装 curl、ca-certificates、tar、coreutils、util-linux' >&2; exit 1; fi
    fi
    for tool in curl tar sha256sum awk sort cmp flock; do command -v "$tool" >/dev/null || { echo "缺少 $tool" >&2; exit 1; }; done
    if [[ $action == auto ]]; then
        if [[ -L /opt/mxioc-go/current ]]; then action=update
        elif [[ -e /opt/mxioc-rule-manager || -e /etc/mxioc-rule-manager.auth.json ]]; then action=install
        else action=fresh; fi
    fi
    if [[ $action == install ]]; then
        echo '检测到已有数据，将使用迁移模式，不覆盖账号。请先备份，并停止/禁用旧 Python 服务。'
        local answer; read -r -p '已完成备份和旧服务停用？输入 YES 继续：' answer
        [[ $answer == YES ]] || exit 1
    fi
    stage=$(mktemp -d /tmp/mx-panel-install.XXXXXXXX)
    trap "rm -rf -- $(printf '%q' "$stage")" EXIT
    package="mxioc-go-$version-linux-$arch.tar.gz"
    base="https://github.com/Angasky/Mx-Panel/releases/download/go-$version"
    echo "下载 Mx-Panel $version / $arch …"
    curl --proto '=https' --tlsv1.2 -fL --retry 3 --connect-timeout 15 "$base/$package" -o "$stage/$package"
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 15 "$base/SHA256SUMS" -o "$stage/all.sha256"
    awk -v name="$package" '$2==name && length($1)==64 && $1 !~ /[^0-9a-f]/ {print $1 "  " $2}' "$stage/all.sha256" > "$stage/SHA256SUMS"
    [[ $(wc -l < "$stage/SHA256SUMS") == 1 ]] || { echo '缺少或重复的校验值' >&2; exit 1; }
    (cd "$stage" && sha256sum --strict -c SHA256SUMS)
    printf '%s\n' ARCH SHA256SUMS VERSION index.html install-go.sh mxioc mxioc-go-release.service | LC_ALL=C sort > "$stage/expected"
    tar -tzf "$stage/$package" | LC_ALL=C sort > "$stage/actual"
    cmp -s "$stage/expected" "$stage/actual" || { echo '安装包文件清单无效' >&2; exit 1; }
    # Reject symlinks, directories, devices and hard links before extracting as root.
    tar -tvzf "$stage/$package" | awk 'substr($0,1,1)!="-" {bad=1} END {exit bad}' || { echo '安装包文件类型无效' >&2; exit 1; }
    mkdir "$stage/bundle"
    tar -xzf "$stage/$package" --no-same-owner --no-same-permissions -C "$stage/bundle"
    bash "$stage/bundle/install-go.sh" "$action"
    rm -rf -- "$stage"; trap - EXIT
    echo '安装完成。以后输入 mx-p 即可管理。'
    if [[ ${1:-auto} == auto ]]; then /usr/local/bin/mx-p; fi
}
# A piped installer still needs the terminal for password and menu prompts.
if [[ -r /dev/tty ]]; then main "$@" </dev/tty; else echo '请在 SSH 交互终端执行安装命令' >&2; exit 1; fi
