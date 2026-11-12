#!/bin/sh
# Run from an extracted release. Existing systemd data is never initialized here.
set -eu
umask 077
[ "$(id -u)" = 0 ] || { echo '请使用 root' >&2; exit 1; }
for cmd in rc-service rc-update supervise-daemon curl sha256sum flock jq; do
    command -v "$cmd" >/dev/null || { echo "缺少命令：$cmd" >&2; exit 1; }
done
[ -d /run/openrc ] || { echo '需要已启动的 OpenRC 环境' >&2; exit 1; }
exec 9>/run/mx-panel-install.lock
flock -n 9 || { echo '另一个安装任务正在运行' >&2; exit 1; }
cd "$(dirname "$0")"
mode=${1:-fresh}
case "$mode" in fresh|update) ;; *) echo '用法：install-openrc.sh fresh [管理员名] ACCESS_JSON | update' >&2; exit 2 ;; esac
base=/opt/mx-panel-openrc
data=/var/lib/mx-panel
config=/etc/mx-panel-openrc
version=$(cat VERSION)
case "$version" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo '版本无效' >&2; exit 1 ;; esac
case "$version" in *[!v0-9.]*) exit 1 ;; esac
case "$(uname -m):$(cat ARCH)" in x86_64:amd64|aarch64:arm64) ;; *) echo '安装包架构不匹配' >&2; exit 1 ;; esac
sha256sum -c SHA256SUMS
for file in mxioc index.html openrc/mx-panel openrc/mx-panel-gateway; do [ -f "$file" ] || exit 1; done
old=''
if [ "$mode" = fresh ]; then
    [ ! -e "$base" ] && [ ! -e "$data" ] && [ ! -e "$config" ] && [ ! -e /etc/init.d/mx-panel ] && [ ! -e /etc/init.d/mx-panel-gateway ] || { echo '安装目录已存在，请使用 update；不会覆盖旧数据' >&2; exit 1; }
    [ ! -e /opt/mxioc-go/current ] && [ ! -e /etc/mxioc-rule-manager.auth.json ] || { echo '检测到旧版/systemd 安装，请先按部署文档备份迁移，不可直接 fresh' >&2; exit 1; }
    [ -n "${3:-}" ] && [ -f "$3" ] || { echo 'fresh 需要指定 access.json 路径' >&2; exit 1; }
    ./mxioc --check-access "$3"
    ./mxioc --check-access-ports "$3"
    if curl -fsS --max-time 1 http://127.0.0.1:62578/healthz >/dev/null 2>&1; then echo '后台端口正在使用' >&2; exit 1; fi
    initdir=$(mktemp -d)
    if [ -t 0 ]; then
        printf '设置管理员密码（至少 12 个字符）：' >&2
        saved_tty=$(stty -g)
        trap 'stty "$saved_tty"; rm -rf "$initdir"' EXIT HUP INT TERM
        stty -echo
    fi
    [ -t 0 ] || trap 'rm -rf "$initdir"' EXIT HUP INT TERM
    IFS= read -r password
    printf '%s\n' "$password" | ./mxioc --root "$initdir/data" --auth "$initdir/auth.json" --bootstrap-user "${2:-admin}"
    unset password
    if [ -t 0 ]; then stty "$saved_tty"; printf '\n' >&2; trap - EXIT HUP INT TERM; fi
    getent group mxpanel >/dev/null 2>&1 || addgroup -S mxpanel
    id mxpanel >/dev/null 2>&1 || adduser -S -D -H -G mxpanel -h "$data" -s /sbin/nologin mxpanel
    mkdir -p "$data" "$config" "$base/releases"
    cp -R "$initdir/data" "$initdir/auth.json" "$data/"
    cp "$3" "$config/access.json"
    chmod 600 "$config/access.json"
    chown -R mxpanel:mxpanel "$data"
    rm -rf "$initdir"
    trap - EXIT HUP INT TERM
else
    [ -L "$base/current" ] && [ -f "$data/auth.json" ] || { echo '未找到 OpenRC 安装' >&2; exit 1; }
    old=$(readlink "$base/current")
    ./mxioc --root "$data/data" --auth "$data/auth.json" --check-data
fi
release=$(mktemp -d "$base/releases/$version.XXXXXXXX")
cp mxioc index.html VERSION "$release/"
chmod 755 "$base" "$base/releases" "$release" "$release/mxioc"
chmod 644 "$release/index.html" "$release/VERSION"
update_started=false
backup=''
rollback() {
    code=$?
    trap - EXIT HUP INT TERM
    if [ "$update_started" = true ]; then
        rc-service mx-panel-gateway stop 9>&- || true
        rc-service mx-panel stop 9>&- || true
        ln -s "$old" "$base/.rollback-$$"
        mv -Tf "$base/.rollback-$$" "$base/current"
        if [ -n "$backup" ] && [ -s "$backup" ]; then
            tar -xzf "$backup" -C / etc/init.d/mx-panel etc/init.d/mx-panel-gateway || true
        fi
        rc-service mx-panel start 9>&- && rc-service mx-panel-gateway start 9>&- || true
        echo '更新失败，已尝试恢复旧程序；请检查服务状态和日志。' >&2
    fi
    exit "$code"
}
trap rollback EXIT
trap 'exit 1' HUP INT TERM
if [ "$mode" = update ]; then
    update_started=true
    rc-service mx-panel-gateway stop 9>&- || exit 1
    rc-service mx-panel stop 9>&- || exit 1
    mkdir -p /var/backups/mx-panel
    backup=/var/backups/mx-panel/openrc-$(date -u +%Y%m%dT%H%M%SZ)-$$.tar.gz
    tar -czf "$backup" "$data" "$config" /etc/init.d/mx-panel /etc/init.d/mx-panel-gateway
    chmod 600 "$backup"
    echo "备份：$backup"
fi
cp openrc/mx-panel /etc/init.d/mx-panel
cp openrc/mx-panel-gateway /etc/init.d/mx-panel-gateway
chmod 755 /etc/init.d/mx-panel /etc/init.d/mx-panel-gateway
ln -s "$release" "$base/.current-$$"
mv -Tf "$base/.current-$$" "$base/current"
rc-update add mx-panel default
rc-update add mx-panel-gateway default
ok=false
if rc-service mx-panel start 9>&- && rc-service mx-panel-gateway start 9>&-; then
    count=0
    while [ "$count" -lt 30 ]; do
        if curl -fsS --max-time 2 http://127.0.0.1:62578/healthz | grep -F "\"version\":\"$version\"" >/dev/null; then ok=true; break; fi
        count=$((count+1)); sleep 1
    done
fi
if [ "$ok" != true ]; then
    rc-service mx-panel-gateway stop 9>&- || true
    rc-service mx-panel stop 9>&- || true
    echo '启动失败；更新已尝试回退旧程序，请检查 /var/log/mx-panel' >&2
    exit 1
fi
if [ "$(jq -r '.domain' "$config/access.json")" = false ]; then
    port=$(jq -r '.port' "$config/access.json")
    curl -fkSs --retry 5 --retry-connrefused --retry-delay 1 --max-time 5 "https://127.0.0.1:$port/healthz" >/dev/null
fi
update_started=false
echo "Mx-Panel $version 已运行。OpenRC 管理使用 rc-service；更新请运行新发布包的 install-openrc.sh update。"
