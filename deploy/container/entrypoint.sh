#!/bin/sh
set -eu
umask 077
bin=/usr/local/lib/mx-panel/mxioc
root=/var/lib/mx-panel/data
auth=/var/lib/mx-panel/auth.json
case "${1:-panel}" in
    init)
        user=${2:-admin}
        if [ -t 0 ]; then
            printf '设置管理员密码（至少 12 个字符）：' >&2
            saved_tty=$(stty -g)
            trap 'stty "$saved_tty"' EXIT HUP INT TERM
            stty -echo
        fi
        IFS= read -r password
        printf '%s\n' "$password" | "$bin" --root "$root" --auth "$auth" --bootstrap-user "$user"
        unset password
        if [ -t 0 ]; then stty "$saved_tty"; printf '\n' >&2; fi
        ;;
    panel)
        "$bin" --root "$root" --auth "$auth" --check-data
        exec "$bin" --root "$root" --auth "$auth" --admin-html /usr/local/lib/mx-panel/index.html --listen 127.0.0.1:62578 --trust-loopback-proxy
        ;;
    gateway) exec "$bin" --gateway /etc/mx-panel/access.json ;;
    check) exec "$bin" --root "$root" --auth "$auth" --check-data ;;
    *) echo '用法：init [用户名] | panel | gateway | check' >&2; exit 2 ;;
esac
