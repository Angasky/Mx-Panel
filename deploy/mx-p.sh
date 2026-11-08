#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
base=/opt/mxioc-go
current=$base/current
access=$base/access.json
gateway_unit=/etc/systemd/system/mx-p-gateway.service
[[ $EUID == 0 ]] || { echo '请执行 sudo mx-p'; exit 1; }
[[ -t 0 ]] || { echo '管理菜单需要交互终端'; exit 1; }
fail() { echo "$*" >&2; return 1; }
confirm() { local answer; read -r -p "$1 输入 YES 确认：" answer; [[ $answer == YES ]]; }
backup() {
    local target
    install -d -m 0700 /var/backups/mx-panel
    target=$(mktemp /var/backups/mx-panel/data-XXXXXXXX.tar.gz)
    tar -czf "$target" -C / opt/mxioc-rule-manager etc/mxioc-rule-manager.auth.json || { rm -f "$target"; return 1; }
    echo "数据和凭据已备份至 $target（仅 root 可读）"
}
upgrade() (
    local script
    script=$(mktemp); trap 'rm -f "$script"' EXIT
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 15 \
      https://raw.githubusercontent.com/Angasky/Mx-Panel/main/deploy/quick-install.sh -o "$script"
    bash "$script" update
)
reset_auth() (
    exec 9>/run/lock/mxioc-go-release.lock
    flock -n 9 || { fail '已有安装或维护任务'; exit 1; }
    local username password repeat active=0
    read -r -p '新管理员用户名：' username
    read -rs -p '新密码（至少 12 字符）：' password; echo
    read -rs -p '再次输入密码：' repeat; echo
    [[ $password == "$repeat" ]] || { fail '两次密码不一致'; exit 1; }
    systemctl is-active --quiet mxioc-go.service && active=1
    trap 'if (( active )); then systemctl start mxioc-go.service; fi' EXIT
    systemctl stop mxioc-go.service
    printf '%s\n' "$password" | "$current/mxioc" --reset-auth-user "$username"
    unset password repeat
    echo '管理员凭据已重置，旧登录会话已失效。'
)
configure_access() (
    exec 9>/run/lock/mxioc-go-release.lock
    flock -n 9 || { fail '已有安装或维护任务'; exit 1; }
    local mode=$1 host port email='' domain=false stage was_active=0 success=0
    if [[ $mode == domain ]]; then
        read -r -p '已解析到本机的域名（英文或 punycode）：' host
        [[ $host =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] || { fail '域名格式无效'; exit 1; }
        read -r -p '证书通知邮箱：' email
        [[ $email =~ ^[a-zA-Z0-9._+%-]+@[a-zA-Z0-9.-]+$ ]] || { fail '邮箱格式无效'; exit 1; }
        echo '域名需解析到本机；请放行 TCP 80/443。自动证书由 Let’s Encrypt 签发和续期。'
        confirm '同意 Let’s Encrypt 服务条款并配置 HTTPS？' || exit 0
        port=443; domain=true
    else
        read -r -p '浏览器访问本机使用的 IP 地址：' host
        [[ $host =~ ^[0-9a-fA-F:.]+$ ]] || { fail 'IP 格式无效'; exit 1; }
        port=5656
        if [[ $mode == ip ]]; then read -r -p 'HTTPS 端口 [5656]：' port; port=${port:-5656}; fi
        [[ $port =~ ^[0-9]{1,5}$ ]] && ((10#$port>=1 && 10#$port<=65535 && 10#$port!=62578)) || { fail '端口无效'; exit 1; }
        port=$((10#$port))
        echo 'IP 模式使用本机自签名证书，浏览器会提示证书不受信任。域名 HTTPS 模式可避免此提示。'
    fi
    [[ ! -e $gateway_unit ]] || grep -Fqx '# Managed by mx-p' "$gateway_unit" || { fail '同名服务不属于 mx-p'; exit 1; }
    stage=$(mktemp -d "$base/.access.XXXXXXXX")
    for file in ip.crt ip.key; do [[ ! -e $base/certificates/$file ]] || cp -p "$base/certificates/$file" "$stage/$file"; done
    [[ ! -e $access ]] || cp -p "$access" "$stage/old.json"
    [[ ! -e $gateway_unit ]] || cp -p "$gateway_unit" "$stage/old.service"
    systemctl is-active --quiet mx-p-gateway.service && was_active=1
    restore() {
        local rc=$?
        if (( ! success )); then
            systemctl stop mx-p-gateway.service || true
            for file in ip.crt ip.key; do
                if [[ -f $stage/$file ]]; then cp -p "$stage/$file" "$base/certificates/$file"; else rm -f "$base/certificates/$file"; fi
            done
            if [[ -f $stage/old.json ]]; then cp -p "$stage/old.json" "$access"; else rm -f "$access"; fi
            if [[ -f $stage/old.service ]]; then cp -p "$stage/old.service" "$gateway_unit"; else systemctl disable mx-p-gateway.service 2>/dev/null || true; rm -f "$gateway_unit"; fi
            systemctl daemon-reload
            if (( was_active )); then systemctl start mx-p-gateway.service || { echo "网关恢复失败，保留 $stage" >&2; exit 1; }; fi
        fi
        rm -rf "$stage"
        exit "$rc"
    }
    trap restore EXIT
    printf '{"host":"%s","port":"%s","email":"%s","domain":%s}\n' "$host" "$port" "$email" "$domain" > "$stage/new.json"
    "$current/mxioc" --check-access "$stage/new.json"
    systemctl stop mx-p-gateway.service 2>/dev/null || true
    "$current/mxioc" --check-access-ports "$stage/new.json"
    install -m 0600 "$stage/new.json" "$access"
    cat > "$gateway_unit" <<'UNIT'
# Managed by mx-p
[Unit]
Description=Mx-Panel HTTPS gateway
After=network-online.target mxioc-go.service
Wants=network-online.target mxioc-go.service
[Service]
ExecStart=/opt/mxioc-go/current/mxioc --gateway /opt/mxioc-go/access.json
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now mx-p-gateway.service
    local urlhost=$host
    [[ $host != *:* ]] || urlhost="[$host]"
    if [[ $domain == true ]]; then
        # Resolve locally for verification without disabling certificate validation.
        curl --proto '=https' -fsS --retry 4 --retry-connrefused --retry-delay 2 --max-time 90 \
            --resolve "$host:443:127.0.0.1" "https://$host/healthz" >/dev/null
    else
        # Trust exactly our generated local certificate, not arbitrary certificates.
        local attempt healthy=0
        for attempt in {1..20}; do
            if [[ -f $base/certificates/ip.crt ]] && curl -fsS --max-time 2 --cacert "$base/certificates/ip.crt" \
                --connect-to "$urlhost:$port:127.0.0.1:$port" "https://$urlhost:$port/healthz" >/dev/null; then healthy=1; break; fi
            sleep 1
        done
        (( healthy )) || { fail 'HTTPS 检查失败'; exit 1; }
    fi
    success=1
    echo "访问地址：https://$urlhost:$port/admin/"
)
remove_panel() {
    local purge=$1
    backup
    if [[ $purge == 1 ]]; then
        confirm '彻底卸载并删除订阅数据和管理员凭据（保留刚生成的备份）？' || return 0
    else
        confirm '卸载管理器并保留全部数据？' || return 0
    fi
    local release
    release=$(readlink -f "$current")
    MXIOC_GO_EXPECT_CURRENT="$release" MXIOC_GO_PURGE_DATA="$purge" bash "$current/install-go.sh" uninstall
    if [[ -f $gateway_unit ]] && grep -Fqx '# Managed by mx-p' "$gateway_unit"; then
        systemctl disable --now mx-p-gateway.service
        rm -f "$gateway_unit"; systemctl daemon-reload
    fi
    if [[ -f /usr/local/bin/mx-p ]] && grep -Fqx '# Managed by Mx-Panel' /usr/local/bin/mx-p; then rm -f /usr/local/bin/mx-p; fi
    echo '卸载完成；未删除远端代理节点。'
    exit 0
}
while true; do
    printf '\n===== Mx-Panel 管理菜单 =====\n'
    printf ' 1) IP HTTPS 部署\n 2) 域名 HTTPS（自动申请/续期证书）\n 3) 极速部署（IP HTTPS，5656 端口）\n 4) 升级 / 修复\n 5) 重置管理员凭据\n 6) 卸载并保留数据\n 7) 彻底卸载（先备份）\n 8) 服务状态\n 9) 重启服务\n10) 查看日志\n11) 备份数据\n 0) 退出\n'
    read -r -p '请选择 [0-11]：' choice || exit 0
    case $choice in
        1) configure_access ip ;;
        2) configure_access domain ;;
        3) configure_access fast ;;
        4) upgrade ;;
        5) reset_auth ;;
        6) remove_panel 0 ;;
        7) remove_panel 1 ;;
        8) systemctl status mxioc-go.service --no-pager || true; if [[ -f $gateway_unit ]]; then systemctl status mx-p-gateway.service --no-pager || true; fi ;;
        9) systemctl restart mxioc-go.service; if [[ -f $gateway_unit ]]; then systemctl restart mx-p-gateway.service; fi ;;
        10) journalctl -u mxioc-go.service -u mx-p-gateway.service -n 100 --no-pager ;;
        11) backup ;;
        0) exit 0 ;;
        *) echo '无效选项' ;;
    esac
done
