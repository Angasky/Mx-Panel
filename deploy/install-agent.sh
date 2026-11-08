#!/usr/bin/env bash
set -euo pipefail
# Installs only the monitoring agent; no proxy configuration is changed.
[[ $EUID == 0 ]] || { echo '请使用 root 执行'; exit 1; }
cd "$(dirname "$0")"
[[ -f mxioc-agent && -f SHA256SUMS ]] || { echo '请先解压完整发布包'; exit 1; }
sha256sum --check --ignore-missing SHA256SUMS
[[ -f /etc/mxioc-agent.json && ! -L /etc/mxioc-agent.json ]] || { echo '请先将面板下载的 Agent 配置保存到 /etc/mxioc-agent.json'; exit 1; }
chmod 600 /etc/mxioc-agent.json
./mxioc-agent --config /etc/mxioc-agent.json --check
mapfile -t writable_dirs < <(./mxioc-agent --config /etc/mxioc-agent.json --systemd-paths)
[[ ${#writable_dirs[@]} -gt 0 ]] || { echo "无法读取 Agent 管理目录"; exit 1; }
backup=$(mktemp -d)
trap 'rm -rf -- "$backup"' EXIT
was_active=false
systemctl is-active --quiet mxioc-agent.service && was_active=true
for item in /usr/local/bin/mxioc-agent /etc/systemd/system/mxioc-agent.service; do
    if [[ -e "$item" ]]; then cp -p "$item" "$backup/$(basename "$item")"; fi
done
rollback() {
    trap - ERR
    systemctl stop mxioc-agent.service || true
    for item in /usr/local/bin/mxioc-agent /etc/systemd/system/mxioc-agent.service; do
        if [[ -f "$backup/$(basename "$item")" ]]; then cp -p "$backup/$(basename "$item")" "$item"; else rm -f "$item"; fi
    done
    systemctl daemon-reload || true
    if $was_active; then systemctl start mxioc-agent.service || true; fi
    echo 'Agent 安装失败，已恢复原二进制和服务文件。请检查配置和日志。' >&2
    exit 1
}
trap rollback ERR
install -m 0755 mxioc-agent /usr/local/bin/mxioc-agent
cat > /etc/systemd/system/mxioc-agent.service <<'UNIT'
[Unit]
Description=Mx-Panel monitoring agent
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/mxioc-agent --config /etc/mxioc-agent.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/run
[Install]
WantedBy=multi-user.target
UNIT
# Directories originate only from the root-owned local configuration, validated by the Agent.
{
 printf '\n[Service]\nReadWritePaths='
 printf '%s ' "${writable_dirs[@]}"
 printf '\n'
} >> /etc/systemd/system/mxioc-agent.service
systemctl daemon-reload
systemctl restart mxioc-agent.service
sleep 2
systemctl is-active --quiet mxioc-agent.service
systemctl enable mxioc-agent.service
trap - ERR
printf 'Agent 进程已运行，请回到面板核对连接状态。\n'
