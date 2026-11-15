#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077
[[ $EUID == 0 ]] || { echo '请使用 root 执行安装命令'; exit 1; }
[[ $(uname -s) == Linux ]] || { echo '仅支持 Linux'; exit 1; }
for dep in curl tar sha256sum flock systemctl install od tr cmp base64; do command -v "$dep" >/dev/null || { echo "缺少依赖：$dep"; exit 1; }; done
[[ -d /run/systemd/system ]] || { echo '需要 systemd 服务管理器'; exit 1; }
origin=${1:-}; enrollment=${2:-}
[[ "$origin" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ && "$enrollment" =~ ^[a-f0-9]{24}$ ]] || { echo '接入参数无效'; exit 1; }
IFS= read -r enrollment_token
[[ "$enrollment_token" =~ ^[A-Za-z0-9_-]{43}$ ]] || { echo '接入凭据无效'; exit 1; }
exec 9>/run/mxioc-agent-install.lock
flock -n 9 || { echo '另一个 Agent 安装正在运行'; exit 1; }
state=/var/lib/mxioc-agent-enroll
[[ ! -L "$state" ]] || { echo '安装状态目录异常'; exit 1; }
install -d -m 0700 "$state"
state="$state/$enrollment"
[[ ! -L "$state" ]] || exit 1
install -d -m 0700 "$state"
for item in client config; do [[ ! -L "$state/$item" ]] || exit 1; done
if [[ ! -f "$state/client" ]]; then od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "$state/client"; fi
client=$(cat "$state/client")
[[ "$client" =~ ^[a-f0-9]{64}$ ]] || exit 1
existing=false
if [[ -e /etc/mxioc-agent.json || -L /etc/mxioc-agent.json || -e /usr/local/bin/mxioc-agent || -L /usr/local/bin/mxioc-agent || -e /etc/systemd/system/mxioc-agent.service || -L /etc/systemd/system/mxioc-agent.service ]]; then
 for item in /etc/mxioc-agent.json /usr/local/bin/mxioc-agent /etc/systemd/system/mxioc-agent.service; do [[ -f "$item" && ! -L "$item" ]] || { echo '发现已有或不完整的 Agent 安装，请先核对，不会覆盖'; exit 1; }; done
 [[ -f "$state/config" ]] && cmp -s "$state/config" /etc/mxioc-agent.json || { echo '已有其他 Agent 配置，不会覆盖。请在原面板核对后手动迁移。'; exit 1; }
 existing=true
fi
stage=$(mktemp -d /var/tmp/mxioc-enroll.XXXXXXXX)
trap 'rm -rf -- "$stage"' EXIT
printf 'Authorization: Bearer %s\n' "$enrollment_token" > "$stage/auth"
unset enrollment_token
detected_hostname=$(hostname 2>/dev/null || uname -n)
hostname_encoded=$(printf '%s' "$detected_hostname" | base64 | tr -d '\n')
printf '{"id":"%s","client":"%s","hostnameBase64":"%s"}' "$enrollment" "$client" "$hostname_encoded" > "$stage/request"
if ! $existing; then
 [[ -z $(systemctl show mxioc-agent.service -p FragmentPath --value 2>/dev/null) ]] || { echo '发现非标准位置的已有 Agent 服务，不会覆盖'; exit 1; }
 case "$(uname -m)" in
  x86_64) arch=amd64; digest=a14c108a292848b7e819bb4e8f5a65c238bbe8ad0eca72af197a9cbf865125d2;;
  aarch64|arm64) arch=arm64; digest=e4ac5ca8880b17b273e28294f80cc19822c734e381c4cd66590024bc8f6f09cf;;
  *) echo '仅支持 amd64 / arm64'; exit 1;;
 esac
 package="mxioc-agent-v0.1.35-linux-$arch.tar.gz"
 echo '正在下载并校验 Agent…'
 curl -fLsS --retry 2 --connect-timeout 15 --max-time 180 --proto '=https' --proto-redir '=https' "https://github.com/Angasky/Mx-Panel/releases/download/go-v0.1.35/$package" -o "$stage/$package"
 (cd "$stage" && printf '%s  %s\n' "$digest" "$package" | sha256sum -c -)
 [[ $(tar -tzf "$stage/$package" | LC_ALL=C sort) == $'SHA256SUMS\ninstall-agent.sh\nmxioc-agent' ]] || { echo '发布包文件清单异常'; exit 1; }
 tar -xOf "$stage/$package" mxioc-agent > "$stage/mxioc-agent"
 chmod 700 "$stage/mxioc-agent"
fi
claim() {
 curl -fsS --connect-timeout 15 --max-time 30 --proto '=https' -H "@$stage/auth" -H 'Content-Type: application/json' --data-binary "@$stage/request" "$origin/sub/agent-enroll" -D "$stage/headers" -o "$stage/config"
}
echo '正在登记服务器…'
claim || { echo '登记失败：令牌可能已撤销或旧命令过期或面板被人机验证拦截。可重新运行命令，或在面板生成新命令。'; exit 1; }
validator="$stage/mxioc-agent"; $existing && validator=/usr/local/bin/mxioc-agent
"$validator" --config "$stage/config" --check
if $existing; then
 cmp -s "$stage/config" /etc/mxioc-agent.json || { echo '已安装配置与登记响应不一致，停止操作'; exit 1; }
else
 install -m 0600 "$stage/config" "$state/config"
 # Never replace an existing installation; remove only newly created files on failure.
 rollback() {
  trap - ERR HUP INT TERM
  systemctl disable --now mxioc-agent.service 9>&- >/dev/null 2>&1 || true
  rm -f /etc/mxioc-agent.json /usr/local/bin/mxioc-agent /etc/systemd/system/mxioc-agent.service
  systemctl daemon-reload 9>&- || true
  echo '安装失败，已移除本次新建的服务文件；登记记录保留，可使用原命令重试。'
  exit 1
 }
 trap rollback ERR HUP INT TERM
 install -m 0600 "$state/config" /etc/mxioc-agent.json
 install -m 0755 "$stage/mxioc-agent" /usr/local/bin/mxioc-agent
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
[Install]
WantedBy=multi-user.target
UNIT
 systemctl daemon-reload 9>&-
 systemctl enable --now mxioc-agent.service 9>&-
 trap - ERR HUP INT TERM
fi
systemctl is-active --quiet mxioc-agent.service || { echo 'Agent 未运行，请检查 systemctl status mxioc-agent'; exit 1; }
echo '等待面板确认收到 Agent 心跳…'
for attempt in {1..12}; do
 if claim && grep -qi '^X-Mxioc-Agent-Connected: true' "$stage/headers"; then
  # Keep the installation identity and config for idempotent reruns.
  chmod 600 "$state/client" "$state/config"
  echo '接入成功：面板已收到心跳，服务器已自动加入列表。无需开放入站端口或提供 SSH 密码。'
  exit 0
 fi
 sleep 3
done
echo 'Agent 服务已安装，但面板尚未确认心跳。请检查网络、Cloudflare 验证和 journalctl -u mxioc-agent；勿将进程运行视为接入成功。'
exit 1
