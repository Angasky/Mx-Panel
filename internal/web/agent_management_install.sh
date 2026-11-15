#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077
[[ $EUID == 0 ]] || { echo '请使用 root 执行管理授权'; exit 1; }
for dep in curl sed base64 flock install awk grep tr; do command -v "$dep" >/dev/null || { echo "缺少依赖：$dep，请安装 openssh-client / openssh-clients 后重试"; exit 1; }; done
config=/etc/mxioc-agent.json
[[ -f "$config" && ! -L "$config" ]] || { echo '请先安装本面板 Agent'; exit 1; }
url=$(sed -nE 's/.*"url"[[:space:]]*:[[:space:]]*"(https:\/\/[^" ]+)".*/\1/p' "$config")
token=$(sed -nE 's/.*"token"[[:space:]]*:[[:space:]]*"([A-Za-z0-9_-]{43})".*/\1/p' "$config")
[[ "$url" =~ ^(https://[A-Za-z0-9.-]+(:[0-9]+)?)/sub/agent/([a-f0-9]{24})$ && "$token" =~ ^[A-Za-z0-9_-]{43}$ ]] || { echo 'Agent 配置格式或来源无效'; exit 1; }
origin=${BASH_REMATCH[1]:-}
# Match URL again: the token expression must not overwrite captures.
[[ "$url" =~ ^(https://[A-Za-z0-9.-]+(:[0-9]+)?)/sub/agent/([a-f0-9]{24})$ ]]
origin=${BASH_REMATCH[1]}; id=${BASH_REMATCH[3]}
exec 8>/run/mxioc-agent-management.lock
flock -n 8 || { echo '另一个管理授权正在运行'; exit 1; }
if ! command -v sshd >/dev/null || ! command -v ssh-keygen >/dev/null; then
 echo '正在安装 SSH 管理依赖…'
 if command -v apt-get >/dev/null; then
  DEBIAN_FRONTEND=noninteractive apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server openssh-client
 elif command -v dnf >/dev/null; then dnf install -y openssh-server openssh-clients
 elif command -v yum >/dev/null; then yum install -y openssh-server openssh-clients
 else echo '无法自动安装 SSH 服务，请安装 openssh-server 后重试'; exit 1; fi
 if systemctl cat ssh.service >/dev/null 2>&1; then systemctl enable --now ssh.service; else systemctl enable --now sshd.service; fi
fi
sshd=$(command -v sshd || true)
[[ -n "$sshd" ]] || { echo '未安装 SSH 服务，请安装 openssh-server 并启动 SSH 后重试；不会仅根据监控在线宣称能安装内核。'; exit 1; }
settings=$("$sshd" -T) || { echo 'SSH 配置检查失败'; exit 1; }
port=$(awk '$1=="port" {print $2;exit}' <<< "$settings")
[[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]] || exit 1
fingerprint=''
while read -r key path; do
 [[ "$key" == hostkey && -f "$path.pub" ]] || continue
 fingerprint=$(ssh-keygen -lf "$path.pub" -E sha256 | awk '{print $2}')
 [[ "$fingerprint" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]] && break
done <<< "$settings"
[[ "$fingerprint" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]] || { echo '无法读取 SSH 主机指纹'; exit 1; }
[[ " $(awk '$1=="authorizedkeysfile" {$1="";print}' <<< "$settings") " == *'.ssh/authorized_keys'* ]] || { echo 'SSH 使用自定义 authorized_keys 路径，请管理员手动接入'; exit 1; }
state=/var/lib/mxioc-agent-management
[[ ! -L "$state" ]] || exit 1
install -d -m 0700 "$state"
for file in "$state/key" "$state/key.pub" /root/.ssh /root/.ssh/authorized_keys; do [[ ! -L "$file" ]] || { echo '管理密钥路径为符号链接，停止'; exit 1; }; done
if [[ ! -e "$state/key" ]]; then ssh-keygen -q -t ed25519 -N '' -C "mx-panel-agent-$id" -f "$state/key"; fi
public=$(ssh-keygen -y -f "$state/key" | awk '{print $1 " " $2}')
install -d -m 0700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 0600 /root/.ssh/authorized_keys
if ! grep -Fq -- "$public" /root/.ssh/authorized_keys; then printf '\nno-agent-forwarding,no-port-forwarding,no-X11-forwarding %s mx-panel-agent-%s\n' "$public" "$id" >> /root/.ssh/authorized_keys; fi
stage=$(mktemp -d /var/tmp/mxioc-management.XXXXXXXX)
trap 'rm -rf -- "$stage"' EXIT
printf 'Authorization: Bearer %s\n' "$token" > "$stage/auth"
unset token
private=$(base64 < "$state/key" | tr -d '\n')
printf '{"privateKeyBase64":"%s","fingerprint":"%s","port":%s}' "$private" "$fingerprint" "$port" > "$stage/request"
unset private
echo "正在验证独立管理密钥与 SSH 端口 $port…"
if ! curl -fsS --connect-timeout 15 --max-time 50 --proto '=https' -H "@$stage/auth" -H 'Content-Type: application/json' --data-binary "@$stage/request" "$origin/sub/agent-manage/$id" -o "$stage/result"; then
 echo '管理接入未完成：请确认面板能访问此机 SSH 端口、允许 root 公钥登录；NAT/端口映射请通过面板连接设置接入。Agent 监控保持运行，可重新执行授权命令。'
 exit 1
fi
grep -Eq '"ok"[[:space:]]*:[[:space:]]*true' "$stage/result" || { echo '管理授权未确认'; exit 1; }
echo '管理接入完成：可在服务器卡片安装 Xray / sing-box，创建节点和中转。'
